import shutil
import sys
from pathlib import Path

from lib4sbom.data.document import SBOMDocument
from lib4sbom.data.package import SBOMPackage
from lib4sbom.data.relationship import SBOMRelationship

from sbom4windows.extract import ExtractFile


class SBOMScanner:

    def __init__(self, directory, debug=False):
        self.directory = directory
        self.debug = debug
        self.DLLlist = []
        self.temp_cab_dir = ".cab_dump"
        self.temp_msi_dir = ".msi_dump"
        self.extract = ExtractFile()
        self.relationships = []
        self.sbom_packages = {}
        self.parent = "windows-installation"

    def _process_cabfile(self, item, file=""):
        Path(self.temp_cab_dir).mkdir(parents=True, exist_ok=True)
        if self.debug:
            print(f"Extract {item} to {self.temp_cab_dir}")
        self.extract.extract_file_cab(item, self.temp_cab_dir)
        # Now process extracted files
        for cab_item in Path(self.temp_cab_dir).glob("**/*"):
            if str(cab_item).endswith(".dll"):
                # Process DLL
                if file == "":
                    if self.debug:
                        print(f"[CAB1] Process DLL {cab_item}")
                    self._process_dllfile(item, cab_item)
                else:
                    if self.debug:
                        print(f"[CAB1] Process DLL {cab_item} within {file}")
                    self._process_dllfile(item, file, cab_item)
            elif str(cab_item).endswith(".cab"):
                print(f"[CAB1] Need to process {str(cab_item)}")
            elif self.debug:
                print(f"[CAB1] Not processing {str(cab_item)}")
        shutil.rmtree(self.temp_cab_dir, ignore_errors=True)

    def _process_dllfile(self, item, file="", b=""):
        if b != "":
            info = self.extract.extract_file_dll(b)
        elif file != "":
            info = self.extract.extract_file_dll(file)
        else:
            info = self.extract.extract_file_dll(item)
        # print (info)
        if len(info) > 0:
            component_details = self.extract.process_dll(info)
            # print (component_details)
            if file != "":
                file = str(file.name)
            if b != "":
                b = str(b.name)
            self.DLLlist.append([str(item.name), file, b, component_details])
            # os.removedirs(temp_msi_dir)

    def process_directory(self):
        file_dir = Path(self.directory)
        if not file_dir.exists():
            if self.debug:
                print("[ERROR] Directory not found.")
            return -1
        for item in file_dir.glob("**/*"):
            # print (item)
            if str(item).endswith(".msi"):
                files = self.extract.extract_file_msi(item, self.temp_msi_dir)
                if files is not None:
                    # Now process files
                    for file in Path(self.temp_msi_dir).glob("**/*"):
                        # print (f"Process {file}")
                        if str(file).endswith(".cab"):
                            # self._process_cabfile(file, item)
                            if self.debug:
                                print(f"Process {file}")
                            Path(self.temp_cab_dir).mkdir(parents=True, exist_ok=True)
                            # print (f"Extract to {temp_cab_dir}")
                            self.extract.extract_file_cab(file, self.temp_cab_dir)
                            # Now process extracted files
                            for cab_item in Path(self.temp_cab_dir).glob("**/*"):
                                if str(cab_item).endswith(".dll"):
                                    # Process DLL
                                    self._process_dllfile(item, file, cab_item)
                                elif str(cab_item).endswith(".cab"):
                                    if self.debug:
                                        print(f"[CAB] Need to process {str(cab_item)}")
                                elif self.debug:
                                    print(f"[CAB] Not processing {str(cab_item)}")
                            shutil.rmtree(self.temp_cab_dir, ignore_errors=True)
                        elif self.debug:
                            print(f"[MSI] Not processing {file}")
                    shutil.rmtree(self.temp_msi_dir, ignore_errors=True)
            elif str(item).endswith(".cab"):
                # print (f"Process {file}")
                self._process_cabfile(item)
            elif str(item).endswith(".dll"):
                # Process DLL
                self._process_dllfile(item)
            elif self.debug:
                print(f"Not processing {str(item)}")
        self._build()
        return 0

    def process_system(self):
        # System directory
        if sys.platform == "win32":
            self.process_directory("c:\\windows\\system32")

    def _build(self):
        self.sbom_relationship = SBOMRelationship()
        my_package = SBOMPackage()
        application = self.parent
        application_id = "CDXRef-DOCUMENT"
        self.sbom_relationship.initialise()
        self.sbom_relationship.set_relationship(
            application_id, "DESCRIBES", application
        )
        self.sbom_relationship.set_relationship_id(None, application_id)
        self.relationships.append(self.sbom_relationship.get_relationship())
        # Create packages
        component_ids = {}
        for d in self.DLLlist:
            component = d[3]
            if "name" in component:
                # Add self.relationships
                if d[1] != "":
                    if component_ids.get((d[0].lower(), "NOTKNOWN")) is None:
                        my_package.initialise()
                        my_package.set_type("file")
                        my_package.set_name(d[0].lower())
                        my_package.set_version("NOTKNOWN")
                        my_package.set_licensedeclared("NOTKNOWN")
                        self.sbom_packages[
                            (my_package.get_name(), my_package.get_value("version"))
                        ] = my_package.get_package()
                        d0_id = my_package.get_value("id")
                        component_ids[(d[0].lower(), "NOTKNOWN")] = d0_id
                    else:
                        d0_id = component_ids.get((d[0], "NOTKNOWN"))
                    self.sbom_relationship.initialise()
                    self.sbom_relationship.set_relationship(
                        application, "DEPENDS_ON", my_package.get_value("name")
                    )
                    self.sbom_relationship.set_relationship_id(application_id, d0_id)
                    self.relationships.append(self.sbom_relationship.get_relationship())
                    parent = d[0].lower()
                    parent_id = d0_id
                else:
                    parent = application
                    parent_id = application_id
                #
                if d[1] != "":
                    if component_ids.get((d[1].lower(), "NOTKNOWN")) is None:
                        my_package.initialise()
                        my_package.set_type("file")
                        my_package.set_name(d[1].lower())
                        my_package.set_version("NOTKNOWN")
                        my_package.set_licensedeclared("NOTKNOWN")
                        self.sbom_packages[
                            (my_package.get_name(), my_package.get_value("version"))
                        ] = my_package.get_package()
                        d1_id = my_package.get_value("id")
                        component_ids[(d[1].lower(), "NOTKNOWN")] = d1_id
                    else:
                        d1_id = component_ids.get((d[1], "NOTKNOWN"))
                    self.sbom_relationship.initialise()
                    self.sbom_relationship.set_relationship(
                        d[0], "DEPENDS_ON", my_package.get_value("name")
                    )
                    self.sbom_relationship.set_relationship_id(d0_id, d1_id)
                    self.relationships.append(self.sbom_relationship.get_relationship())
                    parent = d[1].lower()
                    parent_id = d1_id
                #
                my_package.initialise()

                my_package.set_name(component["name"].lower())
                my_package.set_type("library")
                if "productversion" in component:
                    my_package.set_version(component["productversion"])
                if "companyname" in component:
                    my_package.set_supplier("organisation", component["companyname"])
                if "legalcopyright" in component:
                    my_package.set_copyrighttext(component["legalcopyright"])
                if "filedescription" in component:
                    my_package.set_description(component["filedescription"])
                if "cpu" in component:
                    my_package.set_property("cpu", component["cpu"])
                if "created" in component:
                    my_package.set_property("created", component["created"])
                my_package.set_licensedeclared("NOTKNOWN")
                # my_package.set_checksum("MD5", hex(int(component["checksum"])))
                my_package.set_evidence(d[0])
                if d[1] != "":
                    my_package.set_evidence(d[1])
                if d[2] != "":
                    my_package.set_evidence(d[2])
                self.sbom_packages[
                    (my_package.get_name(), my_package.get_value("version"))
                ] = my_package.get_package()
                self.sbom_relationship.initialise()
                self.sbom_relationship.set_relationship(
                    parent, "DEPENDS_ON", my_package.get_value("name")
                )
                self.sbom_relationship.set_relationship_id(
                    parent_id, my_package.get_value("id")
                )
                self.relationships.append(self.sbom_relationship.get_relationship())

    def set_parent(self, name):
        self.parent = name.replace(" ", "_")

    def get_parent(self):
        return self.parent

    def get_document(self):
        my_doc = SBOMDocument()
        my_doc.set_value("lifecycle", "build")
        return my_doc.get_document()

    def get_packages(self):
        return self.sbom_packages

    def get_relationships(self):
        return self.relationships
