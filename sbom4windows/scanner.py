# Copyright (C) 2025 Anthony Harrison
# SPDX-License-Identifier: Apache-2.0

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
        self.DLLdeps = {}
        self.temp_cab_dir = ".cab_dump"
        self.temp_msi_dir = ".msi_dump"
        self.extract = ExtractFile()
        self.relationships = []
        self.sbom_packages = {}
        self.parent = "windows-installation"

    def _is_pefile(self, item):
        extensions = [
            ".acm",
            ".ax",
            ".cpl",
            ".dll",
            ".drv",
            ".efi",
            ".exe",
            ".mui",
            ".ocx",
            ".scr",
            ".sys",
            ".tsp",
            ".mun",
            ".msstyles",
        ]
        file = str(item).lower()
        for extension in extensions:
            if file.endswith(extension):
                # if self.debug:
                #     print (f"{item} has extension {extension}")
                return True
        return False

    def _process_cabfile(self, item, file=""):
        Path(self.temp_cab_dir).mkdir(parents=True, exist_ok=True)
        if self.debug:
            print(f"Extract {item} to {self.temp_cab_dir}")
        self.extract.extract_file_cab(item, self.temp_cab_dir)
        # Now process extracted files
        for cab_item in Path(self.temp_cab_dir).glob("**/*"):
            if self._is_pefile(cab_item):
                if self.debug:
                    print(f"[CAB1] Process PEFILE {cab_item}")
                if file == "":
                    if self.debug:
                        print(f"[CAB1] Process PEFILE {cab_item}")
                    self._process_pefile(item, cab_item)
                else:
                    if self.debug:
                        print(f"[CAB1] Process PEFILE {cab_item} within {file}")
                    self._process_pefile(item, file, cab_item)
            elif str(cab_item).lower().endswith(".cab"):
                if self.debug:
                    print(f"[CAB1] Need to process {str(cab_item)}")
        shutil.rmtree(self.temp_cab_dir, ignore_errors=True)

    def _process_dllfile(self, item, file="", b=""):
        if self.debug:
            print(f"Processing DLL {item} - {self._is_pefile(item)}")
        if b != "":
            info = self.extract.extract_file_dll(b)
        elif file != "":
            info = self.extract.extract_file_dll(file)
        else:
            info = self.extract.extract_file_dll(item)
        # print (info)
        if info is None:
            return
        if len(info) > 0:
            component_details = self.extract.process_dll(info)
            # print (component_details)
            if file != "":
                file = str(file.name)
            if b != "":
                b = str(b.name)
            self.DLLlist.append([str(item.name), file, b, component_details])
            # os.removedirs(temp_msi_dir)

    def _process_pefile(self, item, file="", b=""):
        if self.debug:
            print(f"[PEFILE] processing DLL {item}")
        if b != "":
            info, dll_list = self.extract.process_pefile(b)
        elif file != "":
            info, dll_list = self.extract.process_pefile(file)
        else:
            info, dll_list = self.extract.process_pefile(item)
        if info is None:
            return
        if len(info) > 0:
            if file != "":
                file = str(file.name)
            if b != "":
                b = str(b.name)
            self.DLLlist.append([str(item.name), file, b, info])
            if info.get("name") is not None and len(dll_list) > 0:
                self.DLLdeps[
                    (info.get("name").lower(), info.get("productversion", "NOTKNOWN"))
                ] = dll_list

    def process_directory(self):
        file_dir = Path(self.directory)
        if not file_dir.exists():
            if self.debug:
                print("[ERROR] Directory not found.")
            return -1
        for item in file_dir.glob("**/*"):
            # print (item)
            if str(item).lower().endswith(".msi"):
                files = self.extract.extract_file_msi(item, self.temp_msi_dir)
                if files is not None:
                    # Now process files
                    for file in Path(self.temp_msi_dir).glob("**/*"):
                        # print (f"Process {file}")
                        if str(file).lower().endswith(".cab"):
                            if self.debug:
                                print(f"Process {file}")
                            Path(self.temp_cab_dir).mkdir(parents=True, exist_ok=True)
                            # print (f"Extract to {temp_cab_dir}")
                            self.extract.extract_file_cab(file, self.temp_cab_dir)
                            # Now process extracted files
                            for cab_item in Path(self.temp_cab_dir).glob("**/*"):
                                if self._is_pefile(cab_item):
                                    self._process_pefile(item, file, cab_item)
                                elif str(cab_item).lower().endswith(".cab"):
                                    if self.debug:
                                        print(f"[CAB] Need to process {str(cab_item)}")
                                elif self.debug:
                                    print(f"[CAB] Not processing {str(cab_item)}")
                            shutil.rmtree(self.temp_cab_dir, ignore_errors=True)
                    shutil.rmtree(self.temp_msi_dir, ignore_errors=True)
            elif str(item).lower().endswith(".cab"):
                # print (f"Process {file}")
                self._process_cabfile(item)
            elif self._is_pefile(item):
                self._process_pefile(item)
        self._build()
        return 0

    def process_system(self):
        # System directory
        if sys.platform == "win32":
            self.directory = "c:\\windows\\system32"
            self.process_directory()

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
            if self.debug:
                print(f"Processing :{d}")
            component = d[3]
            if "name" in component:
                # Add self.relationships
                if d[0] != "":
                    if component_ids.get((d[0].lower(), "NOTKNOWN")) is None:
                        my_package.initialise()
                        my_package.set_type("file")
                        my_package.set_name(d[0].lower())
                        my_package.set_version("NOTKNOWN")
                        my_package.set_licensedeclared("NOTKNOWN")
                        my_package.set_evidence(d[0])
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
                if d[1] != "":
                    if component_ids.get((d[1].lower(), "NOTKNOWN")) is None:
                        my_package.initialise()
                        my_package.set_type("file")
                        my_package.set_name(d[1].lower())
                        my_package.set_version("NOTKNOWN")
                        my_package.set_licensedeclared("NOTKNOWN")
                        my_package.set_evidence(d[1])
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
                my_package.set_type("library")
                my_package.set_name(component["name"].lower())
                # Remove entry if present
                if (my_package.get_value("name"), "NOTKNOWN") in self.sbom_packages:
                    del self.sbom_packages[(my_package.get_value("name"), "NOTKNOWN")]

                if "productversion" in component:
                    my_package.set_version(component["productversion"])
                else:
                    my_package.set_version("NOTKNOWN")
                my_package.set_licensedeclared("NOTKNOWN")
                if "companyname" in component:
                    my_package.set_supplier("organisation", component["companyname"])
                if "legalcopyright" in component:
                    my_package.set_copyrighttext(component["legalcopyright"])
                if "filedescription" in component:
                    my_package.set_description(component["filedescription"])
                if "cpu" in component:
                    my_package.set_property("cpu", component["cpu"])
                if "created" in component:
                    my_package.set_value("build_date", component["created"])
                if "filesize" in component:
                    my_package.set_property("filesize", component["filesize"])
                if "filename" in component:
                    my_package.set_evidence(component["filename"])
                for checksum in ["md5", "sha1", "sha256", "sha512"]:
                    if checksum in component:
                        my_package.set_checksum(checksum.upper(), component[checksum])
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
                d1_id = my_package.get_value("id")
                component_ids[
                    (my_package.get_value("name"), my_package.get_value("version"))
                ] = my_package.get_value("id")
                self.relationships.append(self.sbom_relationship.get_relationship())
        if self.debug:
            print(self.sbom_packages)
        for component, deps in self.DLLdeps.items():
            if self.debug:
                print(f"{component}: {deps}")
            if component in self.sbom_packages:
                component_id = component_ids[component]
                for dependency in deps:
                    if (dependency.lower(), "NOTKNOWN") not in self.sbom_packages:
                        # Dependency not found
                        if self.debug:
                            print(f"Dependency {dependency} not found in SBOM packages")
                        my_package.initialise()
                        my_package.set_name(dependency.lower())
                        my_package.set_type("library")
                        my_package.set_version("NOTKNOWN")
                        my_package.set_licensedeclared("NOTKNOWN")
                        self.sbom_packages[
                            (my_package.get_name(), my_package.get_value("version"))
                        ] = my_package.get_package()
                        component_ids[
                            (my_package.get_name(), my_package.get_value("version"))
                        ] = my_package.get_value("id")
                        dependency_id = my_package.get_value("id")
                    else:
                        dependency_id = component_ids[(dependency.lower(), "NOTKNOWN")]
                    self.sbom_relationship.initialise()
                    self.sbom_relationship.set_relationship(
                        component[0], "DEPENDS_ON", dependency.lower()
                    )
                    self.sbom_relationship.set_relationship_id(
                        component_id, dependency_id
                    )
                    self.relationships.append(self.sbom_relationship.get_relationship())
            elif self.debug:
                print(f"Component {component} not found in SBOM packages")

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
