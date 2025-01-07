import os
import subprocess
import sys
from pathlib import Path


class ExtractFile:

    def __init__(self):
        pass

    def inpath(self, appname):
        # Check application is available on path
        if sys.platform == "win32":
            return any(
                list(
                    map(
                        lambda dirname: (Path(dirname) / (appname + ".exe")).is_file(),
                        os.environ.get("PATH", "").split(";"),
                    )
                )
            )
        return any(
            list(
                map(
                    lambda dirname: (Path(dirname) / appname).is_file(),
                    os.environ.get("PATH", "").split(":"),
                )
            )
        )

    def run_command(self, params):
        # check application is available
        if self.inpath(params[0]):
            # print(f"Run {command_line}")
            res = subprocess.run(params, capture_output=True, text=True)
            return res.stdout, res.stderr, None
        print(f"Unable to locate {params[0]}")
        return None, None, None

    def log_info(self, message):
        print(message)

    def extract_file_msi(self, filename, extraction_path):
        """Extract msi file"""
        if sys.platform.startswith("linux"):
            if not self.inpath("msiextract"):
                # ExtractionToolNotFound
                self.log_info(f"No extraction tool found for {filename}")
                self.log_info("'msiextract' is required to extract msi files")
                return None
            else:
                stdout, stderr, _ = self.run_command(
                    ["msiextract", "-C", extraction_path, filename]
                )
                if stdout is None:
                    return None
        else:
            self.log_info(f"No extraction tool found for {filename}")
            self.log_info("Unable to extract msi files")
            return None
        # Return list of files in installer
        return stdout.splitlines()

    def extract_file_cab(self, filename, extraction_path):
        """Extract cab files"""
        if sys.platform.startswith("linux"):
            if not self.inpath("cabextract"):
                # ExtractionToolNotFound
                self.log_info(f"No extraction tool found for {filename}")
                self.log_info("'cabextract' is required to extract cab files")
            else:
                stdout, stderr, _ = self.run_command(
                    ["cabextract", "-q", "-d", extraction_path, f"{filename}"]
                )
                if stdout is None:
                    return 1
        else:
            if not self.inpath("Expand"):
                # ExtractionToolNotFound
                self.log_info(f"No extraction tool found for {filename}")
                self.log_info("'Expand' is required to extract cab files")
            else:
                stdout, stderr, _ = self.run_command(
                    ["Expand", filename, "-R", "-F:*", extraction_path]
                )
                if stdout is None:
                    return 1
        return 0

    def extract_file_dll(self, filename):
        """Extract dll files"""
        if sys.platform.startswith("linux"):
            if not self.inpath("7z"):
                # ExtractionToolNotFound
                self.log_info(f"No extraction tool found for {filename}")
                self.log_info("'7z' is required to extract msi files")
                return None
            else:
                stdout, stderr, _ = self.run_command(["7z", "l", filename])
                if stdout is None:
                    return None
        else:
            self.log_info(f"No extraction tool found for {filename}")
            self.log_info("Unable to extract msi files")
            return None
        # Return list of files in installer
        return stdout.splitlines()

    def process_dll(self, info):
        # Attributes to extract from 7Zip info
        attributes = ["CPU = ", "Created = ", "Name = ", "Checksum = "]
        comments = [
            "ProductVersion:",
            "CompanyName:",
            "FileDescription:",
            "LegalCopyright:",
            "OriginalFilename:",
        ]
        component = {}
        for line in info:
            # Stop at end of comment
            if "}" in line.strip():
                break
            for a in attributes:
                if line.strip().startswith(a):
                    param = line.strip().split(" = ")
                    component[param[0].lower()] = param[1]
                    continue
            for c in comments:
                if line.strip().startswith(c):
                    param = line.strip().split(": ")
                    if len(param) > 1:
                        component[param[0].lower()] = param[1]
                    continue
        if (
            component.get("name") is None
            and component.get("originalfilename") is not None
        ):
            component["name"] = component.get("originalfilename")
        # Tidy up data
        if component.get("productversion") is not None:
            if " " in component.get("productversion"):
                component["productversion"] = component.get("productversion").split(
                    " "
                )[0]
        return component
