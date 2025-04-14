# Copyright (C) 2025 Anthony Harrison
# SPDX-License-Identifier: Apache-2.0

import datetime
import hashlib
from pathlib import Path

import pefile


class PEUtils:

    def __init__(self, exe_path):
        self.exe_path = exe_path
        self.pe_data = {}
        self.dll_symbols = {}
        self.dll_names = []
        self.file_data = {}
        self.version_info = {}
        # Check file exists
        if len(str(self.exe_path)) > 0:
            # Check path
            filePath = Path(self.exe_path)
            # Check path exists, a valid file and not empty file
            if filePath.exists() and filePath.is_file() and filePath.stat().st_size > 0:
                # Assume that processing can proceed
                # Open file
                self._open_pefile()

    def _open_pefile(self):
        try:
            pe = pefile.PE(self.exe_path)
            raw = pe.write()
            self.file_data["filename"] = str(self.exe_path)
            self.file_data["filesize"] = len(raw)
            # Get file timestamp
            timestamp = Path(self.exe_path).stat().st_mtime
            self.file_data["created"] = datetime.datetime.utcfromtimestamp(
                timestamp
            ).strftime("%Y-%m-%dT%H:%M:%SZ")
            self.file_data["md5"] = hashlib.md5(raw).hexdigest()
            self.file_data["sha1"] = hashlib.sha1(raw).hexdigest()
            self.file_data["sha256"] = hashlib.sha256(raw).hexdigest()
            self.file_data["sha512"] = hashlib.sha512(raw).hexdigest()
            self.pe_data = pe.dump_dict()
            pe.close()
        except Exception as e:
            pass

    def get_version_info(self):
        if "Version Information" not in self.pe_data.keys():
            return
        for entry in self.pe_data["Version Information"]:
            for sub_entry in entry:
                if type(sub_entry) is list:
                    for element in sub_entry:
                        if type(element) is dict:
                            if element.get("Structure") is None:
                                # Found version information!
                                if len(self.version_info) == 0:
                                    if element.get("LangID") is not None:
                                        for key, entry in element.items():
                                            if key != "LangID":
                                                self.version_info[key.decode()] = (
                                                    entry.decode()
                                                )

    def get_dll_info(self):
        if "Imported symbols" not in self.pe_data.keys():
            return
        # Process entries
        for entry in self.pe_data["Imported symbols"]:
            for element in entry:
                if type(element) is dict and element.get("DLL") is not None:
                    dll_name = element["DLL"].decode()
                    if dll_name not in self.dll_names:
                        # New DLL found
                        self.dll_names.append(dll_name)
                        self.dll_symbols[dll_name] = []
                    if element.get("Name") is not None:
                        self.dll_symbols[dll_name].append(element["Name"].decode())

    def get_exe_path(self):
        return self.exe_path

    def get_file_data(self):
        return self.file_data

    def get_version_data(self):
        return self.version_info

    def get_pe_data(self):
        return self.pe_data

    def get_symbols(self):
        return self.dll_symbols

    def get_dlls(self):
        return self.dll_names

    def show_data(self, attribute):
        print(f"Length: {len(self.pe_data[attribute])}")
        print(self.pe_data[attribute])
        for info in self.pe_data[attribute]:
            print(info)
            print("================")
            for entry in info:
                print(f"Type: {type(entry)}]: {entry}")
                print("--------------")
                if type(entry) is list:
                    for sub_entry in entry:
                        print(f"Type: {type(sub_entry)}]: {sub_entry}")

    def show_symbols(self):
        if self.dll_symbols:
            for dll, symbols in self.dll_symbols.items():
                print(f"DLL: {dll}")
                for symbol in symbols:
                    print(f"  - {symbol}")
        else:
            print("No DLL information available.")
