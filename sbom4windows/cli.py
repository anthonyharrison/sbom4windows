# Copyright (C) 2025 Anthony Harrison
# SPDX-License-Identifier: Apache-2.0

import argparse
import sys
import textwrap
from collections import ChainMap

from lib4sbom.generator import SBOMGenerator
from lib4sbom.sbom import SBOM

from sbom4windows.scanner import SBOMScanner
from sbom4windows.version import VERSION

# CLI processing


def main(argv=None):

    argv = argv or sys.argv
    app_name = "sbom4windows"
    parser = argparse.ArgumentParser(
        prog=app_name,
        description=textwrap.dedent(
            """
            SBOM4Windows generates a Software Bill of Materials for a windows installation.
            """
        ),
    )
    input_group = parser.add_argument_group("Input")
    input_group.add_argument(
        "--directory",
        action="store",
        default="",
        help="root directory",
    )
    input_group.add_argument(
        "--system",
        action="store_true",
        help="include all installed modules within system",
    )
    input_group.add_argument(
        "-n",
        "--name",
        action="store",
        default="",
        help="Name of installation",
    )

    output_group = parser.add_argument_group("Output")
    output_group.add_argument(
        "-d",
        "--debug",
        action="store_true",
        default=False,
        help="add debug information",
    )
    output_group.add_argument(
        "--sbom",
        action="store",
        default="spdx",
        choices=["spdx", "cyclonedx"],
        help="specify type of sbom to generate (default: spdx)",
    )
    output_group.add_argument(
        "--format",
        action="store",
        default="tag",
        choices=["tag", "json", "yaml"],
        help="specify format of software bill of materials (sbom) (default: tag)",
    )
    output_group.add_argument(
        "-o",
        "--output-file",
        action="store",
        default="",
        help="output filename (default: output to stdout)",
    )

    parser.add_argument("-V", "--version", action="version", version=VERSION)

    defaults = {
        "directory": "",
        "system": False,
        "name": "",
        "output_file": "",
        "sbom": "spdx",
        "debug": False,
        "format": "tag",
    }

    raw_args = parser.parse_args(argv[1:])
    args = {key: value for key, value in vars(raw_args).items() if value}
    args = ChainMap(args, defaults)

    # Validate CLI parameters

    # Ensure format is aligned with type of SBOM
    bom_format = args["format"]
    if args["sbom"] == "cyclonedx":
        # Only JSON format valid for CycloneDX
        if bom_format != "json":
            bom_format = "json"

    if args["debug"]:
        print("Root directory", args["directory"])
        print("System", args["system"])
        print("SBOM type:", args["sbom"])
        print("Format:", bom_format)
        print("Output file:", args["output_file"])

    sbom_scan = SBOMScanner(args["directory"], debug=args["debug"])

    if len(args["name"]) > 0:
        sbom_scan.set_parent(args["name"])

    if len(args["directory"]) > 0:
        sbom_scan.process_directory()
    elif args["system"]:
        if sys.platform == "win32":
            sbom_scan.process_system()
        else:
            print("[ERROR] System scan not supported on this platform")
            return -1
    else:
        print("[ERROR] Nothing to process")
        return -1

    # Generate SBOM file
    windows_sbom = SBOM()
    windows_sbom.add_document(sbom_scan.get_document())
    windows_sbom.add_packages(sbom_scan.get_packages())
    windows_sbom.add_relationships(sbom_scan.get_relationships())

    sbom_gen = SBOMGenerator(
        sbom_type=args["sbom"], format=bom_format, application=app_name, version=VERSION
    )
    sbom_gen.generate(
        project_name=sbom_scan.get_parent(),
        sbom_data=windows_sbom.get_sbom(),
        filename=args["output_file"],
    )

    return 0


if __name__ == "__main__":
    sys.exit(main())
