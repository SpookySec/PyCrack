#!/usr/bin/python3
from __future__ import unicode_literals
from elftools.elf.elffile import ELFFile
from elftools.common import exceptions
import sys, os
import extract
from time import sleep

print("Coded by: @spooky_sec")

if len(sys.argv) != 2:
    print("Usage: %s <binary file>" % sys.argv[0])
    sys.exit(1)

file  = sys.argv[1]
out_f = "pydata.dump"

if not os.path.exists(file):
    print("E: '%s' doesn't exist" % file)
    sys.exit(1)

try:
    with open(file, "rb") as f:
        try:
            elf_file = ELFFile(f)
            print("-> File looks like an ELF")
            pydata = elf_file.get_section_by_name("pydata")

            if not pydata:
                print("W: Could not locate 'pydata' section")
                sys.exit(1)

            print(f"-> Located section: '{pydata.name}'")

            print("-> Writing section to %s" % out_f)
            sleep(1)

            # WRITE DATA TO FILE
            out = open(out_f, "w+b")
            out.write(pydata.data())
            out.close()

            print("-> Successfully written to %s" % out_f)

            arch = extract.PyInstArchive(out_f)
            if arch.open():
                if arch.checkFile():
                    if arch.getCArchiveInfo():
                        arch.parseTOC()
                        arch.extractFiles()
                        arch.close()
                        print("-> Finished extracting...")
            arch.close()

            if os.remove(os.getcwd() + "/../" + out_f):
                print("W: Couldn't delete %s" % out_f)
            

        except exceptions.ELFError:
            f.close()
            bytes = str(open(file, "rb").read(2).decode("utf-8"))
            if bytes == "MZ":
                print("-> File looks like a PE file")
                arch = extract.PyInstArchive(file)
                if arch.open():
                    if arch.checkFile():
                        if arch.getCArchiveInfo():
                            arch.parseTOC()
                            arch.extractFiles()
                            arch.close()
                            print("-> Finished extracting...")
                arch.close()


except PermissionError:
    print("E: '%s' permission denied" % file)
    sys.exit(1)
