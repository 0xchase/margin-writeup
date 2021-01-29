#!/usr/bin/python3

from qiling import *
import os

def hook_block(ql, address, size):
    if "0x4" in hex(address):
        print("At address: 0x%x" % address)
        with open("output.txt", "a+") as f:
            f.write(hex(address) + "\n")

def go():
    ql = Qiling(["/home/oem/margin2/hl_client"], "/home/oem/software/qiling/examples/rootfs/mips32_linux")

    ql.hook_block(hook_block)
    os.system("rm output.txt; touch output.txt")

    ql.run()

go()
