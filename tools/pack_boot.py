#!/usr/bin/env python3
"""Pack an Android boot image (header v0-v2) from kernel + ramdisk + header.json."""
import argparse
import json
import os
import struct
import sys


def pad(n, page):
    return (n + page - 1) // page * page


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--kernel", required=True)
    ap.add_argument("--ramdisk", required=True)
    ap.add_argument("--header", required=True)
    ap.add_argument("--out", required=True)
    args = ap.parse_args()

    m = json.load(open(args.header, encoding="utf-8"))
    kernel = open(args.kernel, "rb").read()
    ramdisk = open(args.ramdisk, "rb").read()
    page = m.get("page_size", 2048)
    hv = m.get("header_version", 0)

    if kernel[:2] != b"\x1f\x8b":
        print("ERROR: %s does not start with gzip magic" % args.kernel, file=sys.stderr)
        return 2
    dtb_off = kernel.find(b"\xd0\x0d\xfe\xed", 2)
    print("kernel blob : %d bytes" % len(kernel))
    print("ramdisk blob: %d bytes" % len(ramdisk))
    if dtb_off > 0:
        print("appended dtb: offset %d, %d bytes" % (dtb_off, len(kernel) - dtb_off))
        if b"EEBBK S5" not in kernel[dtb_off:]:
            print("ERROR: appended dtb does not contain 'EEBBK S5'", file=sys.stderr)
            return 3
        print("dtb model check: OK (EEBBK S5)")
    else:
        print("ERROR: no FDT magic after gzip stream", file=sys.stderr)
        return 4

    hdr = bytearray(page)
    hdr[0:8] = b"ANDROID!"
    struct.pack_into("<8I", hdr, 8, len(kernel), m.get("kernel_addr", 0x8000),
                     len(ramdisk), m.get("ramdisk_addr", 0x1000000),
                     0, m.get("second_addr", 0xF00000),
                     m.get("tags_addr", 0x100), page)
    struct.pack_into("<I", hdr, 40, hv)
    struct.pack_into("<I", hdr, 44, m.get("os_version", 0))
    name = m.get("name", "").encode()[:16]
    cmd = m.get("cmdline", "").encode()[:512]
    extra = m.get("extra_cmdline", "").encode()[:1024]
    hdr[48:48 + len(name)] = name
    hdr[64:64 + len(cmd)] = cmd
    hdr[576:608] = bytes.fromhex(m.get("id", "00" * 32))[:32].ljust(32, b"\0")
    hdr[608:608 + len(extra)] = extra
    if hv >= 1:
        struct.pack_into("<I", hdr, 1632, 0)
        struct.pack_into("<Q", hdr, 1636, 0)
        struct.pack_into("<I", hdr, 1644, 1648)
    if hv >= 2:
        struct.pack_into("<I", hdr, 1644, 1660)
        struct.pack_into("<I", hdr, 1648, 0)
        struct.pack_into("<Q", hdr, 1652, 0)

    with open(args.out, "wb") as f:
        f.write(hdr)
        for blob in (kernel, ramdisk):
            f.write(blob)
            f.write(b"\0" * (pad(len(blob), page) - len(blob)))
    total = os.path.getsize(args.out)
    print("wrote %s: %d bytes (%.2f MiB)" % (args.out, total, total / 1048576.0))
    return 0


if __name__ == "__main__":
    sys.exit(main())
