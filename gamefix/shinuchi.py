#!/opt/local/bin/python3
# coding: utf-8

import sys
import os
import io
import struct
import binascii
from util import Xorshift

def fix_order(bs, sections, order):
    bs.seek(0)
    data = bs.read(sections[0]["offset"])
    for s in order:
        section = [x for x in sections if x["type"] == s][0]
        bs.seek(section["offset"])
        data += bs.read(section["size"])
    bs.seek(sections[-1]["offset"] + sections[-1]["size"])
    data += bs.read()
    return data

def validate(input_data):
    # data MUST NOT contain nonce and ccm
    state = [
        0x01, 0x03, 0x0B, 0x0F, 0x10, 0x11, 0x02, 0x07,
        0x08, 0x0C, 0x0D, 0x0E, 0x12, 0x14, 0x15, 0x00,
    ]
    bs = io.BytesIO(input_data)
    bs.seek(0, os.SEEK_END)
    length = bs.tell() - 8 # CRC32 and key
    bs.seek(0)

    a, b = struct.unpack("<2I", bs.read(8))
    if a & 0xFFFF != 0xFFFE:
        return None
    if (b >> 8 + 8) > length:
        return None
    if b & 0xFF != 0xF1:
        return None

    while True:
        a, b = struct.unpack("<H2xI", bs.read(8))
        if bs.tell() >= length:
            break
        if a & 0xFFFF != 0xFFFE:
            return None
        if b >> 8 > 0x12000:
            return None
        if b & 0xFF == 0xF2:
            data = bs.read(b >> 8)
            if data[0] != 0x4:
                return None
            bs.read(4)
        elif b & 0xFF == 0xF3:
            section_end =  (b >> 8) + bs.tell()
            sections = []
            while True:
                section_offset = bs.tell()
                if section_offset >= section_end:
                    break
                c, d = struct.unpack("<H2xI", bs.read(8))
                if c & 0xFFFF != 0xFFFE:
                    return None
                if d >> 8 > 0x12000:
                    return None
                section_type = d & 0xFF
                section_size = (d >> 8) + 8 + 4  # 8 is for header, 4 for footer
                bs.seek(-8, os.SEEK_CUR)
                data = bs.read(section_size)
                if section_type in [0x00, 0x04, 0x05, 0x06, 0x09, 0x0A, 0x13]:
                    return None
                else:
                    sections.append({"type": section_type, "offset": section_offset, "size": section_size})
                    if section_type == 0x01:
                        rng_0x01 = Xorshift(binascii.crc32(data))
                    elif section_type == 0x07:
                        rng_0x07 = Xorshift(binascii.crc32(data))
            for i in range(5, 0, -1):
                pos = rng_0x01.xorshift(i + 1)
                state[pos + 1], state[i + 1] = state[i + 1], state[pos + 1]
            for i in range(6, 0, -1):
                pos = rng_0x07.xorshift(i + 1)
                state[pos + 8], state[i + 8] = state[i + 8], state[pos + 8]
            if [x["type"] for x in sections][:0xF] != state[:0xF]:
                print("Incorrect section order detected.")
                return fix_order(bs, sections, state[:0xF])
        else:
            return None
    return input_data
