#!/usr/bin/env python3
"""Pinned original CNMB 12.5.5 SecNeo H Java pipe IPC audit.

Read-only. Works on the original base APK or its diagnostic outer ZIP.
Checks method definitions, referenced method signatures, code instructions and
the argument-to-pipe result path. Does not export original DEX or secrets.
"""
import argparse
import hashlib
import io
import json
import struct
import zipfile
from pathlib import Path

APK_SHA = "6282d2cf05f76f37a60fff322bcf0d6f1d876829e5c9c4eae5cdd93b7a972a83"
DEX_SHA = "6abbe8c56cc92a5d33cc12b2fdfda9a487325382e62b321359db65c98a27ca17"
H = "Lcom/secneo/apkwrapper/H;"


def u16(data, off):
    if off < 0 or off + 2 > len(data):
        raise ValueError("invalid u16 offset")
    return struct.unpack_from("<H", data, off)[0]


def u32(data, off):
    if off < 0 or off + 4 > len(data):
        raise ValueError("invalid u32 offset")
    return struct.unpack_from("<I", data, off)[0]


def uleb(data, pos):
    number = 0
    for shift in range(0, 35, 7):
        if pos >= len(data):
            raise ValueError("truncated DEX uleb128")
        byte = data[pos]
        pos += 1
        number |= (byte & 127) << shift
        if not byte & 128:
            return number, pos
    raise ValueError("oversized DEX uleb128")


def table(data, count_at, offset_at, unit):
    n, off = u32(data, count_at), u32(data, offset_at)
    if n > len(data) // unit or off > len(data) - n * unit:
        raise ValueError("DEX table exceeds file")
    return n, off


def metadata(data):
    n, base = table(data, 0x38, 0x3c, 4)
    strings = []
    for i in range(n):
        _, start = uleb(data, u32(data, base + 4 * i))
        end = data.find(b"\x00", start)
        if end < 0:
            raise ValueError("unterminated DEX string")
        strings.append(data[start:end].decode("utf-8", "replace"))
    n, base = table(data, 0x40, 0x44, 4)
    types = [strings[u32(data, base + 4 * i)] for i in range(n)]
    n, base = table(data, 0x48, 0x4c, 12)
    protos = []
    for i in range(n):
        shorty, ret, params = struct.unpack_from("<III", data, base + 12 * i)
        argc = u32(data, params) if params else 0
        if argc > 1024 or (params and params + 4 + 2 * argc > len(data)):
            raise ValueError("malformed proto")
        args = [types[u16(data, params + 4 + 2 * j)]
                for j in range(argc)] if params else []
        protos.append("(" + "".join(args) + ")" + types[ret])
    n, base = table(data, 0x58, 0x5c, 8)
    methods = []
    for i in range(n):
        cl, proto, name = struct.unpack_from("<HHI", data, base + 8 * i)
        methods.append((types[cl], strings[name], protos[proto]))
    return strings, types, methods


def defined_h_code(data, types, methods):
    n, base = table(data, 0x60, 0x64, 32)
    found = {}
    for i in range(n):
        item = base + 32 * i
        if types[u32(data, item)] != H:
            continue
        pos = u32(data, item + 24)
        counts = []
        for _ in range(4):
            count, pos = uleb(data, pos)
            counts.append(count)
        if sum(counts) > 2000:
            raise ValueError("unreasonable H class data count")
        for _ in range(counts[0] + counts[1]):
            _, pos = uleb(data, pos)
            _, pos = uleb(data, pos)
        for total in counts[2:]:
            mid = 0
            for _ in range(total):
                delta, pos = uleb(data, pos)
                _, pos = uleb(data, pos)
                code_off, pos = uleb(data, pos)
                mid += delta
                if mid >= len(methods) or methods[mid][0] != H:
                    raise ValueError("invalid defined H method index")
                if code_off:
                    found[methods[mid]] = code_off
    return found


def code(data, defined, name, desc, expected_off, expected_units):
    off = defined.get((H, name, desc))
    if off != expected_off:
        raise ValueError("original H method definition changed: " + name)
    regs, ins, outs, tries, debug, units = struct.unpack_from("<HHHHII", data, off)
    if (regs, ins, units) != (7, 1, expected_units) or off + 16 + 2 * units > len(data):
        raise ValueError("original H method code dimensions changed: " + name)
    return data[off + 16:off + 16 + 2 * units]


def words(body, expected, label):
    for off, value in expected.items():
        if u16(body, off) != value:
            raise ValueError(f"original instruction changed at {label}+{off:#x}")


def invokes(body, methods, expected, label):
    for off, target in expected.items():
        opcode = u16(body, off) & 0xff
        if opcode not in range(0x6e, 0x73) and opcode not in range(0x74, 0x79):
            raise ValueError(f"missing invoke at {label}+{off:#x}")
        index = u16(body, off + 2)
        if index >= len(methods) or methods[index] != target:
            raise ValueError(f"wrong invoke target at {label}+{off:#x}")


def const_string(body, strings, off, expected):
    if u16(body, off) & 0xff != 0x1a:
        raise ValueError("missing const-string opcode")
    index = u16(body, off + 2)
    if index >= len(strings) or strings[index] != expected:
        raise ValueError("original const-string reference changed")


def audit(data):
    if hashlib.sha256(data).hexdigest() != DEX_SHA or len(data) != 21820:
        raise ValueError("original classes.dex SHA mismatch")
    if not data.startswith(b"dex\n"):
        raise ValueError("invalid original DEX magic")
    strings, types, methods = metadata(data)
    definitions = defined_h_code(data, types, methods)
    main = code(data, definitions, "main", "([Ljava/lang/String;)V", 0x4e60, 94)
    prep = code(data, definitions, "b", "(I)I", 0x46a8, 57)
    check = code(data, definitions, "a", "(I)I", 0x4328, 123)

    # Dalvik register p0 is v6 (registers=7, ins=1).
    # args[1] yields FD in v3; args[3] yields flags in v0.
    words(main, {
        0x1a:0x6021, 0x1c:0x1112, 0x1e:0x4212, 0x20:0x2032,
        0x2e:0x0346, 0x30:0x0106, 0x38:0x030a, 0x40:0x030c,
        0x42:0x3412, 0x44:0x0646, 0x46:0x0406, 0x4e:0x000a,
        0x60:0x060a, 0x7c:0x060c,
    }, "H.main")
    invokes(main, methods, {
        0x32:("Ljava/lang/Integer;", "parseInt", "(Ljava/lang/String;)I"),
        0x3a:("Landroid/os/ParcelFileDescriptor;", "adoptFd",
              "(I)Landroid/os/ParcelFileDescriptor;"),
        0x48:("Ljava/lang/Integer;", "parseInt", "(Ljava/lang/String;)I"),
        0x5a:(H, "b", "(I)I"),
        0x6a:("Landroid/os/ParcelFileDescriptor$AutoCloseOutputStream;",
              "<init>", "(Landroid/os/ParcelFileDescriptor;)V"),
        0x70:("Ljava/io/DataOutputStream;", "<init>", "(Ljava/io/OutputStream;)V"),
        0x76:("Ljava/lang/Integer;", "toString", "(I)Ljava/lang/String;"),
        0x7e:("Ljava/io/DataOutputStream;", "writeUTF", "(Ljava/lang/String;)V"),
        0x84:("Ljava/io/DataOutputStream;", "close", "()V"),
    }, "H.main")
    const_string(prep, strings, 0x1e, "/system/bin/app_process")
    words(prep, {0x5e:0x0016, 0x60:0x07d0, 0x6e:0x060a}, "H.b")
    invokes(prep, methods, {
        0x22:("Ljava/io/FileInputStream;", "<init>", "(Ljava/lang/String;)V"),
        0x2a:("Ljava/io/FileInputStream;", "read", "()I"),
        0x30:("Ljava/io/FileInputStream;", "close", "()V"),
        0x62:("Landroid/os/SystemClock;", "sleep", "(J)V"),
        0x68:(H, "a", "(I)I"),
    }, "H.b")
    const_string(check, strings, 0x22, "/proc/self/status")
    const_string(check, strings, 0x44, "TracerPid:")
    const_string(check, strings, 0x7e, "PPid:")
    words(check, {
        0x40:0x0639, 0x78:0x1312, 0x7a:0x3633, 0x7c:0xffdd,
        0x76:0x060f, 0xae:0x060f,
    }, "H.a")
    invokes(check, methods, {
        0x26:("Ljava/io/FileReader;", "<init>", "(Ljava/lang/String;)V"),
        0x34:("Ljava/io/BufferedReader;", "readLine", "()Ljava/lang/String;"),
        0x48:("Ljava/lang/String;", "startsWith", "(Ljava/lang/String;)Z"),
        0x58:("Ljava/lang/String;", "substring", "(I)Ljava/lang/String;"),
        0x60:("Ljava/lang/String;", "trim", "()Ljava/lang/String;"),
        0x68:("Ljava/lang/Integer;", "parseInt", "(Ljava/lang/String;)I"),
        0x82:("Ljava/lang/String;", "startsWith", "(Ljava/lang/String;)Z"),
        0x90:("Ljava/lang/String;", "substring", "(I)Ljava/lang/String;"),
        0x98:("Ljava/lang/String;", "trim", "()Ljava/lang/String;"),
        0xa0:("Ljava/lang/Integer;", "parseInt", "(Ljava/lang/String;)I"),
    }, "H.a")
    return {
        "sample_sha256": APK_SHA,
        "classes_dex_sha256": DEX_SHA,
        "original_code_offsets": {"H.main":"0x4e60", "H.b(I)":"0x46a8",
                                  "H.a(I)":"0x4328"},
        "main": {
            "required_argv_length": 4,
            "fd_argument_index": 1,
            "flags_argument_index": 3,
            "fd_wrapper": "ParcelFileDescriptor.adoptFd",
            "wire_encoding": "DataOutputStream.writeUTF(Integer.toString(result))",
        },
        "worker": {
            "pre_check": "open/read/close /system/bin/app_process",
            "delay": "SystemClock.sleep(2000)",
            "flags_zero": "read /proc/self/status TracerPid",
            "flags_one": "read /proc/self/status PPid",
            "result": "integer passed back to H.main; written to adopted FD",
        },
        "limit": ("This proves the original H Java writer path; it does not "
                  "identify the native reader, on-device write success or "
                  "the DEC decision function."),
    }


def load_source(path):
    data = path.read_bytes()
    with zipfile.ZipFile(io.BytesIO(data)) as outer:
        if "apks/01-base.apk" in outer.namelist():
            data = outer.read("apks/01-base.apk")
    if hashlib.sha256(data).hexdigest() != APK_SHA:
        raise ValueError("original APK SHA-256 mismatch")
    with zipfile.ZipFile(io.BytesIO(data)) as apk:
        return apk.read("classes.dex")


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("source", type=Path, help="original APK or diagnostic ZIP")
    args = p.parse_args()
    print(json.dumps(audit(load_source(args.source)), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
