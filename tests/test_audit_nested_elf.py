"""No-original-file tests for nested ELF transforms and fork-path recovery."""
import hashlib
import importlib.util
import struct
import unittest
from pathlib import Path

TOOLS=Path(__file__).resolve().parents[1]/"tools"
spec=importlib.util.spec_from_file_location("audit_nested_elf",TOOLS/"audit_nested_elf.py")
m=importlib.util.module_from_spec(spec)
spec.loader.exec_module(m)


class NestedElfAuditTests(unittest.TestCase):
    def test_rc4_header_plus_mask_recovers_synthetic_inner(self):
        plain=b"\x7fELF\x02\x01\x01\x00"+bytes(range(56))+bytes(range(100))
        self.assertEqual(len(plain),164)
        key=bytes(range(16))
        mask=0x6d
        start=0x90
        end=start+len(plain)
        outer=bytearray(end+20)
        outer[start:start+64]=m.rc4_start(plain[:64],key)
        outer[start+64:end]=bytes(x^mask for x in plain[64:])
        outer[end:end+16]=key
        outer[end+16]=mask
        params=0x30
        struct.pack_into("<7I",outer,params,start,0,0,0,0,0,end)
        conf={"outer_sha":hashlib.sha256(outer).hexdigest(),
              "inner_sha":hashlib.sha256(plain).hexdigest(),
              "start":start,"params":params}
        decoded,meta=m.recover(bytes(outer),conf)
        self.assertEqual(decoded,plain)
        self.assertEqual(meta["rc4_protected_header_bytes"] if "rc4_protected_header_bytes" in meta else meta["first_header_64_bytes"],"RC4 stream")

    def test_string_builder_recovers_exact_path_without_hardcoded_payload(self):
        target=b"/system/bin/app_process\x00"
        raw=bytearray(0xf1e8f+24)
        vector=bytes([254,253,255,254,253,255,254,253,
                      255,254,253,255,254,253,255,254])
        raw[0xf0030:0xf0030+16]=vector
        encoded=bytearray(target)
        for k in range(16):
            encoded[k+1]=(encoded[k+1]-vector[k])&255
        for k,val in enumerate((3,1,2,3,1,2)):
            encoded[k+17]=(encoded[k+17]+val)&255
        raw[0xf1e8f:0xf1e8f+24]=encoded
        self.assertEqual(m.app_process_path(raw),"/system/bin/app_process")

    def test_double_fork_control_flow_signatures(self):
        instructions = m.SPAWN_FLOW_WORDS
        self.assertEqual(instructions[0x5a428], 0x34000480)
        self.assertEqual(instructions[0x5a4e4], 0x35007b20)
        self.assertEqual(instructions[0x5a6f0], 0x911603e0)
        self.assertEqual(instructions[0x5a6f4], 0x911603e1)
        for site,destination in ((0x5a3d0,0xebe0),
                                 (0x5a454,0xf820),
                                 (0x5a418,0xf200),
                                 (0x5a4c4,0xf200),
                                 (0x5a710,0xf7f0)):
            self.assertEqual(
                site + (((instructions[site] & 0x3ffffff) -
                        (1<<26 if instructions[site] & (1<<25) else 0)) * 4),
                destination)

    def test_arm64_branch_targets_and_jni_symbol_range(self):
        sample=bytearray(0x100)
        site=0x40
        target=0x70
        struct.pack_into("<I",sample,site,
                         0x94000000|((target-site)//4))
        self.assertEqual(m.bl_target(sample,site),target)
        with self.assertRaises(ValueError):
            m.bl_target(sample,site+4)
        jni=m.SAMPLES["libDexHelper.so"]
        self.assertFalse(jni["jni_va"] <= 0x5a418 <
                         jni["jni_va"]+jni["jni_size"])


if __name__=="__main__":
    unittest.main()
