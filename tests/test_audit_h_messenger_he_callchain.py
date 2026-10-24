"""Synthetic-only regression for SecNeo Android Messenger/Native he route."""
import importlib.util
from pathlib import Path
import struct
import sys
import unittest
from unittest.mock import patch

TOOLS=Path(__file__).resolve().parents[1]/"tools"
sys.path.insert(0,str(TOOLS))
spec=importlib.util.spec_from_file_location(
    "audit_h_messenger_he_callchain",
    TOOLS/"audit_h_messenger_he_callchain.py")
subject=importlib.util.module_from_spec(spec)
spec.loader.exec_module(subject)


def artificial_base_dex():
    # Byte-sized minimum for the pinned offsets and code items; NOT original.
    b=bytearray(21820)
    for addr, word in subject.WORDS.items():
        struct.pack_into("<H",b,addr,word)
    fields=[(0,1,0),(0,1,1),(0,2,2),(0,1,3)]
    struct.pack_into("<II",b,0x50,7,0x300)
    for i,(cl,typ,name) in enumerate(fields,3):
        struct.pack_into("<HHI",b,0x300+8*i,cl,typ,name)
    code_indices={subject.SENDER:0x518c,
                  subject.RECEIVER:0x41fc, subject.DELEGATE:0x4af0,
                  subject.INITIALIZER:0x427c}
    size={0x518c:73,0x41fc:42,0x4af0:17,0x427c:73}
    for off,count in size.items():
        struct.pack_into("<I",b,off+12,count)
    struct.pack_into("<I",b,0x200+12,1)
    # Scanning 65 bodies: four original-size code items + 61 inert ones.
    codes=[(key,i,off) for i,(key,off) in enumerate(code_indices.items())]
    for i in range(61):
        codes.append((("Lfaketest;",str(i),"()V"),i+3,0x200))
    types=["Landroid/os/Message;","I","Landroid/os/Messenger;"]
    names=["arg1","arg2","replyTo","what"]
    methods=[("Lfaketest;",str(i),"()V") for i in range(155)]
    for idx,val in subject.METHOD_REFS.items():
        methods[idx]=val
    return b,types,names,methods,codes


class SecneoMessengerRouteTests(unittest.TestCase):
    def test_original_source_pins_select_meaningful_dex_fields(self):
        self.assertEqual(subject.FIELD_REFS[3][1],"arg1")
        self.assertEqual(subject.FIELD_REFS[4][1],"arg2")
        self.assertEqual(subject.FIELD_REFS[5][1],"replyTo")
        self.assertEqual(subject.FIELD_REFS[6][1],"what")
        self.assertEqual(subject.WORDS[0x51fc],1000)
        self.assertEqual(subject.WORDS[0x422c],1000)
        self.assertEqual(subject.WORDS[0x5228],55)
        self.assertEqual(subject.WORDS[0x4b1c],141)
        self.assertEqual(subject.WORDS[0x4304],154)
        self.assertEqual(subject.CODE_OFFSETS[subject.INITIALIZER],0x427c)

    def test_complete_flow_with_synthetic_dex(self):
        b,types,names,methods,codes=artificial_base_dex()
        with patch.object(subject.hashlib,"sha256") as sha, \
             patch.object(subject,"metadata",return_value=(names,types,methods)), \
             patch.object(subject,"code_items",return_value=codes):
            sha.return_value.hexdigest.return_value=subject.DEX_SHA
            report=subject.pin_source(bytes(b))
        self.assertEqual(report["validated_code_items"],65)
        self.assertIn("Message.arg2",report["receiver"]["forwards"])
        self.assertIn("H.<clinit>",report["service_connection_created"])
        self.assertIn("Message.arg1",report["sender"]["sets_arg1"])
        self.assertEqual(len(report["direct_calls_to_six_native_methods_in_base_dex"]),1)
        self.assertEqual(report["direct_calls_to_six_native_methods_in_base_dex"][0]["callee"],"he")

    def test_mutated_handler_arg2_field_fails(self):
        b,types,names,methods,codes=artificial_base_dex()
        struct.pack_into("<H",b,0x4256,3)  # arg1 substituted for arg2
        with patch.object(subject.hashlib,"sha256") as sha, \
             patch.object(subject,"metadata",return_value=(names,types,methods)), \
             patch.object(subject,"code_items",return_value=codes):
            sha.return_value.hexdigest.return_value=subject.DEX_SHA
            with self.assertRaisesRegex(ValueError,"instruction changed"):
                subject.pin_source(bytes(b))

    def test_refuses_unauthenticated_binary(self):
        with self.assertRaisesRegex(ValueError,"SHA-256"):
            subject.pin_source(b"not an original DEX")


if __name__=="__main__":
    unittest.main()
