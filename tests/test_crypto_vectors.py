"""Seam secundario: testes de resposta conhecida contra os vetores oficiais (JCS e HPKE)."""

import json
import struct
import unittest
from pathlib import Path

from selo import jcs
from selo.crypto import hpke
from selo.crypto.primitives import x25519_from_bytes, x25519_priv, x25519_pub
from selo.errors import SeloError

VEC = Path(__file__).with_name("vectors")


def _load(name):
    return json.loads((VEC / name).read_text(encoding="utf-8"))


class JcsVectors(unittest.TestCase):
    def test_rfc8785_appendix_b_numbers(self):
        cases = _load("jcs_rfc8785_numbers.json")["numbers"]
        self.assertEqual(len(cases), 26)
        for case in cases:
            x = struct.unpack(">d", bytes.fromhex(case["ieee754"]))[0]
            with self.subTest(ieee=case["ieee754"]):
                if case["json"] is None:
                    with self.assertRaises(SeloError):
                        jcs.number(x)
                else:
                    self.assertEqual(jcs.number(x), case["json"])

    def test_reference_testdata(self):
        def parse_int(s):
            v = int(s)
            return v if abs(v) <= jcs.MAX_SAFE_INT else float(s)
        for name, case in _load("jcs_cyberphone_testdata.json")["cases"].items():
            with self.subTest(case=name):
                value = json.loads(case["input"], parse_int=parse_int)
                self.assertEqual(jcs.canonicalize(value).decode("utf-8"), case["output"].rstrip("\n"))

    def test_rfc8785_section_3_2_2_example(self):
        src = ('{"numbers": [333333333.33333329, 1E30, 4.50, 2e-3, 0.000000000000000000000000001],'
               '"string": "\\u20ac$\\u000F\\u000aA\'\\u0042\\u0022\\u005c\\\\\\"\\/",'
               '"literals": [null, true, false]}')
        expected = ('{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],'
                    '"string":"€$\\u000f\\nA\'B\\"\\\\\\\\\\"/"}')
        self.assertEqual(jcs.canonicalize(json.loads(src)).decode("utf-8"), expected)

    def test_rejects_non_json_values(self):
        for bad in (float("nan"), 2 ** 60, {1: "x"}, "\ud800", b"bytes"):
            with self.subTest(bad=repr(bad)), self.assertRaises(SeloError):
                jcs.canonicalize(bad)


class HpkeVectors(unittest.TestCase):
    def setUp(self):
        data = _load("hpke_base_x25519_sha256_chachapoly.json")
        self.assertEqual(len(data["vectors"]), 1)
        self.v = data["vectors"][0]
        self.h = {k: bytes.fromhex(v) for k, v in self.v.items() if isinstance(v, str)}

    def test_derive_keypair(self):
        sk_e = hpke.derive_keypair(self.h["ikmE"])
        sk_r = hpke.derive_keypair(self.h["ikmR"])
        self.assertEqual(x25519_priv(sk_e), self.h["skEm"])
        self.assertEqual(x25519_pub(sk_e), self.h["pkEm"])
        self.assertEqual(x25519_priv(sk_r), self.h["skRm"])
        self.assertEqual(x25519_pub(sk_r), self.h["pkRm"])

    def test_key_schedule_and_encryptions(self):
        sk_e = x25519_from_bytes(self.h["skEm"])
        enc, ctx = hpke.setup_base_s(self.h["pkRm"], self.h["info"], sk_e)
        self.assertEqual(enc, self.h["enc"])
        self.assertEqual(ctx.key, self.h["key"])
        self.assertEqual(ctx.base_nonce, self.h["base_nonce"])
        self.assertEqual(ctx.exporter_secret, self.h["exporter_secret"])
        rctx = hpke.setup_base_r(enc, x25519_from_bytes(self.h["skRm"]), self.h["info"])
        for i, e in enumerate(self.v["encryptions"]):
            aad, pt, ct = (bytes.fromhex(e[k]) for k in ("aad", "pt", "ct"))
            with self.subTest(seq=i):
                self.assertEqual(ctx.seal(aad, pt), ct)
                self.assertEqual(rctx.open(aad, ct), pt)
        self.assertEqual(len(self.v["encryptions"]), 257)

    def test_shared_secret(self):
        shared, enc = hpke.encap(self.h["pkRm"], x25519_from_bytes(self.h["skEm"]))
        self.assertEqual(shared, self.h["shared_secret"])
        self.assertEqual(hpke.decap(enc, x25519_from_bytes(self.h["skRm"])), shared)

    def test_exports(self):
        ctx = hpke.setup_base_r(self.h["enc"], x25519_from_bytes(self.h["skRm"]), self.h["info"])
        for e in self.v["exports"]:
            self.assertEqual(ctx.export(bytes.fromhex(e["exporter_context"]), e["L"]),
                             bytes.fromhex(e["exported_value"]))

    def test_wrong_inputs_fail(self):
        sk_r = x25519_from_bytes(self.h["skRm"])
        enc, ct = hpke.seal_base(self.h["pkRm"], b"info", b"aad", b"mensagem")
        self.assertEqual(hpke.open_base(enc, sk_r, b"info", b"aad", ct), b"mensagem")
        tampered = bytearray(ct)
        tampered[0] ^= 1
        other = hpke.derive_keypair(b"outra chave")
        for args in ((enc, sk_r, b"info", b"aad", bytes(tampered)),   # mensagem alterada
                     (enc, other, b"info", b"aad", ct),                # chave errada
                     (enc, sk_r, b"outro", b"aad", ct),                # contexto (info) errado
                     (enc, sk_r, b"info", b"outro", ct)):              # aad errado
            with self.assertRaises(SeloError):
                hpke.open_base(*args)

    def test_low_order_point_rejected(self):
        with self.assertRaises(SeloError):
            hpke.encap(b"\x00" * 32)


if __name__ == "__main__":
    unittest.main()
