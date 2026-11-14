"""Vetores proprios do SELO (especificacao, secao 18): reproducao byte a byte e verificacao."""

import json
import unittest
from pathlib import Path

from selo import envelope, jcs
from selo.card import verify_card
from selo.crypto.noise import HandshakeState
from selo.crypto.primitives import b64u, unb64u, x25519_from_bytes
from selo.crypto.ratchet import Ratchet
from selo.identity import Identity, derive_agent_id, verify_kel
from tests.vectors.make_selo_vectors import build, ed, xk

VEC = Path(__file__).with_name("vectors") / "selo_v1.json"


class SeloVectorsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.v = json.loads(VEC.read_text(encoding="utf-8"))

    def test_regenerates_byte_for_byte(self):
        self.assertEqual(json.loads(json.dumps(build())), self.v)

    def test_agent_id_and_kel(self):
        pub = bytes.fromhex(self.v["public"]["alice-sig-0"])
        self.assertEqual(derive_agent_id(pub), self.v["agent_id"]["alice"])
        st = verify_kel(self.v["kel_alice"])
        self.assertEqual(st.agent_id, self.v["agent_id"]["alice"])
        self.assertEqual(st.seq, 1)
        self.assertEqual(st.current.agree_pub.hex(), self.v["public"]["alice-agree-1"])

    def test_card_signature(self):
        info = verify_card(self.v["card_bob"], now=self.v["time"] + 1)
        self.assertEqual(info.agent_id, self.v["agent_id"]["bob"])
        body = {k: v for k, v in self.v["card_bob"].items() if k != "signatures"}
        self.assertEqual(
            jcs.canonicalize(body).decode(), self.v["card_bob_jcs_without_signatures"]
        )

    def test_envelope_opens(self):
        T = self.v["time"]
        bob = Identity.generate(T, sig=ed("bob-sig-0"), agree=xk("bob-agree-0"))
        alice = Identity.generate(T, sig=ed("alice-sig-0"), agree=xk("alice-agree-0"))
        alice.rotate(T + 60, sig=ed("alice-sig-1"), agree=xk("alice-agree-1"))
        from selo.card import build_card

        alice_info = verify_card(
            build_card(alice, "https://alice.example", name="alice", iat=T + 60),
            now=T + 120,
        )
        opened = envelope.open_envelope(
            self.v["envelope"]["value"],
            me=bob,
            now=T + 121,
            resolve_sender=lambda h: alice_info,
            replay=lambda *a: None,
        )
        self.assertEqual(opened.body["rpc"], self.v["envelope"]["rpc"])
        self.assertEqual(
            jcs.canonicalize(opened.header).decode(), self.v["envelope"]["header_jcs"]
        )

    def test_session_handshake_and_first_message(self):
        s = self.v["session"]
        resp = HandshakeState(
            "IK",
            False,
            bytes.fromhex(s["prologue"]),
            s=xk("bob-agree-0"),
            e=xk("hs-resp-eph"),
        )
        self.assertEqual(
            resp.read_message(bytes.fromhex(s["m1"])).decode(), s["m1_payload"]
        )
        self.assertEqual(resp.write_message(s["m2_payload"].encode()).hex(), s["m2"])
        self.assertEqual(resp.h.hex(), s["handshake_hash"])
        from selo.crypto.ratchet import root_from_handshake

        sk = root_from_handshake(resp.ck, resp.h)
        self.assertEqual(sk.hex(), s["ratchet_root"])
        bob_r = Ratchet.init_bob(sk, resp.e)
        fm = s["first_message"]
        pt, _mk = bob_r.decrypt(fm["hdr"], bytes.fromhex(fm["ad"]), unb64u(fm["ct"]))
        self.assertEqual(pt.decode(), fm["plaintext"])
        self.assertEqual(b64u(unb64u(fm["sid"])), fm["sid"])
        self.assertIsNotNone(
            x25519_from_bytes(bytes.fromhex(self.v["keys"]["ratchet-alice-dh-0"]))
        )


if __name__ == "__main__":
    unittest.main()
