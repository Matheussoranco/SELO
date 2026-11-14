"""Seam secundario: Noise (vetores Cacophony) e Double Ratchet (propriedades)."""

import json
import unittest
from pathlib import Path

from selo import channel
from selo.crypto.noise import HandshakeState, one_way
from selo.crypto.primitives import x25519_from_bytes, x25519_generate, x25519_pub
from selo.crypto.ratchet import MAX_SKIP, Ratchet, root_from_handshake
from selo.errors import SeloError

VEC = (
    Path(__file__).with_name("vectors") / "noise_cacophony_25519_chachapoly_sha256.json"
)


def _k(hexstr):
    return x25519_from_bytes(bytes.fromhex(hexstr)) if hexstr else None


class NoiseVectors(unittest.TestCase):
    def test_cacophony_vectors(self):
        vectors = json.loads(VEC.read_text())["vectors"]
        names = {v["protocol_name"] for v in vectors}
        self.assertIn("Noise_IK_25519_ChaChaPoly_SHA256", names)
        for v in vectors:
            pattern = v["protocol_name"].split("_")[1]
            with self.subTest(protocol=v["protocol_name"]):
                init = HandshakeState(
                    pattern,
                    True,
                    bytes.fromhex(v.get("init_prologue", "")),
                    s=_k(v.get("init_static")),
                    e=_k(v.get("init_ephemeral")),
                    rs=(
                        bytes.fromhex(v["init_remote_static"])
                        if v.get("init_remote_static")
                        else None
                    ),
                )
                resp = HandshakeState(
                    pattern,
                    False,
                    bytes.fromhex(v.get("resp_prologue", "")),
                    s=_k(v.get("resp_static")),
                    e=_k(v.get("resp_ephemeral")),
                    rs=(
                        bytes.fromhex(v["resp_remote_static"])
                        if v.get("resp_remote_static")
                        else None
                    ),
                )
                sender, receiver = init, resp
                transports = None
                for i, m in enumerate(v["messages"]):
                    payload, expected = (
                        bytes.fromhex(m["payload"]),
                        bytes.fromhex(m["ciphertext"]),
                    )
                    if transports is None:
                        ct = sender.write_message(payload)
                        self.assertEqual(ct, expected, f"mensagem de handshake {i}")
                        self.assertEqual(receiver.read_message(ct), payload)
                        if init.finished():
                            self.assertEqual(init.h, bytes.fromhex(v["handshake_hash"]))
                            self.assertEqual(resp.h, init.h)
                            transports = {"i": init.transport(), "r": resp.transport()}
                            # proximo remetente: em padroes de uma via, sempre o iniciador
                            nxt_init = one_way(pattern) or sender is resp
                        else:
                            sender, receiver = receiver, sender
                            continue
                    else:
                        s_side, r_side = ("i", "r") if nxt_init else ("r", "i")
                        ct = transports[s_side][0].encrypt_with_ad(b"", payload)
                        self.assertEqual(ct, expected, f"mensagem de transporte {i}")
                        self.assertEqual(
                            transports[r_side][1].decrypt_with_ad(b"", ct), payload
                        )
                        if not one_way(pattern):
                            nxt_init = not nxt_init
                        continue
                    sender, receiver = receiver, sender

    def test_ik_rejects_wrong_responder_key(self):
        resp_s = x25519_generate()
        init = HandshakeState(
            "IK", True, b"p", s=x25519_generate(), rs=x25519_pub(x25519_generate())
        )
        resp = HandshakeState("IK", False, b"p", s=resp_s)
        with self.assertRaises(SeloError):
            resp.read_message(init.write_message(b"oi"))

    def test_ik_rejects_wrong_prologue(self):
        resp_s = x25519_generate()
        init = HandshakeState(
            "IK", True, b"a", s=x25519_generate(), rs=x25519_pub(resp_s)
        )
        resp = HandshakeState("IK", False, b"b", s=resp_s)
        with self.assertRaises(SeloError):
            resp.read_message(init.write_message(b"oi"))


def _pair():
    """Handshake IK completo seguido da passagem para o ratchet (especificacao 9.2)."""
    resp_s, init_s = x25519_generate(), x25519_generate()
    init = HandshakeState("IK", True, b"selo", s=init_s, rs=x25519_pub(resp_s))
    resp = HandshakeState("IK", False, b"selo", s=resp_s)
    resp.read_message(init.write_message(b"m1"))
    init.read_message(resp.write_message(b"m2"))
    sk_i, sk_r = (
        root_from_handshake(init.ck, init.h),
        root_from_handshake(resp.ck, resp.h),
    )
    assert sk_i == sk_r
    alice = Ratchet.init_alice(sk_i, init.re)
    bob = Ratchet.init_bob(sk_r, resp.e)
    return alice, bob


def _send(r, pt, ad=b"ad"):
    from selo.crypto.ratchet import seal_with

    hdr, mk = r.next_send()
    return hdr, seal_with(mk, ad + json.dumps(hdr, sort_keys=True).encode(), pt)


def _recv(r, msg, ad=b"ad"):
    hdr, ct = msg
    return r.decrypt(hdr, ad + json.dumps(hdr, sort_keys=True).encode(), ct)[0]


class RatchetTest(unittest.TestCase):
    def test_conversation_in_order_with_dh_steps(self):
        alice, bob = _pair()
        self.assertFalse(bob.can_send())
        for i in range(3):
            self.assertEqual(_recv(bob, _send(alice, b"a%d" % i)), b"a%d" % i)
            self.assertEqual(_recv(alice, _send(bob, b"b%d" % i)), b"b%d" % i)

    def test_out_of_order_within_limit(self):
        alice, bob = _pair()
        msgs = [_send(alice, b"m%d" % i) for i in range(5)]
        for i in (4, 0, 3, 1, 2):
            self.assertEqual(_recv(bob, msgs[i]), b"m%d" % i)

    def test_replay_rejected(self):
        alice, bob = _pair()
        m = _send(alice, b"uma vez")
        _recv(bob, m)
        with self.assertRaises(SeloError):
            _recv(bob, m)

    def test_skip_beyond_limit_rejected(self):
        alice, bob = _pair()
        for _ in range(MAX_SKIP + 1):
            alice.next_send()
        with self.assertRaises(SeloError):
            _recv(bob, _send(alice, b"longe demais"))

    def test_failed_decrypt_leaves_state_unchanged(self):
        alice, bob = _pair()
        hdr, ct = _send(alice, b"ok")
        bad = bytearray(ct)
        bad[0] ^= 1
        before = bob.to_dict()
        with self.assertRaises(SeloError):
            _recv(bob, (hdr, bytes(bad)))
        self.assertEqual(bob.to_dict(), before)
        self.assertEqual(_recv(bob, (hdr, ct)), b"ok")

    def test_forward_secrecy_state_after_cannot_read_past(self):
        alice, bob = _pair()
        m = _send(alice, b"segredo passado")
        _recv(bob, m)
        stolen = Ratchet.from_dict(bob.to_dict())  # atacante copia o estado atual
        with self.assertRaises(SeloError):
            _recv(stolen, m)

    def test_persistence_roundtrip(self):
        alice, bob = _pair()
        msgs = [_send(alice, b"x%d" % i) for i in range(3)]
        _recv(bob, msgs[2])  # gera chaves puladas
        bob2 = Ratchet.from_dict(json.loads(json.dumps(bob.to_dict())))
        self.assertEqual(_recv(bob2, msgs[0]), b"x0")
        self.assertEqual(_recv(bob2, _send(alice, b"depois")), b"depois")

    def test_header_validation(self):
        _, bob = _pair()
        for hdr in (
            {},
            {"dh": "AA", "pn": 0, "n": 0},
            {"dh": "A" * 43, "pn": -1, "n": 0},
            {"dh": "A" * 43, "pn": 0, "n": True},
        ):
            with self.assertRaises(SeloError):
                bob.decrypt(hdr, b"", b"x" * 20)


class ChannelRule(unittest.TestCase):
    def test_rule(self):
        self.assertEqual(channel.choose("SendMessage", False), channel.ENVELOPE)
        self.assertEqual(channel.choose("SendMessage", True), channel.SESSION)
        self.assertEqual(channel.choose("GetTask", False), channel.ENVELOPE)
        self.assertEqual(channel.choose("SendStreamingMessage", False), channel.SESSION)
        self.assertEqual(channel.choose("SubscribeToTask", True), channel.SESSION)
        self.assertEqual(
            channel.fallback_after_lost_session("CancelTask"), channel.ENVELOPE
        )
        self.assertEqual(
            channel.fallback_after_lost_session("SubscribeToTask"), channel.SESSION
        )


if __name__ == "__main__":
    unittest.main()
