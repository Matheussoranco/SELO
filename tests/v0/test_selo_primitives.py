"""Testes dos blocos criptograficos do SELO: Shamir, hierarquia de chaves, Merkle, tokens, envelope."""

import json
import unittest

from selo_v0 import SeloError
from selo_v0.envelope import open_envelope, seal
from selo_v0.keys import EpochKeys, agree_private, pub_raw, seed_at, seed_epoch0
from selo_v0.manifest import (
    MerkleLog,
    inclusion_path,
    merkle_root,
    validate_args,
    verify_inclusion,
)
from selo_v0.sandbox import World
from selo_v0.shamir import P, combine, random_secret, split
from selo_v0.tokens import Token, TokenContext, mint, verify
from selo_v0.util import b64d, canon


def is_probable_prime(n):
    if n < 2:
        return False
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % p == 0:
            return n == p
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for a in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


class ShamirTests(unittest.TestCase):
    def test_modulus_is_prime(self):
        self.assertTrue(is_probable_prime(P))

    def test_threshold_reconstruction(self):
        secret = random_secret()
        parts = split(secret, 3, 5)
        for subset in ([0, 1, 2], [4, 2, 0], [1, 3, 4], [0, 1, 2, 3, 4]):
            self.assertEqual(combine([parts[i] for i in subset]), secret)

    def test_below_threshold_reveals_nothing_useful(self):
        secret = random_secret()
        parts = split(secret, 3, 5)
        self.assertNotEqual(combine(parts[:2]), secret)

    def test_bad_inputs(self):
        with self.assertRaises(SeloError):
            split(b"short", 2, 3)
        with self.assertRaises(SeloError):
            split(random_secret(), 4, 3)
        parts = split(random_secret(), 2, 3)
        with self.assertRaises(SeloError):
            combine([parts[0], parts[0]])


class KeyHierarchyTests(unittest.TestCase):
    def setUp(self):
        self.master = random_secret()

    def test_org_recomputes_agent_key_for_any_epoch(self):
        keys = EpochKeys.start(0, seed_epoch0(self.master, "acme", "erp"))
        for epoch in (1, 2, 7):
            keys.advance_to(epoch)
            org_side = agree_private(seed_at(self.master, "acme", "erp", epoch))
            self.assertEqual(
                pub_raw(keys.agree_key(epoch).public_key()),
                pub_raw(org_side.public_key()),
            )

    def test_agents_and_epochs_have_independent_keys(self):
        a = pub_raw(agree_private(seed_at(self.master, "acme", "a", 3)).public_key())
        b = pub_raw(agree_private(seed_at(self.master, "acme", "b", 3)).public_key())
        a4 = pub_raw(agree_private(seed_at(self.master, "acme", "a", 4)).public_key())
        self.assertEqual(len({a, b, a4}), 3)

    def test_epoch_forward_secrecy_window(self):
        keys = EpochKeys.start(0, seed_epoch0(self.master, "acme", "erp"))
        keys.advance_to(5)
        self.assertNotIn(3, keys.seeds)  # semente antiga apagada
        keys.agree_key(4)  # tolerancia (epoca anterior)
        keys.agree_key(5)
        keys.agree_key(6)  # remetente com relogio adiantado
        for bad in (3, 7):
            with self.assertRaises(SeloError):
                keys.agree_key(bad)

    def test_clock_cannot_go_back(self):
        keys = EpochKeys.start(4, seed_epoch0(self.master, "acme", "erp"))
        with self.assertRaises(SeloError):
            keys.advance_to(3)


class MerkleTests(unittest.TestCase):
    def test_all_inclusion_proofs_verify_and_tampering_fails(self):
        for n in range(1, 34):
            leaves = [f"leaf-{i}".encode() for i in range(n)]
            root = merkle_root(leaves)
            for i in range(n):
                path = inclusion_path(i, leaves)
                self.assertTrue(verify_inclusion(leaves[i], i, n, path, root), (n, i))
                self.assertFalse(verify_inclusion(b"forged", i, n, path, root))
                if n > 1:
                    self.assertFalse(
                        verify_inclusion(leaves[i], (i + 1) % n, n, path, root)
                    )

    def test_proof_length_is_logarithmic(self):
        leaves = [bytes([i % 256, i // 256]) for i in range(1000)]
        self.assertLessEqual(
            max(len(inclusion_path(i, leaves)) for i in (0, 499, 999)), 10
        )

    def test_log_is_append_only_in_structure(self):
        log = MerkleLog()
        log.append({"a": 1})
        r1 = log.root()
        log.append({"a": 2})
        self.assertNotEqual(r1, log.root())


class TokenTests(unittest.TestCase):
    def ctx(self, **kw):
        base = dict(
            sender="assistant",
            cap="x",
            manifest_hash="h",
            now=100.0,
            args={"amount": 50, "to": "corp"},
            taint=set(),
            uses=lambda _i: 0,
        )
        base.update(kw)
        return TokenContext(**base)

    def test_mint_verify_and_wrong_key(self):
        key = b"k" * 32
        token = mint(key, "x")
        verify(key, token, self.ctx())
        with self.assertRaises(SeloError):
            verify(b"z" * 32, token, self.ctx())

    def test_attenuation_narrows_authority(self):
        key = b"k" * 32
        token = mint(key, "x", [{"holder": "assistant"}]).attenuate(
            {"arg_max": {"field": "amount", "max": 100}}
        )
        verify(key, token, self.ctx())
        with self.assertRaises(SeloError):
            verify(key, token, self.ctx(args={"amount": 500, "to": "corp"}))
        with self.assertRaises(SeloError):
            verify(key, token, self.ctx(sender="web"))

    def test_caveats_cannot_be_removed_or_edited(self):
        key = b"k" * 32
        token = mint(key, "x", [{"holder": "assistant"}, {"exp": 150}])
        stripped = Token(token.ident, token.cap, token.caveats[:1], token.sig)
        with self.assertRaises(SeloError):
            verify(key, stripped, self.ctx())
        edited = Token(
            token.ident, token.cap, ({"holder": "web"}, token.caveats[1]), token.sig
        )
        with self.assertRaises(SeloError):
            verify(key, edited, self.ctx(sender="web"))

    def test_expiry_taint_manifest_uses_and_unknown_caveat(self):
        key = b"k" * 32
        verify(key, mint(key, "x", [{"exp": 200}]), self.ctx())
        for caveat, ctx in [
            ({"exp": 100}, self.ctx()),
            ({"forbid_taint": ["WEB"]}, self.ctx(taint={"WEB"})),
            ({"manifest": "other"}, self.ctx()),
            ({"max_uses": 1}, self.ctx(uses=lambda _i: 1)),
            ({"arg_in": {"field": "to", "values": ["other"]}}, self.ctx()),
            ({"novel_predicate": 1}, self.ctx()),
        ]:
            with self.assertRaises(SeloError, msg=caveat):
                verify(key, mint(key, "x", [caveat]), ctx)

    def test_token_bound_to_capability(self):
        key = b"k" * 32
        with self.assertRaises(SeloError):
            verify(key, mint(key, "other"), self.ctx())


class SchemaTests(unittest.TestCase):
    schema = {
        "properties": {
            "n": {"type": "integer", "minimum": 1, "maximum": 10},
            "s": {"type": "string", "maxLength": 3},
            "e": {"enum": ["a", "b"]},
        },
        "required": ["n", "s", "e"],
    }

    def test_accepts_and_rejects(self):
        validate_args(self.schema, {"n": 5, "s": "abc", "e": "a"})
        for bad in (
            {"n": 0, "s": "a", "e": "a"},
            {"n": 5, "s": "abcd", "e": "a"},
            {"n": 5, "s": "a", "e": "z"},
            {"n": 5, "s": "a"},
            {"n": 5, "s": "a", "e": "a", "x": 1},
            {"n": True, "s": "a", "e": "a"},
        ):
            with self.assertRaises(ValueError):
                validate_args(self.schema, bad)


class SchemaRecursiveTests(unittest.TestCase):
    schema = {
        "type": "object",
        "properties": {
            "to": {
                "type": "array",
                "items": {"type": "string", "maxLength": 20},
                "maxItems": 2,
            },
            "note": {"anyOf": [{"type": "string"}, {"type": "null"}]},
            "amount": {"type": "number", "minimum": 0},
            "kind": {"$ref": "#/$defs/Kind"},
            "meta": {"type": "object", "additionalProperties": True},
        },
        "required": ["to", "amount"],
        "$defs": {"Kind": {"type": "string", "enum": ["a", "b"]}},
    }

    def test_valid_and_invalid(self):
        validate_args(
            self.schema,
            {
                "to": ["x@y.z"],
                "amount": 10.5,
                "note": None,
                "kind": "a",
                "meta": {"k": 1},
            },
        )
        validate_args(self.schema, {"to": [], "amount": 3})
        for bad in (
            {"to": "x", "amount": 1},
            {"to": ["a", "b", "c"], "amount": 1},
            {"to": [1], "amount": 1},
            {"amount": 1},
            {"to": [], "amount": -1},
            {"to": [], "amount": 1, "kind": "z"},
            {"to": [], "amount": 1, "note": 5},
            {"to": [], "amount": 1, "extra": 1},
        ):
            with self.assertRaises(ValueError, msg=bad):
                validate_args(self.schema, bad)


class EnvelopeTests(unittest.TestCase):
    def setUp(self):
        self.w = World().standard()
        self.addCleanup(self.w.close)
        self.a, self.erp = self.w.agents["assistant"], self.w.agents["erp"]
        entry = self.a.remote_entry("erp")
        self.env = seal(
            org=self.w.org.params,
            sender_id="assistant",
            sender_sk=self.a.sig_sk,
            sender_cert=self.a.cert,
            recipient_id="erp",
            recipient_epoch=entry["epoch"],
            recipient_agree_pub=b64d(entry["agree_pub"]),
            body={"t": "ping", "secret": "SEGREDO-123"},
            now=self.a.now(),
        )
        self.epoch = entry["epoch"]

    def open_as(self, agent, env=None, now=None):
        env = env or self.env
        return open_envelope(
            env,
            org=self.w.org.params,
            agree_sk=agent.keys.agree_key(self.epoch),
            my_id=agent.id,
            now=agent.now() if now is None else now,
        )

    def test_round_trip_and_ciphertext_hides_content(self):
        self.assertEqual(self.open_as(self.erp).body["secret"], "SEGREDO-123")
        self.assertNotIn("SEGREDO", json.dumps(self.env))

    def test_third_party_cannot_open(self):
        web = self.w.agents["web"]
        with self.assertRaises(SeloError):
            open_envelope(
                self.env,
                org=self.w.org.params,
                agree_sk=web.keys.agree_key(self.epoch),
                my_id=None,
                now=web.now(),
            )

    def test_org_can_read_with_audit_trail(self):
        opened = self.w.org.open(self.env, auditor="ciso", reason="incidente 42")
        self.assertEqual(opened.body["secret"], "SEGREDO-123")
        self.assertEqual(len(self.w.org.audit.records), 1)
        self.assertTrue(self.w.org.audit.verify())
        with self.assertRaises(SeloError):
            self.w.org.open(self.env, auditor="ciso", reason="")

    def test_audit_log_detects_tampering(self):
        self.w.org.open(self.env, "ciso", "r1")
        self.w.org.open(self.env, "ciso", "r2")
        self.w.org.audit.records[0]["reason"] = "apagado"
        self.assertFalse(self.w.org.audit.verify())

    def test_tampering_is_detected(self):
        import copy

        for mutate in (
            lambda e: e["h"].update(iat=e["h"]["iat"] + 1),
            lambda e: e["h"].update(recipient="web"),
            lambda e: e.update(
                ct=e["ct"][:-2] + ("AA" if e["ct"][-2:] != "AA" else "BB")
            ),
            lambda e: e.update(
                sig=e["sig"][:-2] + ("AA" if e["sig"][-2:] != "AA" else "BB")
            ),
        ):
            env = copy.deepcopy(self.env)
            mutate(env)
            with self.assertRaises(SeloError):
                self.open_as(self.erp, env)

    def test_sender_certificate_must_match_header(self):
        import copy

        env = copy.deepcopy(self.env)
        env["cert"] = self.w.agents["web"].cert
        with self.assertRaises(SeloError):
            self.open_as(self.erp, env)

    def test_org_cannot_forge_a_message_from_an_agent(self):
        entry = self.a.remote_entry("erp")
        forged = seal(
            org=self.w.org.params,
            sender_id="assistant",
            sender_sk=self.w.org._sig_sk,
            sender_cert=self.a.cert,
            recipient_id="erp",
            recipient_epoch=entry["epoch"],
            recipient_agree_pub=b64d(entry["agree_pub"]),
            body={"t": "x"},
            now=self.a.now(),
        )
        with self.assertRaises(SeloError) as cm:
            self.open_as(self.erp, forged)
        self.assertEqual(cm.exception.code, "bad_signature")

    def test_lifetime_window(self):
        self.w.clock.advance(300)
        with self.assertRaises(SeloError) as cm:
            self.open_as(self.erp)
        self.assertEqual(cm.exception.code, "invalid_lifetime")

    def test_floats_roundtrip_but_non_finite_are_rejected(self):
        import json as _json

        value = {"x": 1.5, "y": [0.1, 1e-7, 123456789.123]}
        self.assertEqual(_json.loads(canon(value)), value)
        self.assertEqual(canon(_json.loads(canon(value))), canon(value))
        for bad in (float("nan"), float("inf")):
            with self.assertRaises(SeloError):
                canon({"x": bad})

    def test_canonical_json_is_deterministic(self):
        self.assertEqual(
            canon({"b": 1, "a": [1, {"d": 2, "c": 3}]}),
            canon({"a": [1, {"c": 3, "d": 2}], "b": 1}),
        )


if __name__ == "__main__":
    unittest.main()
