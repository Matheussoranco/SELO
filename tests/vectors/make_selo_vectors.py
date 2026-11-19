"""Gera tests/vectors/selo_v1.json: vetores proprios do SELO (especificacao, secao 18).

Todas as chaves e toda a aleatoriedade sao fixas (derivadas de rotulos por SHA-256), entao
uma implementacao independente pode reproduzir cada valor byte a byte:

* agent_id e KEL (inception + rotation) de Alice;
* Agent Card de Bob com a assinatura JWS EdDSA;
* envelope de Alice para Bob (cabecalho, enc, ct, sig);
* handshake Noise IK de Alice com Bob, raiz do ratchet e a primeira mensagem de sessao.

Uso: python tests/vectors/make_selo_vectors.py   (reescreve o arquivo)
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from selo import jcs
from selo.card import build_card
from selo.crypto.noise import HandshakeState
from selo.crypto.primitives import (
    b64u,
    ed25519_from_bytes,
    ed25519_pub,
    x25519_from_bytes,
    x25519_pub,
)
from selo.crypto.ratchet import Ratchet, root_from_handshake, seal_with
from selo.envelope import seal
from selo.identity import Identity
from selo.sessions import _ad_base, prologue

T = 1_800_000_000  # instante fixo dos vetores (2027-01-15T08:00:00Z)
OUT = Path(__file__).with_name("selo_v1.json")


def seed(label: str) -> bytes:
    return hashlib.sha256(b"selo/1/test-vector\x00" + label.encode()).digest()


def ed(label: str):
    return ed25519_from_bytes(seed(label))


def xk(label: str):
    return x25519_from_bytes(seed(label))


def build() -> dict:
    alice = Identity.generate(T, sig=ed("alice-sig-0"), agree=xk("alice-agree-0"))
    kel_inception = json.loads(json.dumps(alice.kel))
    alice.rotate(T + 60, sig=ed("alice-sig-1"), agree=xk("alice-agree-1"))
    bob = Identity.generate(T, sig=ed("bob-sig-0"), agree=xk("bob-agree-0"))
    card_bob = build_card(bob, "https://bob.example", name="bob", iat=T, validity=86400)

    from selo.card import verify_card

    bob_info = verify_card(card_bob, now=T + 1)
    rpc = {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "SendMessage",
        "params": {
            "message": {
                "messageId": "m-1",
                "role": "ROLE_USER",
                "parts": [{"text": "ola"}],
            }
        },
    }
    env = seal(
        sender=alice,
        sender_card_url="https://alice.example",
        recipient=bob_info,
        body={"rpc": rpc},
        t="req",
        now=T + 120,
        _fixed={"msg": seed("envelope-msg")[:16], "eph": xk("envelope-eph")},
    )

    # handshake Noise IK (Alice inicia; chaves de acordo atuais de cada lado)
    pro = prologue(bob.agent_id, bob.seq)
    m1_payload = jcs.canonicalize(
        {
            "agent_id": alice.agent_id,
            "card": "https://alice.example",
            "seq": alice.seq,
            "iat": T + 120,
        }
    )
    init = HandshakeState(
        "IK", True, pro, s=alice.agree_key, e=xk("hs-init-eph"), rs=bob_info.agree_pub
    )
    resp = HandshakeState("IK", False, pro, s=bob.agree_key, e=xk("hs-resp-eph"))
    m1 = init.write_message(m1_payload)
    assert resp.read_message(m1) == m1_payload
    sid = b64u(seed("session-id")[:16])
    m2_payload = jcs.canonicalize({"sid": sid, "exp": T + 120 + 86400})
    m2 = resp.write_message(m2_payload)
    assert init.read_message(m2) == m2_payload
    sk = root_from_handshake(init.ck, init.h)
    assert sk == root_from_handshake(resp.ck, resp.h)
    alice_r = Ratchet.init_alice(sk, init.re, dhs=xk("ratchet-alice-dh-0"))
    hdr, mk = alice_r.next_send()
    ad = _ad_base(sid, "i2r", hdr) + hashlib.sha256(b"").digest()
    ct = seal_with(mk, ad, jcs.canonicalize({"rpc": rpc}))

    return {
        "description": "Vetores do SELO v1 (docs/spec/selo-v1.md, secao 18). Chaves privadas = "
        "SHA-256('selo/1/test-vector' || 0x00 || rotulo).",
        "time": T,
        "keys": {
            label: seed(label).hex()
            for label in (
                "alice-sig-0",
                "alice-agree-0",
                "alice-sig-1",
                "alice-agree-1",
                "bob-sig-0",
                "bob-agree-0",
                "envelope-eph",
                "hs-init-eph",
                "hs-resp-eph",
                "ratchet-alice-dh-0",
            )
        },
        "public": {
            "alice-sig-0": ed25519_pub(ed("alice-sig-0")).hex(),
            "alice-agree-1": x25519_pub(xk("alice-agree-1")).hex(),
            "bob-agree-0": x25519_pub(xk("bob-agree-0")).hex(),
        },
        "agent_id": {"alice": alice.agent_id, "bob": bob.agent_id},
        "kel_alice_inception": kel_inception,
        "kel_alice": alice.kel,
        "card_bob": card_bob,
        "card_bob_jcs_without_signatures": jcs.canonicalize(
            {k: v for k, v in card_bob.items() if k != "signatures"}
        ).decode(),
        "envelope": {
            "rpc": rpc,
            "envelope_msg": seed("envelope-msg")[:16].hex(),
            "header_jcs": jcs.canonicalize(env["h"]).decode(),
            "value": env,
        },
        "session": {
            "prologue": pro.hex(),
            "m1_payload": m1_payload.decode(),
            "m1": m1.hex(),
            "m2_payload": m2_payload.decode(),
            "m2": m2.hex(),
            "handshake_hash": init.h.hex(),
            "ratchet_root": sk.hex(),
            "first_message": {
                "sid": sid,
                "hdr": hdr,
                "ad": ad.hex(),
                "ct": b64u(ct),
                "plaintext": jcs.canonicalize({"rpc": rpc}).decode(),
            },
        },
    }


if __name__ == "__main__":
    OUT.write_text(
        json.dumps(build(), indent=1, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    print(f"escrito {OUT}")
