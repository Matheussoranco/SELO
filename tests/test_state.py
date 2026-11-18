"""Ticket #8: estado persistente (anti-replay sobrevive a reinicio) e chaves no cofre."""

import base64
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import unittest

from selo.crypto.primitives import ed25519_priv, x25519_priv
from selo.errors import SeloError
from selo.keystore import FileKeyStore, open_keystore
from selo.sidecar import Sidecar
from selo.store import SCHEMA_VERSION, Store
from tests.e2e import World, send_message


def _all_bytes(directory):
    blobs = []
    for root, _dirs, files in os.walk(directory):
        for f in files:
            with open(os.path.join(root, f), "rb") as fh:
                blobs.append((os.path.join(root, f), fh.read()))
    return blobs


def _forms(raw: bytes):
    """Formas em que uma chave privada poderia aparecer em claro."""
    return [
        raw,
        raw.hex().encode(),
        base64.b64encode(raw).rstrip(b"="),
        base64.urlsafe_b64encode(raw).rstrip(b"="),
    ]


class ReplayAcrossRestartTest(unittest.TestCase):
    def test_message_accepted_before_restart_is_replay_after(self):
        with World() as w:
            a, b = w.node("a"), w.node("b", proxied=True)
            resp = a.client.call(b.url, send_message("uma vez so"))
            self.assertNotIn("error", resp)
            ex = b.proxy.find("/selo/v1/envelope")[-1]
            b.restart()
            status, body = b.proxy.replay(ex)
            self.assertEqual((status, json.loads(body)["error"]), (409, "replay"))
            self.assertEqual([r["text"] for r in b.received()].count("uma vez so"), 1)
            # e o sidecar reiniciado continua com a mesma identidade
            self.assertEqual(b.client.whoami()["agent_id"], b.agent_id)


@unittest.skipUnless(sys.platform == "win32", "DPAPI so no Windows")
class KeysNeverInClearTest(unittest.TestCase):
    def test_private_keys_absent_from_disk(self):
        tmp = tempfile.mkdtemp(prefix="selo-keys-")
        cfg = {
            "name": "k",
            "state_dir": tmp,
            "agent": {"url": "http://127.0.0.1:9/"},
            "keystore": {"backend": "dpapi"},
            "local": {"mode": "http"},
        }
        sc = Sidecar(cfg).start()
        try:
            ident = sc.identity
            secrets = [ed25519_priv(k) for k in ident.sig_keys] + [
                x25519_priv(k) for k in ident.agree_keys
            ]
            secrets.append(sc.store._data_key)
            sc.store.save_session(
                "sid", "peer", "url", "i", 2**31, {"segredo": "x" * 40}
            )
        finally:
            sc.stop()
        files = _all_bytes(tmp)
        self.assertTrue(any(p.endswith(".dpapi") for p, _ in files))
        for path, data in files:
            for s in secrets:
                for form in _forms(s):
                    self.assertNotIn(form, data, f"chave em claro em {path}")
            self.assertNotIn(b"x" * 40, data, f"estado de sessao em claro em {path}")
        # o cofre DPAPI reabre a mesma identidade
        sc2 = Sidecar(cfg)
        self.assertEqual(sc2.identity.agent_id, ident.agent_id)
        sc2.store.close()


class FileKeyStoreTest(unittest.TestCase):
    def test_password_file_roundtrip_and_errors(self):
        d = tempfile.mkdtemp(prefix="selo-fileks-")
        ks = FileKeyStore(d, password="correta")
        ks.store("identity", b"segredo-bem-guardado")
        raw = open(os.path.join(d, "identity.sealed"), "rb").read()
        self.assertNotIn(b"segredo-bem-guardado", raw)
        self.assertEqual(
            FileKeyStore(d, password="correta").load("identity"),
            b"segredo-bem-guardado",
        )
        with self.assertRaises(SeloError) as cm:
            FileKeyStore(d, password="errada").load("identity")
        self.assertEqual(cm.exception.code, "keystore_password")

    def test_file_backend_asks_for_password(self):
        d = tempfile.mkdtemp(prefix="selo-fileks-")
        env = {k: v for k, v in os.environ.items() if k != "SELO_KEY_PASSWORD"}
        code = (
            "import sys; from selo.keystore import FileKeyStore\n"
            "try:\n FileKeyStore(sys.argv[1]).store('x', b'y')\n"
            "except Exception as e: print(type(e).__name__, e.code)"
        )
        out = subprocess.run(
            [sys.executable, "-c", code, d],
            capture_output=True,
            text=True,
            env=env,
            stdin=subprocess.DEVNULL,
            timeout=60,
        ).stdout
        self.assertIn("keystore_password", out)
        env["SELO_KEY_PASSWORD"] = "pela-variavel"
        subprocess.run([sys.executable, "-c", code, d], check=True, env=env, timeout=60)
        self.assertEqual(FileKeyStore(d, password="pela-variavel").load("x"), b"y")

    def test_sidecar_with_file_backend(self):
        tmp = tempfile.mkdtemp(prefix="selo-filesc-")
        previous = os.environ.get("SELO_KEY_PASSWORD")
        os.environ["SELO_KEY_PASSWORD"] = "senha-do-teste"
        try:
            cfg = {
                "name": "f",
                "state_dir": tmp,
                "agent": {"url": "http://127.0.0.1:9/"},
                "keystore": {"backend": "file"},
            }
            sc = Sidecar(cfg)
            agent_id = sc.identity.agent_id
            sc.store.close()
            self.assertTrue(
                os.path.exists(os.path.join(tmp, "keys", "identity.sealed"))
            )
            sc2 = Sidecar(cfg)
            self.assertEqual(sc2.identity.agent_id, agent_id)
            sc2.store.close()
        finally:
            if previous is None:
                del os.environ["SELO_KEY_PASSWORD"]
            else:
                os.environ["SELO_KEY_PASSWORD"] = previous

    def test_unknown_backend(self):
        with self.assertRaises(SeloError):
            open_keystore("inexistente", tempfile.mkdtemp(), "x")


class SchemaTest(unittest.TestCase):
    def test_schema_is_versioned(self):
        path = os.path.join(tempfile.mkdtemp(prefix="selo-db-"), "s.sqlite3")
        st = Store(path)
        self.assertEqual(st.schema_version(), SCHEMA_VERSION)
        st.close()
        db = sqlite3.connect(path)
        db.execute("UPDATE meta SET v='999' WHERE k='schema_version'")
        db.commit()
        db.close()
        with self.assertRaises(SeloError) as cm:
            Store(path)
        self.assertEqual(cm.exception.code, "schema_version")

    def test_session_state_encrypted_and_bound_to_sid(self):
        st = Store(":memory:", data_key=b"k" * 32)
        st.save_session("s1", "p", "u", "i", 10**10, {"mk": "material-secreto"})
        (blob,) = st.raw_session_blobs()
        self.assertNotIn(b"material-secreto", blob)
        self.assertEqual(st.load_session("s1")[4], {"mk": "material-secreto"})
        st._db.execute("UPDATE sessions SET sid='s2'")  # mover o blob para outra sessao
        with self.assertRaises(SeloError):
            st.load_session("s2")


if __name__ == "__main__":
    unittest.main()
