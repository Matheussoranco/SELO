"""Cofre de chaves (especificacao, secao 14). Chaves privadas nunca ficam em claro no disco.

Backends:

* ``dpapi`` (Windows): blob protegido por ``CryptProtectData``, ligado a conta do usuario.
* ``keychain`` (macOS): ``security add-generic-password`` / ``find-generic-password``.
* ``secret-service`` (Linux): ``secret-tool store`` / ``lookup``.
* ``file``: arquivo cifrado com senha (scrypt + ChaCha20-Poly1305); senha em
  ``SELO_KEY_PASSWORD`` ou digitada no terminal.
* ``auto``: o cofre do sistema operacional.
* ``memory``: so para testes em processo (nao persiste).

Somente ``dpapi`` e ``file`` sao exercitados pela suite de testes (desenvolvida no Windows);
``keychain`` e ``secret-service`` seguem a interface das ferramentas do sistema e nao foram
executados aqui.
"""

from __future__ import annotations

import getpass
import os
import shutil
import subprocess
import sys
from typing import Dict, Optional

from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from .crypto.primitives import aead_open, aead_seal
from .errors import SeloError

SERVICE = "selo"


class KeyStore:
    name = "abstract"

    def load(self, key: str) -> Optional[bytes]:
        raise NotImplementedError

    def store(self, key: str, data: bytes) -> None:
        raise NotImplementedError


def _write_private(path: str, data: bytes) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    fd = os.open(
        tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_BINARY", 0), 0o600
    )
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)


class MemoryKeyStore(KeyStore):
    name = "memory"

    def __init__(self) -> None:
        self._d: Dict[str, bytes] = {}

    def load(self, key: str) -> Optional[bytes]:
        return self._d.get(key)

    def store(self, key: str, data: bytes) -> None:
        self._d[key] = data


class DpapiKeyStore(KeyStore):
    name = "dpapi"

    def __init__(self, directory: str) -> None:
        if sys.platform != "win32":
            raise SeloError("keystore_unavailable", "DPAPI so existe no Windows")
        self.dir = directory

    def _path(self, key: str) -> str:
        return os.path.join(self.dir, f"{key}.dpapi")

    def load(self, key: str) -> Optional[bytes]:
        p = self._path(key)
        if not os.path.exists(p):
            return None
        with open(p, "rb") as fh:
            return _dpapi(fh.read(), protect=False)

    def store(self, key: str, data: bytes) -> None:
        _write_private(self._path(key), _dpapi(data, protect=True))


def _dpapi(data: bytes, protect: bool) -> bytes:
    import ctypes
    from ctypes import wintypes

    class BLOB(ctypes.Structure):
        _fields_ = [
            ("cbData", wintypes.DWORD),
            ("pbData", ctypes.POINTER(ctypes.c_char)),
        ]

    crypt32, kernel32 = ctypes.windll.crypt32, ctypes.windll.kernel32
    buf = ctypes.create_string_buffer(data, len(data))
    entropy_raw = b"selo/1/keystore"
    ebuf = ctypes.create_string_buffer(entropy_raw, len(entropy_raw))
    blob_in = BLOB(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char)))
    entropy = BLOB(len(entropy_raw), ctypes.cast(ebuf, ctypes.POINTER(ctypes.c_char)))
    blob_out = BLOB()
    CRYPTPROTECT_UI_FORBIDDEN = 0x1
    fn = crypt32.CryptProtectData if protect else crypt32.CryptUnprotectData
    if protect:
        ok = fn(
            ctypes.byref(blob_in),
            "selo",
            ctypes.byref(entropy),
            None,
            None,
            CRYPTPROTECT_UI_FORBIDDEN,
            ctypes.byref(blob_out),
        )
    else:
        ok = fn(
            ctypes.byref(blob_in),
            None,
            ctypes.byref(entropy),
            None,
            None,
            CRYPTPROTECT_UI_FORBIDDEN,
            ctypes.byref(blob_out),
        )
    if not ok:
        raise SeloError(
            "keystore_error", f"DPAPI falhou (erro {ctypes.GetLastError()})"
        )
    try:
        return ctypes.string_at(blob_out.pbData, blob_out.cbData)
    finally:
        kernel32.LocalFree(blob_out.pbData)


class KeychainKeyStore(KeyStore):
    name = "keychain"

    def __init__(self, account_prefix: str) -> None:
        if sys.platform != "darwin" or not shutil.which("security"):
            raise SeloError("keystore_unavailable", "Keychain (security) indisponivel")
        self.prefix = account_prefix

    def load(self, key: str) -> Optional[bytes]:
        r = subprocess.run(
            [
                "security",
                "find-generic-password",
                "-a",
                f"{self.prefix}/{key}",
                "-s",
                SERVICE,
                "-w",
            ],
            capture_output=True,
            text=True,
        )
        return bytes.fromhex(r.stdout.strip()) if r.returncode == 0 else None

    def store(self, key: str, data: bytes) -> None:
        r = subprocess.run(
            [
                "security",
                "add-generic-password",
                "-U",
                "-a",
                f"{self.prefix}/{key}",
                "-s",
                SERVICE,
                "-w",
                data.hex(),
            ],
            capture_output=True,
            text=True,
        )
        if r.returncode != 0:
            raise SeloError("keystore_error", r.stderr.strip())


class SecretServiceKeyStore(KeyStore):
    name = "secret-service"

    def __init__(self, account_prefix: str) -> None:
        if not shutil.which("secret-tool"):
            raise SeloError("keystore_unavailable", "secret-tool indisponivel")
        self.prefix = account_prefix

    def load(self, key: str) -> Optional[bytes]:
        r = subprocess.run(
            [
                "secret-tool",
                "lookup",
                "service",
                SERVICE,
                "account",
                f"{self.prefix}/{key}",
            ],
            capture_output=True,
            text=True,
        )
        return (
            bytes.fromhex(r.stdout.strip())
            if r.returncode == 0 and r.stdout.strip()
            else None
        )

    def store(self, key: str, data: bytes) -> None:
        r = subprocess.run(
            [
                "secret-tool",
                "store",
                "--label",
                f"SELO {self.prefix}/{key}",
                "service",
                SERVICE,
                "account",
                f"{self.prefix}/{key}",
            ],
            input=data.hex(),
            capture_output=True,
            text=True,
        )
        if r.returncode != 0:
            raise SeloError("keystore_error", r.stderr.strip())


class FileKeyStore(KeyStore):
    """Arquivo cifrado por senha: magic || salt(16) || nonce(12) || ChaCha20-Poly1305."""

    name = "file"
    MAGIC = b"SELOKS1\x00"

    def __init__(self, directory: str, password: Optional[str] = None) -> None:
        self.dir = directory
        self._password = password

    def _pw(self) -> bytes:
        pw = self._password or os.environ.get("SELO_KEY_PASSWORD")
        if not pw:
            if not _interactive():
                raise SeloError(
                    "keystore_password",
                    "defina SELO_KEY_PASSWORD para o cofre em arquivo",
                )
            pw = getpass.getpass("Senha do cofre SELO: ")
        self._password = pw
        return pw.encode("utf-8")

    @staticmethod
    def _kdf(pw: bytes, salt: bytes) -> bytes:
        return Scrypt(salt=salt, length=32, n=2**15, r=8, p=1).derive(pw)

    def _path(self, key: str) -> str:
        return os.path.join(self.dir, f"{key}.sealed")

    def load(self, key: str) -> Optional[bytes]:
        p = self._path(key)
        if not os.path.exists(p):
            return None
        with open(p, "rb") as fh:
            raw = fh.read()
        if not raw.startswith(self.MAGIC):
            raise SeloError("keystore_error", "arquivo de cofre invalido")
        salt, nonce, ct = raw[8:24], raw[24:36], raw[36:]
        try:
            return aead_open(
                self._kdf(self._pw(), salt), nonce, self.MAGIC + key.encode(), ct
            )
        except SeloError:
            raise SeloError(
                "keystore_password", "senha errada ou cofre adulterado"
            ) from None

    def store(self, key: str, data: bytes) -> None:
        salt, nonce = os.urandom(16), os.urandom(12)
        ct = aead_seal(
            self._kdf(self._pw(), salt), nonce, self.MAGIC + key.encode(), data
        )
        _write_private(self._path(key), self.MAGIC + salt + nonce + ct)


def _interactive() -> bool:
    """Ha um terminal de verdade para digitar a senha?

    No Windows, o dispositivo NUL tambem responde isatty(); so um console aceita
    GetConsoleMode."""
    if not sys.stdin or not sys.stdin.isatty():
        return False
    if sys.platform != "win32":
        return True
    import ctypes
    import msvcrt

    mode = ctypes.c_uint32()
    handle = msvcrt.get_osfhandle(sys.stdin.fileno())
    return bool(ctypes.windll.kernel32.GetConsoleMode(handle, ctypes.byref(mode)))


def open_keystore(backend: str, state_dir: str, account: str) -> KeyStore:
    key_dir = os.path.join(state_dir, "keys")
    if backend == "auto":
        if sys.platform == "win32":
            backend = "dpapi"
        elif sys.platform == "darwin":
            backend = "keychain"
        elif shutil.which("secret-tool"):
            backend = "secret-service"
        else:
            raise SeloError(
                "keystore_unavailable",
                'nenhum cofre do sistema encontrado; use keystore.backend = "file"',
            )
    if backend == "dpapi":
        return DpapiKeyStore(key_dir)
    if backend == "keychain":
        return KeychainKeyStore(account)
    if backend == "secret-service":
        return SecretServiceKeyStore(account)
    if backend == "file":
        return FileKeyStore(key_dir)
    if backend == "memory":
        return MemoryKeyStore()
    raise SeloError("keystore_unavailable", f"backend desconhecido: {backend}")
