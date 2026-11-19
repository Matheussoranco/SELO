"""Diretorio de pares: busca, verificacao, fixacao de KEL e politica de confianca.

Especificacao, secoes 5.2, 6.2 e 7. Toda decisao de aceitar um par passa por `PeerDirectory.get`.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass
from typing import Any, Callable, Dict, Optional, Tuple

from .card import WELL_KNOWN, CardInfo, normalize_base, verify_card
from .errors import SeloError
from .identity import check_extends
from .net import HttpClient
from .store import Store

REFRESH = 30  # segundos entre buscas do mesmo Card


@dataclass
class PeerTrust:
    """Resultado da politica de confianca para um par aceito."""

    org: Optional[str]  # organizacao confiavel que atesta o par, ou None


class TrustPolicy:
    """Politica da secao 6.2. A parte de organizacoes e fornecida por `orgs` (selo.org)."""

    def __init__(self, cfg: Dict[str, Any], orgs: Any = None) -> None:
        trust = cfg.get("trust") or {}
        self.orgs = orgs  # selo.org.OrgTrust ou None
        member = orgs is not None and orgs.own_org is not None
        allow = trust.get("allow_unattested")
        self.allow_unattested = (not member) if allow is None else bool(allow)
        self.allowed_peers = set(trust.get("peers") or [])

    def evaluate(self, info: CardInfo, now: float) -> PeerTrust:
        if self.orgs is not None:
            org = self.orgs.attested_org(
                info, now
            )  # levanta se lista de revogacao vencida / revogado
            if org is not None:
                return PeerTrust(org)
        if not self.allow_unattested:
            raise SeloError(
                "peer_untrusted",
                f"{info.agent_id} sem atestacao de organizacao confiavel",
            )
        if self.allowed_peers and info.agent_id not in self.allowed_peers:
            raise SeloError("peer_untrusted", f"{info.agent_id} fora de trust.peers")
        return PeerTrust(None)


class PeerDirectory:
    def __init__(
        self,
        store: Store,
        http: HttpClient,
        clock: Callable[[], float],
        policy: TrustPolicy,
        max_card_age: int,
        preconfigured_pins: Optional[Dict[str, Dict[str, Any]]] = None,
    ) -> None:
        self.store, self.http, self.clock, self.policy = store, http, clock, policy
        self.max_card_age = max_card_age
        self._cache: Dict[str, Tuple[Dict[str, Any], float]] = {}
        self._lock = threading.Lock()
        # Carrega pins pre-configurados (trust.pins) no store
        if preconfigured_pins:
            for agent_id, pin_data in preconfigured_pins.items():
                seq = int(pin_data.get("seq", 0))
                hash_val = pin_data.get("hash", "")
                if seq > 0 and hash_val:
                    self.store.set_pin(agent_id, seq, hash_val)

    def _verify(
        self, card: Dict[str, Any], url: str, expected_id: Optional[str]
    ) -> CardInfo:
        now = self.clock()
        info = verify_card(
            card, now=now, max_card_age=self.max_card_age, expected_id=expected_id
        )
        check_extends(self.store.get_pin(info.agent_id), info.kel, info.kel_raw)
        return info

    def get(
        self, url: str, expected_id: Optional[str] = None, refresh: bool = False
    ) -> Tuple[CardInfo, PeerTrust]:
        base = normalize_base(url)
        now = self.clock()
        with self._lock:
            cached = self._cache.get(base)
        card = None
        fetched = False
        if cached and not refresh and now - cached[1] < REFRESH:
            card = cached[0]
        if card is None:
            try:
                status, body = self.http.json("GET", base + WELL_KNOWN)
                if status != 200 or not isinstance(body, dict):
                    raise SeloError("card_unavailable", f"{base}: HTTP {status}")
                card, fetched = body, True
            except SeloError:
                if not cached:
                    raise
                card = cached[0]  # ainda pode valer; verify_card decide
        info = self._verify(card, base, expected_id)
        if fetched:  # so Cards que passaram na verificacao entram no cache
            with self._lock:
                self._cache[base] = (card, now)
        self.store.set_pin(info.agent_id, *info.pin())
        trust = self.policy.evaluate(info, now)
        return info, trust

    def forget(self, url: str) -> None:
        with self._lock:
            self._cache.pop(normalize_base(url), None)

    def get_cached_sender_key(
        self, sender_id: str, sender_card_url: str, sender_seq: int
    ) -> Optional[bytes]:
        """
        Retorna a chave de assinatura do remetente a partir do cache, sem busca de rede.
        Usado para verificar a assinatura do envelope ANTES de buscar o Card fresco.
        """
        base = normalize_base(sender_card_url)
        with self._lock:
            cached = self._cache.get(base)
        if cached is None:
            return None
        card, _ = cached
        try:
            info = verify_card(
                card,
                now=self.clock(),
                max_card_age=self.max_card_age,
                expected_id=sender_id,
            )
            if info.kel.seq != sender_seq:
                return None
            return info.kel.current.sig_pub
        except SeloError:
            return None
