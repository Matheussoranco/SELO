"""Organizacoes, atestacao, federacao e escrow (especificacao, secoes 6 e 11). Tickets #13 e #14."""

from __future__ import annotations

from typing import Any


def add_cli(sub: Any) -> None:
    sub.add_parser("org", help="organizacao (tickets #13/#14)")


def run_cli(a: Any) -> int:
    raise NotImplementedError("tickets #13/#14")
