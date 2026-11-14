"""Notificacoes push (especificacao, secao 10). Implementacao no ticket #16."""

from __future__ import annotations

from typing import Any, Dict

from .net import Request, Response


def rewrite_outbound(sc: Any, rpc: Dict[str, Any], info: Any) -> Dict[str, Any]:
    return rpc


def rewrite_inbound(sc: Any, rpc: Dict[str, Any], sender: Any) -> Dict[str, Any]:
    return rpc


def handle_delivery(sc: Any, req: Request, ref: str) -> Response:
    return Response(404, {"error": "not_found"})


def handle_intake(sc: Any, req: Request) -> Response:
    return Response(404, {"error": "not_found"})
