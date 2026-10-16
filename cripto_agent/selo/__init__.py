"""SELO: Sealed Envelope with Labeled Operations.

Protocolo de comunicacao segura entre agentes LLM, tools e skills em redes organizacionais.
"""

from .agent import Agent, RemoteError
from .envelope import VERSION
from .org import Organization
from .provenance import Principal, Session
from .tokens import Token
from .util import SeloError

__all__ = ["Agent", "RemoteError", "VERSION", "Organization", "Principal", "Session", "Token",
           "SeloError"]
