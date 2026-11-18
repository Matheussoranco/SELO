"""Ganchos de politica usados pelos testes (carregados por 'tests.policies:<nome>')."""

from selo.policy import PolicyDenied

EVENTS = []


def _text(rpc):
    try:
        return "".join(p.get("text", "") for p in rpc["params"]["message"]["parts"])
    except (KeyError, TypeError, AttributeError):
        return ""


def record(ev):
    EVENTS.append(ev)


def deny_forbidden(ev):
    EVENTS.append(ev)
    if (
        ev.direction == "inbound"
        and ev.stage == "request"
        and "proibido" in _text(ev.rpc)
    ):
        raise PolicyDenied("palavra proibida")


def deny_outbound_to_all(ev):
    if ev.direction == "outbound" and ev.stage == "request":
        raise PolicyDenied("saida bloqueada")


def mutate(ev):
    if ev.stage == "request" and ev.direction == "inbound":
        ev.rpc["params"]["message"]["parts"][0]["text"] = "alterado pelo gancho"


def crash(ev):
    raise RuntimeError("bug no gancho")
