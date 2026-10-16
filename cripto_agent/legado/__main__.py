import argparse
import json
from pathlib import Path
from .protocol import Agent, Capability, envelope, make_server, request, tls_context


def echo(arguments):
    if set(arguments) != {'text'} or not isinstance(arguments['text'], str) or len(arguments['text']) > 4000:
        raise ValueError('expected text with at most 4000 characters')
    return {'text': arguments['text']}


def summarize(arguments):
    text = echo(arguments)['text']
    return {'characters': len(text), 'words': len(text.split())}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('action', choices=['serve', 'catalog', 'call'])
    parser.add_argument('--config', required=True)
    parser.add_argument('--recipient', default='agent-b')
    parser.add_argument('--kind', choices=['tool', 'skill'], default='tool')
    parser.add_argument('--name', default='echo')
    parser.add_argument('--text', default='Ola entre agentes')
    args = parser.parse_args()
    path = Path(args.config).resolve()
    cfg = json.loads(path.read_text(encoding='utf-8'))
    resolve = lambda key: path.parent / cfg[key]
    context = tls_context(resolve('ca'), resolve('cert'), resolve('key'), server=args.action == 'serve')
    if args.action == 'serve':
        agent = Agent(cfg['organization'], cfg['agent_id'], cfg['peers'],
                      [tuple(p) for p in cfg['permissions']], resolve('database'))
        agent.register(Capability('tool', 'echo', 'Retorna o texto fornecido', echo))
        agent.register(Capability('skill', 'text.stats', 'Calcula estatisticas de texto', summarize))
        server = make_server((cfg.get('bind', '127.0.0.1'), cfg['port']), agent, context)
        print(f"Agente {agent.agent_id} pronto em HTTPS na porta {server.server_port}", flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass
        finally:
            server.server_close()
            agent.db.close()
    else:
        # Addresses come from administrator configuration, never from incoming messages.
        url = cfg['directory'][args.recipient]
        message = None if args.action == 'catalog' else envelope(
            cfg['organization'], cfg['agent_id'], args.recipient, args.kind, args.name, {'text': args.text})
        fingerprint = next(fp for fp, identity in cfg['peers'].items() if identity == args.recipient)
        print(json.dumps(request(url, context, message, expected_fingerprint=fingerprint), ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
