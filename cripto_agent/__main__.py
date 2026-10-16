"""python -m cripto_agent demo | bench | test"""

import argparse
import sys


def main() -> int:
    parser = argparse.ArgumentParser(prog="cripto_agent", description="Protocolo SELO")
    parser.add_argument("acao", choices=["demo", "bench"],
                        help="demo: cenarios narrados; bench: tamanhos e latencias")
    args = parser.parse_args()
    from .selo import demo as demo_module
    demo_module.demo() if args.acao == "demo" else demo_module.bench()
    return 0


if __name__ == "__main__":
    sys.exit(main())
