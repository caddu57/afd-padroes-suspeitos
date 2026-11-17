import argparse
import sys

from .dfa import DFA
from .scanner import Scanner
from .signatures import SIGNATURES


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(
        prog="afd", description="Verifica se um arquivo e suspeito usando um AFD.")
    ap.add_argument("arquivo", nargs="?", help="arquivo a verificar")
    ap.add_argument("-v", "--verbose", action="store_true", help="lista os padroes encontrados")
    ap.add_argument("--dot", metavar="SAIDA.dot",
                    help="exporta o AFD (Graphviz) e sai; ex.: dot -Tpng SAIDA.dot -o afd.png")
    ap.add_argument("--fail", action="store_true", help="com --dot, desenha tambem os links de falha")
    args = ap.parse_args(argv)

    if args.dot:
        dfa = DFA({s.name: s.pattern for s in SIGNATURES}, ignore_case=True)
        with open(args.dot, "w", encoding="utf-8") as f:
            f.write(dfa.to_dot(show_fail=args.fail))
        print(f"AFD com {dfa.num_states} estados salvo em {args.dot}")
        return 0

    if not args.arquivo:
        ap.error("informe um arquivo (ou use --dot)")

    try:
        report = Scanner().scan_file(args.arquivo)
    except OSError as e:
        print(f"erro: {e}", file=sys.stderr)
        return 2

    print(f"{args.arquivo}: {'SUSPEITO' if report.suspicious else 'LIMPO'}")
    if args.verbose:
        for name, off in report.matches:
            print(f"  - {name} (termina no offset {off})")
    return 1 if report.suspicious else 0


if __name__ == "__main__":
    sys.exit(main())
