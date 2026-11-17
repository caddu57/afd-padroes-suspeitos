"""AFD (Automato Finito Deterministico) para busca simultanea de padroes.

Construcao em duas etapas (ideia do Aho-Corasick):
  1. Trie de todos os padroes  -> transicoes "para frente".
  2. BFS que completa a funcao de transicao delta(q, a) para TODO estado e
     TODO simbolo (os "retornos" por sufixo), tornando o automato um AFD total:
     cada byte lido causa exatamente uma transicao, sem retrocesso.

Definicao formal:  M = (Q, Sigma, delta, q0, F)
  Q      = estados (nos da trie)
  Sigma  = {0..255} (bytes)
  delta  = Q x Sigma -> Q  (total)
  q0     = estado 0 (raiz)
  F      = estados em que algum padrao termina (inclui sufixos) -> out[q] != {}
"""
from collections import deque
from typing import Dict, Iterable, List, Set, Tuple

ALPHABET = 256


def _casefold_table() -> bytes:
    return bytes(b + 32 if 65 <= b <= 90 else b for b in range(256))


class DFA:
    def __init__(self, patterns: Dict[str, bytes], ignore_case: bool = False):
        self.ignore_case = ignore_case
        self._fold = _casefold_table() if ignore_case else bytes(range(256))
        self.delta: List[List[int]] = [[-1] * ALPHABET]
        self.out: List[Set[str]] = [set()]
        self.fail: List[int] = [0]
        self.depth: List[int] = [0]
        self._build(patterns)

    # ---- construcao -------------------------------------------------
    def _new_state(self, depth: int) -> int:
        self.delta.append([-1] * ALPHABET)
        self.out.append(set())
        self.fail.append(0)
        self.depth.append(depth)
        return len(self.delta) - 1

    def _build(self, patterns: Dict[str, bytes]) -> None:
        for name, pat in patterns.items():
            if not pat:
                raise ValueError(f"padrao vazio: {name}")
            q = 0
            for b in pat.translate(self._fold):
                nxt = self.delta[q][b]
                if nxt == -1:
                    nxt = self._new_state(self.depth[q] + 1)
                    self.delta[q][b] = nxt
                q = nxt
            self.out[q].add(name)

        # BFS: completa delta e calcula fail/out
        queue = deque([0])
        while queue:
            s = queue.popleft()
            for c in range(ALPHABET):
                t = self.delta[s][c]
                if t != -1:  # aresta da trie
                    self.fail[t] = 0 if s == 0 else self.delta[self.fail[s]][c]
                    self.out[t] |= self.out[self.fail[t]]
                    queue.append(t)
                else:  # transicao de retorno
                    self.delta[s][c] = 0 if s == 0 else self.delta[self.fail[s]][c]

    # ---- execucao ---------------------------------------------------
    def scan_chunks(self, chunks: Iterable[bytes]) -> List[Tuple[str, int]]:
        """Retorna lista de (nome, offset_do_ultimo_byte) em fluxo continuo."""
        matches: List[Tuple[str, int]] = []
        delta, out, fold = self.delta, self.out, self._fold
        q = 0
        pos = 0
        for chunk in chunks:
            for b in chunk.translate(fold):
                q = delta[q][b]
                if out[q]:
                    for name in sorted(out[q]):
                        matches.append((name, pos))
                pos += 1
        return matches

    def scan_bytes(self, data: bytes) -> List[Tuple[str, int]]:
        return self.scan_chunks([data])

    @property
    def num_states(self) -> int:
        return len(self.delta)

    # ---- visualizacao (Graphviz) -----------------------------------
    def to_dot(self, show_fail: bool = False) -> str:
        def lbl(b: int) -> str:
            ch = chr(b)
            if ch.isprintable() and ch not in '"\\ ':
                return ch
            return f"0x{b:02X}"

        lines = ["digraph AFD {", "  rankdir=LR;", "  node [shape=circle];",
                 '  __start [shape=point];', "  __start -> q0;"]
        for q in range(self.num_states):
            if self.out[q]:
                names = ",".join(sorted(self.out[q]))
                lines.append(f'  q{q} [shape=doublecircle, xlabel="{names}"];')
        for s in range(self.num_states):
            for c in range(ALPHABET):
                t = self.delta[s][c]
                if t != 0 and self.depth[t] == self.depth[s] + 1:  # aresta da trie
                    lines.append(f'  q{s} -> q{t} [label="{lbl(c)}"];')
        if show_fail:
            for s in range(1, self.num_states):
                lines.append(f"  q{s} -> q{self.fail[s]} [style=dashed, color=gray];")
        lines.append("}")
        return "\n".join(lines)
