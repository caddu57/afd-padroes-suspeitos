"""Junta assinaturas + AFD e decide o veredito."""
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

from .dfa import DFA
from .signatures import SIGNATURES, WEAK_THRESHOLD, Signature

CHUNK = 64 * 1024


@dataclass
class Report:
    suspicious: bool
    matches: List[Tuple[str, int]] = field(default_factory=list)  # (nome, offset)


class Scanner:
    def __init__(self, signatures: Optional[List[Signature]] = None):
        sigs = SIGNATURES if signatures is None else signatures
        self.by_name = {s.name: s for s in sigs}
        # Um AFD para padroes case-sensitive e outro para case-insensitive
        cs = {s.name: s.pattern for s in sigs if not s.nocase}
        ci = {s.name: s.pattern for s in sigs if s.nocase}
        self.dfas = [DFA(p, ignore_case=ic) for p, ic in ((cs, False), (ci, True)) if p]

    def scan_bytes(self, data: bytes) -> Report:
        return self._report([d.scan_bytes(data) for d in self.dfas])

    def scan_file(self, path: str) -> Report:
        results = []
        for dfa in self.dfas:
            with open(path, "rb") as f:
                results.append(dfa.scan_chunks(iter(lambda: f.read(CHUNK), b"")))
        return self._report(results)

    def _report(self, results) -> Report:
        matches = sorted((m for r in results for m in r), key=lambda m: m[1])
        names = {n for n, _ in matches}
        strong = any(self.by_name[n].strong for n in names)
        weak = sum(1 for n in names if not self.by_name[n].strong)
        return Report(strong or weak >= WEAK_THRESHOLD, matches)
