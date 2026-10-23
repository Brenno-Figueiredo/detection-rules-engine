"""Carrega um arquivo de regra ou uma pasta inteira (.yml, .yaml, .json), juntando os erros em vez de parar no primeiro."""
from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import List, Tuple

from .sigma import Rule, RuleError, build_rule, load_rule_text

EXTENSIONS = (".yml", ".yaml", ".json")
MAX_FILES = 20000


@dataclass
class RuleSet:
    rules: List[Rule] = field(default_factory=list)
    errors: List[Tuple[str, str]] = field(default_factory=list)        # (arquivo, mensagem)
    files: int = 0

    def find(self, ref: str):
        ref = ref.strip().lower()
        return next((r for r in self.rules if ref in r.keys() or os.path.basename(r.path).lower() == ref or r.path.lower().endswith(ref)), None)


def load_path(path: str) -> RuleSet:
    rs = RuleSet()
    if os.path.isdir(path):
        paths = []
        for root, dirs, files in os.walk(path):
            dirs[:] = sorted(d for d in dirs if not d.startswith("."))
            paths += [os.path.join(root, f) for f in sorted(files) if f.lower().endswith(EXTENSIONS)]
            if len(paths) > MAX_FILES:
                rs.errors.append((path, f"pasta com arquivos demais (limite de {MAX_FILES})"))
                break
    elif os.path.isfile(path):
        paths = [path]
    else:
        raise FileNotFoundError(f"não encontrei '{path}'")
    for p in paths:
        rs.files += 1
        rel = os.path.relpath(p, path) if os.path.isdir(path) else os.path.basename(p)
        try:
            with open(p, encoding="utf-8-sig") as f:
                text = f.read()
            if p.lower().endswith(".json"):
                data = json.loads(text)
                rules = [build_rule(d, p) for d in (data if isinstance(data, list) else [data])]
            else:
                rules = load_rule_text(text, p)
            rs.rules.extend(rules)
        except (RuleError, ValueError, OSError) as exc:
            rs.errors.append((rel, str(exc)))
    return rs
