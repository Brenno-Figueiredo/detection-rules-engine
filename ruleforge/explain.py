"""Traduz uma regra para português: o que ela procura, quando dispara e a que técnica do ATT&CK se liga."""
from __future__ import annotations

from typing import List

from .attack import Attack
from .sigma import FieldCond, Node, Rule, Selection

LEVEL_PT = {"informational": "informativo", "low": "baixo", "medium": "médio", "high": "alto", "critical": "crítico"}


def _vals(values: List, joiner: str) -> str:
    shown = [f"'{v}'" if isinstance(v, str) else str(v) for v in values]
    return joiner.join(shown)


def describe_field(fc: FieldCond) -> str:
    mods = set(fc.mods)
    name = fc.name
    if "exists" in mods:
        return f"o campo {name} {'existe' if fc.values[0] else 'NÃO existe'}"
    if fc.values == [None]:
        return f"o campo {name} está vazio ou ausente"
    joiner = " E " if fc.all_values else " OU "
    extra = []
    if "windash" in mods:
        extra.append("aceita '-', '/' e traços tipográficos no início do parâmetro")
    if {"base64", "base64offset"} & mods:
        extra.append("procura o texto codificado em base64" + (" (UTF-16)" if {"wide", "utf16le", "utf16"} & mods else ""))
    if "re" in mods:
        flags = "".join(sorted(mods & {"i", "m", "s"}))
        text = f"o campo {name} casa com a expressão regular {_vals(fc.values, joiner)}" + (f" (opções: {flags})" if flags else "")
    elif "cidr" in mods:
        text = f"o campo {name} está na rede {_vals(fc.values, ' OU ')}"
    elif mods & {"lt", "lte", "gt", "gte"}:
        op = {"lt": "é menor que", "lte": "é menor ou igual a", "gt": "é maior que", "gte": "é maior ou igual a"}[next(m for m in fc.mods if m in ("lt", "lte", "gt", "gte"))]
        text = f"o campo {name} {op} {_vals(fc.values, ' OU ')}"
    else:
        verb = "contém" if "contains" in mods else "começa com" if "startswith" in mods else "termina com" if "endswith" in mods else "é igual a"
        text = f"o campo {name} {verb} {_vals(fc.values, joiner)}"
    return text + (f" ({'; '.join(extra)})" if extra else "")


def describe_selection(sel: Selection) -> List[str]:
    if sel.keywords:
        return [f"qualquer campo do evento contém {_vals(sel.keyword_values, ' OU ')}"]
    lines = []
    for i, alt in enumerate(sel.alternatives, 1):
        parts = [describe_field(fc) for fc in alt]
        prefix = f"alternativa {i}: " if len(sel.alternatives) > 1 else ""
        lines.append(prefix + " E ".join(parts))
    return lines


def describe_condition(node: Node) -> str:
    if node.kind == "name":
        return f"[{node.value}]"
    if node.kind == "not":
        return f"NÃO {describe_condition(node.children[0])}"
    if node.kind in ("and", "or"):
        j = " E " if node.kind == "and" else " OU "
        return "(" + j.join(describe_condition(c) for c in node.children) + ")"
    group = "as seleções" if node.value is None else f"as seleções '{node.value}'"
    return f"[TODAS {group}]" if node.quant == "all" else f"[pelo menos {node.quant} entre {group}]"


def explain(rule: Rule, attack: Attack) -> str:
    info = attack.parse_tags(rule.tags)
    ls = rule.logsource
    where = ", ".join(f"{k} = {v}" for k, v in ls.items()) or "não informado"
    lines = [f"REGRA: {rule.title}", f"Nível: {LEVEL_PT.get(rule.level, rule.level or 'não informado')}  ·  status: {rule.status or 'não informado'}  ·  id: {rule.id or 'sem id'}",
             f"Onde procura (logsource): {where}"]
    if rule.description:
        lines += ["", rule.description.strip()]
    if rule.detection is not None:
        lines += ["", "DISPARA QUANDO:", "  " + describe_condition(rule.detection.condition), "", "ONDE CADA PARTE SIGNIFICA:"]
        for name, sel in rule.detection.selections.items():
            lines.append(f"  [{name}]")
            lines += [f"    - {t}" for t in describe_selection(sel)]
    else:
        c = rule.correlation
        op = {"gte": "pelo menos", "gt": "mais de", "lte": "no máximo", "lt": "menos de", "eq": "exatamente"}[c.op]
        what = "ocorrências" if c.type == "event_count" else f"valores distintos de {c.value_field}"
        grp = f", para cada combinação de {', '.join(c.group_by)}" if c.group_by else ""
        lines += ["", "DISPARA QUANDO:", f"  houver {op} {c.threshold:g} {what} das regras {', '.join(repr(r) for r in c.rules)} em {c.timespan} s{grp}.",
                  "  (por padrão, as regras de base não geram alerta sozinhas: só a correlação)" if not c.generate else "  (as regras de base também geram alerta)"]
    if info.techniques or info.tactics:
        lines += ["", "ATT&CK:"]
        for tid in info.techniques:
            st = attack.status(tid)
            cur = attack.current(tid)
            if st == "active":
                lines.append(f"  {tid} {attack.name(tid)} ({', '.join(attack.tactic_names.get(t, t) for t in attack.tactics_of(tid))})")
            elif st == "revoked":
                lines.append(f"  {tid} {attack.name(tid)}: REVOGADA no v{attack.major}; hoje é {cur} {attack.name(cur)} ({', '.join(attack.tactic_names.get(t, t) for t in attack.tactics_of(cur))})")
            else:
                lines.append(f"  {tid}: {st}")
    if rule.falsepositives:
        lines += ["", "FALSOS POSITIVOS CONHECIDOS:"] + [f"  - {f}" for f in rule.falsepositives]
    return "\n".join(lines)
