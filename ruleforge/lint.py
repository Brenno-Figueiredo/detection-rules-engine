"""Validador de regras: o que um engenheiro de detecção revisa antes de aceitar uma regra no repositório."""
from __future__ import annotations

import fnmatch
import json
import re
from collections import Counter
from dataclasses import dataclass
from typing import List

from .attack import Attack, OLD_TACTICS
from .ruleset import RuleSet
from .sigma import LEVELS, STATUSES, Rule, referenced_names, valid_uuid

SEVERITY_ORDER = {"error": 0, "warning": 1, "info": 2}
PLACEHOLDERS = ("SUBSTITUA", "DESCREVA", "SEU NOME")


@dataclass
class Issue:
    severity: str          # error | warning | info
    code: str
    message: str
    rule: str = ""
    path: str = ""


def _issue(sev, code, msg, rule: Rule = None, path: str = "") -> Issue:
    return Issue(sev, code, msg, rule.title if rule else "", (rule.path if rule else path))


def lint_rule(r: Rule, attack: Attack) -> List[Issue]:
    out: List[Issue] = []
    add = lambda sev, code, msg: out.append(_issue(sev, code, msg, r))  # noqa: E731
    if not r.title:
        add("error", "E008", "falta o título (title)")
    if r.id and not valid_uuid(r.id):
        add("error", "E003", f"o id '{r.id}' não é um UUID válido")
    if not r.id:
        add("warning", "W101", "falta o id (UUID): sem ele a regra não tem identidade estável")
    if r.level and r.level not in LEVELS:
        add("error", "E004", f"nível '{r.level}' inválido (use: {', '.join(LEVELS)})")
    if not r.level:
        add("warning", "W106", "falta o nível (level)")
    if r.status and r.status not in STATUSES:
        add("error", "E005", f"status '{r.status}' inválido (use: {', '.join(STATUSES)})")
    if r.detection is not None and not r.logsource:
        add("error", "E007", "falta a origem do log (logsource): sem ela não dá para saber a que eventos a regra se aplica")
    for key, label in (("description", "a descrição"), ("author", "o autor"), ("date", "a data")):
        if not getattr(r, key):
            add("warning", {"description": "W102", "author": "W103", "date": "W104"}[key], f"falta {label} ({key})")
    if not r.falsepositives:
        add("warning" if r.level in ("high", "critical") else "info", "W105", "faltam os falsos positivos conhecidos (falsepositives)")
    if len(r.title) > 110 or r.title.endswith("."):
        add("info", "W116", "o título deve ser curto (até 110 caracteres) e sem ponto final")
    if not r.raw.get("references") and r.kind == "detection":
        add("info", "I201", "sem referências (references): link para o artigo ou o relatório que embasou a regra")

    # ---- ATT&CK ------------------------------------------------------------------------------------------------------------------
    info = attack.parse_tags(r.tags)
    if not info.techniques:
        add("warning", "W107", "nenhuma técnica do ATT&CK nas etiquetas (tags): a regra não entra no mapa de cobertura")
    for tid in info.techniques:
        st = attack.status(tid)
        if st == "revoked":
            new = attack.revoked[tid]["to"]
            add("warning", "W108", f"{tid} ({attack.name(tid)}) foi revogada no ATT&CK v{attack.major}: use {new} ({attack.name(new)}). Rode 'migrate' para trocar")
        elif st == "deprecated":
            add("warning", "W110", f"{tid} ({attack.name(tid)}) está obsoleta no ATT&CK v{attack.major}, sem substituta")
        elif st == "unknown":
            add("warning", "W109", f"{tid} não existe no ATT&CK v{attack.major}: confira o ID")
    for raw in r.tags:
        t = str(raw).lower()
        if t.startswith("attack.") and t[7:] in OLD_TACTICS:
            add("warning", "W111", f"a tática '{t[7:]}' foi dividida em 'stealth' e 'defense-impairment' no ATT&CK v{attack.major}: use a tática da técnica")
    for bad in info.unknown:
        add("warning", "W112", f"etiqueta '{bad}' não é técnica, tática, grupo nem software do ATT&CK")

    # ---- detecção ----------------------------------------------------------------------------------------------------------------
    if r.detection is not None:
        used = set()
        for name, is_pat in referenced_names(r.detection.condition):
            if is_pat:
                used.update(n for n in r.detection.selections if fnmatch.fnmatchcase(n, name))
            else:
                used.add(name)
        if any(q.kind == "quant" and q.value is None for q in _walk(r.detection.condition)):
            used.update(n for n in r.detection.selections if not n.startswith("_"))
        for name in r.detection.selections:
            if name not in used:
                add("warning", "W122", f"a seleção '{name}' está definida mas não é usada na condição")
        for sel in r.detection.selections.values():
            for alt in sel.alternatives:
                for fc in alt:
                    for v in fc.values:
                        if isinstance(v, str) and re.search(r"\\[*?]", v):
                            add("warning", "W115", f"'{v[:50]}' em {fc.name}: a barra antes de * ou ? ESCAPA o curinga (vira texto literal). Para barra literal + curinga escreva \\\\*")
                        if isinstance(v, str) and "contains" in fc.mods and len(v.strip("*?")) <= 2 and len(alt) == 1 and len(r.detection.selections) == 1:
                            add("warning", "W114", f"valor curto demais ('{v}') em {fc.name}|contains: a regra vai disparar o tempo todo")
                        if "re" in fc.mods and isinstance(v, str):
                            add("info", "W124", f"{fc.name}|re usa expressão regular: o Python não tem limite de tempo para regex, então confira se o padrão não pode travar (evite repetições que se sobrepõem)")
                        if isinstance(v, str) and v.strip() and set(v) <= {"*", "?"}:
                            add("warning", "W114", f"o valor '{v}' em {fc.name} casa com qualquer coisa")
    # ---- modelo não preenchido ---------------------------------------------------------------------------------------------------
    if any(tok in json.dumps(r.raw, ensure_ascii=False) for tok in PLACEHOLDERS):
        add("error", "E009", "a regra ainda tem texto de modelo (SUBSTITUA, DESCREVA ou SEU NOME): preencha antes de usar")
    # ---- testes ------------------------------------------------------------------------------------------------------------------
    if not r.tests["positive"] and not r.tests["negative"]:
        add("warning", "W113", "regra sem testes (x_tests): não há como provar que ela dispara no que deve e fica quieta no que não deve")
    elif not r.tests["positive"]:
        add("warning", "W123", "faltam testes positivos (eventos que DEVEM disparar a regra)")
    elif not r.tests["negative"]:
        add("warning", "W123", "faltam testes negativos (eventos parecidos que NÃO devem disparar): é o que evita falso positivo")
    return out


def _walk(node):
    yield node
    for c in node.children:
        yield from _walk(c)


def lint_ruleset(rs: RuleSet, attack: Attack) -> List[Issue]:
    issues: List[Issue] = [Issue("error", "E001", msg, "", path) for path, msg in rs.errors]
    ids = Counter(r.id for r in rs.rules if r.id)
    for rule_id, n in ids.items():
        if n > 1:
            dup = [r for r in rs.rules if r.id == rule_id]
            issues.append(Issue("error", "E002", f"o id {rule_id} aparece em {n} regras: {', '.join(r.title for r in dup)}", dup[0].title, dup[0].path))
    keys = {k for r in rs.rules for k in r.keys()}
    for r in rs.rules:
        issues.extend(lint_rule(r, attack))
        if r.correlation:
            for ref in r.correlation.rules:
                if ref.lower() not in keys:
                    issues.append(_issue("error", "E006", f"a correlação cita '{ref}', que não é o nome, o id nem o título de nenhuma regra", r))
    return sorted(issues, key=lambda i: (SEVERITY_ORDER[i.severity], i.path, i.rule, i.code))
