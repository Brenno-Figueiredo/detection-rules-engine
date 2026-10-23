"""Linha de comando do RuleForge."""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import unicodedata
import uuid
from datetime import date
from typing import List, Optional

from . import __version__, report
from .attack import Attack
from .engine import filter_level, parse_source, run_rule_tests, scan_files
from .explain import explain
from .lint import lint_ruleset
from .ruleset import RuleSet, load_path
from .sigma import LEVELS

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_RULES = os.path.join(ROOT, "rules")
SAMPLES = os.path.join(ROOT, "samples")
DEMO_SOURCES = [("windows_sysmon.jsonl", {"product": "windows"}), ("windows_security.jsonl", {"product": "windows"}), ("linux_logs.jsonl", {"product": "linux"}),
                ("web_access.jsonl", {"category": "webserver"})]


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="ruleforge", description="Detecção como código: regras Sigma, testes de regra e cobertura do MITRE ATT&CK.",
                                 epilog="Os alertas são hipóteses para o analista confirmar. Regras e logs vêm de fora: a ferramenta os trata como não confiáveis.")
    sub = ap.add_subparsers(dest="cmd")

    def rules_opt(p):
        p.add_argument("--rules", default=DEFAULT_RULES, help="pasta ou arquivo de regras (padrão: a pasta rules/ do projeto)")

    v = sub.add_parser("validate", help="valida as regras (o que um revisor conferiria)")
    rules_opt(v)
    v.add_argument("--strict", action="store_true", help="avisos também fazem o comando falhar")
    v.add_argument("--no-color", action="store_true")
    t = sub.add_parser("test", help="roda os testes das regras (x_tests): positivos devem disparar, negativos não")
    rules_opt(t)
    t.add_argument("--no-color", action="store_true")
    s = sub.add_parser("scan", help="aplica as regras a arquivos de log")
    rules_opt(s)
    s.add_argument("--events", nargs="+", required=True, metavar="ARQ[:product=..,category=..,service=..]",
                   help="logs em JSONL, JSON ou CSV; o sufixo diz de que tipo de log é (filtra as regras pelo logsource)")
    s.add_argument("--field-map", metavar="MAPA.json", help="traduz os nomes de campo das regras para os do seu log")
    s.add_argument("--time-field", action="append", help="campo com a data/hora do evento (necessário para correlação); pode repetir")
    s.add_argument("--min-level", choices=LEVELS)
    s.add_argument("--max-per-rule", type=int, default=1000, help="alertas listados por regra (o excedente é só contado)")
    _outputs(s)
    c = sub.add_parser("coverage", help="mostra a cobertura das regras sobre o MITRE ATT&CK")
    rules_opt(c)
    c.add_argument("--html", metavar="ARQ.html")
    c.add_argument("--layer", metavar="ARQ.json", help="camada para o MITRE ATT&CK Navigator")
    c.add_argument("--no-color", action="store_true")
    e = sub.add_parser("explain", help="explica uma regra em português")
    e.add_argument("rule", help="arquivo, título, nome ou id da regra")
    rules_opt(e)
    ls = sub.add_parser("list", help="lista as regras")
    rules_opt(ls)
    at = sub.add_parser("attack", help="consulta uma técnica do ATT&CK (inclusive as revogadas)")
    at.add_argument("id")
    rules_opt(at)
    mg = sub.add_parser("migrate", help="troca as etiquetas de técnicas REVOGADAS do ATT&CK pelas substitutas")
    rules_opt(mg)
    mg.add_argument("--write", action="store_true", help="grava as trocas nos arquivos (sem isso, só mostra). Revise o resultado com o git")
    nw = sub.add_parser("new", help="cria o esqueleto de uma regra nova, já ligado a uma técnica do ATT&CK")
    nw.add_argument("--title", required=True)
    nw.add_argument("--technique", required=True, help="ex.: T1059.001")
    nw.add_argument("--product", default="windows")
    nw.add_argument("--category", default="process_creation")
    nw.add_argument("--out", default=DEFAULT_RULES, help="pasta onde gravar")
    dm = sub.add_parser("demo", help="executa as regras de exemplo sobre os logs FICTÍCIOS")
    _outputs(dm)
    ap.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return ap


def _outputs(p) -> None:
    p.add_argument("--json", metavar="ARQ.json")
    p.add_argument("--csv", metavar="ARQ.csv")
    p.add_argument("--html", metavar="ARQ.html")
    p.add_argument("--layer", metavar="ARQ.json", help="camada para o MITRE ATT&CK Navigator")
    p.add_argument("--feed", metavar="ARQ.jsonl", help="eventos para o Venator e o CorrelAI (sem trechos de log)")
    p.add_argument("--compliancemap", metavar="ARQ.json", help="evidência agregada para o ComplianceMap (--auto)")
    p.add_argument("--fail-on", choices=LEVELS, help="código de saída 1 se houver alerta neste nível ou acima")
    p.add_argument("--no-color", action="store_true")


def _color(a) -> bool:
    return not a.no_color and sys.stdout.isatty()


def _write(path: str, text: str, bom: bool = False) -> None:
    with open(path, "w", encoding="utf-8-sig" if bom else "utf-8", newline="") as f:
        f.write(text)
    print(f"Salvo em: {path}")


def _load(path: str) -> RuleSet:
    rs = load_path(path)
    for p, msg in rs.errors:
        print(f"Regra inválida ({p}): {msg}", file=sys.stderr)
    return rs


def cmd_validate(a) -> int:
    rs, atk = load_path(a.rules), Attack()
    issues = lint_ruleset(rs, atk)
    print(report.render_issues(issues, len(rs.rules), _color(a)))
    errors = any(i.severity == "error" for i in issues)
    warns = any(i.severity == "warning" for i in issues)
    return 1 if errors or (a.strict and warns) else 0


def _run_tests(rs: RuleSet):
    results = []
    for r in rs.rules:
        results += run_rule_tests(r, rs.rules)
    return results


def cmd_test(a) -> int:
    rs = _load(a.rules)
    results = _run_tests(rs)
    failed = [t for t in results if not t.passed]
    untested = [r for r in rs.rules if not r.tests["positive"] and not r.tests["negative"]]
    for t in failed:
        print(f"FALHOU  {t.rule.title}: teste {t.kind} #{t.index}: {t.message}")
    for r in untested:
        print(f"sem testes  {r.title}")
    print(f"\n{len(results) - len(failed)} de {len(results)} teste(s) passaram em {len(rs.rules)} regra(s)" + (f" · {len(untested)} regra(s) sem testes" if untested else ""))
    return 1 if failed or rs.errors else 0


def _field_map(path: Optional[str]):
    if not path:
        return None
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, dict):
        raise ValueError("o mapa de campos deve ser um objeto JSON: {\"CampoDaRegra\": \"campo.do.log\"}")
    return data


def _scan(a, rs: RuleSet, sources, atk: Attack) -> int:
    res = scan_files(rs.rules, sources, _field_map(getattr(a, "field_map", None)), getattr(a, "time_field", None), getattr(a, "max_per_rule", 1000))
    res.alerts = filter_level(res.alerts, getattr(a, "min_level", None))
    print(report.render_scan(res, rs.rules, atk, _color(a)))
    cov = atk.coverage(rs.rules, {(al.rule.id or al.rule.title): 1 for al in res.alerts})
    if a.json:
        _write(a.json, report.alerts_json(res, atk))
    if a.csv:
        _write(a.csv, report.alerts_csv(res, atk), bom=True)
    if a.html:
        _write(a.html, report.render_html(res, rs.rules, atk, cov))
    if a.layer:
        _write(a.layer, json.dumps(atk.layer(rs.rules, {}), ensure_ascii=False, indent=2))
    if a.feed:
        events = report.to_feed(res, atk)
        with open(a.feed, "w", encoding="utf-8") as f:
            for ev in events:
                f.write(json.dumps(ev, ensure_ascii=False) + "\n")
        print(f"{len(events)} evento(s) salvos em: {a.feed}")
    if a.compliancemap:
        tests = _run_tests(rs)
        issues = lint_ruleset(rs, atk)
        _write(a.compliancemap, report.to_compliancemap(rs.rules, issues, len(tests), sum(1 for t in tests if not t.passed), cov))
    if a.fail_on and any(al.rule.level in LEVELS and LEVELS.index(al.rule.level) >= LEVELS.index(a.fail_on) for al in res.alerts):
        return 1
    return 0


def cmd_scan(a) -> int:
    rs, atk = _load(a.rules), Attack()
    if not rs.rules:
        print("Nenhuma regra válida encontrada.", file=sys.stderr)
        return 2
    sources = [parse_source(spec) for spec in a.events]
    for p, _ in sources:
        if not os.path.isfile(p):
            print(f"Arquivo de log não encontrado: {p}", file=sys.stderr)
            return 2
    return _scan(a, rs, sources, atk)


def cmd_demo(a) -> int:
    rs, atk = _load(DEFAULT_RULES), Attack()
    sources = [(os.path.join(SAMPLES, f), ctx) for f, ctx in DEMO_SOURCES]
    print(f"DEMONSTRAÇÃO: {len(rs.rules)} regras de exemplo sobre logs FICTÍCIOS (pasta samples/)\n")
    a.field_map, a.time_field, a.min_level, a.max_per_rule = None, None, None, 1000
    return _scan(a, rs, sources, atk)


def cmd_coverage(a) -> int:
    rs, atk = _load(a.rules), Attack()
    cov = atk.coverage(rs.rules)
    print(report.render_coverage(cov, atk, _color(a)))
    if a.html:
        from .engine import ScanResult
        _write(a.html, report.render_html(ScanResult(), rs.rules, atk, cov))
    if a.layer:
        _write(a.layer, json.dumps(atk.layer(rs.rules), ensure_ascii=False, indent=2))
    return 0


def cmd_explain(a) -> int:
    atk = Attack()
    target = a.rule
    rs = load_path(target) if os.path.exists(target) else load_path(a.rules)
    rule = rs.rules[0] if os.path.isfile(target) and rs.rules else rs.find(target)
    if rule is None:
        print(f"Regra '{a.rule}' não encontrada.", file=sys.stderr)
        return 2
    print(explain(rule, atk))
    return 0


def cmd_list(a) -> int:
    rs, atk = _load(a.rules), Attack()
    for r in sorted(rs.rules, key=lambda x: (LEVELS.index(x.level) if x.level in LEVELS else -1), reverse=True):
        techs = ",".join(atk.rule_techniques(r.tags)) or "-"
        print(f"{r.level or '-':<14}{r.kind:<12}{techs:<22}{r.title}")
    print(f"\n{len(rs.rules)} regra(s)")
    return 0


def cmd_attack(a) -> int:
    atk = Attack()
    tid = a.id.upper()
    st = atk.status(tid)
    if st == "unknown":
        print(f"{tid} não existe no ATT&CK v{atk.version}.")
        return 2
    if st == "deprecated":
        print(f"{tid} ({atk.name(tid)}) está OBSOLETA no ATT&CK v{atk.version}, sem substituta.")
        return 0
    cur = atk.current(tid)
    if st == "revoked":
        print(f"{tid} ({atk.name(tid)}) foi REVOGADA no ATT&CK v{atk.version}.\nSubstituta: {cur} ({atk.name(cur)})")
    print(f"{cur}: {atk.name(cur)}\nTáticas: {', '.join(atk.tactic_names.get(t, t) for t in atk.tactics_of(cur))}")
    rs = load_path(a.rules) if os.path.exists(a.rules) else None
    if rs:
        mine = [r for r in rs.rules if cur in atk.rule_techniques(r.tags)]
        print("Regras que cobrem: " + (", ".join(r.title for r in mine) if mine else "nenhuma"))
    print(f"\n{atk.notice}")
    return 0


def cmd_migrate(a) -> int:
    rs, atk = _load(a.rules), Attack()
    changed = 0
    for r in rs.rules:
        moves = atk.migration(r.tags)
        if not moves:
            continue
        print(f"{os.path.relpath(r.path)}: {r.title}")
        for old, new, why in moves:
            print(f"  {old}  ->  {new}\n      {why}")
        changed += 1
        if a.write:
            with open(r.path, encoding="utf-8") as f:
                text = f.read()
            for old, new, _ in moves:
                text = re.sub(re.escape(old), new, text, flags=re.IGNORECASE)
            with open(r.path, "w", encoding="utf-8", newline="") as f:
                f.write(text)
    if not changed:
        print(f"Nenhuma etiqueta de técnica revogada no ATT&CK v{atk.version}.")
    elif not a.write:
        print(f"\n{changed} regra(s) com etiquetas revogadas. Rode de novo com --write para gravar (e revise com o git).")
    else:
        print(f"\n{changed} arquivo(s) atualizado(s). Revise com 'git diff'.")
    return 0


def _slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "_", unicodedata.normalize("NFKD", text).encode("ascii", "ignore").decode().lower()).strip("_")[:60] or "regra"


def cmd_new(a) -> int:
    atk = Attack()
    tid = a.technique.upper()
    st = atk.status(tid)
    if st == "unknown":
        print(f"{tid} não existe no ATT&CK v{atk.version}.", file=sys.stderr)
        return 2
    if st != "active":
        cur = atk.current(tid)
        print(f"{tid} está {'revogada' if st == 'revoked' else 'obsoleta'}" + (f": use {cur} ({atk.name(cur)})." if cur else "."), file=sys.stderr)
        return 2
    tactics = " ".join(f"\n    - attack.{t.replace('-', '_')}" for t in atk.tactics_of(tid))
    path = os.path.join(a.out, _slug(a.title) + ".yml")
    if os.path.exists(path):
        print(f"'{path}' já existe: não vou sobrescrever.", file=sys.stderr)
        return 2
    os.makedirs(a.out, exist_ok=True)
    esc = a.title.replace("'", "''")
    text = f"""title: '{esc}'
id: '{uuid.uuid4()}'
status: experimental
description: 'DESCREVA o comportamento que a regra detecta e por que ele importa.'
references:
    - '{"https://attack.mitre.org/techniques/" + tid.replace(".", "/") + "/"}'
author: 'SEU NOME'
date: '{date.today():%Y/%m/%d}'
tags:{tactics}
    - attack.{tid.lower()}
logsource:
    category: '{a.category}'
    product: '{a.product}'
detection:
    selection:
        Image|endswith: '\\exemplo.exe'
        CommandLine|contains: 'SUBSTITUA'
    condition: selection
falsepositives:
    - 'DESCREVA o que é legítimo e parecido'
level: medium
x_tests:
    positive:
        - {{Image: 'C:\\Windows\\exemplo.exe', CommandLine: 'exemplo.exe SUBSTITUA'}}
    negative:
        - {{Image: 'C:\\Windows\\exemplo.exe', CommandLine: 'exemplo.exe /ajuda'}}
"""
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)
    print(f"Regra criada: {path}\nLigada a {tid} ({atk.name(tid)}). Edite os campos marcados, depois rode: validate e test.")
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    ap = build_parser()
    a = ap.parse_args(argv)
    if not a.cmd:
        ap.print_help()
        return 0
    try:
        return {"validate": cmd_validate, "test": cmd_test, "scan": cmd_scan, "coverage": cmd_coverage, "explain": cmd_explain, "list": cmd_list, "attack": cmd_attack,
                "migrate": cmd_migrate, "new": cmd_new, "demo": cmd_demo}[a.cmd](a)
    except BrokenPipeError:                       # ex.: 'ruleforge ... | head': quem lê fechou o pipe, não é erro
        try:
            sys.stdout = open(os.devnull, "w")
        except OSError:
            pass
        return 0
    except (FileNotFoundError, ValueError, OSError) as exc:
        print(f"Erro: {exc}", file=sys.stderr)
        return 2
