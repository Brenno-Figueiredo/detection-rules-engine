"""Saídas: terminal, JSON, CSV, painel HTML (alertas e cobertura do ATT&CK), camada do Navigator, feed do Venator e evidência do ComplianceMap.

Confidencialidade: um alerta pode trazer trechos reais de log (comandos, usuários, endereços). O relatório completo é confidencial. As exportações
para o ComplianceMap e o Venator são AGREGADAS e NÃO levam trechos de log: só a regra, o nível e a técnica."""
from __future__ import annotations

import csv
import html
import io
import json
import time
from collections import Counter
from datetime import datetime
from typing import Dict, List, Optional

from .attack import Attack
from .engine import Alert, ScanResult
from .lint import Issue
from .sigma import LEVELS, Rule

ANSI = {"critical": "\033[1;97;41m", "high": "\033[1;31m", "medium": "\033[1;33m", "low": "\033[1;34m", "informational": "\033[2m", "b": "\033[1m", "d": "\033[2m",
        "ok": "\033[32m", "x": "\033[0m"}
COLOR = {"critical": "#ff5c7a", "high": "#ff9a45", "medium": "#f2cd3b", "low": "#5aa9ff", "informational": "#8ba2b4"}
LEVEL_PT = {"critical": "Crítico", "high": "Alto", "medium": "Médio", "low": "Baixo", "informational": "Informativo", "": "Sem nível"}
FEED_SEVERITY = {"critical": "critical", "high": "high", "medium": "medium", "low": "low", "informational": "low", "": "low"}
CSV_PREFIX = ("=", "+", "-", "@", "\t", "\r")
COVERAGE_NOTE = ("Cobertura de regras não é cobertura de detecção: uma técnica com regra pode ser detectada só em parte, só em certos logs, ou só se o log existir e "
                 "for coletado. As técnicas do ATT&CK também mudam entre versões.")


def _safe(v):
    return ("'" + v) if isinstance(v, str) and v.startswith(CSV_PREFIX) else v


def _when(a: Alert) -> str:
    return a.time.strftime("%d/%m/%Y %H:%M:%S") if a.time else "sem hora"


def _techs(rule: Rule, attack: Attack) -> List[str]:
    return attack.rule_techniques(rule.tags)


def _order(alerts: List[Alert]) -> List[Alert]:
    rank = {lvl: i for i, lvl in enumerate(reversed(LEVELS))}
    return sorted(alerts, key=lambda a: (rank.get(a.rule.level, 99), a.rule.title, a.time is None, a.time or datetime.min))


def render_scan(res: ScanResult, rules: List[Rule], attack: Attack, color: bool = False, examples: int = 2) -> str:
    p = (lambda t, k: f"{ANSI[k]}{t}{ANSI['x']}") if color else (lambda t, k: t)
    by_level = Counter(a.rule.level for a in res.alerts)
    lines = [p("VARREDURA DE DETECÇÃO", "b"), f"{res.events} evento(s) lidos · {res.rules_run} regra(s) aplicadas · {len(res.alerts)} alerta(s)"
             + (f" · {len(res.rules_skipped)} regra(s) fora do tipo de log" if res.rules_skipped else ""),
             "Por nível: " + (" · ".join(f"{LEVEL_PT[l].lower()} {by_level[l]}" for l in reversed(LEVELS) if by_level.get(l)) or "nenhum alerta"), ""]
    groups: Dict[str, List[Alert]] = {}
    for a in _order(res.alerts):
        groups.setdefault(a.rule.id or a.rule.title, []).append(a)
    for alerts in groups.values():
        r = alerts[0].rule
        techs = ", ".join(f"{t} {attack.name(t)}" for t in _techs(r, attack)) or "sem técnica do ATT&CK"
        lines.append(f"{p('[' + LEVEL_PT.get(r.level, r.level) + ']', r.level if r.level in ANSI else 'low')} {r.title}: {len(alerts)} alerta(s)")
        lines.append(p(f"    ATT&CK: {techs}", "d"))
        for a in alerts[:examples]:
            if a.kind == "correlação":
                detail = f"{a.count} ocorrência(s) · " + ", ".join(f"{k}={v}" for k, v in a.group.items())
            else:
                detail = "; ".join(f"{k}={v[:70]}" for k, v in list(a.evidence.items())[:3])
            lines.append(f"    {_when(a)}  {a.source}:{a.line}  {detail}")
        if len(alerts) > examples:
            lines.append(p(f"    ... e mais {len(alerts) - examples}", "d"))
    if res.suppressed:
        lines += ["", p(f"{sum(res.suppressed.values())} disparo(s) de regras-base contaram só para a correlação (não geram alerta sozinhos).", "d")]
    if res.truncated:
        lines.append(p(f"{sum(res.truncated.values())} alerta(s) além do limite por regra foram contados mas não listados.", "d"))
    if res.bad:
        lines += ["", f"{len(res.bad)} linha(s) inválida(s) ignorada(s) (ex.: {res.bad[0][0]}:{res.bad[0][1]}: {res.bad[0][2]})"]
    lines += [f"Nota: {n}" for n in res.notes]
    lines += ["", p("Os alertas são hipóteses para o analista confirmar; o relatório pode conter trechos reais de log: confidencial.", "d")]
    return "\n".join(lines)


def render_issues(issues: List[Issue], n_rules: int, color: bool = False) -> str:
    p = (lambda t, k: f"{ANSI[k]}{t}{ANSI['x']}") if color else (lambda t, k: t)
    count = Counter(i.severity for i in issues)
    lines = [p("VALIDAÇÃO DAS REGRAS", "b"), f"{n_rules} regra(s) · {count.get('error', 0)} erro(s) · {count.get('warning', 0)} aviso(s) · {count.get('info', 0)} sugestão(ões)", ""]
    tone = {"error": "high", "warning": "medium", "info": "informational"}
    label = {"error": "ERRO", "warning": "aviso", "info": "info"}
    for i in issues:
        where = f"{i.path.split('/')[-1]}" if i.path else ""
        lines.append(f"{p(label[i.severity].ljust(5), tone[i.severity])} {i.code} {i.rule[:48] + ': ' if i.rule else (where + ': ' if where else '')}{i.message}")
    if not issues:
        lines.append(p("Nenhum problema encontrado.", "ok"))
    return "\n".join(lines)


def render_coverage(cov: Dict, attack: Attack, color: bool = False, show_gaps: bool = False) -> str:
    p = (lambda t, k: f"{ANSI[k]}{t}{ANSI['x']}") if color else (lambda t, k: t)
    lines = [p(f"COBERTURA DO MITRE ATT&CK v{cov['version']} (Enterprise)", "b"),
             f"{cov['covered_techniques']} de {cov['total_techniques']} técnicas ({cov['percent']}%) têm ao menos uma regra · {cov['rules_with_attack']} de {cov['rules_total']} regras têm técnica",
             "", f"{'TÁTICA':<24}{'COBERTAS':>10}  BARRA"]
    for t in cov["per_tactic"]:
        pct = t["covered"] / t["total"] if t["total"] else 0
        bar = "█" * round(pct * 24) + "░" * (24 - round(pct * 24))
        lines.append(f"{t['name']:<24}{str(t['covered']) + '/' + str(t['total']):>10}  {bar} {round(pct * 100):>3}%")
    lines += ["", p(COVERAGE_NOTE, "d"), p(attack.disclaimer, "d"), p(attack.notice, "d")]
    return "\n".join(lines)


def alerts_json(res: ScanResult, attack: Attack) -> str:
    return json.dumps({"generated_at": datetime.now().isoformat(timespec="seconds"), "attack_version": attack.version, "events": res.events, "rules_run": res.rules_run,
                       "alerts": [{"rule": a.rule.title, "rule_id": a.rule.id, "level": a.rule.level, "kind": a.kind, "time": a.time.isoformat() if a.time else None,
                                   "source": a.source, "line": a.line, "count": a.count, "group": a.group, "evidence": a.evidence, "techniques": _techs(a.rule, attack),
                                   "tags": a.rule.tags} for a in res.alerts]}, ensure_ascii=False, indent=2)


def alerts_csv(res: ScanResult, attack: Attack) -> str:
    buf = io.StringIO()
    w = csv.writer(buf, delimiter=";", lineterminator="\n")
    w.writerow(["hora", "nivel", "regra", "tipo", "tecnicas", "arquivo", "linha", "ocorrencias", "evidencia"])
    for a in _order(res.alerts):
        w.writerow([a.time.isoformat() if a.time else "", a.rule.level, _safe(a.rule.title), a.kind, " ".join(_techs(a.rule, attack)), _safe(a.source), a.line, a.count,
                    _safe("; ".join(f"{k}={v}" for k, v in a.evidence.items()))])
    return buf.getvalue()


def to_feed(res: ScanResult, attack: Attack) -> List[Dict]:
    """Um evento por alerta, no formato genérico do Venator e do CorrelAI. SEM trechos de log: só a regra, o nível e as técnicas."""
    out = []
    for a in res.alerts:
        techs = ", ".join(_techs(a.rule, attack))
        out.append({"ts": a.time.timestamp() if a.time else time.time(), "source": "ruleforge", "type": "generic", "severity": FEED_SEVERITY.get(a.rule.level, "low"),
                    "ip": a.ip, "message": f"Detecção: {a.rule.title}" + (f" ({techs})" if techs else "") + (f" x{a.count}" if a.count > 1 else "")})
    return out


def to_compliancemap(rules: List[Rule], issues: List[Issue], test_total: int, test_failed: int, cov: Dict) -> str:
    """Evidência AGREGADA (sem nomes de regras) para o ComplianceMap (--auto): MON-02 (monitoramento de eventos atípicos) e TEC-04 (detecção de intrusão).
    É evidência de PROCESSO: as regras existem, são validadas e testadas. Não prova que os logs reais são coletados e monitorados."""
    errors = sum(1 for i in issues if i.severity == "error")
    if not rules:
        rows = [{"check": "ruleforge", "control": c, "status": "unknown", "detail": "nenhuma regra de detecção carregada", "platform": "detection"} for c in ("MON-02", "TEC-04")]
    else:
        untested = sum(1 for r in rules if not r.tests["positive"] and not r.tests["negative"])
        problems = [x for x in (f"{errors} erro(s) de validação" if errors else "", f"{test_failed} de {test_total} teste(s) de regra falhando" if test_failed else "",
                                f"{untested} regra(s) sem testes" if untested else "") if x]
        detail_ok = (f"{len(rules)} regra(s) validadas, {test_total} teste(s) de regra passando, {cov['covered_techniques']} técnica(s) do ATT&CK v{cov['version']} com regra "
                     "(evidência de processo: não prova a coleta de logs reais)")
        status = "fail" if problems else "pass"
        rows = [{"check": "ruleforge", "control": c, "status": status, "detail": ("; ".join(problems)) if problems else detail_ok, "platform": "detection"} for c in ("MON-02", "TEC-04")]
    return json.dumps({"collected_at": datetime.now().isoformat(timespec="seconds"), "system": "detection",
                       "note": "Gerado pelo RuleForge. Resultado agregado, sem nomes de regras nem trechos de log.", "results": rows}, ensure_ascii=False, indent=2)


CSS = """
:root{color-scheme:dark;--bg:#0b1118;--panel:#121b26;--line:#263a4b;--text:#e6eef5;--muted:#8ba2b4;--ok:#3ddc84}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font:14px/1.55 "Segoe UI",system-ui,sans-serif}
main{max-width:1060px;margin:0 auto;padding:30px 22px 70px}h1{margin:0;font-size:26px}h2{font-size:17px;margin:28px 0 8px}.sub{color:var(--muted);margin:4px 0 0}
.top{display:flex;gap:12px;flex-wrap:wrap;margin:22px 0}.card{flex:1;min-width:130px;background:var(--panel);border:1px solid var(--line);border-radius:12px;padding:14px 18px}
.card b{display:block;font-size:30px;line-height:1.1}.card span{color:var(--muted);font-size:13px}
.badge{font-size:11.5px;font-weight:700;border-radius:999px;padding:1px 9px;color:#07121b;white-space:nowrap}.muted{color:var(--muted);font-size:12.5px}
.a{background:var(--panel);border:1px solid var(--line);border-left-width:4px;border-radius:10px;padding:11px 14px;margin:8px 0}
code{font-family:ui-monospace,Consolas,monospace;font-size:12px;word-break:break-all}
.tac{display:grid;grid-template-columns:200px 1fr 70px;gap:10px;align-items:center;padding:5px 0}.bar{height:10px;background:#223244;border-radius:5px;overflow:hidden}.bar i{display:block;height:100%;background:#5aa9ff}
.chips{display:flex;flex-wrap:wrap;gap:4px;margin:2px 0 8px}.chip{font-size:11.5px;border:1px solid var(--line);border-radius:4px;padding:0 6px;color:var(--text)}
.note{color:var(--muted);font-size:12.5px;margin-top:30px;border-top:1px solid var(--line);padding-top:14px}
"""


def render_html(res: ScanResult, rules: List[Rule], attack: Attack, cov: Dict) -> str:
    e = html.escape
    by_level = Counter(a.rule.level for a in res.alerts)
    groups: Dict[str, List[Alert]] = {}
    for a in _order(res.alerts):
        groups.setdefault(a.rule.id or a.rule.title, []).append(a)
    blocks = []
    for alerts in groups.values():
        r = alerts[0].rule
        c = COLOR.get(r.level, "#8ba2b4")
        techs = ", ".join(f"{t} {attack.name(t)}" for t in _techs(r, attack))
        rows = "".join(f"<div class='muted'>{e(_when(a))} · <code>{e(a.source)}:{a.line}</code> · "
                       + e((f"{a.count} ocorrência(s) " + ", ".join(f"{k}={v}" for k, v in a.group.items())) if a.kind == "correlação"
                           else "; ".join(f"{k}={v[:90]}" for k, v in list(a.evidence.items())[:3])) + "</div>" for a in alerts[:5])
        more = f"<div class='muted'>... e mais {len(alerts) - 5}</div>" if len(alerts) > 5 else ""
        blocks.append(f"<div class='a' style='border-left-color:{c}'><span class='badge' style='background:{c}'>{e(LEVEL_PT.get(r.level, r.level))}</span> <b>{e(r.title)}</b> "
                      f"· {len(alerts)} alerta(s)<div class='muted'>{e(techs or 'sem técnica do ATT&CK')}</div>{rows}{more}</div>")
    tactics = ""
    for t in cov["per_tactic"]:
        pct = round(100 * t["covered"] / t["total"]) if t["total"] else 0
        chips = "".join(f"<span class='chip' title='{e(attack.name(x))}'>{e(x)}</span>" for x in t["covered_ids"])
        tactics += (f"<div class='tac'><span>{e(t['name'])}</span><div class='bar'><i style='width:{pct}%'></i></div><span class='muted'>{t['covered']}/{t['total']}</span></div>"
                    + (f"<div class='chips'>{chips}</div>" if chips else ""))
    return f"""<!DOCTYPE html><html lang="pt-BR"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>RuleForge - relatório</title><style>{CSS}</style></head><body><main>
<h1>RuleForge</h1><p class="sub">Detecção como código · {len(rules)} regra(s) · MITRE ATT&amp;CK v{e(attack.version)} · {datetime.now():%d/%m/%Y %H:%M}</p>
<div class="top"><div class="card"><span>Eventos lidos</span><b>{res.events}</b></div><div class="card"><span>Alertas</span><b>{len(res.alerts)}</b></div>
<div class="card"><span>Críticos</span><b style="color:#ff5c7a">{by_level.get('critical', 0)}</b></div><div class="card"><span>Altos</span><b style="color:#ff9a45">{by_level.get('high', 0)}</b></div>
<div class="card"><span>Técnicas cobertas</span><b>{cov['covered_techniques']}/{cov['total_techniques']}</b></div></div>
<h2>Alertas por regra</h2>{''.join(blocks) or "<p class='sub'>Nenhum alerta.</p>"}
<h2>Cobertura do ATT&amp;CK por tática</h2>{tactics}
<p class="note">{e(COVERAGE_NOTE)}<br><br>{e(attack.disclaimer)}<br><br>{e(attack.notice)}<br>Os alertas são hipóteses para o analista confirmar. Este relatório pode conter trechos reais de log: confidencial.</p>
</main></body></html>"""
