"""Execução das regras sobre eventos: leitura de logs (JSONL, JSON, CSV), varredura, correlação e testes de regra."""
from __future__ import annotations

import csv
import io
import json
import os
import re
from collections import Counter, defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Deque, Dict, Iterable, Iterator, List, Optional, Tuple

from .sigma import EventView, LEVELS, Rule, compare_op, logsource_matches

TIME_FIELDS = ("timestamp", "@timestamp", "time", "TimeCreated", "UtcTime", "EventTime", "datetime", "date", "ts")
IP_FIELDS = ("src_ip", "SourceIp", "IpAddress", "ClientIP", "c-ip", "client_ip", "remote_ip", "source.ip", "SourceAddress", "ip")
MAX_LINE = 1_000_000
MAX_FILE = 500 * 1024 * 1024
DEFAULT_MAX_PER_RULE = 1000


def rule_key(r: Rule) -> str:
    return r.id or r.title


def parse_ts(v: Any) -> Optional[datetime]:
    """Aceita ISO 8601 (com Z ou deslocamento), 'AAAA-MM-DD HH:MM:SS', o formato do Apache e o 'epoch' (segundos ou milissegundos). Sem fuso = UTC."""
    if v is None or isinstance(v, bool):
        return None
    if isinstance(v, (int, float)):
        n = float(v)
        try:
            return datetime.fromtimestamp(n / 1000 if n > 1e11 else n, tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    s = str(v).strip()
    if not s:
        return None
    if re.fullmatch(r"\d{9,13}(\.\d+)?", s):
        return parse_ts(float(s))
    for fmt in ("%d/%b/%Y:%H:%M:%S %z",):
        try:
            return datetime.strptime(s, fmt).astimezone(timezone.utc)
        except ValueError:
            pass
    s2 = s.replace(",", ".").replace("Z", "+00:00")
    if re.match(r"\d{4}-\d{2}-\d{2} \d", s2):
        s2 = s2.replace(" ", "T", 1)
    try:
        dt = datetime.fromisoformat(s2)
    except ValueError:
        return None
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)


# ---- leitura de eventos ----------------------------------------------------------------------------------------------------------
def read_events(path: str, bad: List[Tuple[str, int, str]]) -> Iterator[Tuple[int, Dict[str, Any]]]:
    """Gera (número da linha, evento). Linhas inválidas vão para 'bad' em vez de derrubar a leitura."""
    name = os.path.basename(path)
    if os.path.getsize(path) > MAX_FILE:
        bad.append((name, 0, "arquivo grande demais (limite de 500 MB)"))
        return
    ext = os.path.splitext(path)[1].lower()
    with open(path, encoding="utf-8-sig", errors="replace", newline="") as f:
        if ext == ".csv":
            head = f.readline()
            f.seek(0)
            delim = ";" if head.count(";") > head.count(",") else ","
            for n, row in enumerate(csv.DictReader(f, delimiter=delim), 2):
                yield n, {k: v for k, v in row.items() if k}
            return
        first = f.read(1)
        while first and first.isspace():
            first = f.read(1)
        f.seek(0)
        if first == "[":
            try:
                data = json.load(f)
            except ValueError as exc:
                bad.append((name, 0, f"JSON inválido: {exc}"))
                return
            for n, item in enumerate(data, 1):
                if isinstance(item, dict):
                    yield n, item
                else:
                    bad.append((name, n, "o item não é um objeto"))
            return
        for n, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            if len(line) > MAX_LINE:
                bad.append((name, n, "linha grande demais (limite de 1 MB)"))
                continue
            try:
                obj = json.loads(line)
            except ValueError:
                bad.append((name, n, "não é JSON válido"))
                continue
            if isinstance(obj, dict):
                yield n, obj
            else:
                bad.append((name, n, "a linha não é um objeto JSON"))


# ---- resultado ----------------------------------------------------------------------------------------------------------------------
@dataclass
class Alert:
    rule: Rule
    source: str
    line: int
    time: Optional[datetime]
    evidence: Dict[str, str]
    count: int = 1
    group: Dict[str, str] = field(default_factory=dict)
    kind: str = "regra"
    ip: str = ""


@dataclass
class ScanResult:
    alerts: List[Alert] = field(default_factory=list)
    events: int = 0
    bad: List[Tuple[str, int, str]] = field(default_factory=list)
    rules_run: int = 0
    rules_skipped: List[Rule] = field(default_factory=list)
    matches: Counter = field(default_factory=Counter)                 # disparos por regra (inclui os que viraram só correlação)
    suppressed: Counter = field(default_factory=Counter)
    truncated: Counter = field(default_factory=Counter)
    notes: List[str] = field(default_factory=list)


def _clip(v: Any, n: int = 160) -> str:
    s = "true" if v is True else "false" if v is False else str(v)
    return s if len(s) <= n else s[:n - 1] + "…"


class Scanner:
    def __init__(self, rules: List[Rule], field_map: Optional[Dict[str, Any]] = None, time_fields: Optional[Iterable[str]] = None,
                 max_per_rule: int = DEFAULT_MAX_PER_RULE):
        self.fm: Dict[str, Tuple[str, ...]] = {k: ((v,) if isinstance(v, str) else tuple(v)) for k, v in (field_map or {}).items()}
        self.time_fields = tuple(time_fields) if time_fields else TIME_FIELDS
        self.max_per_rule = max_per_rule
        self.result = ScanResult()
        self.detections = [r for r in rules if r.detection is not None]
        self.correlations = [r for r in rules if r.correlation is not None]
        self._applicable: Dict[Tuple, List[Rule]] = {}
        self._ever_applied: set = set()
        self._by_key: Dict[str, Rule] = {}
        for r in self.detections:
            for k in r.keys():
                self._by_key.setdefault(k, r)
        self.watch: Dict[str, List[Any]] = defaultdict(list)          # chave da regra-base -> correlações que a usam
        self.generate: Dict[str, bool] = {}
        for c in self.correlations:
            for ref in c.correlation.rules:
                base = self._by_key.get(ref.lower())
                if base is None:
                    self.result.notes.append(f"a correlação '{c.title}' cita '{ref}', que não é uma regra aplicável a este log")
                    continue
                self.watch[rule_key(base)].append(c)
                self.generate[rule_key(base)] = self.generate.get(rule_key(base), False) or c.correlation.generate
        self.collected: Dict[Tuple[str, str], List[Tuple[datetime, int, str, Tuple[str, ...], Any]]] = defaultdict(list)

    def _time(self, ev: EventView) -> Optional[datetime]:
        for f in self.time_fields:
            vals = ev.values((f,))
            if vals:
                dt = parse_ts(vals[0])
                if dt:
                    return dt
        return None

    def _ip(self, ev: EventView) -> str:
        for f in IP_FIELDS:
            vals = ev.values((self.fm[f][0],)) if f in self.fm else ev.values((f,))
            if vals and vals[0] not in (None, ""):
                return _clip(vals[0], 64)
        return ""

    def rules_for(self, ctx: Optional[Dict[str, str]]) -> List[Rule]:
        """As regras cuja origem do log (logsource) combina com a do arquivo. Sem contexto, todas."""
        key = tuple(sorted((ctx or {}).items()))
        if key not in self._applicable:
            self._applicable[key] = [r for r in self.detections if logsource_matches(r, ctx or {})]
            self._ever_applied.update(id(r) for r in self._applicable[key])
        return self._applicable[key]

    def feed(self, source: str, line: int, obj: Dict[str, Any], ctx: Optional[Dict[str, str]] = None) -> None:
        self.result.events += 1
        ev = EventView(obj)
        when: Optional[datetime] = None
        got_time = False
        for rule in self.rules_for(ctx):
            if not rule.detection.matches(ev, self.fm):          # avaliação rápida: quase todo evento para aqui
                continue
            ok, used = rule.detection.match(ev, self.fm)       # casou: só agora monta a evidência (campos que sustentam o alerta)
            key = rule_key(rule)
            self.result.matches[key] += 1
            if not got_time:
                when, got_time = self._time(ev), True
            for corr in self.watch.get(key, []):
                c = corr.correlation
                grp = tuple(_clip(next(iter(ev.values(self.fm.get(g, (g,)))), ""), 120) for g in c.group_by)
                vfield = _clip(next(iter(ev.values(self.fm.get(c.value_field, (c.value_field,)))), ""), 120) if c.value_field else None
                self.collected[(rule_key(corr), key)].append((when, line, source, grp, vfield))
            if key in self.watch and not self.generate.get(key, False):
                self.result.suppressed[key] += 1
                continue
            if self.result.matches[key] > self.max_per_rule:
                self.result.truncated[key] += 1
                continue
            evidence = {f: _clip(next(iter(ev.values(self.fm.get(f, (f,)))), "")) for f in used}
            self.result.alerts.append(Alert(rule, source, line, when, evidence, ip=self._ip(ev)))

    def finish(self) -> ScanResult:
        self.result.rules_run = len(self._ever_applied)
        self.result.rules_skipped = [r for r in self.detections if id(r) not in self._ever_applied]
        for corr in self.correlations:
            c = corr.correlation
            items = []
            for ref in c.rules:
                base = self._by_key.get(ref.lower())
                if base is not None:
                    items.extend(self.collected.get((rule_key(corr), rule_key(base)), []))
            if not items:
                continue
            untimed = [i for i in items if i[0] is None]
            if untimed:
                self.result.notes.append(f"correlação '{corr.title}': {len(untimed)} evento(s) sem data/hora foram ignorados (use --time-field para indicar o campo de tempo)")
            groups: Dict[Tuple[str, ...], List] = defaultdict(list)
            for it in items:
                if it[0] is not None:
                    groups[it[3]].append(it)
            for gkey, evs in groups.items():
                evs.sort(key=lambda x: (x[0], x[1]))
                window: Deque = deque()
                active: Optional[Alert] = None          # a rajada em andamento (um alerta por rajada, não um por evento)
                prev = None
                burst: set = set()
                for it in evs:
                    if active is not None:
                        if (it[0] - prev).total_seconds() <= c.timespan:
                            prev = it[0]
                            burst.add(it[4])
                            active.count += 1 if c.type == "event_count" else 0
                            if c.type == "value_count":
                                active.count = len(burst)
                            active.evidence["total"] = str(active.count)
                            continue
                        active = None                   # silêncio maior que o intervalo: a rajada acabou
                        window.clear()
                    window.append(it)
                    while window and (it[0] - window[0][0]).total_seconds() > c.timespan:
                        window.popleft()
                    metric = len(window) if c.type == "event_count" else len({w[4] for w in window})
                    if compare_op(c.op, metric, c.threshold):
                        group = dict(zip(c.group_by, gkey))
                        active = Alert(corr, it[2], it[1], it[0], {**group, "total": str(metric)}, count=metric, group=group, kind="correlação",
                                       ip=next((v for k, v in group.items() if k in IP_FIELDS or "ip" in k.lower()), ""))
                        self.result.alerts.append(active)
                        prev, burst = it[0], {w[4] for w in window}
                        window.clear()
        self.result.alerts.sort(key=lambda a: (a.time is None, a.time or datetime.min.replace(tzinfo=timezone.utc), a.source, a.line))
        return self.result


def parse_source(spec: str) -> Tuple[str, Dict[str, str]]:
    """'arquivo.jsonl' ou 'arquivo.jsonl:product=windows,category=process_creation' (o contexto diz de que tipo de log o arquivo é).
    Funciona também com caminhos do Windows (C:\\pasta\\log.jsonl:product=windows)."""
    m = re.match(r"^(.*?):((?:category|product|service)=[^:]*)$", spec)
    if not m:
        return spec, {}
    ctx: Dict[str, str] = {}
    for pair in m.group(2).split(","):
        k, _, v = pair.partition("=")
        if k.strip() in ("category", "product", "service") and v.strip():
            ctx[k.strip()] = v.strip()
    return m.group(1), ctx


def scan_files(rules: List[Rule], sources: List[Any], field_map: Optional[Dict[str, Any]] = None, time_fields: Optional[Iterable[str]] = None,
               max_per_rule: int = DEFAULT_MAX_PER_RULE) -> ScanResult:
    """'sources' é uma lista de caminhos ou de pares (caminho, contexto do logsource)."""
    sc = Scanner(rules, field_map, time_fields, max_per_rule)
    for src in sources:
        p, ctx = (src, {}) if isinstance(src, str) else src
        for line, obj in read_events(p, sc.result.bad):
            sc.feed(os.path.basename(p), line, obj, ctx)
    return sc.finish()


def filter_level(alerts: List[Alert], minimum: Optional[str]) -> List[Alert]:
    if not minimum:
        return alerts
    floor = LEVELS.index(minimum)
    return [a for a in alerts if a.rule.level in LEVELS and LEVELS.index(a.rule.level) >= floor]


# ---- testes de regra (detecção como código) -------------------------------------------------------------------------------------
@dataclass
class TestResult:
    rule: Rule
    kind: str            # positive | negative
    index: int
    passed: bool
    message: str = ""


def run_rule_tests(rule: Rule, all_rules: Optional[List[Rule]] = None, field_map: Optional[Dict[str, Any]] = None) -> List[TestResult]:
    """Cada evento de x_tests.positive DEVE disparar a regra; cada um de x_tests.negative NÃO deve.
    Em regras de correlação, cada item é um mapa com 'events': uma lista de eventos (com data/hora) tratada como um pequeno log."""
    out: List[TestResult] = []
    for kind in ("positive", "negative"):
        for i, item in enumerate(rule.tests[kind], 1):
            try:
                if rule.correlation is not None:
                    events = item.get("events")
                    if not isinstance(events, list) or not all(isinstance(e, dict) for e in events):
                        out.append(TestResult(rule, kind, i, False, "em regra de correlação, cada teste precisa de 'events' (lista de eventos)"))
                        continue
                    base = [r for r in (all_rules or []) if r.detection is not None and any(k in [x.lower() for x in rule.correlation.rules] for k in r.keys())]
                    sc = Scanner(base + [rule], field_map, max_per_rule=10 ** 6)
                    for n, e in enumerate(events, 1):
                        sc.feed("teste", n, e)
                    fired = any(a.rule is rule for a in sc.finish().alerts)
                else:
                    fired = rule.detection.match(EventView(item), {k: ([v] if isinstance(v, str) else v) for k, v in (field_map or {}).items()})[0]
            except Exception as exc:                                      # teste malformado não pode derrubar a execução dos outros
                out.append(TestResult(rule, kind, i, False, f"erro ao executar: {type(exc).__name__}: {exc}"))
                continue
            ok = fired if kind == "positive" else not fired
            out.append(TestResult(rule, kind, i, ok, "" if ok else ("a regra NÃO disparou, mas deveria" if kind == "positive" else "a regra disparou, mas NÃO deveria")))
    return out
