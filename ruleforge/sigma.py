"""Regras no formato Sigma: leitura, compilação da detecção e avaliação sobre um evento.

Suportado (subconjunto do Sigma): seleções em mapa, lista de mapas e lista de palavras-chave; condição com and, or, not, parênteses,
'1 of selection*', 'all of them', 'N of ...'; modificadores contains, startswith, endswith, all, re (com i, m, s), cidr, base64,
base64offset, utf16le/wide (antes de base64), windash, exists, lt, lte, gt, gte; curingas * e ? (com escape por barra invertida);
valor null (campo ausente ou vazio); regras de correlação event_count e value_count.
NÃO suportado (e a ferramenta avisa, em vez de ignorar): agregações antigas (| count() > 5), fieldref, expand, temporal.

Segurança: a regra vem de fora, então é tratada como não confiável. Expressões regulares com repetição aninhada (ReDoS) e padrões enormes são
recusados, e o valor de cada campo é truncado antes de ser comparado."""
from __future__ import annotations

import base64
import fnmatch
import ipaddress
import re
import uuid
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Iterable, List, Optional, Tuple

from . import yamlite

LEVELS = ("informational", "low", "medium", "high", "critical")
STATUSES = ("stable", "test", "experimental", "deprecated", "unsupported")
MAX_VALUE_LEN = 16384            # o valor de um campo é truncado a este tamanho antes de qualquer comparação
MAX_PATTERN_LEN = 1000
MAX_WILDCARDS = 8                # curingas por valor: limita o custo de casar padrões como a*b*c*d*
MATCH_MODS = {"contains", "startswith", "endswith"}
TRANSFORM_MODS = {"base64", "base64offset", "utf16le", "utf16", "wide", "windash"}
NUMERIC_MODS = {"lt", "lte", "gt", "gte"}
REGEX_MODS = {"i", "m", "s"}
SUPPORTED_MODS = MATCH_MODS | TRANSFORM_MODS | NUMERIC_MODS | REGEX_MODS | {"all", "re", "cidr", "exists"}
UNSUPPORTED_MODS = {"fieldref": "comparação com outro campo", "expand": "variáveis de substituição", "gt-lt": "intervalo"}
_NESTED_QUANTIFIER = re.compile(r"\((?:[^()\\]|\\.)*[+*](?:[^()\\]|\\.)*\)[+*{]")


class RuleError(ValueError):
    """A regra é inválida ou usa algo que esta ferramenta não suporta."""


# ---- eventos -----------------------------------------------------------------------------------------------------------------------
def _flatten(prefix: str, value: Any, out: Dict[str, Any], depth: int = 0) -> None:
    if depth > 12:
        return
    if isinstance(value, dict):
        for k, v in value.items():
            _flatten(f"{prefix}.{k}" if prefix else str(k), v, out, depth + 1)
    elif isinstance(value, list):
        for item in value:
            if isinstance(item, (dict, list)):
                _flatten(prefix, item, out, depth + 1)
            else:
                cur = out.get(prefix)
                out[prefix] = (cur if isinstance(cur, list) else ([] if cur is None else [cur])) + [item]
    else:
        if prefix in out:
            cur = out[prefix]
            out[prefix] = (cur if isinstance(cur, list) else [cur]) + [value]
        else:
            out[prefix] = value


class EventView:
    """Um evento achatado ('a.b.c'), com busca de campo sem diferenciar maiúsculas de minúsculas."""

    __slots__ = ("obj", "flat", "_lower", "_blob", "_pairs", "_blob_pair")

    def __init__(self, obj: Dict[str, Any]):
        self.obj = obj
        self.flat: Dict[str, Any] = {}
        _flatten("", obj, self.flat)
        self._lower: Optional[Dict[str, str]] = None
        self._blob: Optional[str] = None
        self._pairs: Dict[Tuple[str, ...], List[Tuple[Optional[str], Optional[str]]]] = {}
        self._blob_pair: Optional[Tuple[str, str]] = None

    def pairs(self, names: Tuple[str, ...]) -> List[Tuple[Optional[str], Optional[str]]]:
        """[(texto, texto em minúsculas)] dos campos pedidos, calculado UMA vez por evento (vários regras olham os mesmos campos)."""
        got = self._pairs.get(names)
        if got is None:
            got = []
            for v in self.values(names):
                if v is None:
                    got.append((None, None))
                else:
                    t = _text(v)
                    got.append((t, t.lower()))
            self._pairs[names] = got
        return got

    def blob_pair(self) -> Tuple[str, str]:
        if self._blob_pair is None:
            b = self.blob()
            self._blob_pair = (b, b.lower())
        return self._blob_pair

    def values(self, names: Iterable[str]) -> List[Any]:
        out: List[Any] = []
        for name in names:
            if name in self.flat:
                v = self.flat[name]
            else:
                if self._lower is None:
                    self._lower = {k.lower(): k for k in self.flat}
                real = self._lower.get(name.lower())
                if real is None:
                    continue
                v = self.flat[real]
            out.extend(v if isinstance(v, list) else [v])
        return out

    def blob(self) -> str:
        """Todos os valores juntos: é onde as palavras-chave (keywords) procuram."""
        if self._blob is None:
            self._blob = "\n".join(_text(v) for v in self.flat.values() for v in (v if isinstance(v, list) else [v]) if v is not None)
        return self._blob


def _text(v: Any) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    s = v if isinstance(v, str) else str(v)
    return s[:MAX_VALUE_LEN]


# ---- valores: curingas, transformações e comparadores --------------------------------------------------------------------------------
def split_wildcards(value: str) -> List[Tuple[str, str]]:
    """Divide em literais e curingas. Barra invertida antes de * ou ? escapa o curinga; '\\\\' só vale como uma barra literal quando vem antes de um curinga."""
    out: List[Tuple[str, str]] = []
    buf: List[str] = []
    i = 0
    while i < len(value):
        ch = value[i]
        if ch == "\\":
            nxt = value[i + 1:i + 2]
            if nxt in ("*", "?"):
                buf.append(nxt)
                i += 2
                continue
            if nxt == "\\" and value[i + 2:i + 3] in ("*", "?"):
                buf.append("\\")
                i += 2
                continue
            buf.append("\\")
            i += 1
            continue
        if ch in "*?":
            if buf:
                out.append(("lit", "".join(buf)))
                buf = []
            out.append(("star" if ch == "*" else "any", ch))
            i += 1
            continue
        buf.append(ch)
        i += 1
    if buf:
        out.append(("lit", "".join(buf)))
    return out


def string_matcher(value: str, mode: str, case_sensitive: bool = False) -> Callable[[str, str], bool]:
    """Compara sem diferenciar maiúsculas (padrão do Sigma), exceto com base64, que diferencia. mode: exact, contains, startswith ou endswith."""
    toks = split_wildcards(value)
    wild = sum(1 for t in toks if t[0] != "lit")
    if wild > MAX_WILDCARDS:
        raise RuleError(f"curingas demais no valor '{value[:40]}' (máximo {MAX_WILDCARDS})")
    if wild == 0:
        lit = "".join(t[1] for t in toks)
        if case_sensitive:
            return {"exact": lambda s, low: s == lit, "contains": lambda s, low: lit in s, "startswith": lambda s, low: s.startswith(lit),
                    "endswith": lambda s, low: s.endswith(lit)}[mode]
        lit = lit.lower()
        return {"exact": lambda s, low: low == lit, "contains": lambda s, low: lit in low, "startswith": lambda s, low: low.startswith(lit),
                "endswith": lambda s, low: low.endswith(lit)}[mode]
    pat = "".join(re.escape(t[1]) if t[0] == "lit" else (".*" if t[0] == "star" else ".") for t in toks)
    flags = re.DOTALL | (0 if case_sensitive else re.IGNORECASE)
    if mode == "exact":
        rx = re.compile(pat, flags)
        return lambda s, low: rx.fullmatch(s) is not None
    if mode == "contains":
        rx = re.compile(pat, flags)
        return lambda s, low: rx.search(s) is not None
    if mode == "startswith":
        rx = re.compile(pat, flags)
        return lambda s, low: rx.match(s) is not None
    rx = re.compile(f"(?:{pat})\\Z", flags)
    return lambda s, low: rx.search(s) is not None


def safe_regex(pattern: str, flags: int) -> "re.Pattern[str]":
    if len(pattern) > MAX_PATTERN_LEN:
        raise RuleError(f"expressão regular grande demais ({len(pattern)} caracteres; limite {MAX_PATTERN_LEN})")
    if _NESTED_QUANTIFIER.search(pattern):
        raise RuleError(f"expressão regular recusada por risco de travamento (repetição aninhada, ex.: (a+)+): {pattern[:60]}")
    try:
        return re.compile(pattern, flags)
    except re.error as exc:
        raise RuleError(f"expressão regular inválida '{pattern[:60]}': {exc}") from None


_DASHES = ("-", "/", "\u2013", "\u2014", "\u2015")


def windash_variants(value: str) -> List[str]:
    """Parâmetros do Windows aceitam '-', '/' e traços tipográficos: gera as variações para cada '-' que começa um parâmetro."""
    positions = [i for i, ch in enumerate(value) if ch == "-" and (i == 0 or value[i - 1].isspace())]
    variants = {value}
    for pos in positions[:4]:
        variants = {v[:pos] + d + v[pos + 1:] for v in variants for d in _DASHES}
    return sorted(variants)


def base64_offset_variants(raw: bytes) -> List[str]:
    """As três formas em que um texto pode aparecer em base64, conforme o deslocamento dentro do conteúdo codificado."""
    starts, ends = (0, 2, 3), (None, -3, -2)
    return [base64.b64encode(b" " * i + raw).decode("ascii")[starts[i]:ends[(len(raw) + i) % 3]] for i in range(3)]


def transform(value: Any, mods: List[str]) -> List[str]:
    vals: List[Any] = [value if isinstance(value, str) else str(value)]
    for m in mods:
        if m == "windash":
            vals = [w for v in vals for w in windash_variants(v)]
        elif m in ("wide", "utf16le", "utf16"):
            vals = [v.encode("utf-16-le") if isinstance(v, str) else v for v in vals]
        elif m == "base64":
            vals = [base64.b64encode(v if isinstance(v, bytes) else v.encode("utf-8")).decode("ascii") for v in vals]
        elif m == "base64offset":
            vals = [w for v in vals for w in base64_offset_variants(v if isinstance(v, bytes) else v.encode("utf-8"))]
    if any(isinstance(v, bytes) for v in vals):
        raise RuleError("'wide'/'utf16le' só são suportados junto com base64 ou base64offset")
    return vals


@dataclass
class FieldCond:
    """Uma condição sobre um campo: nome, modificadores, valores originais e o teste compilado."""
    name: str
    mods: List[str]
    values: List[Any]
    all_values: bool
    test: Callable[[EventView, Dict[str, Any]], bool]


def compile_field(key: str, raw: Any) -> FieldCond:
    parts = key.split("|")
    name, mods = parts[0].strip(), [m.strip() for m in parts[1:]]
    if not name:
        raise RuleError(f"nome de campo vazio em '{key}'")
    for m in mods:
        if m in UNSUPPORTED_MODS:
            raise RuleError(f"o modificador '{m}' ({UNSUPPORTED_MODS[m]}) não é suportado: '{key}'")
        if m not in SUPPORTED_MODS:
            raise RuleError(f"modificador desconhecido '{m}' em '{key}'")
    values = raw if isinstance(raw, list) else [raw]
    if isinstance(raw, dict):
        raise RuleError(f"o valor de '{key}' deve ser um texto, número ou lista, não um mapa")
    all_values = "all" in mods
    match_mods = [m for m in mods if m in MATCH_MODS]
    if len(match_mods) > 1:
        raise RuleError(f"modificadores incompatíveis em '{key}': {', '.join(match_mods)}")
    mode = match_mods[0] if match_mods else "exact"
    transforms = [m for m in mods if m in TRANSFORM_MODS]
    flags = (re.IGNORECASE if "i" in mods else 0) | (re.MULTILINE if "m" in mods else 0) | (re.DOTALL if "s" in mods else 0)
    checks: List[Callable[[Optional[str], Optional[str]], bool]] = []

    if "exists" in mods:
        if len(values) != 1 or not isinstance(values[0], bool):
            raise RuleError(f"'{key}' precisa de true ou false")
        want = values[0]
        return FieldCond(name, mods, values, False, lambda ev, fm: bool(ev.values(fm.get(name) or (name,))) == want)

    for v in values:
        if v is None:
            checks.append(lambda t, low: t is None or t == "")
        elif "re" in mods:
            rx = safe_regex(str(v), flags)
            checks.append(lambda t, low, rx=rx: t is not None and rx.search(t) is not None)
        elif "cidr" in mods:
            try:
                net = ipaddress.ip_network(str(v), strict=False)
            except ValueError:
                raise RuleError(f"rede inválida em '{key}': {v}") from None
            checks.append(lambda t, low, net=net: t is not None and _in_net(t, net))
        elif NUMERIC_MODS & set(mods):
            op = next(m for m in mods if m in NUMERIC_MODS)
            try:
                limit = float(v)
            except (TypeError, ValueError):
                raise RuleError(f"'{key}' precisa de um número: {v!r}") from None
            checks.append(lambda t, low, op=op, limit=limit: t is not None and _compare(t, op, limit))
        else:
            variants = transform(v, transforms) if transforms else [v if isinstance(v, str) else str(v)]
            if transforms and isinstance(v, str) and ("*" in v or "?" in v) and ({"base64", "base64offset"} & set(transforms)):
                raise RuleError(f"curingas não são permitidos com base64: '{key}'")
            case_sensitive = bool({"base64", "base64offset"} & set(transforms))      # base64 diferencia maiúsculas: 'QQ' e 'qq' são dados diferentes
            matchers = [string_matcher(var, mode, case_sensitive) for var in variants]
            checks.append(lambda t, low, ms=matchers: t is not None and any(m(t, low) for m in ms))

    default = (name,)
    single = checks[0] if len(checks) == 1 else None

    def test(ev: EventView, fm: Dict[str, Any]) -> bool:
        names = fm.get(name)
        names = default if names is None else (names if isinstance(names, tuple) else tuple(names))
        pairs = ev.pairs(names)
        if single is not None:                              # caso mais comum: um valor só
            if not pairs:
                return single(None, None)
            for t, low in pairs:
                if single(t, low):
                    return True
            return False
        if not pairs:
            results = [c(None, None) for c in checks]
        else:
            results = [any(c(t, low) for t, low in pairs) for c in checks]
        return all(results) if all_values else any(results)

    return FieldCond(name, mods, values, all_values, test)


def _in_net(x: Any, net) -> bool:
    try:
        return ipaddress.ip_address(str(x).strip()) in net
    except ValueError:
        return False


def _compare(x: Any, op: str, limit: float) -> bool:
    try:
        n = float(x)
    except (TypeError, ValueError):
        return False
    return {"lt": n < limit, "lte": n <= limit, "gt": n > limit, "gte": n >= limit}[op]


# ---- seleções ---------------------------------------------------------------------------------------------------------------------
@dataclass
class Selection:
    name: str
    alternatives: List[List[FieldCond]] = field(default_factory=list)       # OU de (E de condições de campo)
    keywords: List[Callable[[str, str], bool]] = field(default_factory=list)
    keyword_values: List[str] = field(default_factory=list)

    def fields(self) -> List[str]:
        seen: List[str] = []
        for alt in self.alternatives:
            for fc in alt:
                if fc.name not in seen:
                    seen.append(fc.name)
        return seen

    def evaluate(self, ev: EventView, fm: Dict[str, List[str]]) -> bool:
        if self.keywords:
            blob, low = ev.blob_pair()
            return any(k(blob, low) for k in self.keywords)
        return any(all(fc.test(ev, fm) for fc in alt) for alt in self.alternatives)


def compile_selection(name: str, raw: Any) -> Selection:
    sel = Selection(name)
    if isinstance(raw, dict):
        if not raw:
            raise RuleError(f"a seleção '{name}' está vazia")
        sel.alternatives.append([compile_field(k, v) for k, v in raw.items()])
    elif isinstance(raw, list):
        if not raw:
            raise RuleError(f"a seleção '{name}' está vazia")
        if all(isinstance(x, dict) for x in raw):
            for item in raw:
                if not item:
                    raise RuleError(f"a seleção '{name}' tem um item vazio")
                sel.alternatives.append([compile_field(k, v) for k, v in item.items()])
        elif all(not isinstance(x, (dict, list)) and x is not None for x in raw):
            for kw in raw:
                sel.keyword_values.append(str(kw))
                sel.keywords.append(string_matcher(str(kw), "contains"))
        else:
            raise RuleError(f"a seleção '{name}' mistura mapas e textos em uma mesma lista")
    else:
        raise RuleError(f"a seleção '{name}' deve ser um mapa ou uma lista")
    return sel


# ---- condição ----------------------------------------------------------------------------------------------------------------------
@dataclass
class Node:
    kind: str                           # name | not | and | or | quant
    value: Any = None                   # nome (name) / padrão (quant)
    children: List["Node"] = field(default_factory=list)
    quant: Any = None                   # 'all' ou N
    names: List[str] = field(default_factory=list)     # (quant) seleções alcançadas pelo padrão, calculadas uma vez


class _CondParser:
    def __init__(self, text: str):
        if "|" in text:
            raise RuleError("agregações na condição (| count() ...) não são suportadas: use uma regra de correlação (event_count ou value_count)")
        self.toks = re.findall(r"[()]|[^\s()]+", text)
        self.i = 0

    def peek(self) -> Optional[str]:
        return self.toks[self.i] if self.i < len(self.toks) else None

    def take(self) -> str:
        tok = self.peek()
        if tok is None:
            raise RuleError("a condição termina antes da hora")
        self.i += 1
        return tok

    def parse(self) -> Node:
        if not self.toks:
            raise RuleError("a condição está vazia")
        node = self.expr()
        if self.peek() is not None:
            raise RuleError(f"condição inválida perto de '{self.peek()}'")
        return node

    def expr(self) -> Node:
        parts = [self.and_expr()]
        while (self.peek() or "").lower() == "or":
            self.take()
            parts.append(self.and_expr())
        return parts[0] if len(parts) == 1 else Node("or", children=parts)

    def and_expr(self) -> Node:
        parts = [self.not_expr()]
        while (self.peek() or "").lower() == "and":
            self.take()
            parts.append(self.not_expr())
        return parts[0] if len(parts) == 1 else Node("and", children=parts)

    def not_expr(self) -> Node:
        if (self.peek() or "").lower() == "not":
            self.take()
            return Node("not", children=[self.not_expr()])
        return self.atom()

    def atom(self) -> Node:
        tok = self.take()
        if tok == "(":
            node = self.expr()
            if self.peek() != ")":
                raise RuleError("faltou fechar um parêntese na condição")
            self.take()
            return node
        if tok == ")":
            raise RuleError("parêntese fechado sem abrir")
        if (self.peek() or "").lower() == "of" and (tok.lower() == "all" or tok.isdigit()):
            self.take()
            target = self.take()
            if target.lower() == "them":
                target = None
            return Node("quant", value=target, quant="all" if tok.lower() == "all" else int(tok))
        if tok.lower() in ("and", "or", "not", "of", "them"):
            raise RuleError(f"palavra reservada '{tok}' fora do lugar na condição")
        return Node("name", value=tok)


def parse_condition(text: str) -> Node:
    return _CondParser(str(text)).parse()


def referenced_names(node: Node) -> List[Tuple[str, bool]]:
    """(nome ou padrão, é padrão?) citados na condição."""
    out: List[Tuple[str, bool]] = []
    if node.kind == "name":
        out.append((node.value, False))
    elif node.kind == "quant" and node.value is not None:
        out.append((node.value, True))
    for c in node.children:
        out.extend(referenced_names(c))
    return out


@dataclass
class Detection:
    selections: Dict[str, Selection]
    condition_text: str
    condition: Node

    def _quant_names(self, node: Node) -> List[str]:
        if node.value is None:
            return [n for n in self.selections if not n.startswith("_")]
        return [n for n in self.selections if fnmatch.fnmatchcase(n, node.value)]

    def matches(self, ev: EventView, fm: Optional[Dict[str, Any]] = None) -> bool:
        """Avaliação rápida: só diz se casou (com curto-circuito). Quem precisa dos campos de evidência chama 'match' depois."""
        return self._eval(self.condition, ev, fm or {}, {})

    def _eval(self, node: Node, ev: EventView, fm: Dict[str, Any], memo: Dict[str, bool]) -> bool:
        kind = node.kind
        if kind == "name":
            r = memo.get(node.value)
            if r is None:
                r = memo[node.value] = self.selections[node.value].evaluate(ev, fm)
            return r
        if kind == "not":
            return not self._eval(node.children[0], ev, fm, memo)
        if kind == "and":
            for c in node.children:
                if not self._eval(c, ev, fm, memo):
                    return False
            return True
        if kind == "or":
            for c in node.children:
                if self._eval(c, ev, fm, memo):
                    return True
            return False
        results = []
        for n in node.names:
            r = memo.get(n)
            if r is None:
                r = memo[n] = self.selections[n].evaluate(ev, fm)
            results.append(r)
        return (bool(results) and all(results)) if node.quant == "all" else sum(results) >= node.quant

    def match(self, ev: EventView, fm: Optional[Dict[str, Any]] = None) -> Tuple[bool, List[str]]:
        """Devolve (casou?, campos que sustentam o alerta)."""
        fm = fm or {}
        memo: Dict[str, bool] = {}
        used: List[str] = []

        def sel(name: str) -> bool:
            if name not in memo:
                memo[name] = self.selections[name].evaluate(ev, fm)
            return memo[name]

        def run(node: Node, positive: bool) -> bool:
            if node.kind == "name":
                r = sel(node.value)
                if r and positive:
                    used.extend(f for f in self.selections[node.value].fields() if f not in used)
                return r
            if node.kind == "not":
                return not run(node.children[0], not positive)
            if node.kind == "and":
                results = [run(c, positive) for c in node.children]
                return all(results)
            if node.kind == "or":
                results = [run(c, positive) for c in node.children]
                return any(results)
            names = self._quant_names(node)
            results = [sel(n) for n in names]
            if positive:
                for n, r in zip(names, results):
                    if r:
                        used.extend(f for f in self.selections[n].fields() if f not in used)
            return (bool(names) and all(results)) if node.quant == "all" else sum(results) >= node.quant

        matched = run(self.condition, True)
        return matched, (used if matched else [])


def compile_detection(raw: Any) -> Detection:
    if not isinstance(raw, dict):
        raise RuleError("'detection' deve ser um mapa")
    if "condition" not in raw:
        raise RuleError("falta 'condition' em 'detection'")
    cond_raw = raw["condition"]
    if isinstance(cond_raw, list):
        if len(cond_raw) != 1:
            raise RuleError("várias condições (lista) não são suportadas: combine-as com 'or'")
        cond_raw = cond_raw[0]
    if not isinstance(cond_raw, str):
        raise RuleError("'condition' deve ser um texto")
    selections = {k: compile_selection(k, v) for k, v in raw.items() if k not in ("condition", "timeframe")}
    if not selections:
        raise RuleError("'detection' não tem nenhuma seleção")
    if "timeframe" in raw:
        raise RuleError("'timeframe' (agregação antiga) não é suportado: use uma regra de correlação")
    node = parse_condition(cond_raw)
    for name, is_pattern in referenced_names(node):
        if is_pattern:
            if not any(fnmatch.fnmatchcase(n, name) for n in selections):
                raise RuleError(f"o padrão '{name}' da condição não corresponde a nenhuma seleção")
        elif name not in selections:
            raise RuleError(f"a condição cita '{name}', que não foi definida em 'detection'")
    det = Detection(selections, cond_raw.strip(), node)
    stack = [node]
    while stack:
        n = stack.pop()
        if n.kind == "quant":
            n.names = det._quant_names(n)
        stack.extend(n.children)
    return det


# ---- correlação ---------------------------------------------------------------------------------------------------------------------
@dataclass
class Correlation:
    type: str
    rules: List[str]
    group_by: List[str]
    timespan: int
    op: str
    threshold: float
    value_field: Optional[str]
    generate: bool


_OPS = {"gte": ">=", "gt": ">", "lte": "<=", "lt": "<", "eq": "=="}


def parse_timespan(text: Any) -> int:
    m = re.fullmatch(r"(\d+)\s*([smhd])", str(text).strip())
    if not m or int(m.group(1)) == 0:
        raise RuleError(f"timespan inválido: {text!r} (use 30s, 5m, 1h ou 1d)")
    return int(m.group(1)) * {"s": 1, "m": 60, "h": 3600, "d": 86400}[m.group(2)]


def compile_correlation(raw: Any) -> Correlation:
    if not isinstance(raw, dict):
        raise RuleError("'correlation' deve ser um mapa")
    ctype = str(raw.get("type", "")).strip()
    if ctype not in ("event_count", "value_count"):
        raise RuleError(f"tipo de correlação '{ctype}' não suportado (suportados: event_count e value_count)")
    rules = raw.get("rules")
    if isinstance(rules, str):
        rules = [rules]
    if not rules or not all(isinstance(r, str) for r in rules):
        raise RuleError("'correlation.rules' precisa listar o nome (ou id) das regras de base")
    group = raw.get("group-by", raw.get("group_by", []))
    group = [group] if isinstance(group, str) else list(group or [])
    cond = raw.get("condition")
    if not isinstance(cond, dict):
        raise RuleError("'correlation.condition' deve ser um mapa, como {gte: 10}")
    ops = [k for k in cond if k in _OPS]
    if len(ops) != 1:
        raise RuleError("'correlation.condition' precisa de exatamente um de: gte, gt, lte, lt, eq")
    try:
        threshold = float(cond[ops[0]])
    except (TypeError, ValueError):
        raise RuleError("o limite da condição de correlação deve ser um número") from None
    vfield = cond.get("field")
    if ctype == "value_count" and not vfield:
        raise RuleError("value_count precisa de 'field' em 'condition' (o campo cujos valores distintos serão contados)")
    return Correlation(ctype, rules, group, parse_timespan(raw.get("timespan")), ops[0], threshold, vfield, bool(raw.get("generate", False)))


def compare_op(op: str, value: float, threshold: float) -> bool:
    return {"gte": value >= threshold, "gt": value > threshold, "lte": value <= threshold, "lt": value < threshold, "eq": value == threshold}[op]


# ---- regra --------------------------------------------------------------------------------------------------------------------------
@dataclass
class Rule:
    path: str
    raw: Dict[str, Any]
    title: str
    id: str
    name: str
    status: str
    description: str
    author: str
    date: str
    level: str
    tags: List[str]
    logsource: Dict[str, str]
    falsepositives: List[str]
    detection: Optional[Detection]
    correlation: Optional[Correlation]
    tests: Dict[str, List[Dict[str, Any]]]

    @property
    def kind(self) -> str:
        return "correlation" if self.correlation else "detection"

    def keys(self) -> List[str]:
        return [k.lower() for k in (self.name, self.id, self.title) if k]


def _as_list(v: Any) -> List[Any]:
    return [] if v is None else (v if isinstance(v, list) else [v])


def build_rule(doc: Any, path: str = "") -> Rule:
    if not isinstance(doc, dict):
        raise RuleError("o arquivo de regra deve ser um mapa (chave: valor)")
    tests_raw = doc.get("x_tests") or doc.get("x-tests") or {}
    if tests_raw and not isinstance(tests_raw, dict):
        raise RuleError("'x_tests' deve ser um mapa com 'positive' e 'negative'")
    tests = {"positive": _as_list(tests_raw.get("positive")), "negative": _as_list(tests_raw.get("negative"))}
    for kind, items in tests.items():
        if not all(isinstance(i, dict) for i in items):
            raise RuleError(f"cada item de x_tests.{kind} deve ser um mapa (um evento)")
    if "detection" in doc and "correlation" in doc:
        raise RuleError("uma regra não pode ter 'detection' e 'correlation' ao mesmo tempo")
    if "detection" not in doc and "correlation" not in doc:
        raise RuleError("a regra precisa de 'detection' ou de 'correlation'")
    detection = compile_detection(doc["detection"]) if "detection" in doc else None
    correlation = compile_correlation(doc["correlation"]) if "correlation" in doc else None
    logsource = doc.get("logsource") or {}
    if not isinstance(logsource, dict):
        raise RuleError("'logsource' deve ser um mapa")
    return Rule(path=path, raw=doc, title=str(doc.get("title") or "").strip(), id=str(doc.get("id") or "").strip(), name=str(doc.get("name") or "").strip(),
                status=str(doc.get("status") or "").strip().lower(), description=str(doc.get("description") or "").strip(), author=str(doc.get("author") or "").strip(),
                date=str(doc.get("date") or "").strip(), level=str(doc.get("level") or "").strip().lower(), tags=[str(t) for t in _as_list(doc.get("tags"))],
                logsource={str(k): str(v) for k, v in logsource.items()}, falsepositives=[str(f) for f in _as_list(doc.get("falsepositives"))],
                detection=detection, correlation=correlation, tests=tests)


def load_rule_text(text: str, path: str = "") -> List[Rule]:
    """Um arquivo pode ter vários documentos (ex.: regra-base e regra de correlação separadas por ---)."""
    try:
        docs = yamlite.load_all(text)
    except yamlite.YamlError as exc:
        raise RuleError(f"YAML inválido: {exc}") from None
    if not docs:
        raise RuleError("arquivo vazio")
    return [build_rule(d, path) for d in docs]


def valid_uuid(text: str) -> bool:
    try:
        return str(uuid.UUID(text)) == text.lower()
    except ValueError:
        return False


def logsource_matches(rule: Rule, ctx: Dict[str, str]) -> bool:
    """Sem contexto, a regra vale para todos os eventos. Com contexto, cada chave da regra que o contexto também informa deve coincidir."""
    for k in ("category", "product", "service"):
        if k in rule.logsource and k in ctx and rule.logsource[k].lower() != ctx[k].lower():
            return False
    return True
