import base64
import contextlib
import csv
import io
import json
import os
import re
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from ruleforge import attack as attack_mod, engine, lint, report, sigma, yamlite  # noqa: E402
from ruleforge.attack import Attack  # noqa: E402
from ruleforge.cli import main  # noqa: E402
from ruleforge.explain import explain  # noqa: E402
from ruleforge.ruleset import load_path  # noqa: E402

ATK = Attack()
RULES_DIR = os.path.join(ROOT, "rules")
SAMPLES = os.path.join(ROOT, "samples")


def R(det, cond=None, **extra):
    """Regra mínima a partir de um dicionário de seleções. Sem condição, usa a única seleção (ou 'selection')."""
    cond = cond if cond is not None else (next(iter(det)) if len(det) == 1 else "selection")
    doc = {"title": "t", "logsource": {"product": "windows"}, "detection": {**det, "condition": cond}}
    doc.update(extra)
    return sigma.build_rule(doc)


def H(rule, event, fm=None):
    return rule.detection.match(sigma.EventView(event), fm or {})[0]


def rule_from_yaml(text):
    return sigma.load_rule_text(text)[0]


def write(directory, name, text):
    path = os.path.join(directory, name)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)
    return path


GOOD = """title: Regra boa
id: 11111111-2222-4333-8444-555555555555
status: stable
description: Detecta algo.
references:
    - https://exemplo.invalid/ref
author: Teste
date: 2026/10/23
tags:
    - attack.execution
    - attack.t1059.001
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\\x.exe'
    condition: selection
falsepositives:
    - Nenhum conhecido
level: medium
x_tests:
    positive:
        - {Image: 'C:\\a\\x.exe'}
    negative:
        - {Image: 'C:\\a\\y.exe'}
"""


class YamlTests(unittest.TestCase):
    def test_scalars(self):
        d = yamlite.load("a: 1\nb: 1.5\nc: true\nd: null\ne: ~\nf: texto\ng: '4688'\nh: 0x1F\ni: 0123\nj: \"x\\ty\"\nk:\n")
        self.assertEqual(d, {"a": 1, "b": 1.5, "c": True, "d": None, "e": None, "f": "texto", "g": "4688", "h": 31, "i": "0123", "j": "x\ty", "k": None})

    def test_windows_paths_stay_literal_in_single_quotes(self):
        self.assertEqual(yamlite.load("p: 'C:\\Windows\\System32\\cmd.exe'\n")["p"], "C:\\Windows\\System32\\cmd.exe")
        self.assertEqual(yamlite.load("p: 'it''s'\n")["p"], "it's")

    def test_comments(self):
        d = yamlite.load("a: 1 # comentário\n# linha inteira\nb: 'x # não é comentário'\nc: \"y#z\"\n")
        self.assertEqual(d, {"a": 1, "b": "x # não é comentário", "c": "y#z"})

    def test_block_scalars(self):
        d = yamlite.load("lit: |\n  um\n\n  dois\nfold: >-\n  dobra\n  aqui\nkeep: |-\n  sem quebra final\nnext: 1\n")
        self.assertEqual(d["lit"], "um\n\ndois\n")
        self.assertEqual(d["fold"], "dobra aqui")
        self.assertEqual(d["keep"], "sem quebra final")
        self.assertEqual(d["next"], 1)

    def test_sequences_and_nesting(self):
        d = yamlite.load("tags:\n- a\n- b\nsel:\n    k|contains:\n        - x\n        - 'y: z'\nitems:\n    - n: 1\n      m: 2\n    - n: 3\n")
        self.assertEqual(d["tags"], ["a", "b"])                                    # lista na mesma indentação da chave
        self.assertEqual(d["sel"]["k|contains"], ["x", "y: z"])
        self.assertEqual(d["items"], [{"n": 1, "m": 2}, {"n": 3}])

    def test_flow_collections(self):
        d = yamlite.load("a: [1, 'dois, três', {k: v}]\nb: {x: [1, 2], y: 'C:\\a\\b'}\nc: []\nd: {}\n")
        self.assertEqual(d, {"a": [1, "dois, três", {"k": "v"}], "b": {"x": [1, 2], "y": "C:\\a\\b"}, "c": [], "d": {}})

    def test_multiline_values(self):
        self.assertEqual(yamlite.load("d: Texto que\n    continua aqui\nk: 1\n"), {"d": "Texto que continua aqui", "k": 1})
        self.assertEqual(yamlite.load("d: 'aberto\n   e fechado'\n")["d"], "aberto e fechado")

    def test_multiple_documents_and_bom(self):
        self.assertEqual(yamlite.load_all("\ufeffa: 1\n---\nb: 2\n---\n# vazio\n---\nc: 3\n"), [{"a": 1}, {"b": 2}, {"c": 3}])

    def test_quoted_keys_and_colons_in_values(self):
        self.assertEqual(yamlite.load("'a b': 1\n\"c: d\": 2\nurl: http://x.invalid/a:b\n"), {"a b": 1, "c: d": 2, "url": "http://x.invalid/a:b"})

    def test_refuses_what_it_does_not_understand(self):
        cases = {"a: &x 1": "âncoras", "a: *x": "âncoras", "a: !!python/object:os.system x": "etiquetas", "\ta: 1": "tabulação", "a: [1, 2": "fechado",
                 "a:\n  b: 1\n  b: 2": "repetida", "a: 'abc": "fechado", 'a: "x\\q"': "escape", "a: 'x' y'": "aspa", "? chave": "complexas", "just text": "chave"}
        for text, needle in cases.items():
            with self.assertRaises(yamlite.YamlError, msg=text) as ctx:
                yamlite.load(text)
            self.assertIn(needle, str(ctx.exception).lower(), text)

    def test_errors_report_the_line(self):
        with self.assertRaises(yamlite.YamlError) as ctx:
            yamlite.load("a: 1\nb: 2\nc: &x 3\n")
        self.assertEqual(ctx.exception.line, 3)

    def test_limits(self):
        with self.assertRaises(yamlite.YamlError):
            yamlite.load("a: " + "x" * (yamlite.MAX_BYTES + 10))
        deep = "".join("  " * i + f"k{i}:\n" for i in range(60)) + "  " * 60 + "v: 1\n"
        with self.assertRaises(yamlite.YamlError):
            yamlite.load(deep)
        with self.assertRaises(yamlite.YamlError):
            yamlite.load("a: " + "[" * 60 + "]" * 60)

    def test_empty_file(self):
        with self.assertRaises(yamlite.YamlError):
            yamlite.load("# só comentário\n\n")


class MatchTests(unittest.TestCase):
    def test_condition_precedence_and_grouping(self):
        det = {"a": {"A": 1}, "b": {"B": 1}, "c": {"C": 1}}
        r = R(det, "a or b and c")                                         # and vale mais que or
        self.assertTrue(H(r, {"A": 1}))
        self.assertFalse(H(r, {"B": 1}))
        self.assertTrue(H(r, {"B": 1, "C": 1}))
        r = R(det, "(a or b) and c")
        self.assertFalse(H(r, {"A": 1}))
        self.assertTrue(H(r, {"A": 1, "C": 1}))
        r = R(det, "not (a or b)")
        self.assertTrue(H(r, {"X": 1}))
        self.assertFalse(H(r, {"B": 1}))
        self.assertTrue(H(R(det, "a and not b"), {"A": 1}))
        self.assertFalse(H(R(det, "a and not b"), {"A": 1, "B": 1}))

    def test_quantifiers(self):
        det = {"sel_a": {"A": 1}, "sel_b": {"B": 1}, "filter_x": {"X": 1}, "_hidden": {"H": 1}}
        self.assertTrue(H(R(det, "1 of sel_*"), {"B": 1}))
        self.assertFalse(H(R(det, "all of sel_*"), {"B": 1}))
        self.assertTrue(H(R(det, "all of sel_*"), {"A": 1, "B": 1}))
        self.assertTrue(H(R(det, "2 of sel_*"), {"A": 1, "B": 1}))
        self.assertFalse(H(R(det, "2 of sel_*"), {"A": 1}))
        self.assertTrue(H(R(det, "1 of them and not filter_x"), {"A": 1}))
        self.assertFalse(H(R(det, "1 of them and not filter_x"), {"A": 1, "X": 1}))
        self.assertTrue(H(R(det, "all of them"), {"A": 1, "B": 1, "X": 1}))                  # '_hidden' fica fora de 'them'
        self.assertFalse(H(R(det, "all of them"), {"A": 1, "B": 1}))                         # falta a 'filter_x'


    def test_them_ignores_selections_starting_with_underscore(self):
        det = {"a": {"A": 1}, "_ignorada": {"Z": 1}}
        self.assertTrue(H(R(det, "all of them"), {"A": 1}))

    def test_selection_shapes(self):
        r = R({"selection": [{"A": 1}, {"B": 2, "C": 3}]})                        # lista de mapas = OU
        self.assertTrue(H(r, {"A": 1}))
        self.assertTrue(H(r, {"B": 2, "C": 3}))
        self.assertFalse(H(r, {"B": 2}))
        r = R({"selection": {"A": [1, 2, 3]}})                                    # lista de valores = OU
        self.assertTrue(H(r, {"A": 2}))
        self.assertFalse(H(r, {"A": 9}))

    def test_keywords_search_every_field(self):
        r = R({"selection": ["mimikatz", "sekurlsa::*"]})
        self.assertTrue(H(r, {"msg": "rodou Sekurlsa::logonpasswords"}))
        self.assertTrue(H(r, {"a": {"b": "MIMIKATZ.exe"}}))
        self.assertFalse(H(r, {"msg": "nada"}))

    def test_case_insensitive_by_default_and_regex_is_case_sensitive(self):
        self.assertTrue(H(R({"selection": {"Image|endswith": "\\CMD.exe"}}), {"Image": "c:\\windows\\cmd.EXE"}))
        r = R({"selection": {"A|re": "^Abc$"}})
        self.assertTrue(H(r, {"A": "Abc"}))
        self.assertFalse(H(r, {"A": "abc"}))
        self.assertTrue(H(R({"selection": {"A|re|i": "^abc$"}}), {"A": "ABC"}))

    def test_string_modifiers(self):
        self.assertTrue(H(R({"selection": {"A|contains|all": ["x", "y"]}}), {"A": "..x..y.."}))
        self.assertFalse(H(R({"selection": {"A|contains|all": ["x", "y"]}}), {"A": "..x.."}))
        self.assertTrue(H(R({"selection": {"A|startswith": "ab"}}), {"A": "ABc"}))
        self.assertFalse(H(R({"selection": {"A|startswith": "ab"}}), {"A": "cab"}))
        self.assertTrue(H(R({"selection": {"A": "exato"}}), {"A": "EXATO"}))
        self.assertFalse(H(R({"selection": {"A": "exato"}}), {"A": "exato "}))

    def test_wildcards_and_the_backslash_pitfall(self):
        self.assertTrue(H(R({"selection": {"A": "a*c?e"}}), {"A": "abbbcde"}))
        self.assertFalse(H(R({"selection": {"A": "a*c?e"}}), {"A": "ace"}))
        # barra + curinga: escreve-se DUAS barras antes do asterisco
        r = R({"selection": {"I|startswith": "C:\\Users\\\\*\\AppData\\"}})
        self.assertTrue(H(r, {"I": "c:\\users\\ana\\appdata\\x.exe"}))
        self.assertFalse(H(r, {"I": "c:\\windows\\x.exe"}))
        # a pegadinha: UMA barra antes do asterisco o escapa (texto literal), e a barra é consumida
        r = R({"selection": {"I|contains": "a\\*b"}})
        self.assertTrue(H(r, {"I": "xa*by"}))
        self.assertFalse(H(r, {"I": "xaXXby"}))
        self.assertTrue(H(R({"selection": {"M": "tudo?"}}), {"M": "tudo!"}))

    def test_null_and_exists(self):
        r = R({"selection": {"E": None}})
        self.assertTrue(H(r, {"x": 1}))
        self.assertTrue(H(r, {"E": ""}))
        self.assertTrue(H(r, {"E": None}))
        self.assertFalse(H(r, {"E": "a"}))
        r = R({"selection": {"E|exists": True}})
        self.assertTrue(H(r, {"E": 0}))
        self.assertFalse(H(r, {"x": 1}))
        self.assertTrue(H(R({"selection": {"E|exists": False}}), {"x": 1}))

    def test_numbers_and_comparisons(self):
        r = R({"selection": {"EventID": 4625, "Count|gte": 5, "Score|lt": 0.5}})
        self.assertTrue(H(r, {"EventID": "4625", "Count": "7", "Score": 0.1}))
        self.assertFalse(H(r, {"EventID": 4625, "Count": 4, "Score": 0.1}))
        self.assertFalse(H(r, {"EventID": 4625, "Count": "muitos", "Score": 0.1}))        # não numérico: não casa
        self.assertTrue(H(R({"selection": {"N|gt": 1, "M|lte": 3}}), {"N": 2, "M": 3}))

    def test_cidr(self):
        r = R({"selection": {"Ip|cidr": ["10.0.0.0/8", "192.168.0.0/16", "2001:db8::/32"]}})
        for ip in ("10.4.5.6", "192.168.1.1", "2001:db8::1"):
            self.assertTrue(H(r, {"Ip": ip}), ip)
        for ip in ("8.8.8.8", "lixo", ""):
            self.assertFalse(H(r, {"Ip": ip}), ip)

    def test_windash(self):
        r = R({"selection": {"C|windash|contains": " -enc "}})
        for dash in ("-", "/", "\u2013", "\u2014", "\u2015"):
            self.assertTrue(H(r, {"C": f"ps {dash}enc x"}), dash)
        self.assertFalse(H(r, {"C": "ps enc x"}))

    def test_base64_modifiers(self):
        enc = lambda t, wide=False: base64.b64encode(t.encode("utf-16-le" if wide else "utf-8")).decode()  # noqa: E731
        self.assertTrue(H(R({"selection": {"C|base64": "whoami"}}), {"C": enc("whoami")}))
        for payload, wide in (("whoami /all", True), ("IEX (New-Object Net.WebClient)", True), ("cmd /c calc", False)):
            mods = "wide|base64offset|contains" if wide else "base64offset|contains"
            r = R({"selection": {f"C|{mods}": payload}})
            raw = payload.encode("utf-16-le" if wide else "utf-8")
            for shift in range(3):                                                 # o texto pode cair em qualquer um dos 3 alinhamentos do base64...
                for tail in (b"", b"A", b"QQ", b"depois do texto"):                # ...e pode vir ou não seguido de outros dados (a cauda também importa)
                    blob = base64.b64encode(b"z" * shift + raw + tail).decode()
                    self.assertTrue(H(r, {"C": "powershell -e " + blob}), (payload, shift, tail))
        self.assertFalse(H(R({"selection": {"C|wide|base64offset|contains": "whoami /all"}}), {"C": base64.b64encode("outra coisa qualquer".encode("utf-16-le")).decode()}))
        self.assertFalse(H(R({"selection": {"C|base64offset|contains": "whoami"}}), {"C": "d2hvYW1pIC9hbGw="[::-1]}))

    def test_base64_matching_is_case_sensitive(self):
        """Base64 diferencia maiúsculas: trocar a caixa das letras muda os dados. Comparar sem diferenciar geraria falsos positivos."""
        blob = base64.b64encode("whoami /all".encode("utf-16-le")).decode()
        r = R({"selection": {"C|wide|base64offset|contains": "whoami /all"}})
        self.assertTrue(H(r, {"C": blob}))
        self.assertFalse(H(r, {"C": blob.swapcase()}))
        self.assertFalse(H(R({"selection": {"C|base64": "whoami"}}), {"C": base64.b64encode(b"whoami").decode().swapcase()}))
        self.assertTrue(H(R({"selection": {"C|contains": "WhoAmI"}}), {"C": "x whoami y"}))               # o resto continua sem diferenciar

    def test_nested_fields_lists_and_case_insensitive_names(self):
        self.assertTrue(H(R({"selection": {"process.name": "cmd.exe", "tags": "alerta"}}), {"process": {"name": "CMD.EXE"}, "tags": ["x", "alerta"]}))
        self.assertTrue(H(R({"selection": {"image": "x"}}), {"Image": "X"}))                  # nome de campo sem diferenciar maiúsculas
        self.assertTrue(H(R({"selection": {"u.n": "a"}}), {"u": [{"n": "a"}, {"n": "b"}]}))     # lista de objetos
        self.assertFalse(H(R({"selection": {"A": "x"}}), {"B": "x"}))

    def test_field_map(self):
        r = R({"selection": {"Image|endswith": "\\a.exe"}})
        self.assertTrue(H(r, {"process.executable": "C:\\a.exe"}, {"Image": ["process.executable"]}))
        self.assertTrue(H(r, {"exe2": "C:\\a.exe"}, {"Image": ["exe1", "exe2"]}))
        self.assertFalse(H(r, {"process.executable": "C:\\a.exe"}))

    def test_evidence_lists_only_fields_of_selections_that_support_the_alert(self):
        r = R({"selection": {"A": 1}, "filter": {"B": 2}, "other": {"C": 3}}, "selection and not filter")
        ok, used = r.detection.match(sigma.EventView({"A": 1, "C": 3}))
        self.assertEqual((ok, used), (True, ["A"]))
        r = R({"selection": {"A": 1}, "filter": {"B": 2}}, "selection and not filter")
        self.assertEqual(r.detection.match(sigma.EventView({"A": 1, "B": 2}))[0], False)

    def test_values_are_truncated_before_matching(self):
        r = R({"selection": {"A|contains": "NEEDLE"}})
        self.assertFalse(H(r, {"A": "x" * (sigma.MAX_VALUE_LEN + 100) + "NEEDLE"}))
        self.assertTrue(H(r, {"A": "NEEDLE" + "x" * (sigma.MAX_VALUE_LEN + 100)}))

    def test_refuses_what_it_does_not_support_or_cannot_trust(self):
        bad = [({"s": {"A|re": "(a+)+$"}}, "s", "travamento"), ({"s": {"A|re": "x" * 1001}}, "s", "grande demais"), ({"s": {"A|re": "(unclosed"}}, "s", "inválida"),
               ({"s": {"A": 1}}, "s | count() > 5", "agregações"), ({"s": {"A": 1}}, "s and x", "não foi definida"), ({"s": {"A": 1}}, "1 of z*", "nenhuma seleção"),
               ({"s": {"A|xyz": 1}}, "s", "desconhecido"), ({"s": {"A|fieldref": "B"}}, "s", "não é suportado"), ({"s": {"A": 1}}, "(s", "parêntese"),
               ({"s": {"A": 1}}, "s)", "condição inválida"), ({"s": {"A": "a*b*c*d*e*f*g*h*i*j"}}, "s", "curingas demais"), ({"s": {}}, "s", "vazia"),
               ({"s": {"A": 1}}, "s and and", "reservada"), ({"s": {"A": 1}}, "", "vazia"), ({"s": {"A": 1}}, "s or", "termina"),
               ({"s": {"A|contains|startswith": "x"}}, "s", "incompatíveis"), ({"s": {"A|cidr": "não é rede"}}, "s", "rede inválida"),
               ({"s": {"A|gte": "texto"}}, "s", "número"), ({"s": {"A|exists": "talvez"}}, "s", "true ou false"), ({"s": {"A|base64": "a*b"}}, "s", "curingas"),
               ({"s": {"A|wide|contains": "x"}}, "s", "base64"), ({"s": ["a", {"B": 1}]}, "s", "mistura"), ({"s": {"A": {"x": 1}}}, "s", "mapa")]
        for det, cond, needle in bad:
            with self.assertRaises(sigma.RuleError, msg=f"{det} {cond}") as ctx:
                R(det, cond)
            self.assertIn(needle, str(ctx.exception).lower(), f"{det} {cond}")

    def test_rule_structure_errors(self):
        for doc, needle in (({"title": "x"}, "detection"), ("texto", "mapa"), ({"detection": {"s": {"A": 1}, "condition": "s"}, "correlation": {}}, "ao mesmo tempo"),
                            ({"title": "x", "detection": {"s": {"A": 1}}}, "condition"), ({"title": "x", "detection": {"condition": "s"}}, "nenhuma seleção"),
                            ({"title": "x", "detection": {"s": {"A": 1}, "condition": "s", "timeframe": "5m"}}, "timeframe"),
                            ({"title": "x", "detection": {"s": {"A": 1}, "condition": ["a", "b"]}}, "várias condições")):
            with self.assertRaises(sigma.RuleError, msg=str(doc)) as ctx:
                sigma.build_rule(doc)
            self.assertIn(needle, str(ctx.exception).lower())


class CorrelationParsingTests(unittest.TestCase):
    def test_valid_and_invalid(self):
        c = sigma.compile_correlation({"type": "event_count", "rules": "base", "group-by": "ip", "timespan": "5m", "condition": {"gte": 10}})
        self.assertEqual((c.type, c.rules, c.group_by, c.timespan, c.op, c.threshold, c.generate), ("event_count", ["base"], ["ip"], 300, "gte", 10.0, False))
        self.assertEqual(sigma.parse_timespan("2h"), 7200)
        self.assertEqual(sigma.parse_timespan("1d"), 86400)
        for bad in ("0m", "5", "m", "5 minutos", ""):
            with self.assertRaises(sigma.RuleError):
                sigma.parse_timespan(bad)
        for corr, needle in (({"type": "temporal"}, "não suportado"), ({"type": "event_count", "rules": [], "timespan": "1m", "condition": {"gte": 1}}, "rules"),
                             ({"type": "event_count", "rules": ["a"], "timespan": "1m", "condition": 5}, "mapa"),
                             ({"type": "event_count", "rules": ["a"], "timespan": "1m", "condition": {"gte": 1, "lt": 3}}, "exatamente um"),
                             ({"type": "event_count", "rules": ["a"], "timespan": "1m", "condition": {"gte": "x"}}, "número"),
                             ({"type": "value_count", "rules": ["a"], "timespan": "1m", "condition": {"gte": 3}}, "field")):
            with self.assertRaises(sigma.RuleError) as ctx:
                sigma.compile_correlation(corr)
            self.assertIn(needle, str(ctx.exception).lower())


class LoaderTests(unittest.TestCase):
    def test_directory_with_one_bad_file(self):
        with tempfile.TemporaryDirectory() as d:
            write(d, "ok1.yml", GOOD)
            write(d, "sub/ok2.yaml", GOOD.replace("11111111-2222-4333-8444-555555555555", "99999999-2222-4333-8444-555555555555").replace("Regra boa", "Regra dois"))
            write(d, "quebrada.yml", "title: x\ndetection:\n  s: &a 1\n")
            write(d, "leia-me.txt", "não é regra")
            rs = load_path(d)
            self.assertEqual((len(rs.rules), len(rs.errors), rs.files), (2, 1, 3))
            self.assertIn("quebrada.yml", rs.errors[0][0])
            self.assertIn("YAML inválido", rs.errors[0][1])

    def test_json_rules_and_multi_document_files(self):
        with tempfile.TemporaryDirectory() as d:
            write(d, "a.json", json.dumps({"title": "J", "logsource": {"product": "x"}, "detection": {"s": {"A": 1}, "condition": "s"}}))
            write(d, "b.yml", GOOD + "---\n" + GOOD.replace("Regra boa", "Regra dois").replace("11111111", "22222222"))
            rs = load_path(d)
            self.assertEqual(sorted(r.title for r in rs.rules), ["J", "Regra boa", "Regra dois"])

    def test_find_by_title_id_name_or_file(self):
        rs = load_path(RULES_DIR)
        self.assertIsNotNone(rs.find("win_failed_logon"))
        self.assertIsNotNone(rs.find("PowerShell com comando codificado"))
        self.assertIsNotNone(rs.find("powershell_com_comando_codificado.yml"))
        self.assertIsNone(rs.find("nao-existe"))

    def test_missing_path(self):
        with self.assertRaises(FileNotFoundError):
            load_path("/nao/existe")


class LintTests(unittest.TestCase):
    def codes(self, text, atk=ATK):
        rs = load_path(self._dir(text))
        return {i.code for i in lint.lint_ruleset(rs, atk)}

    def _dir(self, text, name="r.yml"):
        d = tempfile.mkdtemp()
        write(d, name, text)
        return d

    def test_clean_rule_has_no_errors_or_warnings(self):
        rs = load_path(self._dir(GOOD))
        self.assertEqual([i for i in lint.lint_ruleset(rs, ATK) if i.severity != "info"], [])

    def test_missing_basics(self):
        bare = "title: x\nlogsource:\n    product: windows\ndetection:\n    selection:\n        A: 1\n    condition: selection\n"
        self.assertTrue({"W101", "W102", "W103", "W104", "W106", "W107", "W113"} <= self.codes(bare))
        no_logsource = bare.replace("logsource:\n    product: windows\n", "")
        self.assertIn("E007", self.codes(no_logsource))

    def test_invalid_values(self):
        text = GOOD.replace("11111111-2222-4333-8444-555555555555", "nao-e-uuid").replace("level: medium", "level: enorme").replace("status: stable", "status: pronta")
        self.assertTrue({"E003", "E004", "E005"} <= self.codes(text))

    def test_duplicate_ids_across_files(self):
        d = tempfile.mkdtemp()
        write(d, "a.yml", GOOD)
        write(d, "b.yml", GOOD.replace("Regra boa", "Outra"))
        self.assertIn("E002", {i.code for i in lint.lint_ruleset(load_path(d), ATK)})

    def test_attack_tag_problems(self):
        revoked = GOOD.replace("attack.t1059.001", "attack.t1070.001")
        issues = lint.lint_ruleset(load_path(self._dir(revoked)), ATK)
        w108 = next(i for i in issues if i.code == "W108")
        self.assertIn("T1685.005", w108.message)
        self.assertIn("W109", self.codes(GOOD.replace("attack.t1059.001", "attack.t9999")))
        self.assertIn("W111", self.codes(GOOD.replace("attack.execution", "attack.defense_evasion")))
        self.assertIn("W112", self.codes(GOOD.replace("attack.execution", "attack.tatica_inventada")))
        self.assertIn("W107", self.codes(GOOD.replace("    - attack.t1059.001\n", "")))

    def test_unused_selection_and_dangerous_values(self):
        unused = GOOD.replace("    condition: selection", "        Outra: x\n    extra:\n        B: 1\n    condition: selection")
        self.assertIn("W122", self.codes(unused))
        short = GOOD.replace("Image|endswith: '\\x.exe'", "Image|contains: 'ab'")
        self.assertIn("W114", self.codes(short))
        self.assertIn("W114", self.codes(GOOD.replace("Image|endswith: '\\x.exe'", "Image: '*'")))
        self.assertIn("W115", self.codes(GOOD.replace("'\\x.exe'", "'C:\\Users\\*\\x.exe'")))
        self.assertIn("W124", self.codes(GOOD.replace("Image|endswith: '\\x.exe'", "Image|re: 'x.exe$'")))

    def test_tests_coverage(self):
        no_tests = GOOD[:GOOD.index("x_tests:")]
        self.assertIn("W113", self.codes(no_tests))
        only_pos = GOOD[:GOOD.index("    negative:")]
        self.assertIn("W123", self.codes(only_pos))
        only_neg = GOOD.replace("    positive:\n        - {Image: 'C:\\a\\x.exe'}\n", "")
        self.assertIn("W123", self.codes(only_neg))

    def test_template_text_is_an_error(self):
        self.assertIn("E009", self.codes(GOOD.replace("Detecta algo.", "DESCREVA o comportamento")))

    def test_severity_depends_on_level_for_false_positives(self):
        no_fp = GOOD.replace("falsepositives:\n    - Nenhum conhecido\n", "")
        medium = {i.severity for i in lint.lint_ruleset(load_path(self._dir(no_fp)), ATK) if i.code == "W105"}
        high = {i.severity for i in lint.lint_ruleset(load_path(self._dir(no_fp.replace("level: medium", "level: high"))), ATK) if i.code == "W105"}
        self.assertEqual((medium, high), ({"info"}, {"warning"}))

    def test_correlation_must_reference_existing_rules(self):
        corr = ("title: C\nid: 33333333-2222-4333-8444-555555555555\ncorrelation:\n    type: event_count\n    rules:\n        - nao_existe\n    group-by:\n        - ip\n"
                "    timespan: 5m\n    condition:\n        gte: 3\nlevel: high\n")
        self.assertIn("E006", self.codes(corr))

    def test_broken_files_become_e001(self):
        d = tempfile.mkdtemp()
        write(d, "x.yml", "title: x\n\tbad: 1\n")
        self.assertIn("E001", {i.code for i in lint.lint_ruleset(load_path(d), ATK)})


class AttackTests(unittest.TestCase):
    def test_dataset_reflects_the_current_attack(self):
        self.assertTrue(ATK.version.startswith("20"))
        names = {t["shortname"] for t in ATK.tactics}
        self.assertTrue({"stealth", "defense-impairment"} <= names)
        self.assertNotIn("defense-evasion", names)                                        # a tática foi dividida
        self.assertGreater(len([t for t in ATK.techniques.values() if not t["sub"]]), 200)
        self.assertIn("MITRE", ATK.notice)
        self.assertIn("will not guarantee full defensive coverage", ATK.disclaimer)

    def test_revoked_ids_map_to_active_techniques(self):
        self.assertEqual(ATK.status("T1070.001"), "revoked")
        self.assertEqual(ATK.current("T1070.001"), "T1685.005")
        self.assertEqual(ATK.current("T1562.001"), "T1685")
        self.assertEqual(ATK.current("t1059.001"), "T1059.001")
        self.assertIsNone(ATK.current("T9999"))
        self.assertEqual(ATK.status("T9999"), "unknown")
        self.assertTrue(ATK.revoked)
        for old, info in ATK.revoked.items():
            self.assertIn(info["to"], ATK.techniques, f"{old} aponta para um ID que não está ativo")
        self.assertEqual(ATK.tactics_of("T1070.001"), ["defense-impairment"])

    def test_parse_tags(self):
        info = ATK.parse_tags(["attack.execution", "attack.T1059.001", "attack.defense_evasion", "attack.defense-impairment", "attack.g0016", "attack.s0002",
                               "cve.2024-1234", "attack.inventada", "attack.t1059.001"])
        self.assertEqual(info.techniques, ["T1059.001"])
        self.assertEqual(info.tactics, ["execution", "defense-evasion", "defense-impairment"])
        self.assertEqual(info.other, ["attack.g0016", "attack.s0002", "cve.2024-1234"])
        self.assertEqual(info.unknown, ["attack.inventada"])

    def test_rule_techniques_use_current_ids_without_duplicates(self):
        self.assertEqual(ATK.rule_techniques(["attack.t1070.001", "attack.t1685.005", "attack.t9999", "attack.t1059.001"]), ["T1685.005", "T1059.001"])

    def test_migration(self):
        moves = ATK.migration(["attack.t1070.001", "attack.T1562.001", "attack.t1059.001", "attack.execution"])
        self.assertEqual([(o, n) for o, n, _ in moves], [("attack.t1070.001", "attack.t1685.005"), ("attack.T1562.001", "attack.t1685")])
        self.assertIn("revogada", moves[0][2])

    def test_coverage_counts_parents_and_uses_current_ids(self):
        rules = [R({"s": {"A": 1}}, tags=["attack.t1059.001"]), R({"s": {"A": 1}}, tags=["attack.t1070.001"]), R({"s": {"A": 1}}, tags=["attack.execution"])]
        cov = ATK.coverage(rules)
        self.assertEqual(cov["covered_techniques"], 2)                                    # T1059 (pela subtécnica) e T1685 (pela subtécnica revogada)
        self.assertEqual(cov["rules_with_attack"], 2)
        self.assertEqual(cov["rules_total"], 3)
        self.assertIn("T1685.005", cov["by_technique"])
        self.assertNotIn("T1070.001", cov["by_technique"])
        execution = next(t for t in cov["per_tactic"] if t["tactic"] == "execution")
        self.assertIn("T1059", execution["covered_ids"])
        self.assertAlmostEqual(cov["percent"], round(100 * 2 / cov["total_techniques"], 1))

    def test_navigator_layer(self):
        rules = [R({"s": {"A": 1}}, title="A", tags=["attack.t1059.001"]), R({"s": {"A": 1}}, title="B", tags=["attack.t1059.001"]), R({"s": {"A": 1}}, title="C", tags=["attack.t1070.001"])]
        layer = ATK.layer(rules, name="Teste")
        self.assertEqual(layer["domain"], "enterprise-attack")
        self.assertEqual(layer["versions"]["attack"], "20")
        self.assertEqual(layer["versions"]["layer"], "4.5")
        scores = {t["techniqueID"]: t["score"] for t in layer["techniques"]}
        self.assertEqual(scores, {"T1059.001": 2, "T1685.005": 1})
        self.assertEqual(layer["gradient"]["maxValue"], 2)
        json.dumps(layer)

    def test_shipped_rules_use_only_current_active_ids(self):
        for r in load_path(RULES_DIR).rules:
            info = ATK.parse_tags(r.tags)
            self.assertTrue(info.techniques, r.title)
            for tid in info.techniques:
                self.assertEqual(ATK.status(tid), "active", f"{r.title}: {tid}")
            self.assertFalse(info.unknown, r.title)
            self.assertFalse([t for t in info.tactics if t not in ATK.tactic_names], f"{r.title}: tática antiga")


class EventReadingTests(unittest.TestCase):
    def read(self, name, text, **kw):
        d = tempfile.mkdtemp()
        path = write(d, name, text)
        bad = []
        return list(engine.read_events(path, bad)), bad

    def test_jsonl_with_bad_lines(self):
        events, bad = self.read("a.jsonl", '\ufeff{"a": 1}\n\nnão é json\n[1, 2]\n{"b": 2}\n')
        self.assertEqual([(n, e) for n, e in events], [(1, {"a": 1}), (5, {"b": 2})])
        self.assertEqual([(b[1], b[2]) for b in bad], [(3, "não é JSON válido"), (4, "a linha não é um objeto JSON")])

    def test_json_array_and_csv(self):
        events, bad = self.read("a.json", '[{"a": 1}, 5, {"b": 2}]')
        self.assertEqual(len(events), 2)
        self.assertEqual(len(bad), 1)
        events, bad = self.read("a.csv", "host;EventID\nPC1;4625\nPC2;4624\n")
        self.assertEqual([e for _, e in events], [{"host": "PC1", "EventID": "4625"}, {"host": "PC2", "EventID": "4624"}])
        events, _ = self.read("b.csv", "host,EventID\nPC1,4625\n")
        self.assertEqual(events[0][1]["EventID"], "4625")
        _, bad = self.read("c.json", "[{ quebrado")
        self.assertIn("JSON inválido", bad[0][2])

    def test_oversized_line_is_skipped(self):
        events, bad = self.read("a.jsonl", '{"a": "' + "x" * (engine.MAX_LINE + 10) + '"}\n{"b": 1}\n')
        self.assertEqual(events, [(2, {"b": 1})])
        self.assertIn("grande demais", bad[0][2])

    def test_parse_ts_formats(self):
        utc = timezone.utc
        cases = {"2026-10-22T08:00:00Z": datetime(2026, 10, 22, 8, 0, tzinfo=utc), "2026-10-22 08:00:00": datetime(2026, 10, 22, 8, 0, tzinfo=utc),
                 "2026-10-22T05:00:00-03:00": datetime(2026, 10, 22, 8, 0, tzinfo=utc), "2026-10-22 08:00:00,250": datetime(2026, 10, 22, 8, 0, 0, 250000, tzinfo=utc),
                 "22/Oct/2026:08:00:00 +0000": datetime(2026, 10, 22, 8, 0, tzinfo=utc), 1792656000: datetime(2026, 10, 22, 8, 0, tzinfo=utc),
                 1792656000000: datetime(2026, 10, 22, 8, 0, tzinfo=utc), "1792656000": datetime(2026, 10, 22, 8, 0, tzinfo=utc)}
        for raw, expected in cases.items():
            self.assertEqual(engine.parse_ts(raw), expected, raw)
        for bad in ("ontem", "", None, True, "2026-13-45"):
            self.assertIsNone(engine.parse_ts(bad), bad)

    def test_parse_source(self):
        self.assertEqual(engine.parse_source("a.jsonl"), ("a.jsonl", {}))
        self.assertEqual(engine.parse_source("a.jsonl:product=windows,category=process_creation"), ("a.jsonl", {"product": "windows", "category": "process_creation"}))
        self.assertEqual(engine.parse_source("C:\\logs\\a.jsonl:service=security"), ("C:\\logs\\a.jsonl", {"service": "security"}))
        self.assertEqual(engine.parse_source("C:\\logs\\a.jsonl"), ("C:\\logs\\a.jsonl", {}))
        self.assertEqual(engine.parse_source("a:b.jsonl"), ("a:b.jsonl", {}))


def ev(ts, **kw):
    return {"timestamp": ts, **kw}


class ScannerTests(unittest.TestCase):
    def scan(self, rules, events, ctx=None, **kw):
        sc = engine.Scanner(rules, **kw)
        for i, e in enumerate(events, 1):
            sc.feed("t", i, e, ctx)
        return sc.finish()

    def test_logsource_is_applied_per_file(self):
        win = R({"s": {"A": 1}}, title="win", logsource={"product": "windows"})
        lin = R({"s": {"A": 1}}, title="lin", logsource={"product": "linux"})
        res = self.scan([win, lin], [{"A": 1}], {"product": "linux"})
        self.assertEqual([a.rule.title for a in res.alerts], ["lin"])
        self.assertEqual([r.title for r in res.rules_skipped], ["win"])
        res = self.scan([win, lin], [{"A": 1}])                                          # sem contexto: todas as regras valem
        self.assertEqual(len(res.alerts), 2)
        res = self.scan([R({"s": {"A": 1}}, title="x", logsource={"product": "windows", "category": "process_creation"})], [{"A": 1}], {"product": "windows"})
        self.assertEqual(len(res.alerts), 1)                                             # o contexto não diz a categoria: não restringe

    def test_alerts_carry_evidence_time_and_ip(self):
        rule = R({"s": {"Image|endswith": "\\a.exe", "CommandLine|contains": "x"}}, title="r")
        res = self.scan([rule], [ev("2026-10-22T08:00:00Z", Image="C:\\a.exe", CommandLine="run x", src_ip="198.51.100.5")])
        a = res.alerts[0]
        self.assertEqual((a.evidence, a.ip, a.line), ({"Image": "C:\\a.exe", "CommandLine": "run x"}, "198.51.100.5", 1))
        self.assertEqual(a.time, datetime(2026, 10, 22, 8, 0, tzinfo=timezone.utc))

    def test_max_per_rule_counts_but_does_not_list(self):
        res = self.scan([R({"s": {"A": 1}}, title="r")], [{"A": 1}] * 10, max_per_rule=3)
        self.assertEqual((len(res.alerts), res.matches["r"], sum(res.truncated.values())), (3, 10, 7))

    def corr_rules(self, ctype="event_count", cond=None, span="5m", generate=False, group=("ip",), field="user"):
        base = R({"s": {"EventID": 4625}}, title="base", name="falha", id="")
        c = {"type": ctype, "rules": ["falha"], "group-by": list(group), "timespan": span, "condition": cond or {"gte": 3}, "generate": generate}
        if ctype == "value_count":
            c["condition"] = {**(cond or {"gte": 3}), "field": field}
        corr = sigma.build_rule({"title": "corr", "correlation": c})
        return [base, corr]

    def fails(self, n, ip="1.1.1.1", step=10, start=0, user=None):
        base = datetime(2026, 10, 22, 8, 0, 0)
        return [ev((base + timedelta(seconds=start + i * step)).strftime("%Y-%m-%dT%H:%M:%SZ"), EventID=4625, ip=ip, user=user or f"u{i}") for i in range(n)]

    def test_event_count_one_alert_per_burst_with_the_real_total(self):
        res = self.scan(self.corr_rules(), self.fails(8))
        self.assertEqual([(a.rule.title, a.count, a.group) for a in res.alerts], [("corr", 8, {"ip": "1.1.1.1"})])
        self.assertEqual(res.alerts[0].evidence["total"], "8")
        self.assertEqual(res.suppressed["base"], 8)                                      # a regra-base não gerou alerta sozinha

    def test_a_new_burst_after_silence_is_a_new_alert(self):
        events = self.fails(4) + self.fails(4, start=3600)                               # uma hora depois
        res = self.scan(self.corr_rules(), sorted(events, key=lambda e: e["timestamp"]))
        self.assertEqual([a.count for a in res.alerts], [4, 4])

    def test_events_too_far_apart_never_reach_the_threshold(self):
        res = self.scan(self.corr_rules(span="1m"), self.fails(6, step=45))              # 45 s entre eventos: no máximo 2 por minuto
        self.assertEqual(res.alerts, [])

    def test_groups_are_independent(self):
        events = sorted(self.fails(3, ip="1.1.1.1") + self.fails(2, ip="2.2.2.2"), key=lambda e: e["timestamp"])
        res = self.scan(self.corr_rules(), events)
        self.assertEqual([a.group for a in res.alerts], [{"ip": "1.1.1.1"}])

    def test_value_count_counts_distinct_values(self):
        same_user = self.fails(6, user="admin")
        self.assertEqual(self.scan(self.corr_rules("value_count"), same_user).alerts, [])
        res = self.scan(self.corr_rules("value_count"), self.fails(5))
        self.assertEqual([(a.count, a.group) for a in res.alerts], [(5, {"ip": "1.1.1.1"})])

    def test_other_operators(self):
        res = self.scan(self.corr_rules(cond={"eq": 3}), self.fails(3))
        self.assertEqual(len(res.alerts), 1)
        res = self.scan(self.corr_rules(cond={"gt": 3}), self.fails(3))
        self.assertEqual(res.alerts, [])

    def test_generate_true_keeps_the_base_alerts(self):
        res = self.scan(self.corr_rules(generate=True), self.fails(3))
        self.assertEqual(sorted(a.rule.title for a in res.alerts), ["base", "base", "base", "corr"])

    def test_events_without_time_are_reported_and_ignored(self):
        res = self.scan(self.corr_rules(), [{"EventID": 4625, "ip": "1.1.1.1", "user": f"u{i}"} for i in range(5)])
        self.assertEqual(res.alerts, [])
        self.assertTrue(any("sem data/hora" in n for n in res.notes))

    def test_custom_time_field(self):
        events = [{"quando": e["timestamp"], **{k: v for k, v in e.items() if k != "timestamp"}} for e in self.fails(4)]
        self.assertEqual(self.scan(self.corr_rules(), events).alerts, [])
        self.assertEqual(len(self.scan(self.corr_rules(), events, time_fields=["quando"]).alerts), 1)

    def test_correlation_with_unknown_base_is_noted(self):
        corr = sigma.build_rule({"title": "c", "correlation": {"type": "event_count", "rules": ["x"], "timespan": "1m", "condition": {"gte": 1}}})
        res = self.scan([corr], [{"A": 1}])
        self.assertTrue(any("'x'" in n for n in res.notes))

    def test_field_map_applies_to_detection_and_groups(self):
        events = [ev(f"2026-10-22T08:00:0{i}Z", id_evento=4625, origem="1.1.1.1", conta=f"u{i}") for i in range(3)]
        res = self.scan(self.corr_rules(), events, field_map={"EventID": "id_evento", "ip": "origem"})
        self.assertEqual([(a.count, a.group) for a in res.alerts], [(3, {"ip": "1.1.1.1"})])

    def test_min_level_filter(self):
        rules = [R({"s": {"A": 1}}, title="baixa", level="low"), R({"s": {"A": 1}}, title="alta", level="high")]
        res = self.scan(rules, [{"A": 1}])
        self.assertEqual([a.rule.title for a in engine.filter_level(res.alerts, "high")], ["alta"])
        self.assertEqual(len(engine.filter_level(res.alerts, None)), 2)


class RuleTestRunnerTests(unittest.TestCase):
    def test_positive_and_negative(self):
        rule = rule_from_yaml(GOOD)
        results = engine.run_rule_tests(rule)
        self.assertEqual([(t.kind, t.passed) for t in results], [("positive", True), ("negative", True)])

    def test_failures_say_what_went_wrong(self):
        broken = GOOD.replace("Image: 'C:\\a\\x.exe'}\n    negative", "Image: 'C:\\a\\z.exe'}\n    negative").replace("{Image: 'C:\\a\\y.exe'}", "{Image: 'C:\\a\\x.exe'}")
        results = engine.run_rule_tests(rule_from_yaml(broken))
        self.assertEqual([t.passed for t in results], [False, False])
        self.assertIn("deveria", results[0].message)
        self.assertIn("NÃO deveria", results[1].message)

    def test_correlation_tests_use_their_base_rules(self):
        rs = load_path(RULES_DIR)
        corr = rs.find("Muitas falhas de logon no Windows vindas do mesmo endereço")
        results = engine.run_rule_tests(corr, rs.rules)
        self.assertTrue(results and all(t.passed for t in results), [t.message for t in results])
        corr.tests["positive"] = [{"sem_events": 1}]
        self.assertIn("events", engine.run_rule_tests(corr, rs.rules)[0].message)

    def test_a_broken_test_does_not_stop_the_others(self):
        rule = rule_from_yaml(GOOD)
        rule.tests["positive"].append({"Image": ["isto", {"é": "estranho"}]})
        self.assertEqual(len(engine.run_rule_tests(rule)), 3)


class ShippedContentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rs = load_path(RULES_DIR)
        sources = [(os.path.join(SAMPLES, f), c) for f, c in (("windows_sysmon.jsonl", {"product": "windows"}), ("windows_security.jsonl", {"product": "windows"}),
                                                              ("linux_logs.jsonl", {"product": "linux"}), ("web_access.jsonl", {"category": "webserver"}))]
        cls.res = engine.scan_files(cls.rs.rules, sources)

    def test_the_example_ruleset_is_clean_and_tested(self):
        self.assertEqual(len(self.rs.rules), 31)
        self.assertEqual(self.rs.errors, [])
        self.assertEqual([i for i in lint.lint_ruleset(self.rs, ATK) if i.severity != "info"], [])
        results = [t for r in self.rs.rules for t in engine.run_rule_tests(r, self.rs.rules)]
        self.assertEqual((len(results), sum(t.passed for t in results)), (77, 77))
        self.assertTrue(all(r.tests["positive"] and r.tests["negative"] for r in self.rs.rules))

    def test_rule_files_use_single_backslashes(self):
        rule = self.rs.find("PowerShell com comando codificado")
        values = rule.raw["detection"]["selection"]["Image|endswith"]
        self.assertEqual(values, ["\\powershell.exe", "\\pwsh.exe"])

    def test_ids_are_unique_uuids(self):
        ids = [r.id for r in self.rs.rules]
        self.assertEqual(len(ids), len(set(ids)))
        self.assertTrue(all(sigma.valid_uuid(i) for i in ids))

    def test_demo_covers_28_detections_and_3_correlations(self):
        self.assertEqual((self.res.events, self.res.rules_run, len(self.res.bad)), (496, 28, 0))
        fired = {a.rule.title for a in self.res.alerts}
        self.assertEqual(len(fired), 29)                                                  # as 2 regras-base só alimentam as correlações
        self.assertEqual({r.title for r in self.rs.rules} - fired, {"Falha de logon no Windows", "Falha de login SSH no Linux"})
        self.assertEqual(sorted((a.count, a.group.get("IpAddress") or a.group.get("src_ip")) for a in self.res.alerts if a.kind == "correlação"),
                         [(12, "198.51.100.77"), (12, "198.51.100.77"), (14, "192.0.2.99"), (26, "203.0.113.50")])

    def test_benign_lookalikes_never_alert(self):
        benign = {"chrome.exe --type=renderer", "svchost.exe -k netsvcs", "EXCEL.EXE planilha.xlsx", "powershell.exe -File C:\\scripts\\backup.ps1", "whoami",
                  "schtasks /create /tn Setup /tr C:\\app\\s.exe", "reg query HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "net group Vendas /domain"}
        flagged = {a.evidence.get("CommandLine") for a in self.res.alerts}
        self.assertEqual(flagged & benign, set())
        web_ok = [a for a in self.res.alerts if a.source == "web_access.jsonl"]
        self.assertEqual({a.evidence.get("c-ip") or a.evidence.get("cs-user-agent") for a in web_ok} & {"Mozilla/5.0 (Windows NT 10.0; Win64; x64)"}, set())

    def test_every_planted_attack_is_detected(self):
        planted = [l for l in open(os.path.join(SAMPLES, "windows_sysmon.jsonl"), encoding="utf-8")]
        alerted_lines = {a.line for a in self.res.alerts if a.source == "windows_sysmon.jsonl"}
        malicious = {i + 1 for i, l in enumerate(planted) if any(tok in l for tok in ("-enc", "urlcache", "mshta.exe https", "comsvcs", "procdump64", "reg save", "delete shadows", "wevtutil.exe cl",
                                                                                      "Set-MpPreference", "/create /tn Atualiza", "sc.exe create", "reg add", "/add", "Domain Admins", "whoami /priv",
                                                                                      "process call create", "bitsadmin /transfer", "scrobj.dll", "w3wp.exe"))}
        self.assertEqual(len(malicious), 19)
        self.assertEqual(malicious - alerted_lines, set())

    def test_sample_logs_use_documentation_addresses_only(self):
        pat = re.compile(r"\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b")
        for name in ("windows_sysmon.jsonl", "windows_security.jsonl", "linux_logs.jsonl", "web_access.jsonl"):
            text = open(os.path.join(SAMPLES, name), encoding="utf-8").read()
            for m in pat.finditer(text):
                a, b, c, d = map(int, m.groups())
                ok = a == 10 or (a, b, c) in ((192, 0, 2), (198, 51, 100), (203, 0, 113))
                self.assertTrue(ok, f"{name}: {m.group(0)} não é privado nem de documentação")


class ReportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rs = load_path(RULES_DIR)
        sources = [(os.path.join(SAMPLES, f), c) for f, c in (("windows_sysmon.jsonl", {"product": "windows"}), ("windows_security.jsonl", {"product": "windows"}),
                                                              ("linux_logs.jsonl", {"product": "linux"}), ("web_access.jsonl", {"category": "webserver"}))]
        cls.res = engine.scan_files(cls.rs.rules, sources)
        cls.cov = ATK.coverage(cls.rs.rules)

    def test_text_report(self):
        text = report.render_scan(self.res, self.rs.rules, ATK)
        for expected in ("VARREDURA DE DETECÇÃO", "496 evento(s)", "[Crítico]", "T1685.005 Clear Windows Event Logs", "hipóteses para o analista"):
            self.assertIn(expected, text)

    def test_json_and_csv(self):
        data = json.loads(report.alerts_json(self.res, ATK))
        self.assertEqual((data["attack_version"], len(data["alerts"])), (ATK.version, len(self.res.alerts)))
        rows = list(csv.reader(io.StringIO(report.alerts_csv(self.res, ATK)), delimiter=";"))
        self.assertEqual(len(rows) - 1, len(self.res.alerts))
        self.assertEqual(rows[1][1], "critical")

    def test_csv_guard_never_touches_empty_values(self):
        """Regressão do bug do apóstrofo: '' in '=+-@' é True em Python."""
        self.assertEqual(report._safe(""), "")
        self.assertIsNone(report._safe(None))
        for dangerous in ("=1+1", "+1", "-1", "@SUM(A1)", "\tcmd", "\rcmd"):
            self.assertEqual(report._safe(dangerous), "'" + dangerous)

    def test_csv_neutralizes_formulas_from_logs(self):
        rule = R({"s": {"A": "x"}}, title="=HYPERLINK(\"http://x\")")
        sc = engine.Scanner([rule])
        sc.feed("=cmd.jsonl", 1, {"A": "x"})
        rows = list(csv.reader(io.StringIO(report.alerts_csv(sc.finish(), ATK)), delimiter=";"))
        self.assertEqual((rows[1][2], rows[1][5]), ("'=HYPERLINK(\"http://x\")", "'=cmd.jsonl"))

    def test_html_escapes_hostile_titles_and_log_content(self):
        rule = R({"s": {"A": "x"}}, title="<script>alert(1)</script>", tags=["attack.t1059.001"])
        sc = engine.Scanner([rule])
        sc.feed("<img src=x onerror=alert(1)>.jsonl", 1, {"A": "x", "B": "y"})
        res = sc.finish()
        doc = report.render_html(res, [rule], ATK, ATK.coverage([rule]))
        self.assertTrue("<script>alert" not in doc and "<img src=x" not in doc, "HTML sem escape")
        self.assertIn("&lt;script&gt;", doc)

    def test_html_has_coverage_and_the_mitre_notice(self):
        doc = report.render_html(self.res, self.rs.rules, ATK, self.cov)
        for expected in ("Cobertura do ATT&amp;CK", "Defense Impairment", "Stealth", "will not guarantee full defensive coverage", "The MITRE Corporation", "não é cobertura de detecção"):
            self.assertIn(expected, doc)
        self.assertNotIn("Defense Evasion", doc)

    def test_coverage_text(self):
        text = report.render_coverage(self.cov, ATK)
        self.assertIn("ATT&CK v20.0", text)
        self.assertIn("não é cobertura de detecção", text)
        self.assertIn(ATK.notice, text)

    def test_feed_has_no_log_content_and_maps_severity(self):
        events = report.to_feed(self.res, ATK)
        self.assertEqual(len(events), len(self.res.alerts))
        blob = json.dumps(events, ensure_ascii=False)
        for secret in ("CommandLine", "lsass.exe", "Senha123", "procdump64.exe -accepteula", "net1 user"):
            self.assertNotIn(secret, blob)
        self.assertTrue(all((e["source"], e["type"]) == ("ruleforge", "generic") for e in events))
        self.assertEqual({e["severity"] for e in events}, {"critical", "high", "medium", "low"})
        brute = next(e for e in events if "Força bruta de SSH" in e["message"])
        self.assertEqual((brute["ip"], "x14" in brute["message"]), ("192.0.2.99", True))

    def test_compliancemap_evidence(self):
        ok = json.loads(report.to_compliancemap(self.rs.rules, [], 77, 0, self.cov))
        self.assertEqual({r["control"]: r["status"] for r in ok["results"]}, {"MON-02": "pass", "TEC-04": "pass"})
        self.assertIn("não prova a coleta de logs reais", ok["results"][0]["detail"])
        failing = json.loads(report.to_compliancemap(self.rs.rules, [lint.Issue("error", "E001", "x")], 77, 2, self.cov))
        self.assertEqual({r["status"] for r in failing["results"]}, {"fail"})
        self.assertIn("2 de 77", failing["results"][0]["detail"])
        empty = json.loads(report.to_compliancemap([], [], 0, 0, self.cov))
        self.assertEqual({r["status"] for r in empty["results"]}, {"unknown"})
        untested = json.loads(report.to_compliancemap([R({"s": {"A": 1}})], [], 0, 0, self.cov))
        self.assertIn("sem testes", untested["results"][0]["detail"])
        for rule in self.rs.rules:
            self.assertNotIn(rule.title, json.dumps(ok, ensure_ascii=False))

    def test_issues_text(self):
        text = report.render_issues([lint.Issue("error", "E001", "quebrou", "", "a.yml"), lint.Issue("warning", "W101", "sem id", "Regra X")], 2)
        self.assertIn("ERRO", text)
        self.assertIn("aviso", text)
        self.assertIn("Nenhum problema", report.render_issues([], 1))


class ExplainTests(unittest.TestCase):
    def test_detection_rule(self):
        text = explain(rule_from_yaml(GOOD), ATK)
        for expected in ("DISPARA QUANDO", "[selection]", "o campo Image termina com '\\x.exe'", "T1059.001 PowerShell (Execution)", "FALSOS POSITIVOS"):
            self.assertIn(expected, text)

    def test_quantifiers_and_modifiers_in_plain_language(self):
        rule = R({"sel_a": {"A|contains|all": ["x", "y"], "B|re|i": "^ab"}, "sel_b": {"C|cidr": "10.0.0.0/8", "D|gte": 5, "E|exists": False, "F": None},
                  "k": ["palavra"]}, "1 of sel_* and not k", level="high")
        text = explain(rule, ATK)
        for expected in ("contém 'x' E 'y'", "expressão regular '^ab' (opções: i)", "está na rede '10.0.0.0/8'", "é maior ou igual a 5", "NÃO existe", "vazio ou ausente",
                         "qualquer campo do evento contém 'palavra'", "pelo menos 1 entre as seleções 'sel_*'", "NÃO [k]"):
            self.assertIn(expected, text)

    def test_revoked_tag_is_explained(self):
        rule = R({"s": {"A": 1}}, tags=["attack.t1070.001"])
        text = explain(rule, ATK)
        self.assertIn("REVOGADA", text)
        self.assertIn("T1685.005", text)

    def test_correlation_rule(self):
        rs = load_path(RULES_DIR)
        text = explain(rs.find("Força bruta de SSH no Linux"), ATK)
        self.assertIn("pelo menos 8 ocorrências das regras 'lnx_ssh_failed_password' em 120 s, para cada combinação de src_ip", text)


class CLITests(unittest.TestCase):
    def run_cli(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(list(argv))
        return code, out.getvalue(), err.getvalue()

    def test_validate_and_exit_codes(self):
        code, out, _ = self.run_cli("validate", "--no-color")
        self.assertEqual(code, 0)
        self.assertIn("0 erro(s) · 0 aviso(s)", out)
        d = tempfile.mkdtemp()
        write(d, "r.yml", GOOD.replace("attack.t1059.001", "attack.t1070.001"))
        self.assertEqual(self.run_cli("validate", "--rules", d)[0], 0)                      # só aviso
        self.assertEqual(self.run_cli("validate", "--rules", d, "--strict")[0], 1)          # --strict: aviso também falha
        write(d, "quebrada.yml", "title: x\n\tbad: 1\n")
        self.assertEqual(self.run_cli("validate", "--rules", d)[0], 1)

    def test_test_command(self):
        code, out, _ = self.run_cli("test")
        self.assertEqual(code, 0)
        self.assertIn("77 de 77 teste(s) passaram em 31 regra(s)", out)
        d = tempfile.mkdtemp()
        write(d, "r.yml", GOOD.replace("{Image: 'C:\\a\\y.exe'}", "{Image: 'C:\\a\\x.exe'}"))
        code, out, _ = self.run_cli("test", "--rules", d)
        self.assertEqual(code, 1)
        self.assertIn("FALHOU", out)

    def test_scan_with_every_output_and_fail_on(self):
        with tempfile.TemporaryDirectory() as d:
            paths = {k: os.path.join(d, "o." + k) for k in ("json", "csv", "html", "layer", "feed", "cm")}
            code, out, err = self.run_cli("scan", "--events", os.path.join(SAMPLES, "windows_sysmon.jsonl") + ":product=windows", "--no-color", "--json", paths["json"], "--csv", paths["csv"],
                                          "--html", paths["html"], "--layer", paths["layer"], "--feed", paths["feed"], "--compliancemap", paths["cm"], "--fail-on", "critical")
            self.assertEqual((code, err), (1, ""))
            for p in paths.values():
                self.assertGreater(os.path.getsize(p), 40, p)
            self.assertEqual(json.load(open(paths["layer"], encoding="utf-8"))["domain"], "enterprise-attack")
            self.assertEqual(self.run_cli("scan", "--events", os.path.join(SAMPLES, "web_access.jsonl") + ":category=webserver", "--no-color", "--fail-on", "critical")[0], 0)
            code, out, _ = self.run_cli("scan", "--events", os.path.join(SAMPLES, "windows_sysmon.jsonl"), "--min-level", "critical", "--no-color")
            self.assertEqual(out.count("[Crítico]"), 3)
            self.assertNotIn("[Alto]", out)

    def test_scan_field_map_and_errors(self):
        d = tempfile.mkdtemp()
        log = write(d, "l.jsonl", json.dumps({"exe": "C:\\x\\wevtutil.exe", "args": "wevtutil.exe cl Security"}) + "\n")
        fmap = write(d, "m.json", json.dumps({"Image": "exe", "CommandLine": "args"}))
        self.assertIn("Limpeza dos logs", self.run_cli("scan", "--events", log, "--field-map", fmap, "--no-color")[1])
        self.assertNotIn("Limpeza dos logs", self.run_cli("scan", "--events", log, "--no-color")[1])      # sem o mapa, os campos não existem
        self.assertEqual(self.run_cli("scan", "--events", "/nao/existe.jsonl")[0], 2)
        write(d, "lista.json", "[1, 2]")
        self.assertEqual(self.run_cli("scan", "--events", log, "--field-map", os.path.join(d, "lista.json"))[0], 2)
        self.assertEqual(self.run_cli("scan", "--rules", d + "/vazio", "--events", log)[0], 2)

    def test_demo(self):
        with tempfile.TemporaryDirectory() as d:
            html_path = os.path.join(d, "r.html")
            code, out, err = self.run_cli("demo", "--no-color", "--html", html_path, "--feed", os.path.join(d, "f.jsonl"))
            self.assertEqual((code, err), (0, ""))
            self.assertIn("32 alerta(s)", out)
            self.assertIn("FICTÍCIOS", out)
            self.assertGreater(os.path.getsize(html_path), 5000)

    def test_coverage_command(self):
        with tempfile.TemporaryDirectory() as d:
            code, out, _ = self.run_cli("coverage", "--no-color", "--html", os.path.join(d, "c.html"), "--layer", os.path.join(d, "l.json"))
            self.assertEqual(code, 0)
            self.assertIn("COBERTURA DO MITRE ATT&CK v20.0", out)
            self.assertIn("Defense Impairment", out)

    def test_explain_and_list_and_attack(self):
        self.assertIn("DISPARA QUANDO", self.run_cli("explain", os.path.join(RULES_DIR, "windows", "powershell_com_comando_codificado.yml"))[1])
        self.assertIn("DISPARA QUANDO", self.run_cli("explain", "win_failed_logon")[1])
        self.assertEqual(self.run_cli("explain", "nao-existe")[0], 2)
        code, out, _ = self.run_cli("list")
        self.assertIn("31 regra(s)", out)
        self.assertTrue(out.splitlines()[0].startswith("critical"))
        code, out, _ = self.run_cli("attack", "T1070.001")
        self.assertIn("REVOGADA", out)
        self.assertIn("T1685.005", out)
        self.assertIn("The MITRE Corporation", out)
        self.assertEqual(self.run_cli("attack", "T9999")[0], 2)
        self.assertIn("OBSOLETA", "".join(self.run_cli("attack", t)[1] for t in ATK.deprecated))

    def test_migrate_dry_run_and_write(self):
        d = tempfile.mkdtemp()
        path = write(d, "r.yml", GOOD.replace("attack.t1059.001", "attack.T1070.001"))
        code, out, _ = self.run_cli("migrate", "--rules", d)
        self.assertIn("attack.T1070.001  ->  attack.t1685.005", out)
        self.assertIn("attack.T1070.001", open(path, encoding="utf-8").read())                # sem --write, nada muda
        self.run_cli("migrate", "--rules", d, "--write")
        text = open(path, encoding="utf-8").read()
        self.assertIn("attack.t1685.005", text)
        self.assertNotIn("1070", text)
        self.assertIn("Nenhuma etiqueta", self.run_cli("migrate", "--rules", d)[1])

    def test_new_creates_a_valid_but_unfinished_rule(self):
        d = tempfile.mkdtemp()
        code, out, _ = self.run_cli("new", "--title", "Teste de regra", "--technique", "T1055", "--out", d)
        self.assertEqual(code, 0)
        path = os.path.join(d, "teste_de_regra.yml")
        text = open(path, encoding="utf-8").read()
        self.assertIn("attack.t1055", text)
        self.assertIn("attack.defense_impairment", text) if "defense-impairment" in ATK.tactics_of("T1055") else None
        self.assertIn("\\exemplo.exe", text)
        self.assertNotIn("\\\\exemplo.exe", text)                                              # barras simples no esqueleto
        rule = load_path(path).rules[0]
        self.assertTrue(sigma.valid_uuid(rule.id))
        self.assertIn("E009", {i.code for i in lint.lint_ruleset(load_path(d), ATK)})        # o esqueleto cru é recusado pelo validador
        self.assertEqual(self.run_cli("new", "--title", "Teste de regra", "--technique", "T1055", "--out", d)[0], 2)      # não sobrescreve
        code, _, err = self.run_cli("new", "--title", "x", "--technique", "T1070.001", "--out", d)
        self.assertEqual(code, 2)
        self.assertIn("T1685.005", err)
        self.assertEqual(self.run_cli("new", "--title", "x", "--technique", "T9999", "--out", d)[0], 2)

    def test_broken_pipe_is_quiet(self):
        class Closed(io.StringIO):
            def write(self, s):
                raise BrokenPipeError
        with contextlib.redirect_stdout(Closed()):
            self.assertEqual(main(["list"]), 0)

    def test_no_command_prints_help(self):
        self.assertIn("usage", self.run_cli()[1].lower())


class SafetyTests(unittest.TestCase):
    PKG = os.path.join(ROOT, "ruleforge")

    def sources(self):
        for name in sorted(os.listdir(self.PKG)):
            if name.endswith(".py"):
                with open(os.path.join(self.PKG, name), encoding="utf-8") as f:
                    yield name, f.read()

    def test_package_never_uses_the_network_or_runs_programs(self):
        net = re.compile(r"^\s*(import|from)\s+(socket|urllib|http|requests|ftplib|smtplib|ssl|asyncio|subprocess|multiprocessing|ctypes)\b", re.M)
        for name, text in self.sources():
            self.assertIsNone(net.search(text), name)

    def test_no_dynamic_code_execution_or_unsafe_deserialization(self):
        bad = re.compile(r"(?<![\w.])(eval|exec|compile)\(|\bpickle\b|\bmarshal\b|yaml\.(load|unsafe_load)|os\.system|__import__|importlib")     # 're.compile(' é permitido
        for name, text in self.sources():
            code = re.sub(r'""".*?"""', "", text, flags=re.S)
            for n, line in enumerate(code.splitlines(), 1):
                if not line.lstrip().startswith("#"):
                    self.assertIsNone(bad.search(line), f"{name}:{n}: {line.strip()}")

    def test_only_writes_files_the_user_asked_for(self):
        for name, text in self.sources():
            if name in ("cli.py", "report.py"):
                continue
            self.assertIsNone(re.search(r"open\([^)]*[\"'][wax+]", text), name)

    def test_attack_data_notice_travels_with_the_data(self):
        self.assertTrue(os.path.exists(os.path.join(self.PKG, "data", "ATTACK-LICENSE.txt")))
        text = " ".join(open(os.path.join(self.PKG, "data", "ATTACK-LICENSE.txt"), encoding="utf-8").read().split())
        self.assertIn("reproduce MITRE's copyright designation", text)


if __name__ == "__main__":
    unittest.main()
