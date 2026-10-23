"""MITRE ATT&CK: etiquetas das regras, IDs revogados, cobertura e camada para o ATT&CK Navigator.

Os dados (ruleforge/data/attack.json) vêm do conjunto oficial do MITRE (attack-stix-data). O ATT&CK mudou muito nas versões recentes:
técnicas foram revogadas e substituídas (ex.: T1070.001 passou a ser T1685.005) e a tática Defense Evasion foi dividida em Stealth e
Defense Impairment. Por isso a ferramenta SABE de IDs revogados, conta a regra pela técnica nova e avisa quem ainda usa o ID antigo.

© The MITRE Corporation. Reproduzido e distribuído com a permissão da MITRE Corporation (ver ruleforge/data/ATTACK-LICENSE.txt)."""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Tuple

DATA_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "data", "attack.json")
TECH_TAG = re.compile(r"^t\d{4}(\.\d{3})?$")
OLD_TACTICS = {"defense_evasion": "defense-evasion", "defense-evasion": "defense-evasion"}
LAYER_VERSIONS = {"navigator": "5.1.0", "layer": "4.5"}


@dataclass
class TagInfo:
    techniques: List[str] = field(default_factory=list)       # IDs como escritos na regra (maiúsculos)
    tactics: List[str] = field(default_factory=list)
    other: List[str] = field(default_factory=list)            # grupos, software, CVE etc.
    unknown: List[str] = field(default_factory=list)          # 'attack.' que não é técnica nem tática conhecida


class Attack:
    def __init__(self, data: Optional[Dict] = None):
        if data is None:
            with open(DATA_PATH, encoding="utf-8") as f:
                data = json.load(f)
        self.data = data
        self.version: str = data["attack_version"]
        self.techniques: Dict[str, Dict] = data["techniques"]
        self.revoked: Dict[str, Dict] = data.get("revoked", {})
        self.deprecated: Dict[str, str] = data.get("deprecated", {})
        self.tactics: List[Dict] = data["tactics"]
        self.tactic_names = {t["shortname"]: t["name"] for t in self.tactics}
        self.notice: str = data["notice"]
        self.disclaimer: str = data["disclaimer"]

    @property
    def major(self) -> str:
        return self.version.split(".")[0]

    # ---- consulta de um ID -----------------------------------------------------------------------------------------------------
    def status(self, tid: str) -> str:
        """active | revoked | deprecated | unknown"""
        tid = tid.upper()
        if tid in self.techniques:
            return "active"
        if tid in self.revoked:
            return "revoked"
        if tid in self.deprecated:
            return "deprecated"
        return "unknown"

    def current(self, tid: str) -> Optional[str]:
        """O ID vigente: o próprio (se ativo) ou o que o substituiu (se revogado). None se desconhecido ou obsoleto sem substituto."""
        tid = tid.upper()
        if tid in self.techniques:
            return tid
        if tid in self.revoked:
            return self.revoked[tid]["to"]
        return None

    def name(self, tid: str) -> str:
        tid = tid.upper()
        return self.techniques.get(tid, {}).get("name") or self.revoked.get(tid, {}).get("name") or self.deprecated.get(tid, "")

    def tactics_of(self, tid: str) -> List[str]:
        cur = self.current(tid)
        return list(self.techniques[cur]["tactics"]) if cur else []

    def parent(self, tid: str) -> str:
        return tid.split(".")[0]

    # ---- etiquetas ---------------------------------------------------------------------------------------------------------------
    def parse_tags(self, tags: Iterable[str]) -> TagInfo:
        info = TagInfo()
        for raw in tags:
            tag = str(raw).strip().lower()
            if not tag.startswith("attack."):
                info.other.append(raw)
                continue
            rest = tag[len("attack."):]
            if TECH_TAG.match(rest):
                tid = rest.upper()
                if tid not in info.techniques:
                    info.techniques.append(tid)
            elif rest.replace("_", "-") in self.tactic_names or rest in OLD_TACTICS:
                name = OLD_TACTICS.get(rest, rest.replace("_", "-"))
                if name not in info.tactics:
                    info.tactics.append(name)
            elif re.fullmatch(r"[gs]\d{4}", rest):
                info.other.append(raw)
            else:
                info.unknown.append(raw)
        return info

    def rule_techniques(self, tags: Iterable[str]) -> List[str]:
        """IDs VIGENTES das técnicas de uma regra (os revogados são trocados pelo substituto), sem repetição."""
        out: List[str] = []
        for tid in self.parse_tags(tags).techniques:
            cur = self.current(tid)
            if cur and cur not in out:
                out.append(cur)
        return out

    # ---- cobertura ---------------------------------------------------------------------------------------------------------------
    def coverage(self, rules: List, hits: Optional[Dict[str, int]] = None) -> Dict:
        """Cobertura das regras sobre o ATT&CK. 'rules' são objetos com .title, .id, .tags e .kind.
        Uma técnica-mãe conta como coberta se ela ou alguma de suas subtécnicas tem regra."""
        hits = hits or {}
        by_tech: Dict[str, List] = {}
        for r in rules:
            for tid in self.rule_techniques(r.tags):
                by_tech.setdefault(tid, []).append(r)
        covered_parents = {self.parent(t) for t in by_tech}
        parents = {t: v for t, v in self.techniques.items() if not v["sub"]}
        per_tactic = []
        for tac in self.tactics:
            short = tac["shortname"]
            all_parents = sorted(t for t, v in parents.items() if short in v["tactics"])
            cov = [t for t in all_parents if t in covered_parents]
            subs = sorted({t for t in by_tech if short in self.techniques[t]["tactics"]})
            per_tactic.append({"tactic": short, "name": tac["name"], "id": tac["id"], "total": len(all_parents), "covered": len(cov), "covered_ids": cov,
                               "techniques_with_rules": subs})
        total_parents = len(parents)
        covered_total = len([p for p in parents if p in covered_parents])
        return {"version": self.version, "total_techniques": total_parents, "covered_techniques": covered_total,
                "percent": round(100 * covered_total / total_parents, 1) if total_parents else 0.0, "per_tactic": per_tactic, "by_technique": by_tech,
                "rules_with_attack": len({id(r) for rs in by_tech.values() for r in rs}), "rules_total": len(rules),
                "hits": {t: sum(hits.get(getattr(r, "id", "") or r.title, 0) for r in rs) for t, rs in by_tech.items()}}

    def layer(self, rules: List, hits: Optional[Dict[str, int]] = None, name: str = "RuleForge") -> Dict:
        """Camada no formato do MITRE ATT&CK Navigator (layer 4.5): a nota de cada técnica é o número de regras que a cobrem."""
        cov = self.coverage(rules, hits)
        techs = []
        for tid, rs in sorted(cov["by_technique"].items()):
            comment = "; ".join(sorted({r.title for r in rs}))[:300]
            if cov["hits"].get(tid):
                comment += f" | disparos: {cov['hits'][tid]}"
            techs.append({"techniqueID": tid, "score": len(rs), "comment": comment, "enabled": True})
        top = max([t["score"] for t in techs] or [1])
        return {"name": name, "versions": {"attack": self.major, **LAYER_VERSIONS}, "domain": "enterprise-attack",
                "description": f"Cobertura das regras (não é cobertura de detecção garantida). {self.notice}", "sorting": 0,
                "layout": {"layout": "side", "aggregateFunction": "max", "showID": True, "showName": True, "showAggregateScores": False, "countUnscored": False},
                "hideDisabled": False, "techniques": techs,
                "gradient": {"colors": ["#ffffff", "#7ab8f5"], "minValue": 0, "maxValue": top}, "legendItems": [], "metadata": [], "links": [],
                "showTacticRowBackground": False, "tacticRowBackground": "#dddddd", "selectTechniquesAcrossTactics": True, "selectSubtechniquesWithParent": False}

    # ---- migração de IDs ---------------------------------------------------------------------------------------------------------
    def migration(self, tags: Iterable[str]) -> List[Tuple[str, str, str]]:
        """[(tag antiga, tag nova, explicação)] para as etiquetas de técnicas revogadas."""
        out = []
        for raw in tags:
            tag = str(raw).strip()
            m = re.fullmatch(r"(?i)attack\.(t\d{4}(?:\.\d{3})?)", tag)
            if not m:
                continue
            tid = m.group(1).upper()
            if self.status(tid) == "revoked":
                new = self.revoked[tid]["to"]
                out.append((tag, f"attack.{new.lower()}", f"{tid} ({self.name(tid)}) foi revogada no ATT&CK v{self.major}; substituta: {new} ({self.name(new)})"))
        return out
