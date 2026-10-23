#!/usr/bin/env python3
"""Atualiza ruleforge/data/attack.json a partir do conjunto oficial do MITRE ATT&CK (STIX).

    python tools/update_attack.py --input enterprise-attack.json     # arquivo já baixado
    python tools/update_attack.py --download                         # baixa de github.com/mitre-attack/attack-stix-data (usa a internet)

O ATT&CK muda (técnicas são revogadas e substituídas, táticas são divididas): rode isto de tempos em tempos e depois 'python app.py validate'
para ver quais das suas regras passaram a usar IDs revogados. O resultado carrega o aviso de direitos e a ressalva do MITRE."""
from __future__ import annotations

import argparse
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "ruleforge", "data", "attack.json")
BASE = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master"
NOTICE_YEAR_FALLBACK = "2026"


def external_id(obj):
    for r in obj.get("external_references", []):
        if r.get("source_name") == "mitre-attack":
            return r.get("external_id")
    return None


def build(bundle: dict, license_text: str = "") -> dict:
    objs = bundle["objects"]
    by_id = {o["id"]: o for o in objs}
    by_type = {}
    for o in objs:
        by_type.setdefault(o["type"], []).append(o)
    coll = by_type["x-mitre-collection"][0]
    tactic_by_ref = {t["id"]: t["x_mitre_shortname"] for t in by_type["x-mitre-tactic"]}
    tactics = {t["x_mitre_shortname"]: {"id": external_id(t), "name": t["name"], "shortname": t["x_mitre_shortname"]} for t in by_type["x-mitre-tactic"]}
    order = [tactic_by_ref[r] for r in by_type["x-mitre-matrix"][0]["tactic_refs"] if r in tactic_by_ref]
    techniques, names = {}, {}
    for o in by_type["attack-pattern"]:
        tid = external_id(o)
        if tid:
            names[tid] = o["name"]
        if o.get("revoked") or o.get("x_mitre_deprecated") or not tid:
            continue
        phases = [p["phase_name"] for p in o.get("kill_chain_phases", []) if p.get("kill_chain_name") == "mitre-attack"]
        techniques[tid] = {"name": o["name"], "tactics": phases, "sub": bool(o.get("x_mitre_is_subtechnique"))}
    raw = {}
    for o in objs:
        if o["type"] == "relationship" and o.get("relationship_type") == "revoked-by":
            s, t = by_id.get(o["source_ref"]), by_id.get(o["target_ref"])
            if s and t and s["type"] == "attack-pattern" and t["type"] == "attack-pattern" and external_id(s) and external_id(t):
                raw[external_id(s)] = external_id(t)

    def resolve(tid):
        seen = set()
        while tid in raw and tid not in seen:
            seen.add(tid)
            tid = raw[tid]
        return tid
    revoked = {old: {"name": names.get(old, ""), "to": resolve(old)} for old in raw}
    broken = [o for o, v in revoked.items() if v["to"] not in techniques]
    if broken:
        raise SystemExit(f"IDs revogados sem substituto ativo: {broken[:5]}")
    deprecated = {external_id(o): o["name"] for o in by_type["attack-pattern"] if o.get("x_mitre_deprecated") and external_id(o)}
    return {"attack_version": coll.get("x_mitre_version"), "modified": coll.get("modified"), "domain": "enterprise-attack",
            "source": "https://github.com/mitre-attack/attack-stix-data (enterprise-attack.json)",
            "notice": f"© {NOTICE_YEAR_FALLBACK} The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation.",
            "disclaimer": ("MITRE does not claim ATT&CK enumerates all possibilities for the types of actions and behaviors documented as part of its adversary model and framework of techniques. "
                           "Using the information contained within ATT&CK to address or cover full categories of techniques will not guarantee full defensive coverage as there may be undisclosed "
                           "techniques or variations on existing techniques not documented by ATT&CK."),
            "license": ("The MITRE Corporation (MITRE) hereby grants you a non-exclusive, royalty-free license to use ATT&CK® for research, development, and commercial purposes. "
                        "Any copy you make for such purposes is authorized provided that you reproduce MITRE's copyright designation and this license in any such copy."),
            "tactics": [tactics[s] for s in order], "techniques": techniques, "revoked": revoked, "deprecated": deprecated, "tactic_split": {"defense-evasion": ["stealth", "defense-impairment"]}}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--input", help="enterprise-attack.json já baixado")
    ap.add_argument("--download", action="store_true", help="baixa os arquivos do repositório do MITRE")
    ap.add_argument("--out", default=OUT)
    a = ap.parse_args()
    if a.download:
        import urllib.request
        with urllib.request.urlopen(f"{BASE}/enterprise-attack/enterprise-attack.json", timeout=120) as r:           # nosec: https, repositório oficial do MITRE
            bundle = json.load(r)
        with urllib.request.urlopen(f"{BASE}/LICENSE.txt", timeout=30) as r:
            license_text = r.read().decode("utf-8")
        with open(os.path.join(os.path.dirname(a.out), "ATTACK-LICENSE.txt"), "w", encoding="utf-8") as f:
            f.write(license_text)
    elif a.input:
        with open(a.input, encoding="utf-8") as f:
            bundle = json.load(f)
    else:
        ap.error("informe --input ARQUIVO ou --download")
    data = build(bundle)
    with open(a.out, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, separators=(",", ":"), sort_keys=True)
    parents = sum(1 for t in data["techniques"].values() if not t["sub"])
    print(f"ATT&CK v{data['attack_version']}: {parents} técnicas + {len(data['techniques']) - parents} subtécnicas, {len(data['tactics'])} táticas, "
          f"{len(data['revoked'])} IDs revogados com substituto, {len(data['deprecated'])} obsoletos -> {a.out}")
    print("Revise as regras: python app.py validate")
    return 0


if __name__ == "__main__":
    sys.exit(main())
