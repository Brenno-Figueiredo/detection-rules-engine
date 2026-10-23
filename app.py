#!/usr/bin/env python3
"""RuleForge - detecção como código: regras Sigma, testes de regra e cobertura do MITRE ATT&CK.
Exemplos:
    python app.py demo --html relatorio.html --layer cobertura.json
    python app.py validate                       # valida as regras de rules/
    python app.py test                           # roda os testes de cada regra
    python app.py scan --events meu.jsonl:product=windows
    python app.py explain powershell_com_comando_codificado.yml
    python app.py attack T1070.001               # técnica revogada? qual é a nova?
"""
import sys

from ruleforge.cli import main

if __name__ == "__main__":
    sys.exit(main())
