# RuleForge

**Detecção como código**: regras no formato **Sigma** (o padrão aberto de regras de detecção), **testes para cada regra**, execução sobre logs,
correlação e **mapa de cobertura do MITRE ATT&CK**. Em Python, **sem dependências externas** (até o leitor de YAML é próprio).

```
python app.py demo --html relatorio.html --layer cobertura.json     # 31 regras sobre logs FICTÍCIOS
python app.py validate                                              # o que um revisor conferiria
python app.py test                                                  # cada regra dispara no que deve e fica quieta no resto
python app.py scan --events meu.jsonl:product=windows               # os seus logs
```

## Por que isso importa

Quem trabalha em um SOC não "escreve alertas": escreve **regras de detecção**, versiona, **testa**, ajusta falsos positivos e mostra **o que está e o que não está
coberto**. Isso é *detection engineering*. O RuleForge mostra o ciclo inteiro: escrever a regra (`new`), validar (`validate`), provar que funciona (`test`),
explicar (`explain`), aplicar (`scan`) e medir a cobertura (`coverage`). A detecção de eventos anômalos e de intrusão faz parte de qualquer programa de segurança,
e a ferramenta exporta evidência para os controles **MON-02** e **TEC-04** do ComplianceMap.

## O ATT&CK mudou (e a ferramenta sabe)

Os dados do ATT&CK vêm do **conjunto oficial do MITRE (versão 20.0)**, não da memória de ninguém. E ele mudou bastante:

- A tática **Defense Evasion foi dividida** em **Stealth** e **Defense Impairment**.
- Técnicas foram **revogadas e substituídas**: por exemplo, **T1070.001** (limpar logs de eventos do Windows) hoje é **T1685.005**, e **T1562.001** é **T1685**.
- A maioria dos tutoriais e das regras públicas **ainda usa os IDs antigos**.

Por isso a ferramenta: **avisa** quando uma regra usa ID revogado (`validate`), **conta a regra pela técnica nova** na cobertura, mostra o substituto (`attack T1070.001`) e
**troca as etiquetas** (`migrate --write`). O arquivo de dados se atualiza com `python tools/update_attack.py` (o caminho `--download` usa a mesma lógica da extração,
mas não foi executado de ponta a ponta nos testes).

## O que o formato Sigma suporta aqui

| Suportado | Não suportado (a ferramenta avisa, não ignora) |
|---|---|
| seleções em mapa, lista de mapas e lista de palavras-chave | agregação antiga (`| count() > 5`), `timeframe` |
| condição com `and`, `or`, `not`, parênteses, `1 of selection*`, `all of them` | `fieldref`, `expand` |
| `contains`, `startswith`, `endswith`, `all`, `re` (+`i`,`m`,`s`), `cidr`, `exists`, `lt/lte/gt/gte` | correlação `temporal` |
| `base64`, `base64offset`, `wide`/`utf16le`, `windash` | |
| curingas `*` e `?`, `null` | |
| correlação `event_count` e `value_count` | |

Detalhes de semântica que **pegam todo mundo** (e que os testes cobrem):
- Texto casa **sem diferenciar maiúsculas**; **base64 diferencia** (`QQ` e `qq` são dados diferentes); regex diferencia, a menos que use `re|i`.
- **A barra antes do `*` escapa o curinga.** `C:\Users\*\x` procura um asterisco **literal**; para barra + curinga escreva `C:\Users\\*\x`. O validador avisa (W115).
- `them` **ignora** seleções que começam com `_`. `campo: null` casa com campo **ausente ou vazio**.
- Na correlação, as regras-base **não geram alerta sozinhas** por padrão (`generate: false`); é a minha implementação desse campo, confira com a especificação.

## Testes de regra (o diferencial)

Cada regra carrega os seus próprios testes no campo `x_tests`:

```yaml
x_tests:
    positive:                       # DEVEM disparar a regra
        - {Image: 'C:\Windows\System32\powershell.exe', CommandLine: 'powershell -enc SQBFAFgA'}
    negative:                       # parecidos, mas NÃO devem disparar (é o que evita falso positivo)
        - {Image: 'C:\Windows\System32\powershell.exe', CommandLine: 'powershell -File backup.ps1'}
```
`python app.py test` roda todos e falha se algum mudar de comportamento: é o que permite alterar uma regra sem medo. Em regras de correlação, cada teste traz uma lista de
`events` (com data e hora). O validador cobra: regra **sem testes** (W113) ou **sem teste negativo** (W123) recebe aviso.

## Correlação

```yaml
correlation:
    type: event_count            # ou value_count (valores distintos de 'field')
    rules: [win_failed_logon]    # nome, id ou título da regra-base
    group-by: [IpAddress]
    timespan: 5m
    condition: {gte: 10}
```
**Um alerta por rajada**, com o total real (26 falhas de logon viram **um** alerta com `26 ocorrências`, e não três). O campo de tempo é detectado (`timestamp`, `@timestamp`,
`UtcTime`...) ou indicado com `--time-field`. Eventos sem data e hora são ignorados na correlação, e a ferramenta avisa.

## Origem do log e mapa de campos

`--events arquivo.jsonl:product=windows,category=process_creation` diz de que tipo de log o arquivo é: só as regras daquele `logsource` rodam nele (funciona com caminhos
do Windows, como `C:\logs\a.jsonl:product=windows`). Se os campos do seu log têm outros nomes: `--field-map mapa.json` com `{"Image": "process.executable"}`.
Formatos de entrada: **JSONL**, **JSON** (lista) e **CSV**.

## Modelo de confiança: regras e logs vêm de fora

Uma regra é código de outra pessoa, e um log é dado de um sistema que pode estar comprometido. Por isso:
- O **leitor de YAML recusa** âncoras, apelidos, etiquetas (`!!python/object`), tabulação, chave repetida e aninhamento exagerado, e **nunca constrói objetos** a partir do arquivo.
  Recusar é de propósito: interpretar mal uma regra de detecção é pior do que falhar.
- **Regex:** padrões grandes e a repetição aninhada óbvia, como `(a+)+`, são recusados. **Isto NÃO pega todos os casos** (por exemplo `(a|aa)+$`), e o Python não tem limite de tempo
  para regex. O validador marca toda regra com `|re` (W124): **revise o padrão** antes de aceitar uma regra de fonte desconhecida.
- O valor de cada campo é **truncado em 16 KB** antes de comparar; linhas de log acima de 1 MB e curingas demais em um valor são recusados.
- O pacote **não usa rede, não executa programas e não usa `eval`/`exec`** (um teste vigia o código-fonte). Só escreve os arquivos de saída que você pede.

## Privacidade

Um **alerta pode conter trechos reais de log** (comandos, usuários, endereços): o relatório completo é **confidencial**. As exportações para outras ferramentas **não levam
trechos de log**: o feed do Venator traz só a regra, o nível, a técnica e o endereço de origem; a evidência do ComplianceMap é agregada (contagens), sem nomes de regras. O
`.gitignore` bloqueia logs reais e relatórios. Os logs de exemplo são **fictícios** e usam só endereços de documentação (RFC 5737).

## Saídas

Terminal · JSON · CSV · **painel HTML** (alertas e cobertura por tática) · **camada para o MITRE ATT&CK Navigator** (`--layer`) · feed do Venator e do CorrelAI (`--feed`) ·
evidência do ComplianceMap (`--compliancemap`). A camada segue o formato 4.5 do Navigator, **mas eu não a abri no aplicativo**: se algo não importar, me avise.

## Comandos

| Comando | O que faz |
|---|---|
| `validate` | lint das regras (E = erro, W = aviso). `--strict` faz os avisos também falharem |
| `test` | roda os testes de cada regra |
| `scan` | aplica as regras aos logs (`--min-level`, `--fail-on`, `--json`, `--csv`, `--html`, ...) |
| `coverage` | cobertura do ATT&CK por tática (`--html`, `--layer`) |
| `explain` | a regra em português: quando dispara e o que significa cada parte |
| `attack T1070.001` | consulta uma técnica, inclusive as revogadas, e mostra quais regras a cobrem |
| `migrate` | troca as etiquetas de técnicas revogadas (`--write` grava; revise com o `git diff`) |
| `new` | cria o esqueleto de uma regra ligada a uma técnica **ativa** (o validador recusa o esqueleto até você preenchê-lo) |

## Desempenho (medido)

**Cerca de 6.500 eventos por segundo** com 28 regras em um núcleo: 200 mil eventos (38 MB) em ~30 s. Serve para **analisar arquivos**, não para detecção em tempo
real. Para ganhar velocidade seria preciso indexar as regras por campo.

## Estrutura
```
app.py
ruleforge/
  yamlite.py   leitor de YAML do subconjunto Sigma (sem dependências)
  sigma.py     regras, condições, modificadores, correlação
  engine.py    leitura de logs, varredura, correlação, testes de regra
  attack.py    ATT&CK: etiquetas, IDs revogados, cobertura, camada do Navigator
  lint.py  explain.py  ruleset.py  report.py  cli.py
  data/        attack.json (ATT&CK v20.0) e a licença do MITRE
rules/         31 regras de exemplo ORIGINAIS (windows, linux, web, correlações), cada uma com testes
samples/       4 logs FICTÍCIOS (496 eventos) com ataques plantados no meio do tráfego normal
tools/         build_samples.py (gera regras e logs) e update_attack.py (atualiza o ATT&CK)
tests/         117 testes automatizados
```

## Testes
```bash
python -m unittest discover -s tests -v
```
Cobrem o leitor de YAML (inclusive o que ele recusa), cada modificador e condição (inclusive as pegadinhas), a correlação, o validador, o ATT&CK (IDs revogados,
cobertura, camada), os relatórios e os comandos. O conteúdo de exemplo é verificado: as 31 regras passam no validador, os **77 testes de regra** passam, cada um dos 19 ataques
plantados é detectado e **nenhum dos "sósias" legítimos** (como `schtasks /create` vindo de um instalador) gera alerta. Os testes foram **validados por mutação** (quebrei o código em
24 pontos, como precedência, escape de curinga, base64 e o guarda de regex, e confirmei que eles falham), e esse processo **achou falhas reais**, entre elas o base64 que ignorava
maiúsculas e minúsculas e um teste de `base64offset` que não cobria a cauda do texto.

## Limitações (leia)
- **Cobertura de regras não é cobertura de detecção.** Uma técnica com regra pode ser detectada só em parte, só em certos logs, ou só se o log existir. O MITRE avisa o mesmo
  na sua licença. O conjunto de exemplo é pequeno **de propósito**: o mapa mostra os buracos (por exemplo, nenhuma regra de movimento lateral ou de exfiltração).
- As regras de exemplo são **minhas** e didáticas: não substituem um conjunto mantido (como o do SigmaHQ) e **precisam ser ajustadas ao seu ambiente** (falsos positivos).
- É um **subconjunto** do Sigma (tabela acima) e não é um conversor para o SIEM de ninguém: executa as regras sobre arquivos de log.
- A proteção contra regex é uma **heurística** (veja o modelo de confiança).
- Os logs de exemplo são sintéticos: acertar neles **não prova** que a regra funciona nos seus.

## Ideias para evoluir
Conversor de regras para consultas de um SIEM real, índice de regras por campo para ganhar velocidade, regras de movimento lateral e exfiltração, leitura direta de arquivos `.evtx`,
correlação `temporal`, e um painel no Venator que mostre a cobertura do ATT&CK ao longo do tempo.

## ATT&CK
Os dados do MITRE ATT&CK® são reproduzidos com a licença do MITRE (`ruleforge/data/ATTACK-LICENSE.txt`):

> © 2026 The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation.

## Projetos da série
[network-scanner](https://github.com/Brenno-Figueiredo/network-scanner) ·
[logwatch](https://github.com/Brenno-Figueiredo/logwatch) ·
[loginguard](https://github.com/Brenno-Figueiredo/loginguard) ·
[web-vuln-scanner](https://github.com/Brenno-Figueiredo/web-vuln-scanner) ·
[ssh-honeypot](https://github.com/Brenno-Figueiredo/ssh-honeypot) ·
[security-event-correlator](https://github.com/Brenno-Figueiredo/security-event-correlator) ·
[malware-static-analyzer](https://github.com/Brenno-Figueiredo/malware-static-analyzer) ·
[phishguard](https://github.com/Brenno-Figueiredo/phishguard) ·
[phishguard-ui](https://github.com/Brenno-Figueiredo/phishguard-ui) ·
[threat-intel-enricher](https://github.com/Brenno-Figueiredo/threat-intel-enricher) ·
[document-verifier](https://github.com/Brenno-Figueiredo/document-verifier) ·
[compliance-mapper](https://github.com/Brenno-Figueiredo/compliance-mapper) ·
[hardening-auditor](https://github.com/Brenno-Figueiredo/hardening-auditor) ·
[access-review-analyzer](https://github.com/Brenno-Figueiredo/access-review-analyzer) ·
[incident-register](https://github.com/Brenno-Figueiredo/incident-register)
