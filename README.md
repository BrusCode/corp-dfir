# Corp-DFIR

Coleta e análise local de artefatos de **agentes de IA**, **logs de acesso remoto** e **certificados digitais** de PCs Windows da empresa, para resposta a incidentes (origem: incidente Bonanza, 11/2026).

Os dados ficam na rede local: o servidor roda numa máquina Ubuntu de gestão, sem nuvem.

## Como funciona

1. **Coletor** (`collector/Invoke-DfirCollect.ps1`), executado como SYSTEM pelo Tactical RMM.
   - Copia em baixa prioridade os históricos de Claude, Codex, Gemini/Antigravity, Cursor, VS Code (Copilot/Cline/Roo/Continue), Windsurf, ChatGPT Desktop e Aider.
   - Copia também históricos de shell, `.env`, e os logs do AnyDesk, TeamViewer e RustDesk.
   - Faz o inventário de **certificados** (repositórios do Windows e arquivos `.pfx/.p12/.cer/.crt/.pem`) **apenas com metadados**: titular, CNPJ, emissor, validade, thumbprint, se tem chave privada e a origem do download (`Zone.Identifier`).
   - Gera um zip com `manifest.json` (SHA-256 de cada arquivo), `certs.json` e `custody.json`, e envia por HTTPS.
2. **Servidor** (`server/`, Docker Compose): FastAPI recebe e valida o hash e grava a evidência como somente leitura. O worker Taskiq/Redis extrai eventos, aplica as regras (`server/rules/*.yaml`) e, opcionalmente, faz triagem com um LLM local.
3. **Painel** (Basic Auth) com:
   - coletas;
   - achados por severidade;
   - segredos correlacionados entre máquinas, mostrados mascarados;
   - acessos remotos;
   - certificados (CNPJs de terceiros e de onde foram baixados);
   - exportação CSV/JSON.

## Garantias

- Chaves privadas de certificados **nunca** são copiadas.
- O painel, o banco de eventos e o LLM só veem segredos **mascarados**. O valor completo fica apenas no pacote original de evidência, como prova.
- A evidência é imutável (`0444`), com o SHA-256 conferido no recebimento. O reenvio do mesmo pacote é idempotente.
- Cadeia de custódia registrada: host, conta, data/hora, versão do coletor e hashes.

> Use somente em equipamentos da empresa, dentro da política de uso e com o propósito de investigação registrado.

## Instalação (Ubuntu de gestão)

```bash
git clone <este-repo> corp-dfir && cd corp-dfir
sudo ./install.sh 192.168.0.50     # IP da máquina na rede local
```

O instalador imprime a URL do painel, a senha, o token e o thumbprint, junto com a linha de argumentos pronta para o Tactical. Depois, edite `deploy/.env`:

- `DFIR_OWN_CNPJS=` — CNPJs da própria empresa, separados por vírgula, para não marcá-los como terceiros.
- `LLM_BASE_URL`, `LLM_MODEL`, `LLM_API_KEY` — triagem opcional por IA (endpoint compatível com OpenAI, de preferência local).

Aplique com `cd deploy && docker compose up -d`.

## Documentação

- [Tactical RMM](docs/tactical.md)
- [Exceções do Bitdefender](docs/bitdefender.md)
- [Especificação](docs/superpowers/specs/2026-11-17-corp-dfir-design.md) e [plano](docs/superpowers/plans/2026-11-17-corp-dfir.md)

## Desenvolvimento

```bash
python3 -m venv .venv && .venv/bin/pip install -r server/requirements.txt
cd server && ../.venv/bin/pytest -q
```

Para ajustar a detecção, edite `server/rules/secrets.yaml` e `fraud.yaml`, adicione um teste em `server/tests/test_rules.py` e rode o pytest.
