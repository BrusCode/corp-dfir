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

## Relatório e análise por IA

- **Relatório** (menu "Relatório"):
  - página formatada por máquina ou geral;
  - indicadores no topo: certificados de terceiros com chave, PFX em disco, senha no nome do arquivo e certificados de API bancária;
  - tabelas de certificados, linha do tempo, achados, acessos remotos, segredos e cadeia de custódia;
  - "Imprimir / salvar PDF" e "Baixar HTML" geram um arquivo autocontido para enviar à diretoria.
- **Análise por IA** ("Solicitar análise por IA" no relatório):
  - a IA recebe o resumo dos mesmos dados do relatório, com segredos mascarados;
  - escreve resumo executivo, riscos, evidências, limitações, recomendações e próximos passos;
  - a análise fica guardada e entra no relatório na seção "Análise dos resultados".
- **Contexto da empresa** (Configurações): descreva o que é rotina no suporte. O texto vai junto em toda triagem e análise, para a IA separar o rotineiro do anômalo.

## Garantias

- Chaves privadas de certificados **nunca** são copiadas.
- O painel, o banco de eventos e o LLM só veem segredos **mascarados**. O valor completo fica apenas no pacote original de evidência, como prova.
- A evidência é imutável (`0444`), com o SHA-256 conferido no recebimento. O reenvio do mesmo pacote é idempotente.
- Cadeia de custódia registrada: host, conta, data/hora, versão do coletor e hashes.

> Use somente em equipamentos da empresa, dentro da política de uso e com o propósito de investigação registrado.

## Instalação (Ubuntu de gestão)

O repositório é privado. O GitHub não aceita a senha da conta no `git clone`: autentique antes com `gh auth login` ou use um token de acesso (de preferência com permissão só de leitura neste repositório) no lugar da senha.

```bash
git clone https://github.com/BrusCode/corp-dfir.git corp-dfir && cd corp-dfir
sudo ./install.sh 192.168.10.56     # IP da máquina na rede local
```

O instalador imprime a URL do painel (com a porta), a senha, o token e o thumbprint, junto com a linha de argumentos pronta para o Tactical. A senha do painel aparece **uma única vez**: guarde no cofre.

### Atualizar

```bash
cd ~/corp-dfir
git pull
sudo ./install.sh 192.168.10.56
```

Pode rodar de novo quantas vezes precisar. O instalador preserva o token, o certificado, a senha e a porta já configurados, e reconstrói os serviços com o código novo.

### Porta

- Padrão: `8443`. Se estiver ocupada por outro serviço, o instalador usa a próxima livre (até `8543`), avisa e grava em `deploy/.env` (`DFIR_PORT`). As execuções seguintes mantêm essa porta.
- Use sempre a porta impressa pelo instalador no painel e no argumento `-Port` do Tactical.

### Senha do painel

```bash
sudo ./install.sh 192.168.10.56 --reset-password
```

Gera e mostra uma senha nova. O instalador também regenera a senha sozinho se encontrar um hash gravado por versões antigas, em que o Docker Compose corrompia o `$` do hash.

Depois, abra o painel em `https://<IP>:8443` (usuário `dfir`) e acesse **Configurações**:

- **CNPJs da empresa**, para que os certificados próprios não sejam marcados como de terceiros.
- **Triagem por IA (opcional).** Para a OpenRouter, use:
  - URL: `https://openrouter.ai/api/v1`;
  - modelo, por exemplo `deepseek/deepseek-chat`;
  - sua chave `sk-or-...`.

  Use **Testar conexão** para validar e **Rodar triagem nos achados pendentes** para classificar o que já foi coletado. A chave fica salva no servidor e nunca é exibida de volta. As requisições à OpenRouter exigem provedores sem retenção nem treino (`data_collection: deny`).

O que é salvo no painel sobrepõe o `deploy/.env`, que continua valendo como padrão, e não precisa de reinício.

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
