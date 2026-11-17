# Corp-DFIR — coleta e análise de artefatos de agentes de IA e acesso remoto

Data: 2026-11-17. Contexto: investigação do incidente Bonanza (saídas não autorizadas via API Sicoob em 12/11/2026).

## Objetivo

Coletar, de PCs Windows da empresa, os artefatos locais de agentes de IA e os logs de ferramentas de acesso remoto. Depois, analisá-los numa máquina Ubuntu de gestão, na rede local, para encontrar:

- segredos expostos (tokens, chaves de API, client IDs/secrets, certificados);
- conversas com indício de golpe;
- acessos remotos suspeitos.

Os dados não saem da empresa: nada vai para a VPS ou para a nuvem.

## Escopo

- **Piloto:** máquinas do suporte (ex.: `JHONS-SUPWP`). Expansão posterior, se necessária, sem mudar o código.
- **Governança:** a coleta é feita sob a política de uso de equipamentos da empresa, com propósito declarado (o incidente) e cadeia de custódia. Toda coleta registra máquina, operador, data/hora e hashes.

## Componentes

### 1. Coletor (`collector/Invoke-DfirCollect.ps1`)

Script PowerShell 5.1, executado como SYSTEM pelo Tactical RMM.

Variáveis do Tactical:
- `-Server` — IP ou host do Ubuntu (obrigatório).
- `-Token` — token de envio (obrigatório).
- `-Port` — padrão 8443.

Funcionamento:
- **Staging fixo:** `C:\ProgramData\CorpDFIR\` (única exceção do Bitdefender).
- **Baixo impacto:**
  - prioridade do processo `Idle` e pausa de 150 ms entre arquivos;
  - arquivos acima de 200 MB são ignorados (registrados no manifesto como `skipped`) e o pacote é limitado a 2 GB;
  - a cópia usa leitura compartilhada (`FileShare.ReadWrite`), funcionando com arquivos abertos, como o SQLite do Cursor e do VS Code.
- **Varredura:** todos os perfis em `C:\Users\*`, exceto `Public`, `Default` e `Default User`.
- **Fontes por perfil:**
  - **IA:**
    - `.claude`, `AppData\Roaming\Claude`;
    - `.codex`, `.gemini` (inclui Antigravity), `.aider*`, `.continue`, `.cursor`;
    - `AppData\Roaming\Cursor\User\{workspaceStorage,globalStorage,History}`;
    - `AppData\Roaming\Code\User\{workspaceStorage,globalStorage}` (Copilot, Cline, Roo);
    - `AppData\Roaming\Windsurf\User\{workspaceStorage,globalStorage}`;
    - `AppData\Roaming\Antigravity\User\{workspaceStorage,globalStorage}`;
    - `AppData\Local\Packages\OpenAI.ChatGPT*`, `AppData\Roaming\com.openai.chat`.
  - **Segredos soltos** (OpenRouter e outros):
    - históricos do PowerShell (`AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\*.txt`), `.bash_history`, `.gitconfig`, `.npmrc`, `.env*` na raiz do perfil;
    - `.env*`, `*.pfx`, `*.p12`, `*.key` em `Desktop`, `Documents` e `Downloads`, com profundidade máxima 4. Dos certificados (`.pfx`, `.p12`, `.key`) só vai para o manifesto o hash e o metadado; o arquivo não é copiado.
  - **Acesso remoto (por perfil):**
    - `AppData\Roaming\AnyDesk\*.trace`, `connection_trace.txt`;
    - `AppData\Roaming\TeamViewer\*.log`, `Connections*.txt`;
    - `AppData\Roaming\RustDesk\{log,config}`.
- **Fontes de sistema:**
  - `C:\ProgramData\AnyDesk\*`;
  - `C:\Program Files*\TeamViewer\*.log`, `Connections_incoming.txt`;
  - `C:\Windows\ServiceProfiles\LocalService\AppData\Roaming\RustDesk\{log,config}`;
  - `C:\ProgramData\RustDesk`.
- **Saída:**
  - `manifest.json`, com uma linha por arquivo: perfil, categoria, caminho original, tamanho, mtime, SHA-256 e status;
  - `custody.json`, com hostname, usuário do RMM, data/hora UTC, versão do coletor e SHA-256 do zip, calculado depois de fechar o pacote;
  - tudo dentro de `CorpDFIR-<host>-<utc>.zip`.
- **Envio:**
  - `POST https://<Server>:<Port>/api/v1/upload`, multipart, com cabeçalho `X-DFIR-Token` e `X-DFIR-SHA256`; o servidor usa certificado autoassinado;
  - a confiança é feita por pinning da impressão digital do certificado, informada opcionalmente em `-CertThumbprint`; sem ela, a confiança é aceita na rede local;
  - se o envio falhar, o zip permanece no staging e é reenviado na próxima execução;
  - zips enviados com sucesso são apagados do staging.
- **Silencioso:** sem janela e sem prompt; o stdout traz só um resumo para o Tactical.

### 2. Servidor (Ubuntu, Docker Compose)

Serviços:
- `api` (FastAPI): upload, consulta e painel;
- `worker` (Taskiq + Redis);
- `redis`;
- `caddy`, que faz TLS autoassinado na porta 8443.

Etapas:
- **Recepção:**
  - valida o token e o SHA-256 do upload contra o cabeçalho;
  - grava em `data/evidence/<host>/<arquivo>.zip` como somente leitura (`chmod 0444`) e registra a custódia no SQLite;
  - a evidência original nunca é alterada.
- **Etapa 1 — extração (worker):**
  - descompacta numa área de trabalho separada;
  - os parsers produzem `events` (host, perfil, fonte, timestamp, papel, texto, caminho de origem):
    - JSONL e JSON genérico (Claude, Codex, Gemini, Antigravity);
    - SQLite (`state.vscdb` do Cursor, VS Code, Windsurf e Antigravity: tabela `ItemTable`, chaves de chat);
    - logs de texto (AnyDesk, TeamViewer, RustDesk), extraindo eventos de conexão (ID remoto, IP, direção, horário).
- **Etapa 2 — detecção determinística:** regras em `rules/*.yaml`:
  - regex de segredos: `sk-or-v1-`, `sk-ant-`, `sk-proj-`/`sk-`, JWT, AWS, GitHub, UUID de client ID, PEM e chave privada, padrões Sicoob, PIX e boleto;
  - palavras-chave de fraude em PT-BR: laranja, conta de passagem, PIX, boleto, certificado, senha do certificado, "não conta pra ninguém" etc.;
  - nas linhas de acesso remoto, IDs e IPs de uma lista de interesse definida pelo operador;
  - cada achado guarda severidade e score, e o segredo aparece **mascarado** no painel (o valor completo fica só na evidência);
  - os segredos ganham uma impressão SHA-256, para correlacionar o mesmo segredo entre máquinas sem exibi-lo.
- **Etapa 3 — triagem por IA (opcional):**
  - só achados com score acima do limiar, com janela de contexto de ±20 eventos;
  - endpoint compatível com OpenAI configurável (`LLM_BASE_URL`, `LLM_API_KEY`, `LLM_MODEL`), pensado para um modelo local ou o OmniRoute interno;
  - desligada se `LLM_BASE_URL` estiver vazio;
  - saída: classificação (`benigno` | `suspeito` | `fraude_provavel`) e justificativa;
  - segredos são mascarados **antes** de enviar o contexto ao modelo.
- **Painel:**
  - lista de coletas e achados, com filtros por host, severidade e categoria;
  - linha do tempo por host;
  - acessos remotos;
  - correlação de segredos entre máquinas;
  - exportação CSV/JSON;
  - protegido por senha (Basic Auth no Caddy).

### 3. Instalador (`install.sh`)

- Instala Docker, se faltar.
- Gera token, senha do painel e certificado.
- Sobe o Compose.
- Imprime: URL do painel, token, impressão digital do certificado e o comando de exemplo para o Tactical.

### 4. Bitdefender

Exclusões:
- pasta `C:\ProgramData\CorpDFIR\`;
- processo `powershell.exe` **somente** com a linha de comando contendo `Invoke-DfirCollect`, se a política permitir; senão, só a pasta.

Documentar em `docs/bitdefender.md`.

## Fora do escopo

- Análise de memória ou disco completo.
- Captura de tela.
- Coleta contínua ou agente residente.
- Coleta de dados de navegador fora dos apps listados.
- Bloqueio ou resposta automática nas máquinas.

## Testes

- **Coletor:** modo `-DryRun`, que lista o que coletaria sem copiar, e teste numa VM.
- **Servidor:** pytest para parsers (fixtures de cada formato), regras de detecção (positivos e negativos), validação de hash/token no upload e mascaramento.
- **Ponta a ponta:** script de smoke que monta um zip fake, envia e confere os achados no painel.

## Adendo (17/11): análise de certificados

Pedido durante a implementação: verificar se as máquinas têm certificados de clientes, possivelmente baixados em sessões de suporte remoto.

- **Coletor (`certs.json`):** só metadados, nunca a chave privada.
  - Repositórios `LocalMachine\My`, `Root` e `CA`, e `CurrentUser\My` de cada perfil, lido dos blobs em `AppData\Roaming\Microsoft\SystemCertificates`. A propriedade 0x02 do blob indica se há chave privada associada.
  - Arquivos `.pfx/.p12` (tentativa de leitura sem senha; se falhar, `readable=false` + hash) e `.cer/.crt/.pem`.
  - Origem do download pelo `Zone.Identifier` (`HostUrl`, `ReferrerUrl`, `ZoneId`).
- **Servidor (`app/certs.py`):**
  - `cert_terceiro` (alta com chave privada, média sem) quando o CNPJ não está em `DFIR_OWN_CNPJS`;
  - `cert_baixado` (alta) quando há origem de download;
  - `cert_pfx_protegido` (alta) para PFX ilegível;
  - `cert_icp_sem_cnpj` (média);
  - `cert_raiz_suspeita` (alta) para raiz autoassinada imitando ICP-Brasil ou banco;
  - correlação entre máquinas pelo thumbprint (ou pelo SHA-256 do arquivo, quando ilegível).
- **Painel:** página `/certs`.
