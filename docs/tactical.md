# Tactical RMM — executar a coleta

## 1. Cadastrar o script

Settings → Script Manager → New Script

- **Name:** `CorpDFIR - Coleta`
- **Shell:** PowerShell
- **Run as user:** desmarcado (precisa rodar como **SYSTEM** para ler todos os perfis e os logs de serviço)
- **Timeout:** 3600 segundos (a coleta é lenta de propósito, para não pesar)
- **Script:** conteúdo de `collector/Invoke-DfirCollect.ps1`
- **Script Arguments (padrão):** os parâmetros impressos pelo `install.sh`, com a porta que ele escolheu (não necessariamente 8443). Por exemplo:

```
-Server 192.168.10.56 -Port <PORTA> -Token <TOKEN> -CertThumbprint <THUMBPRINT>
```

Para não deixar o token salvo no script, você pode cadastrá-lo como **Global Key Store** (Settings → Global Settings → Key Store) e usar `{{global.dfir_token}}` nos argumentos.

## 2. Testar primeiro em uma máquina (sem enviar nada)

Rode com `-DryRun` adicionado aos argumentos. A saída lista categoria, perfil, tamanho e caminho de cada arquivo que seria coletado, mais o total em MB. Confira se faz sentido antes da coleta real.

## 3. Rodar no piloto

Selecione as máquinas do suporte → Run Script → `CorpDFIR - Coleta`. Saída esperada:

```
OK host=JHONS-SUPWP arquivos=812 copiados=790 certificados=6 MB=143.2 enviados=1 pendentes=0
```

- `pendentes>0` (código de saída 2): o envio falhou; o pacote fica em `C:\ProgramData\CorpDFIR\` e é reenviado na próxima execução.
- Nenhuma janela aparece para o usuário; o processo roda em prioridade Idle, com pausas entre arquivos.

## Validação pendente

A sintaxe do script não pôde ser validada em PowerShell durante o desenvolvimento. Antes do piloto, rode o `-DryRun` numa máquina de teste Windows 10/11 (PowerShell 5.1) e confira a saída.

## Script de certificados (`collector/Invoke-DfirCertCollect.ps1`)

Coleta focada em certificados digitais:

- quais estão instalados (repositórios do Windows) e quando foram importados;
- quais estão salvos em arquivo (`.pfx/.p12` em todo o perfil e na raiz dos discos; `.cer/.crt/.pem/.key` em Desktop, Documentos e Downloads), com a origem do download;
- quando foram abertos (atalhos de "Recentes");
- comandos de exportação e importação no histórico do PowerShell;
- linhas dos logs do AnyDesk, TeamViewer e RustDesk que citam arquivos de certificado (transferência);
- certificados apagados na lixeira, com a data em que foram apagados;
- eventos do Windows ligados a certificados e chaves;
- execução de `certutil`, `certmgr` e `mmc`;
- data de chegada das chaves privadas.

Só vão metadados e hashes; chaves privadas e `.pfx` nunca são copiados. No painel, tudo aparece em **Certificados**, inclusive a linha do tempo de atividade.

Cadastre como um segundo script (`CorpDFIR - Certificados`), com os mesmos argumentos do coletor principal. Também roda como SYSTEM; o timeout de 1800 s é suficiente.

## Diagnóstico: "rodou mas nada chegou no painel"

1. **Teste de conexão primeiro.** Rode o script com `-TestConnection` adicionado aos argumentos.
   - `conexao ... status=ok`: o servidor foi alcançado e o token é válido.
   - `HTTP 401`: token errado.
   - `Unable to connect`, tempo esgotado ou recusado: IP ou **porta** errados, ou firewall. Confira a porta no servidor com `grep DFIR_PORT ~/corp-dfir/deploy/.env`; ela pode não ser 8443.
   - Erro de confiança/SSL: o `-CertThumbprint` não confere. Copie de novo o valor impresso pelo `install.sh`.
2. **Log na máquina:**
   - `C:\ProgramData\CorpDFIR\cert-collect.log`: uma linha por passo, com o ID da execução;
   - `C:\ProgramData\CorpDFIR\collect.log`: transcrição completa do coletor principal.
3. **Pacotes pendentes:** arquivos `CorpDFIR-*.zip` em `C:\ProgramData\CorpDFIR\` foram coletados, mas não enviados. São reenviados na próxima execução.
4. **No servidor:** `cd ~/corp-dfir/deploy && docker compose logs --tail 100 api caddy`.

## Acompanhar a execução no painel ("Execuções")

Desde a versão 1.1 (principal) e cert-1.1.0 (certificados), os dois scripts informam o progresso ao painel enquanto rodam:

- **Painel → Execuções** (e um bloco "Execuções em andamento" na página inicial). Mostra máquina, script, passo atual, barra de porcentagem, último sinal e início. A página se atualiza a cada 15 s. Clicando na máquina, aparece o histórico de passos da execução.
- O progresso é enviado a cada passo concluído e, nos passos longos (busca e cópia de arquivos, leitura de logs), no máximo a cada 15 s, com detalhes como "copiando 120/800".
- Situações:
  - **em andamento**;
  - **concluído**;
  - **concluído com erro**: coletou, mas algum envio ficou pendente;
  - **falhou**: o script parou; o detalhe traz a linha do erro;
  - **sem sinal há +10 min**: o script travou, a máquina desligou ou perdeu a rede.
- O envio do progresso tem tempo-limite de 5 s e não interrompe a coleta se o painel estiver fora do ar.
- Execuções iniciadas com versões anteriores dos scripts não aparecem nessa página.

## Coletor principal sem conversas de IA

Adicione `-SemIA` aos argumentos do coletor principal (1.3.0+). Ele deixa de coletar conversas de agentes de IA e mantém os logs de acesso remoto, segredos soltos (`.env`, históricos de terminal) e o inventário de certificados.

## Quarentena de certificados (`collector/Invoke-DfirCertQuarantine.ps1`)

Remove certificados digitais **de terceiros** das máquinas, preservando-os como prova.

| Modo | O que faz |
|---|---|
| `Relatorio` (padrão) | Só lista o que faria (`MOVERIA`, `MANTIDO`, `INSTALADO`). Não altera nada. **Rode este primeiro.** |
| `-Modo Quarentena` | Move `.pfx/.p12/.key/.pem` (e `.cer/.crt` com `-IncluirPublicos`) das pastas Área de Trabalho, Documentos, Downloads e OneDrive, além das cópias na lixeira, para `C:\ProgramData\CorpDFIR\quarentena\<lote>\`. A pasta fica acessível só para SYSTEM e Administradores, com `manifesto.json` (caminho original, SHA-256, datas, origem do download). |
| `-Modo Restaurar -Lote <lote>` | Devolve os arquivos do lote aos caminhos originais. |

- **Mantidos:**
  - CNPJs em `-ManterCnpj` (padrão `10353336000191`, Quality; vários separados por vírgula);
  - nomes que casam com `-ManterNome` (padrão `quality|webposto`), tanto no titular do certificado quanto no nome do arquivo.
- **AppData e pastas de programas não são tocados**, porque softwares podem usar certificados guardados ali. Eles aparecem como `IGNORADO`.
- **Certificados instalados no Windows:**
  - Só são removidos com `-Modo Quarentena -RemoverInstalados`. A chave privada não pode ser movida, só apagada, então antes da remoção o script salva a parte pública (`.cer`) e os dados.
  - Como **SYSTEM**: trata o repositório da máquina e apenas lista os perfis com certificados instalados.
  - Para os do **perfil do usuário**: cadastre uma cópia do script no Tactical com "Run as user" (o usuário precisa estar logado).
- O progresso aparece em **Execuções** como `quarentena-relatorio` ou `quarentena-quarentena`, e o log local fica em `C:\ProgramData\CorpDFIR\quarentena.log`.
- **Atenção a máquinas de desenvolvimento:** arquivos `.pem/.key` podem ser chaves de outros sistemas. Confira o modo `Relatorio` antes.
- Remover os arquivos não desfaz a exposição. Os certificados que ficaram expostos (principalmente os com senha no nome) devem ser **revogados e reemitidos pelos clientes**.
