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
