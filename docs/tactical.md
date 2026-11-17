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
