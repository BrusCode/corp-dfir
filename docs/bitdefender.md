# Bitdefender — exceções para o Corp-DFIR

O coletor usa um caminho fixo de staging nos PCs:

```
C:\ProgramData\CorpDFIR\
```

## Exceção recomendada (GravityZone → Políticas → Antimalware → Configurações → Exclusões personalizadas)

| Tipo | Valor | Módulos |
|---|---|---|
| Pasta | `C:\ProgramData\CorpDFIR\` | On-access e On-demand |

Isso basta na maioria dos casos: evita que o antivírus bloqueie ou atrase a cópia de logs e históricos para o pacote `.zip`.

## Se o Bitdefender bloquear a execução do script (ATC/Advanced Threat Control)

Prefira, nesta ordem:

1. **Exclusão por linha de comando** (se sua versão do GravityZone suportar): processo `powershell.exe` com a linha de comando contendo `Invoke-DfirCollect`.
2. **Exclusão por hash** do arquivo `Invoke-DfirCollect.ps1`. Recalcule e atualize a exceção a cada nova versão do script:
   ```powershell
   Get-FileHash .\collector\Invoke-DfirCollect.ps1 -Algorithm SHA256
   ```
3. **Não** exclua `powershell.exe` inteiro nem o agente do Tactical: isso abre uma porta de entrada para malware em todas as máquinas.

## Aplicar só às máquinas do piloto

Crie uma política filha da política padrão, adicione a exceção nela e atribua só às máquinas do suporte do piloto. Remova a exceção ao fim da investigação.
