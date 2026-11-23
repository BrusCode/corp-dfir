<#
.SYNOPSIS
  Corp-DFIR — quarentena de certificados digitais de TERCEIROS numa máquina da empresa.

  Modos:
    Relatorio  (padrão) lista o que seria feito, sem alterar nada.
    Quarentena move os arquivos de certificado para C:\ProgramData\CorpDFIR\quarentena\<lote>,
               acessível só por SYSTEM e Administradores, com manifesto (caminho, hash, datas, origem).
    Restaurar  devolve um lote aos caminhos originais (-Lote <nome da pasta>).

  Mantém certificados da própria empresa: CNPJs em -ManterCnpj e nomes que casam com -ManterNome.
  Só atua nas pastas do usuário (Área de Trabalho, Documentos, Downloads, OneDrive); AppData e
  pastas de programas são apenas listadas, para não quebrar softwares que usem certificados.

  Certificados INSTALADOS no Windows: a chave privada não pode ser movida com segurança, só
  apagada. Por isso só são removidos com -RemoverInstalados (a parte pública e os dados são
  salvos antes). Os do perfil do usuário exigem executar como o usuário logado (Tactical
  "Run as user"); como SYSTEM, o script trata o repositório da máquina e só lista os de usuário.

.EXAMPLE
  Relatório:   -Server 192.168.10.56 -Port 8444 -Token XXXX
  Quarentena:  -Server 192.168.10.56 -Port 8444 -Token XXXX -Modo Quarentena
  Restaurar:   -Modo Restaurar -Lote 20261124T120000Z
#>
[CmdletBinding()]
param(
    [string]$Server = "",
    [string]$Token = "",
    [int]$Port = 8443,
    [string]$CertThumbprint = "",
    [ValidateSet("Relatorio", "Quarentena", "Restaurar")][string]$Modo = "Relatorio",
    [string]$ManterCnpj = "10353336000191",
    [string]$ManterNome = "quality|webposto",
    [switch]$IncluirPublicos,
    [switch]$RemoverInstalados,
    [string]$Lote = ""
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
$Version = "quarentena-1.0.0"
$Root = "C:\ProgramData\CorpDFIR"
$QuarantineRoot = Join-Path $Root "quarentena"
$RunId = [Guid]::NewGuid().ToString("N").Substring(0, 12)
$Utf8 = New-Object System.Text.UTF8Encoding($false)
$KeepCnpjs = @($ManterCnpj -split "[,; ]+" | ForEach-Object { $_ -replace "\D", "" } | Where-Object { $_ })
$UserFolders = @("Desktop", "Documents", "Downloads", "OneDrive")
$PrivateExt = @(".pfx", ".p12", ".key", ".pem")
$PublicExt = @(".cer", ".crt")
$IsSystem = ([Security.Principal.WindowsIdentity]::GetCurrent().User.Value -eq "S-1-5-18")

if (-not (Test-Path -LiteralPath $Root)) { New-Item -ItemType Directory -Path $Root -Force | Out-Null }
$LogFile = Join-Path $Root "quarentena.log"

# --- Progresso no painel (opcional) e log local ---------------------------------------------
if ($Server) {
    [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $Pin = ($CertThumbprint -replace "[^0-9A-Fa-f]", "").ToUpperInvariant()
    [Net.ServicePointManager]::ServerCertificateValidationCallback = {
        param($sender, $cert, $chain, $errors)
        if ($Pin) { return ($cert.GetCertHashString().ToUpperInvariant() -eq $Pin) }
        return $true
    }.GetNewClosure()
}

function Write-Step([string]$Step, [string]$Status, [int]$Percent, [string]$Detail = "") {
    $line = "{0} run={1} modo={2} passo={3} status={4} {5}" -f (Get-Date).ToUniversalTime().ToString("o"), $RunId, $Modo, $Step, $Status, $Detail
    try { [IO.File]::AppendAllText($LogFile, $line + "`r`n", $Utf8) } catch { }
    if ($Server -and $Token) {
        try {
            $payload = New-Object PSObject -Property ([ordered]@{
                run_id = $RunId; host = $env:COMPUTERNAME; collector = "quarentena-$Modo".ToLowerInvariant()
                version = $Version; step = $Step; status = $Status; percent = $Percent
                detail = $(if ($Detail.Length -gt 900) { $Detail.Substring(0, 900) } else { $Detail }) })
            $bytes = $Utf8.GetBytes((ConvertTo-Json $payload -Compress))
            $req = [Net.HttpWebRequest]::Create("https://${Server}:$Port/api/v1/progress")
            $req.Method = "POST"; $req.ContentType = "application/json"; $req.Timeout = 5000
            $req.Headers.Add("X-DFIR-Token", $Token)
            $req.ContentLength = $bytes.Length
            $st = $req.GetRequestStream(); $st.Write($bytes, 0, $bytes.Length); $st.Dispose()
            $req.GetResponse().Dispose()
        } catch { }
    }
    Write-Output $line
}

trap {
    Write-Step "falha" "erro" 0 ("linha {0}: {1}" -f $_.InvocationInfo.ScriptLineNumber, $_.Exception.Message)
    break
}

# --- Helpers -----------------------------------------------------------------------------------
function Get-Sha256OfFile([string]$Path) {
    $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
    try {
        $sha = [Security.Cryptography.SHA256]::Create()
        return ([BitConverter]::ToString($sha.ComputeHash($stream)) -replace "-", "").ToLowerInvariant()
    } finally { $stream.Dispose() }
}

function Get-ZoneUrl([string]$Path) {
    try {
        foreach ($l in (Get-Content -LiteralPath $Path -Stream Zone.Identifier -ErrorAction Stop)) {
            if ($l -match "^HostUrl=(.+)") { return $Matches[1] }
        }
    } catch { }
    return ""
}

function Get-CertSubject([string]$Path, [string]$Ext) {
    # Reads the subject without exporting anything; PFX only if it opens without a password.
    try {
        if ($Ext -eq ".pfx" -or $Ext -eq ".p12") {
            $c = New-Object Security.Cryptography.X509Certificates.X509Certificate2 ($Path, "",
                [Security.Cryptography.X509Certificates.X509KeyStorageFlags]::EphemeralKeySet)
        } else {
            $c = New-Object Security.Cryptography.X509Certificates.X509Certificate2 ($Path)
        }
        $s = $c.Subject
        $c.Reset()
        return $s
    } catch { return "" }
}

function Test-Keep([string]$Text) {
    # True when the text (subject or file name) belongs to the company itself.
    if (-not $Text) { return $false }
    $digits = $Text -replace "\D", ""
    foreach ($c in $KeepCnpjs) { if ($c -and $digits.Contains($c)) { return $true } }
    return ($Text -match "(?i)$ManterNome")
}

function Add-JsonRecord($List, $Dict) {
    # Lists only hold JSON strings (Windows PowerShell 5.1 fails enumerating lists of [ordered]).
    $plain = New-Object System.Collections.Specialized.OrderedDictionary
    foreach ($k in $Dict.Keys) { $v = $Dict[$k]; $plain[[string]$k] = $(if ($null -eq $v) { $null } elseif ($v -is [bool]) { $v } else { [string]$v }) }
    $List.Add([string](ConvertTo-Json (New-Object PSObject -Property $plain) -Compress))
}

function Protect-Folder([string]$Path) {
    # Only SYSTEM (S-1-5-18) and Administrators (S-1-5-32-544); SIDs work in any Windows language.
    & icacls.exe $Path /inheritance:r /grant:r "*S-1-5-18:(OI)(CI)F" "*S-1-5-32-544:(OI)(CI)F" | Out-Null
}

$profiles = @(Get-ChildItem -LiteralPath "C:\Users" -Directory -Force -ErrorAction SilentlyContinue |
    Where-Object { @("Public", "Default", "Default User", "All Users", "WDAGUtilityAccount") -notcontains $_.Name -and
        -not ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) })

Write-Step "inicio" "ok" 0 ("host={0} modo={1} contexto={2} manter_cnpj={3} manter_nome={4}" -f $env:COMPUTERNAME, $Modo, $(if ($IsSystem) { "SYSTEM" } else { "usuario" }), ($KeepCnpjs -join ","), $ManterNome)

# --- Restaurar ---------------------------------------------------------------------------------
if ($Modo -eq "Restaurar") {
    if (-not $Lote) { Write-Step "restaurar" "erro" 0 "informe -Lote <pasta do lote em $QuarantineRoot>"; exit 2 }
    $batchDir = Join-Path $QuarantineRoot $Lote
    $manifestPath = Join-Path $batchDir "manifesto.json"
    if (-not (Test-Path -LiteralPath $manifestPath)) { Write-Step "restaurar" "erro" 0 "manifesto não encontrado: $manifestPath"; exit 2 }
    $restored = 0; $skipped = 0
    foreach ($item in (Get-Content -LiteralPath $manifestPath -Raw -Encoding UTF8 | ConvertFrom-Json)) {
        $src = Join-Path $batchDir $item.quarantine_name
        if (-not (Test-Path -LiteralPath $src)) { $skipped++; continue }
        if (Test-Path -LiteralPath $item.original_path) {
            Write-Output ("JA_EXISTE   {0}" -f $item.original_path); $skipped++; continue
        }
        $parent = Split-Path -Parent $item.original_path
        if (-not (Test-Path -LiteralPath $parent)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
        Move-Item -LiteralPath $src -Destination $item.original_path
        Write-Output ("RESTAURADO  {0}" -f $item.original_path)
        $restored++
    }
    Write-Step "fim" "ok" 100 ("restaurados={0} ignorados={1} lote={2}" -f $restored, $skipped, $Lote)
    exit 0
}

# --- Levantamento dos arquivos -----------------------------------------------------------------
$targets = New-Object System.Collections.Generic.List[object]   # PSCustomObject (seguro no PS 5.1)
$listed = 0
foreach ($p in $profiles) {
    foreach ($folder in $UserFolders) {
        $base = Join-Path $p.FullName $folder
        if (-not (Test-Path -LiteralPath $base)) { continue }
        $exts = $PrivateExt + $(if ($IncluirPublicos) { $PublicExt } else { @() })
        foreach ($ext in $exts) {
            foreach ($f in (Get-ChildItem -LiteralPath $base -Filter "*$ext" -File -Recurse -Depth 8 -Force -ErrorAction SilentlyContinue)) {
                $targets.Add([pscustomobject]@{ File = $f; ProfileName = $p.Name; Source = "pasta" })
            }
        }
    }
    # Informative only: certificates kept by applications under AppData are never touched.
    foreach ($ext in @(".pfx", ".p12")) {
        foreach ($f in (Get-ChildItem -LiteralPath (Join-Path $p.FullName "AppData") -Filter "*$ext" -File -Recurse -Depth 8 -Force -ErrorAction SilentlyContinue)) {
            Write-Output ("IGNORADO    (AppData, pode estar em uso por aplicativo) {0}" -f $f.FullName); $listed++
        }
    }
}
# Recoverable copies in the Recycle Bin ($R files, with the original name in the matching $I).
foreach ($drive in (Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" -ErrorAction SilentlyContinue)) {
    $bin = "$($drive.DeviceID)\`$Recycle.Bin"
    foreach ($i in (Get-ChildItem -LiteralPath $bin -Filter '$I*' -File -Recurse -Force -ErrorAction SilentlyContinue)) {
        try {
            $b = [IO.File]::ReadAllBytes($i.FullName)
            if ($b.Length -lt 28) { continue }
            if ([BitConverter]::ToInt64($b, 0) -eq 2) {
                $orig = [Text.Encoding]::Unicode.GetString($b, 28, [Math]::Min([BitConverter]::ToInt32($b, 24) * 2, $b.Length - 28)).TrimEnd([char]0)
            } else {
                $orig = [Text.Encoding]::Unicode.GetString($b, 24, [Math]::Min(520, $b.Length - 24)).TrimEnd([char]0)
            }
            $ext = [IO.Path]::GetExtension($orig).ToLowerInvariant()
            $wanted = ($PrivateExt -contains $ext) -or ($IncluirPublicos -and ($PublicExt -contains $ext))
            $rPath = Join-Path $i.DirectoryName ($i.Name -replace '^\$I', '$R')
            if ($wanted -and (Test-Path -LiteralPath $rPath)) {
                $targets.Add([pscustomobject]@{ File = (Get-Item -LiteralPath $rPath -Force); ProfileName = (Split-Path -Leaf $i.DirectoryName); Source = "lixeira:$orig" })
            }
        } catch { }
    }
}
Write-Step "levantamento" "ok" 30 ("arquivos candidatos={0}" -f $targets.Count)

# --- Decisão e quarentena dos arquivos ---------------------------------------------------------
$stamp = (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssZ")
$batchDir = Join-Path $QuarantineRoot $stamp
$manifest = New-Object System.Collections.Generic.List[string]
$moved = 0; $kept = 0; $wouldMove = 0; $errors = 0; $seq = 0
if ($Modo -eq "Quarentena" -and $targets.Count -gt 0) {
    if (-not (Test-Path -LiteralPath $QuarantineRoot)) { New-Item -ItemType Directory -Path $QuarantineRoot -Force | Out-Null }
    Protect-Folder $QuarantineRoot
    New-Item -ItemType Directory -Path $batchDir -Force | Out-Null
}
foreach ($t in $targets) {
    $f = $t.File
    $original = $(if ($t.Source -like "lixeira:*") { $t.Source.Substring(8) } else { $f.FullName })
    $ext = [IO.Path]::GetExtension($original).ToLowerInvariant()
    $subject = Get-CertSubject $f.FullName $ext
    if ((Test-Keep $subject) -or (Test-Keep ([IO.Path]::GetFileName($original)))) {
        Write-Output ("MANTIDO     (empresa) {0}" -f $original); $kept++; continue
    }
    if ($Modo -ne "Quarentena") {
        Write-Output ("MOVERIA     {0}{1}" -f $original, $(if ($t.Source -like "lixeira:*") { "  [cópia na lixeira]" } else { "" })); $wouldMove++; continue
    }
    try {
        $seq++
        $qName = "{0:D4}_{1}" -f $seq, ([IO.Path]::GetFileName($original) -replace '[\\/:*?"<>|]', "_")
        $record = [ordered]@{
            quarantine_name = $qName; original_path = $original; source = $t.Source; profile = $t.ProfileName
            sha256 = (Get-Sha256OfFile $f.FullName); size = $f.Length; subject = $subject
            created = $f.CreationTimeUtc.ToString("o"); modified = $f.LastWriteTimeUtc.ToString("o")
            download_url = (Get-ZoneUrl $f.FullName); quarantined_at = (Get-Date).ToUniversalTime().ToString("o")
        }
        Move-Item -LiteralPath $f.FullName -Destination (Join-Path $batchDir $qName)
        Add-JsonRecord $manifest $record
        Write-Output ("QUARENTENA  {0}" -f $original); $moved++
    } catch {
        Write-Output ("ERRO        {0}: {1}" -f $original, $_.Exception.Message); $errors++
    }
}
if ($Modo -eq "Quarentena" -and $manifest.Count -gt 0) {
    [IO.File]::WriteAllText((Join-Path $batchDir "manifesto.json"), "[" + ($manifest -join ",") + "]", $Utf8)
}
Write-Step "arquivos" $(if ($errors) { "erro" } else { "ok" }) 70 ("quarentena={0} moveria={1} mantidos={2} erros={3} lote={4}" -f $moved, $wouldMove, $kept, $errors, $(if ($moved) { $stamp } else { "-" }))

# --- Certificados instalados -------------------------------------------------------------------
function Test-ThirdPartyCert($Cert) {
    if (Test-Keep $Cert.Subject) { return $false }
    if ($Cert.Subject -match "\d{14}") { return $true }                         # e-CNPJ de outra empresa
    return ($Cert.Issuer -match "(?i)itau|sts-s\d+|bradesco|santander|sicoob|sicredi|banco do brasil|caixa econ|banco inter")
}

$installedStores = @()
if ($IsSystem) { $installedStores += "Cert:\LocalMachine\My" } else { $installedStores += "Cert:\CurrentUser\My" }
$removed = 0; $wouldRemove = 0
$exportDir = $(if ($IsSystem) { Join-Path $batchDir "instalados" } else { Join-Path $env:LOCALAPPDATA "CorpDFIR\removidos\$stamp" })
foreach ($store in $installedStores) {
    foreach ($c in (Get-ChildItem $store -ErrorAction SilentlyContinue)) {
        if (-not (Test-ThirdPartyCert $c)) { continue }
        $label = "{0} | chave privada: {1} | {2}" -f $c.Subject, $(if ($c.HasPrivateKey) { "sim" } else { "não" }), $store
        if ($Modo -ne "Quarentena" -or -not $RemoverInstalados) {
            Write-Output ("INSTALADO   {0}{1}" -f $label, $(if ($Modo -eq "Quarentena") { "  (use -RemoverInstalados para remover)" } else { "" })); $wouldRemove++; continue
        }
        try {
            if (-not (Test-Path -LiteralPath $exportDir)) {
                New-Item -ItemType Directory -Path $exportDir -Force | Out-Null
                if ($IsSystem) { Protect-Folder $QuarantineRoot }
            }
            # Public part and metadata only: the private key is destroyed, never exported.
            [IO.File]::WriteAllBytes((Join-Path $exportDir "$($c.Thumbprint).cer"), $c.Export([Security.Cryptography.X509Certificates.X509ContentType]::Cert))
            [IO.File]::WriteAllText((Join-Path $exportDir "$($c.Thumbprint).txt"), ("{0}`r`nemissor: {1}`r`nvalidade: {2}`r`nchave privada: {3}`r`nremovido em: {4}" -f $c.Subject, $c.Issuer, $c.NotAfter.ToString("o"), $c.HasPrivateKey, (Get-Date).ToUniversalTime().ToString("o")), $Utf8)
            Remove-Item -LiteralPath (Join-Path $store $c.Thumbprint) -DeleteKey
            Write-Output ("REMOVIDO    {0}" -f $label); $removed++
        } catch {
            Write-Output ("ERRO        {0}: {1}" -f $label, $_.Exception.Message); $errors++
        }
    }
}
if ($IsSystem) {
    # SYSTEM cannot remove certificates from users' stores with their keys: list them for a user run.
    foreach ($p in $profiles) {
        $blobDir = Join-Path $p.FullName "AppData\Roaming\Microsoft\SystemCertificates\My\Certificates"
        $n = @(Get-ChildItem -LiteralPath $blobDir -File -Force -ErrorAction SilentlyContinue).Count
        if ($n -gt 0) { Write-Output ("USUARIO     perfil {0}: {1} certificado(s) instalados; para remover os de terceiros, rode como o usuário logado com -Modo Quarentena -RemoverInstalados" -f $p.Name, $n) }
    }
}
Write-Step "instalados" $(if ($errors) { "erro" } else { "ok" }) 90 ("removidos={0} listados={1}" -f $removed, $wouldRemove)

$summary = "modo={0} quarentena={1} moveria={2} mantidos={3} instalados_removidos={4} instalados_listados={5} erros={6}" -f $Modo, $moved, $wouldMove, $kept, $removed, $wouldRemove, $errors
if ($moved) { $summary += " lote=$stamp (restaurar: -Modo Restaurar -Lote $stamp)" }
Write-Step "fim" $(if ($errors) { "erro" } else { "ok" }) 100 $summary
if ($errors) { exit 2 }
exit 0
