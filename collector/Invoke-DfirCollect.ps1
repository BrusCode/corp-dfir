<#
.SYNOPSIS
  Corp-DFIR collector: copies AI agent artifacts and remote-access logs and sends them
  to the analysis server. Run as SYSTEM by Tactical RMM.

.PARAMETER Server
  IP or host of the Ubuntu analysis server.
.PARAMETER Token
  Upload token printed by install.sh.
.PARAMETER Port
  HTTPS port of the server (default 8443).
.PARAMETER CertThumbprint
  SHA-1 thumbprint of the server certificate (printed by install.sh). Recommended.
.PARAMETER TestConnection
  Only checks that the server is reachable and the token is valid.
.PARAMETER SemIA
  Skips AI agent conversations (Claude, Codex, Gemini/Antigravity, Cursor, VS Code, ...);
  keeps remote access logs, loose secrets and certificates.
.PARAMETER DryRun
  Lists what would be collected, without copying or sending.

.EXAMPLE
  Tactical > Script Arguments:
  -Server 192.168.0.50 -Token XXXX -CertThumbprint AB12...
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Server,
    [Parameter(Mandatory = $true)][string]$Token,
    [int]$Port = 8443,
    [string]$CertThumbprint = "",
    [switch]$TestConnection,
    [switch]$SemIA,
    [switch]$DryRun
)

$ErrorActionPreference = "Stop"
trap {
    # Uncaught error: print the line number (also captured by the transcript) and stop.
    $failMsg = "linha {0}: {1}" -f $_.InvocationInfo.ScriptLineNumber, $_.Exception.Message
    Write-Output ("FALHA " + $failMsg)
    if (Get-Command Send-Progress -ErrorAction SilentlyContinue) { Send-Progress "falha" "erro" $script:LastPercent $failMsg }
    break
}
$ProgressPreference = "SilentlyContinue"

$CollectorVersion = "1.3.0"
$StagingRoot = "C:\ProgramData\CorpDFIR"      # Única exceção do Bitdefender.
$MaxFileBytes = 200MB
$MaxBundleBytes = 2GB
$PauseMs = 150
$HashOnlyExtensions = @(".pfx", ".p12", ".key", ".cer", ".crt", ".pem")
$SkipProfiles = @("Public", "Default", "Default User", "All Users", "WDAGUtilityAccount")

# --- Log local e teste de conexão ----------------------------------------------------------
if (-not (Test-Path -LiteralPath $StagingRoot)) { New-Item -ItemType Directory -Path $StagingRoot -Force | Out-Null }
# Registra toda a execução (inclusive erros) em C:\ProgramData\CorpDFIR\collect.log.
try { Start-Transcript -LiteralPath (Join-Path $StagingRoot "collect.log") -Append -Force | Out-Null } catch { }
"INICIO host={0} versao={1} servidor=https://{2}:{3}" -f $env:COMPUTERNAME, $CollectorVersion, $Server, $Port
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$pinEarly = ($CertThumbprint -replace "[^0-9A-Fa-f]", "").ToUpperInvariant()
[Net.ServicePointManager]::ServerCertificateValidationCallback = {
    param($sender, $cert, $chain, $errors)
    if ($pinEarly) { return ($cert.GetCertHashString().ToUpperInvariant() -eq $pinEarly) }
    return $true
}.GetNewClosure()
# --- Progresso no painel ("Execuções") -----------------------------------------------------
$RunId = [Guid]::NewGuid().ToString("N").Substring(0, 12)
$ProgUtf8 = New-Object System.Text.UTF8Encoding($false)
$script:LastPercent = 0
$script:LastProgressAt = [DateTime]::MinValue

function Send-Progress([string]$Step, [string]$Status, [int]$Percent, [string]$Detail = "") {
    # Fire-and-forget: never slows down or breaks the collection if the panel is unreachable.
    try {
        $payload = New-Object PSObject -Property ([ordered]@{
            run_id = $RunId; host = $env:COMPUTERNAME; collector = "principal"; version = $CollectorVersion
            step = $Step; status = $Status; percent = $Percent
            detail = $(if ($Detail.Length -gt 900) { $Detail.Substring(0, 900) } else { $Detail }) })
        $bytes = $ProgUtf8.GetBytes((ConvertTo-Json $payload -Compress))
        $req = [Net.HttpWebRequest]::Create("https://${Server}:$Port/api/v1/progress")
        $req.Method = "POST"
        $req.ContentType = "application/json"
        $req.Headers.Add("X-DFIR-Token", $Token)
        $req.Timeout = 5000
        $req.ReadWriteTimeout = 5000
        $req.ContentLength = $bytes.Length
        $st = $req.GetRequestStream(); $st.Write($bytes, 0, $bytes.Length); $st.Dispose()
        $req.GetResponse().Dispose()
    } catch { }
    if ($Percent -gt $script:LastPercent) { $script:LastPercent = $Percent }
    $script:LastProgressAt = Get-Date
    "PROGRESSO run={0} passo={1} status={2} {3}% {4}" -f $RunId, $Step, $Status, $Percent, $Detail
}

function Send-SubProgress([string]$Step, [string]$Detail, [int]$From, [int]$To, [int]$Done, [int]$Total) {
    if (((Get-Date) - $script:LastProgressAt).TotalSeconds -lt 15) { return }
    $pct = $From
    if ($Total -gt 0) { $pct = [int]($From + ($To - $From) * [Math]::Min(1, $Done / $Total)) }
    Send-Progress $Step "info" $pct $Detail | Out-Null
}

Send-Progress "inicio" "ok" 0 ("servidor=https://{0}:{1}" -f $Server, $Port)
try {
    $pingReq = [Net.HttpWebRequest]::Create("https://${Server}:$Port/api/v1/ping")
    $pingReq.Headers.Add("X-DFIR-Token", $Token)
    $pingReq.Timeout = 15000
    $pingResp = $pingReq.GetResponse(); $pingResp.Dispose()
    "CONEXAO ok (servidor alcançado e token válido)"
    Send-Progress "conexao" "ok" 2 "servidor alcançado e token válido"
} catch {
    $r = $_.Exception.Response
    if ($r) { "CONEXAO erro HTTP {0} (401 = token errado)" -f [int]$r.StatusCode }
    else { "CONEXAO erro: {0}" -f $_.Exception.Message }
    if ($TestConnection) { exit 3 }
}
if ($TestConnection) { exit 0 }

# --- Baixo impacto -----------------------------------------------------------------------
try { (Get-Process -Id $PID).PriorityClass = "Idle" } catch { }

# --- Fontes --------------------------------------------------------------------------------
# Cada entrada: Category, relative path under the profile, file filter, recurse, max depth.
$ProfileSources = @(
    @{ Cat = "ia"; Path = ".claude"; Filter = "*"; Depth = 8 },
    @{ Cat = "ia"; Path = "AppData\Roaming\Claude"; Filter = "*.json*"; Depth = 6 },
    @{ Cat = "ia"; Path = ".codex"; Filter = "*"; Depth = 8 },
    @{ Cat = "ia"; Path = ".gemini"; Filter = "*"; Depth = 8 },
    @{ Cat = "ia"; Path = ".continue"; Filter = "*"; Depth = 6 },
    @{ Cat = "ia"; Path = ".cursor"; Filter = "*.json*"; Depth = 6 },
    @{ Cat = "ia"; Path = ".aider.chat.history.md"; Filter = "*"; Depth = 0 },
    @{ Cat = "ia"; Path = ".aider.input.history"; Filter = "*"; Depth = 0 },
    @{ Cat = "ia"; Path = "AppData\Roaming\Cursor\User\workspaceStorage"; Filter = "state.vscdb"; Depth = 3 },
    @{ Cat = "ia"; Path = "AppData\Roaming\Cursor\User\globalStorage"; Filter = "*"; Depth = 4 },
    @{ Cat = "ia"; Path = "AppData\Roaming\Code\User\workspaceStorage"; Filter = "state.vscdb"; Depth = 3 },
    @{ Cat = "ia"; Path = "AppData\Roaming\Code\User\globalStorage"; Filter = "*"; Depth = 5 },
    @{ Cat = "ia"; Path = "AppData\Roaming\Windsurf\User\workspaceStorage"; Filter = "state.vscdb"; Depth = 3 },
    @{ Cat = "ia"; Path = "AppData\Roaming\Windsurf\User\globalStorage"; Filter = "*"; Depth = 5 },
    @{ Cat = "ia"; Path = "AppData\Roaming\Antigravity\User\workspaceStorage"; Filter = "state.vscdb"; Depth = 3 },
    @{ Cat = "ia"; Path = "AppData\Roaming\Antigravity\User\globalStorage"; Filter = "*"; Depth = 5 },
    @{ Cat = "ia"; Path = "AppData\Roaming\com.openai.chat"; Filter = "*"; Depth = 6 },
    @{ Cat = "segredo"; Path = "AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine"; Filter = "*.txt"; Depth = 1 },
    @{ Cat = "segredo"; Path = ".bash_history"; Filter = "*"; Depth = 0 },
    @{ Cat = "segredo"; Path = ".gitconfig"; Filter = "*"; Depth = 0 },
    @{ Cat = "segredo"; Path = ".npmrc"; Filter = "*"; Depth = 0 },
    @{ Cat = "acesso_remoto"; Path = "AppData\Roaming\AnyDesk"; Filter = "*.trace"; Depth = 1 },
    @{ Cat = "acesso_remoto"; Path = "AppData\Roaming\AnyDesk"; Filter = "connection_trace.txt"; Depth = 1 },
    @{ Cat = "acesso_remoto"; Path = "AppData\Roaming\TeamViewer"; Filter = "*.log"; Depth = 2 },
    @{ Cat = "acesso_remoto"; Path = "AppData\Roaming\TeamViewer"; Filter = "Connections*.txt"; Depth = 2 },
    @{ Cat = "acesso_remoto"; Path = "AppData\Roaming\RustDesk\log"; Filter = "*"; Depth = 4 },
    @{ Cat = "acesso_remoto"; Path = "AppData\Roaming\RustDesk\config"; Filter = "*.toml"; Depth = 2 }
)
# Package-based apps (ChatGPT Desktop from the Store) have variable folder names.
$ProfileGlobSources = @(
    @{ Cat = "ia"; Glob = "AppData\Local\Packages\OpenAI.ChatGPT*"; Filter = "*.json*"; Depth = 8 }
)
# Loose secrets in work folders (OpenRouter keys and others).
$LooseFolders = @("Desktop", "Documents", "Downloads")
$LooseFilters = @(".env*", "*.pfx", "*.p12", "*.key", "*.cer", "*.crt", "*.pem")
$LooseDepth = 4

$SystemSources = @(
    @{ Cat = "acesso_remoto"; Path = "C:\ProgramData\AnyDesk"; Filter = "*.trace"; Depth = 2 },
    @{ Cat = "acesso_remoto"; Path = "C:\ProgramData\AnyDesk"; Filter = "connection_trace.txt"; Depth = 2 },
    @{ Cat = "acesso_remoto"; Path = "C:\Program Files\TeamViewer"; Filter = "*.log"; Depth = 1 },
    @{ Cat = "acesso_remoto"; Path = "C:\Program Files\TeamViewer"; Filter = "Connections*.txt"; Depth = 1 },
    @{ Cat = "acesso_remoto"; Path = "C:\Program Files (x86)\TeamViewer"; Filter = "*.log"; Depth = 1 },
    @{ Cat = "acesso_remoto"; Path = "C:\Program Files (x86)\TeamViewer"; Filter = "Connections*.txt"; Depth = 1 },
    @{ Cat = "acesso_remoto"; Path = "C:\Windows\ServiceProfiles\LocalService\AppData\Roaming\RustDesk\log"; Filter = "*"; Depth = 4 },
    @{ Cat = "acesso_remoto"; Path = "C:\Windows\ServiceProfiles\LocalService\AppData\Roaming\RustDesk\config"; Filter = "*.toml"; Depth = 2 },
    @{ Cat = "acesso_remoto"; Path = "C:\ProgramData\RustDesk"; Filter = "*"; Depth = 4 }
)

# --- Helpers -------------------------------------------------------------------------------
function ConvertTo-PlainValue($Value) {
    if ($null -eq $Value) { return $null }
    if ($Value -is [bool] -or $Value -is [int] -or $Value -is [long] -or $Value -is [double] -or $Value -is [decimal]) { return $Value }
    if ($Value -is [datetime]) { return $Value.ToUniversalTime().ToString("o") }
    return [string]$Value
}

function Add-Record($List, $Dict) {
    # Windows PowerShell 5.1 throws "Argument types do not match" when enumerating a list of
    # [ordered] dictionaries. Each record is turned into compact JSON right away, so the lists
    # only ever hold strings; a record that cannot be converted is counted and skipped.
    try {
        $plain = New-Object System.Collections.Specialized.OrderedDictionary
        foreach ($k in $Dict.Keys) { $plain[[string]$k] = ConvertTo-PlainValue $Dict[$k] }
        $List.Add([string](ConvertTo-Json (New-Object PSObject -Property $plain) -Compress -Depth 3))
    } catch { $script:JsonSkipped++ }
}

function Get-FilesBounded {
    param([string]$Root, [string]$Filter, [int]$Depth)
    if (-not (Test-Path -LiteralPath $Root)) { return @() }
    $item = Get-Item -LiteralPath $Root -Force -ErrorAction SilentlyContinue
    if ($null -eq $item) { return @() }
    if (-not $item.PSIsContainer) { return @($item) }
    if ($Depth -le 0) {
        return @(Get-ChildItem -LiteralPath $Root -Filter $Filter -File -Force -ErrorAction SilentlyContinue)
    }
    return @(Get-ChildItem -LiteralPath $Root -Filter $Filter -File -Recurse -Depth $Depth -Force -ErrorAction SilentlyContinue)
}

function Get-Sha256OfFile([string]$Path) {
    $stream = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read,
        [System.IO.FileShare]::ReadWrite -bor [System.IO.FileShare]::Delete)
    try {
        $sha = [System.Security.Cryptography.SHA256]::Create()
        return ([BitConverter]::ToString($sha.ComputeHash($stream)) -replace "-", "").ToLowerInvariant()
    } finally { $stream.Dispose() }
}

function Copy-Shared([string]$Source, [string]$Destination) {
    # Leitura compartilhada: funciona com SQLite/logs abertos pelos apps.
    $dir = Split-Path -Parent $Destination
    if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    $in = [System.IO.File]::Open($Source, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read,
        [System.IO.FileShare]::ReadWrite -bor [System.IO.FileShare]::Delete)
    try {
        $out = [System.IO.File]::Create($Destination)
        try { $in.CopyTo($out, 1MB) } finally { $out.Dispose() }
    } finally { $in.Dispose() }
}

function ConvertTo-ArchivePath([string]$Profile, [string]$FullName) {
    $rel = $FullName -replace "^[A-Za-z]:\\", "" -replace "[:*?""<>|]", "_"
    return ("files/{0}/{1}" -f $Profile, ($rel -replace "\\", "/"))
}


# --- Certificados (somente metadados; nunca a chave privada) -------------------------------
function Get-ZoneInfo([string]$Path) {
    # Zone.Identifier: origem do download (URL e página de referência), quando houver.
    $info = @{ zone_id = $null; host_url = $null; referrer_url = $null }
    try {
        $lines = Get-Content -LiteralPath $Path -Stream Zone.Identifier -ErrorAction Stop
        foreach ($l in $lines) {
            if ($l -match "^ZoneId=(\d+)") { $info.zone_id = [int]$Matches[1] }
            elseif ($l -match "^HostUrl=(.+)") { $info.host_url = $Matches[1] }
            elseif ($l -match "^ReferrerUrl=(.+)") { $info.referrer_url = $Matches[1] }
        }
    } catch { }
    return $info
}

function ConvertTo-CertRecord($Cert, [string]$Origin, [string]$Profile, [string]$Path) {
    $cnpj = $null
    if ($Cert.Subject -match "(\d{14})") { $cnpj = $Matches[1] }
    return [ordered]@{
        origin          = $Origin
        profile         = $Profile
        path            = $Path
        readable        = $true
        thumbprint      = $Cert.Thumbprint
        subject         = $Cert.Subject
        issuer          = $Cert.Issuer
        serial          = $Cert.SerialNumber
        not_before      = $Cert.NotBefore.ToUniversalTime().ToString("o")
        not_after       = $Cert.NotAfter.ToUniversalTime().ToString("o")
        has_private_key = $Cert.HasPrivateKey
        cnpj            = $cnpj
    }
}

function Get-StoreBlobCert([string]$BlobPath) {
    # User-store blobs: sequence of [propId(4) | reserved(4) | length(4) | data].
    # prop 0x20 = cert DER; prop 0x02 = KEY_PROV_INFO (a private key is associated).
    $bytes = [IO.File]::ReadAllBytes($BlobPath)
    $cert = $null; $hasKey = $false; $i = 0
    while ($i + 12 -le $bytes.Length) {
        $prop = [BitConverter]::ToUInt32($bytes, $i)
        $len = [BitConverter]::ToUInt32($bytes, $i + 8)
        if (($i + 12 + $len) -gt $bytes.Length) { break }
        if ($prop -eq 0x02) { $hasKey = $true }
        if ($prop -eq 0x20) {
            $der = New-Object byte[] $len
            [Array]::Copy($bytes, $i + 12, $der, 0, $len)
            $cert = New-Object Security.Cryptography.X509Certificates.X509Certificate2 (, $der)
        }
        $i += 12 + $len
    }
    if ($null -eq $cert) { return $null }
    return @{ Cert = $cert; HasKey = $hasKey }
}

function Get-CertInventory($Profiles, $Target) {
    foreach ($storePath in @("Cert:\LocalMachine\My", "Cert:\LocalMachine\Root", "Cert:\LocalMachine\CA")) {
        foreach ($c in (Get-ChildItem $storePath -ErrorAction SilentlyContinue)) {
            $r = ConvertTo-CertRecord $c "store:$storePath" "_system" $null
            # Root/CA store: only non-ICP or recently added roots are interesting; keep all, filter on server.
            Add-Record $Target $r
        }
    }
    foreach ($p in $Profiles) {
        $blobDir = Join-Path $p.FullName "AppData\Roaming\Microsoft\SystemCertificates\My\Certificates"
        foreach ($blob in (Get-ChildItem -LiteralPath $blobDir -File -Force -ErrorAction SilentlyContinue)) {
            try {
                $parsed = Get-StoreBlobCert $blob.FullName
                if ($parsed) {
                    $r = ConvertTo-CertRecord $parsed.Cert "store:CurrentUser\My" $p.Name $blob.FullName
                    $r.has_private_key = $parsed.HasKey
                    $r.file_created = $blob.CreationTimeUtc.ToString("o")
                    Add-Record $Target $r
                }
            } catch { }
            Start-Sleep -Milliseconds $PauseMs
        }
    }
}

function Get-CertFileRecord($File, [string]$Profile) {
    $ext = $File.Extension.ToLowerInvariant()
    $zone = Get-ZoneInfo $File.FullName
    $r = $null
    try {
        if ($ext -eq ".pfx" -or $ext -eq ".p12") {
            # Tenta sem senha; nunca exporta a chave privada.
            $c = New-Object Security.Cryptography.X509Certificates.X509Certificate2 ($File.FullName, "",
                [Security.Cryptography.X509Certificates.X509KeyStorageFlags]::EphemeralKeySet)
        } else {
            $c = New-Object Security.Cryptography.X509Certificates.X509Certificate2 ($File.FullName)
        }
        $r = ConvertTo-CertRecord $c "file" $Profile $File.FullName
        $c.Reset()
    } catch {
        $r = [ordered]@{ origin = "file"; profile = $Profile; path = $File.FullName; readable = $false;
            thumbprint = $null; subject = $null; issuer = $null; serial = $null; not_before = $null;
            not_after = $null; has_private_key = ($ext -in ".pfx", ".p12", ".key"); cnpj = $null }
    }
    $r.extension = $ext
    $r.file_sha256 = Get-Sha256OfFile $File.FullName
    $r.file_created = $File.CreationTimeUtc.ToString("o")
    $r.file_modified = $File.LastWriteTimeUtc.ToString("o")
    $r.zone_id = $zone.zone_id
    $r.host_url = $zone.host_url
    $r.referrer_url = $zone.referrer_url
    return $r
}

# --- Coleta --------------------------------------------------------------------------------
$hostName = $env:COMPUTERNAME
$stamp = (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssZ")
$runDir = Join-Path $StagingRoot "run-$stamp"
$bundleName = "CorpDFIR-$hostName-$stamp.zip"

$candidates = New-Object System.Collections.Generic.List[object]
function Add-Candidates($Files, [string]$Profile, [string]$Cat) {
    foreach ($f in $Files) { $candidates.Add([pscustomobject]@{ File = $f; Profile = $Profile; Cat = $Cat }) }
}

$profiles = Get-ChildItem -LiteralPath "C:\Users" -Directory -Force -ErrorAction SilentlyContinue |
    Where-Object { $SkipProfiles -notcontains $_.Name -and -not ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) }

foreach ($p in $profiles) {
    foreach ($s in $ProfileSources) {
        Add-Candidates (Get-FilesBounded (Join-Path $p.FullName $s.Path) $s.Filter $s.Depth) $p.Name $s.Cat
    }
    foreach ($g in $ProfileGlobSources) {
        foreach ($dir in (Get-Item -Path (Join-Path $p.FullName $g.Glob) -Force -ErrorAction SilentlyContinue)) {
            Add-Candidates (Get-FilesBounded $dir.FullName $g.Filter $g.Depth) $p.Name $g.Cat
        }
    }
    Add-Candidates (Get-FilesBounded $p.FullName ".env*" 0) $p.Name "segredo"
    foreach ($folder in $LooseFolders) {
        foreach ($flt in $LooseFilters) {
            Add-Candidates (Get-FilesBounded (Join-Path $p.FullName $folder) $flt $LooseDepth) $p.Name "segredo"
        }
    }
}
foreach ($s in $SystemSources) {
    Add-Candidates (Get-FilesBounded $s.Path $s.Filter $s.Depth) "_system" $s.Cat
}

# -SemIA: drop AI agent conversation sources before copying anything.
if ($SemIA) {
    $kept = New-Object System.Collections.Generic.List[object]
    foreach ($cand in $candidates) { if ($cand.Cat -ne "ia") { $kept.Add($cand) } }
    "SEMIA: {0} arquivo(s) de conversas de IA ignorados" -f ($candidates.Count - $kept.Count)
    $candidates = $kept
}

# Remove duplicates (overlapping filters).
$unique = $candidates | Sort-Object { $_.File.FullName } -Unique
$totalFiles = @($unique).Count
Send-Progress "varredura" "ok" 15 ("arquivos encontrados={0}" -f $totalFiles)

if ($DryRun) {
    $unique | ForEach-Object {
        "{0}`t{1}`t{2}`t{3}" -f $_.Cat, $_.Profile, $_.File.Length, $_.File.FullName
    }
    "DRYRUN: {0} arquivos, {1:N1} MB" -f @($unique).Count, (($unique | Measure-Object { $_.File.Length } -Sum).Sum / 1MB)
    Send-Progress "fim" "ok" 100 "DryRun: nada copiado nem enviado" | Out-Null
    exit 0
}

New-Item -ItemType Directory -Path $runDir -Force | Out-Null
$manifest = New-Object System.Collections.Generic.List[string]    # JSON por arquivo
$JsonSkipped = 0
$copiedCount = 0
$total = 0L
$fileIndex = 0
foreach ($c in $unique) {
    $fileIndex++
    Send-SubProgress "copia" ("copiando {0}/{1}" -f $fileIndex, $totalFiles) 15 75 $fileIndex $totalFiles
    $f = $c.File
    $entry = [ordered]@{
        profile       = $c.Profile
        category      = $c.Cat
        original_path = $f.FullName
        archive_path  = $null
        size          = $f.Length
        mtime         = $f.LastWriteTimeUtc.ToString("o")
        sha256        = $null
        status        = "copied"
    }
    try {
        $ext = $f.Extension.ToLowerInvariant()
        if ($HashOnlyExtensions -contains $ext) {
            $entry.sha256 = Get-Sha256OfFile $f.FullName
            $entry.status = "hash_only"
        } elseif ($f.Length -gt $MaxFileBytes) {
            $entry.status = "skipped_too_large"
        } elseif (($total + $f.Length) -gt $MaxBundleBytes) {
            $entry.status = "skipped_bundle_limit"
        } else {
            $arc = ConvertTo-ArchivePath $c.Profile $f.FullName
            Copy-Shared $f.FullName (Join-Path $runDir ($arc -replace "/", "\"))
            $entry.archive_path = $arc
            $entry.sha256 = Get-Sha256OfFile (Join-Path $runDir ($arc -replace "/", "\"))
            $total += $f.Length
        }
    } catch {
        $entry.status = "error: " + $_.Exception.GetType().Name
    }
    if ($entry.status -eq "copied") { $copiedCount++ }
    Add-Record $manifest $entry
    Start-Sleep -Milliseconds $PauseMs
}

$utf8 = New-Object System.Text.UTF8Encoding($false)
[string]$manifestJson = "[" + ($manifest -join ",") + "]"
[IO.File]::WriteAllText((Join-Path $runDir "manifest.json"), $manifestJson, $utf8)

Send-Progress "copia" "ok" 75 ("copiados={0}" -f $copiedCount)
$certRecords = New-Object System.Collections.Generic.List[string]  # JSON por certificado
try { Get-CertInventory $profiles $certRecords } catch { }
foreach ($c in $unique) {
    if (@(".pfx", ".p12", ".cer", ".crt", ".pem") -contains $c.File.Extension.ToLowerInvariant()) {
        try { Add-Record $certRecords (Get-CertFileRecord $c.File $c.Profile) } catch { }
    }
}
[string]$certsJson = "[" + ($certRecords -join ",") + "]"
if ($JsonSkipped -gt 0) { "AVISO: {0} registro(s) ignorado(s) por erro de conversão" -f $JsonSkipped }
[IO.File]::WriteAllText((Join-Path $runDir "certs.json"), $certsJson, $utf8)
$custody = [ordered]@{
    hostname          = $hostName
    operator          = [Security.Principal.WindowsIdentity]::GetCurrent().Name
    collected_at      = (Get-Date).ToUniversalTime().ToString("o")
    collector_version = $CollectorVersion
    files_total       = $manifest.Count
    files_copied      = $copiedCount
    json_skipped      = $JsonSkipped
    bytes_copied      = $total
    certificates      = $certRecords.Count
}
[IO.File]::WriteAllText((Join-Path $runDir "custody.json"), [string](ConvertTo-Json (New-Object PSObject -Property $custody) -Depth 3), $utf8)

Send-Progress "certificados" "ok" 80 ("certificados={0}" -f $certRecords.Count)
Add-Type -AssemblyName System.IO.Compression.FileSystem
$bundlePath = Join-Path $StagingRoot $bundleName
[IO.Compression.ZipFile]::CreateFromDirectory($runDir, $bundlePath, [IO.Compression.CompressionLevel]::Optimal, $false)
Remove-Item -LiteralPath $runDir -Recurse -Force -ErrorAction SilentlyContinue

# --- Envio ---------------------------------------------------------------------------------
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$pin = ($CertThumbprint -replace "[^0-9A-Fa-f]", "").ToUpperInvariant()
[Net.ServicePointManager]::ServerCertificateValidationCallback = {
    param($sender, $cert, $chain, $errors)
    if ($pin) { return ($cert.GetCertHashString().ToUpperInvariant() -eq $pin) }
    return $true   # sem pinning: aceita o certificado autoassinado da rede local
}.GetNewClosure()

function Send-Bundle([string]$Path) {
    $sha = Get-Sha256OfFile $Path
    $boundary = [Guid]::NewGuid().ToString("N")
    $name = [IO.Path]::GetFileName($Path)
    $head = $utf8.GetBytes("--$boundary`r`nContent-Disposition: form-data; name=""file""; filename=""$name""`r`nContent-Type: application/zip`r`n`r`n")
    $tail = $utf8.GetBytes("`r`n--$boundary--`r`n")
    $fileLen = (Get-Item -LiteralPath $Path).Length

    $req = [Net.HttpWebRequest]::Create("https://${Server}:$Port/api/v1/upload")
    $req.Method = "POST"
    $req.ContentType = "multipart/form-data; boundary=$boundary"
    $req.Headers.Add("X-DFIR-Token", $Token)
    $req.Headers.Add("X-DFIR-SHA256", $sha)
    $req.ContentLength = $head.Length + $fileLen + $tail.Length
    $req.AllowWriteStreamBuffering = $false
    $req.SendChunked = $false
    $req.Timeout = 3600000
    $req.ReadWriteTimeout = 3600000

    $body = $req.GetRequestStream()
    try {
        $body.Write($head, 0, $head.Length)
        $fs = [IO.File]::OpenRead($Path)
        try { $fs.CopyTo($body, 1MB) } finally { $fs.Dispose() }
        $body.Write($tail, 0, $tail.Length)
    } finally { $body.Dispose() }

    $resp = $req.GetResponse()
    try { return [int]$resp.StatusCode } finally { $resp.Dispose() }
}

# Envia o pacote atual e qualquer pendente de execuções anteriores.
Send-Progress "pacote" "ok" 88 ("pacote={0}" -f $bundleName)
$sent = 0; $failed = 0
foreach ($zip in (Get-ChildItem -LiteralPath $StagingRoot -Filter "CorpDFIR-*.zip" -File -ErrorAction SilentlyContinue)) {
    Send-Progress "envio" "info" 90 ("enviando {0} ({1:N1} MB)" -f $zip.Name, ($zip.Length / 1MB))
    try {
        $code = Send-Bundle $zip.FullName
        if ($code -eq 200 -or $code -eq 201) {
            Remove-Item -LiteralPath $zip.FullName -Force
            $sent++
        } else { $failed++ }
    } catch {
        $failed++
        "ENVIO_FALHOU {0}: {1}" -f $zip.Name, $_.Exception.Message
    }
}
# Limpa diretórios de execução que ficaram de execuções interrompidas.
Get-ChildItem -LiteralPath $StagingRoot -Directory -Filter "run-*" -ErrorAction SilentlyContinue |
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue

Send-Progress "fim" $(if ($failed) { "erro" } else { "ok" }) 100 ("enviados={0} pendentes={1}" -f $sent, $failed)
"OK host={0} arquivos={1} copiados={2} certificados={3} MB={4:N1} enviados={5} pendentes={6}" -f `
    $hostName, $custody.files_total, $custody.files_copied, $custody.certificates, ($total / 1MB), $sent, $failed
if ($failed -gt 0) { exit 2 }
exit 0
