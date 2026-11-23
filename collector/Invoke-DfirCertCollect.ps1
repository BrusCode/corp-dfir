<#
.SYNOPSIS
  Corp-DFIR — coleta focada em CERTIFICADOS DIGITAIS: quais existem na máquina, quais estão
  instalados ou salvos em arquivo, e quando/como foram abertos, importados, exportados,
  transferidos por acesso remoto ou apagados. Executado como SYSTEM pelo Tactical RMM.

  Só metadados e hashes: chaves privadas e arquivos .pfx NUNCA são copiados.

.PARAMETER Server         IP ou host do servidor Corp-DFIR.
.PARAMETER Token          Token de upload impresso pelo install.sh.
.PARAMETER Port           Porta do servidor (a impressa pelo install.sh).
.PARAMETER CertThumbprint Impressão SHA-1 do certificado do servidor (recomendado).
.PARAMETER TestConnection Só testa a conexão e o token; não coleta nada.
.PARAMETER DryRun         Coleta e mostra o resumo, mas não envia.

.EXAMPLE
  -Server 192.168.10.56 -Port 8444 -Token XXXX -CertThumbprint AB12... -TestConnection
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)][string]$Server,
    [Parameter(Mandatory = $true)][string]$Token,
    [int]$Port = 8443,
    [string]$CertThumbprint = "",
    [switch]$TestConnection,
    [switch]$DryRun
)

$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
$CollectorVersion = "cert-1.3.0"
$StagingRoot = "C:\ProgramData\CorpDFIR"      # Mesma exceção do Bitdefender do coletor principal.
$PauseMs = 50
$CertExtensions = @(".pfx", ".p12", ".cer", ".crt", ".pem", ".key")
$CertExtPattern = "\.(pfx|p12|cer|crt|pem|key)\b"
$SkipProfiles = @("Public", "Default", "Default User", "All Users", "WDAGUtilityAccount")
$RunId = [Guid]::NewGuid().ToString("N").Substring(0, 12)

try { (Get-Process -Id $PID).PriorityClass = "Idle" } catch { }
if (-not (Test-Path -LiteralPath $StagingRoot)) { New-Item -ItemType Directory -Path $StagingRoot -Force | Out-Null }
$LogFile = Join-Path $StagingRoot "cert-collect.log"
$Utf8 = New-Object System.Text.UTF8Encoding($false)

# Percent reached when each step finishes (progress shown in the panel's "Execuções" page).
$StepPercent = @{ inicio = 0; conexao = 2; instalados = 10; arquivos = 40; recentes = 45; historico = 48
    acesso_remoto = 60; lixeira = 65; eventos = 75; execucao = 78; chaves = 80; pacote = 88; envio = 95; fim = 100 }
$script:LastPercent = 0
$script:LastProgressAt = [DateTime]::MinValue

function Send-Progress([string]$Step, [string]$Status, [int]$Percent, [string]$Detail) {
    # Fire-and-forget: never slows down or breaks the collection if the panel is unreachable.
    try {
        $payload = New-Object PSObject -Property ([ordered]@{
            run_id = $RunId; host = $env:COMPUTERNAME; collector = "certificados"; version = $CollectorVersion
            step = $Step; status = $Status; percent = $Percent
            detail = $(if ($Detail.Length -gt 900) { $Detail.Substring(0, 900) } else { $Detail }) })
        $bytes = $Utf8.GetBytes((ConvertTo-Json $payload -Compress))
        $req = [Net.HttpWebRequest]::Create("https://${Server}:$Port/api/v1/progress")
        $req.Method = "POST"
        $req.ContentType = "application/json"
        $req.Headers.Add("X-DFIR-Token", $Token)
        $req.Timeout = 5000
        $req.ReadWriteTimeout = 5000
        $req.ContentLength = $bytes.Length
        $s = $req.GetRequestStream(); $s.Write($bytes, 0, $bytes.Length); $s.Dispose()
        $req.GetResponse().Dispose()
    } catch { }
    $script:LastProgressAt = Get-Date
}

function Write-Step([string]$Step, [string]$Status, [string]$Detail = "") {
    # Uma linha por passo: permite saber até onde a execução chegou, mesmo sem envio.
    $line = "{0} run={1} passo={2} status={3} {4}" -f (Get-Date).ToUniversalTime().ToString("o"), $RunId, $Step, $Status, $Detail
    try { [IO.File]::AppendAllText($LogFile, $line + "`r`n", $Utf8) } catch { }
    if ($StepPercent.ContainsKey($Step)) { $script:LastPercent = $StepPercent[$Step] }
    Send-Progress $Step $Status $script:LastPercent $Detail
    Write-Output $line
}

function Write-SubProgress([string]$Step, [string]$Detail, [int]$Done, [int]$Total) {
    # Inside long steps: at most one update every 15 s, interpolating toward the step's percent.
    if (((Get-Date) - $script:LastProgressAt).TotalSeconds -lt 15) { return }
    $target = $(if ($StepPercent.ContainsKey($Step)) { $StepPercent[$Step] } else { $script:LastPercent })
    $pct = $script:LastPercent
    if ($Total -gt 0) { $pct = [int]($script:LastPercent + ($target - $script:LastPercent) * [Math]::Min(1, $Done / $Total)) }
    Send-Progress $Step "info" $pct $Detail
}

trap {
    # Any uncaught error: record step context and line number in the local log, then stop.
    Write-Step "falha" "erro" ("linha {0}: {1}" -f $_.InvocationInfo.ScriptLineNumber, $_.Exception.Message)
    break
}

# --- Conexão -------------------------------------------------------------------------------
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
$Pin = ($CertThumbprint -replace "[^0-9A-Fa-f]", "").ToUpperInvariant()
[Net.ServicePointManager]::ServerCertificateValidationCallback = {
    param($sender, $cert, $chain, $errors)
    if ($Pin) { return ($cert.GetCertHashString().ToUpperInvariant() -eq $Pin) }
    return $true
}.GetNewClosure()
$BaseUrl = "https://${Server}:$Port"

function Test-Portal {
    try {
        $req = [Net.HttpWebRequest]::Create("$BaseUrl/api/v1/ping")
        $req.Headers.Add("X-DFIR-Token", $Token)
        $req.Timeout = 15000
        $resp = $req.GetResponse()
        $code = [int]$resp.StatusCode
        $resp.Dispose()
        return @{ Ok = ($code -eq 200); Detail = "HTTP $code" }
    } catch [Net.WebException] {
        $r = $_.Exception.Response
        if ($r) { return @{ Ok = $false; Detail = "HTTP $([int]$r.StatusCode) (token errado se 401)" } }
        return @{ Ok = $false; Detail = $_.Exception.Message }
    } catch {
        return @{ Ok = $false; Detail = $_.Exception.Message }
    }
}

Write-Step "inicio" "ok" "host=$env:COMPUTERNAME versao=$CollectorVersion servidor=$BaseUrl"
$conn = Test-Portal
Write-Step "conexao" $(if ($conn.Ok) { "ok" } else { "erro" }) $conn.Detail
if ($TestConnection) { if ($conn.Ok) { exit 0 } else { exit 3 } }

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

# --- Helpers -------------------------------------------------------------------------------
function Get-Sha256OfFile([string]$Path) {
    $stream = [IO.File]::Open($Path, [IO.FileMode]::Open, [IO.FileAccess]::Read,
        [IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete)
    try {
        $sha = [Security.Cryptography.SHA256]::Create()
        return ([BitConverter]::ToString($sha.ComputeHash($stream)) -replace "-", "").ToLowerInvariant()
    } finally { $stream.Dispose() }
}

function Get-ZoneInfo([string]$Path) {
    $info = @{ zone_id = $null; host_url = $null; referrer_url = $null }
    try {
        foreach ($l in (Get-Content -LiteralPath $Path -Stream Zone.Identifier -ErrorAction Stop)) {
            if ($l -match "^ZoneId=(\d+)") { $info.zone_id = [int]$Matches[1] }
            elseif ($l -match "^HostUrl=(.+)") { $info.host_url = $Matches[1] }
            elseif ($l -match "^ReferrerUrl=(.+)") { $info.referrer_url = $Matches[1] }
        }
    } catch { }
    return $info
}

function ConvertTo-CertRecord($Cert, [string]$Origin, [string]$ProfileName, [string]$Path) {
    $cnpj = $null
    if ($Cert.Subject -match "(\d{14})") { $cnpj = $Matches[1] }
    return [ordered]@{
        origin = $Origin; profile = $ProfileName; path = $Path; readable = $true
        thumbprint = $Cert.Thumbprint; subject = $Cert.Subject; issuer = $Cert.Issuer
        serial = $Cert.SerialNumber
        not_before = $Cert.NotBefore.ToUniversalTime().ToString("o")
        not_after = $Cert.NotAfter.ToUniversalTime().ToString("o")
        has_private_key = $Cert.HasPrivateKey; cnpj = $cnpj
    }
}

function Get-StoreBlobCert([string]$BlobPath) {
    # Blob do repositório do usuário: [propId(4) | reservado(4) | tamanho(4) | dados].
    # prop 0x20 = certificado (DER); prop 0x02 = há chave privada associada.
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

function Get-FilesSafe([string]$Root, [string]$Filter, [int]$Depth) {
    if (-not (Test-Path -LiteralPath $Root)) { return @() }
    return @(Get-ChildItem -LiteralPath $Root -Filter $Filter -File -Recurse -Depth $Depth -Force -ErrorAction SilentlyContinue)
}

function Add-Activity([string]$Type, $When, [string]$ProfileName, [string]$Source, [string]$Path, [string]$Detail, $Extra = $null) {
    $ts = $null
    if ($When -is [datetime]) { $ts = $When.ToUniversalTime().ToString("o") } elseif ($When) { $ts = [string]$When }
    $rec = [ordered]@{
        type = $Type; ts = $ts; profile = $ProfileName; source = $Source; path = $Path
        file_name = $(if ($Path) { [IO.Path]::GetFileName($Path) } else { $null })
        detail = $(if ($Detail.Length -gt 3000) { $Detail.Substring(0, 3000) } else { $Detail })
    }
    if ($Extra) { foreach ($k in $Extra.Keys) { $rec[$k] = $Extra[$k] } }
    Add-Record $script:Activity $rec
    $script:ActivityCounts[$Type] = 1 + [int]$script:ActivityCounts[$Type]
}

$profiles = @(Get-ChildItem -LiteralPath "C:\Users" -Directory -Force -ErrorAction SilentlyContinue |
    Where-Object { $SkipProfiles -notcontains $_.Name -and -not ($_.Attributes -band [IO.FileAttributes]::ReparsePoint) })
$Certs = New-Object System.Collections.Generic.List[string]       # JSON por certificado
$Activity = New-Object System.Collections.Generic.List[string]    # JSON por atividade
$ActivityCounts = @{}
$JsonSkipped = 0

# --- 1. Certificados instalados --------------------------------------------------------------
try {
    foreach ($store in @("Cert:\LocalMachine\My", "Cert:\LocalMachine\Root", "Cert:\LocalMachine\CA", "Cert:\LocalMachine\TrustedPeople")) {
        foreach ($c in (Get-ChildItem $store -ErrorAction SilentlyContinue)) {
            Add-Record $Certs (ConvertTo-CertRecord $c "store:$store" "_system" $null)
        }
    }
    foreach ($p in $profiles) {
        $blobDir = Join-Path $p.FullName "AppData\Roaming\Microsoft\SystemCertificates\My\Certificates"
        foreach ($blob in (Get-ChildItem -LiteralPath $blobDir -File -Force -ErrorAction SilentlyContinue)) {
            try {
                $parsed = Get-StoreBlobCert $blob.FullName
                if ($parsed) {
                    $r = ConvertTo-CertRecord $parsed.Cert "store:CurrentUser\My" $p.Name $blob.FullName
                    $r.has_private_key = $parsed.HasKey
                    $r.file_created = $blob.CreationTimeUtc.ToString("o")   # ~ data da importação
                    $r.file_modified = $blob.LastWriteTimeUtc.ToString("o")
                    Add-Record $Certs $r
                    Add-Activity "certificado_instalado" $blob.CreationTime $p.Name "repositorio_usuario" $blob.FullName `
                        ("instalado no repositório do usuário: {0}" -f $parsed.Cert.Subject)
                }
            } catch { }
        }
    }
    Write-Step "instalados" "ok" ("certificados={0}" -f $Certs.Count)
} catch { Write-Step "instalados" "erro" $_.Exception.Message }

# --- 2. Arquivos de certificado --------------------------------------------------------------
function Add-CertFile($File, [string]$ProfileName) {
    $ext = $File.Extension.ToLowerInvariant()
    $zone = Get-ZoneInfo $File.FullName
    $r = $null
    try {
        if ($ext -eq ".pfx" -or $ext -eq ".p12") {
            # Tenta abrir sem senha só para ler o titular; nunca exporta a chave.
            $c = New-Object Security.Cryptography.X509Certificates.X509Certificate2 ($File.FullName, "",
                [Security.Cryptography.X509Certificates.X509KeyStorageFlags]::EphemeralKeySet)
        } else {
            $c = New-Object Security.Cryptography.X509Certificates.X509Certificate2 ($File.FullName)
        }
        $r = ConvertTo-CertRecord $c "file" $ProfileName $File.FullName
        $c.Reset()
    } catch {
        $r = [ordered]@{ origin = "file"; profile = $ProfileName; path = $File.FullName; readable = $false
            thumbprint = $null; subject = $null; issuer = $null; serial = $null; not_before = $null
            not_after = $null; has_private_key = ($ext -in ".pfx", ".p12", ".key"); cnpj = $null }
    }
    $r.extension = $ext
    $r.size = $File.Length
    $r.file_sha256 = $(try { Get-Sha256OfFile $File.FullName } catch { $null })
    $r.file_created = $File.CreationTimeUtc.ToString("o")
    $r.file_modified = $File.LastWriteTimeUtc.ToString("o")
    $r.file_accessed = $File.LastAccessTimeUtc.ToString("o")
    $r.zone_id = $zone.zone_id; $r.host_url = $zone.host_url; $r.referrer_url = $zone.referrer_url
    Add-Record $script:Certs $r
    $origin = $(if ($zone.host_url) { " baixado de $($zone.host_url)" } else { "" })
    Add-Activity "arquivo_certificado" $File.CreationTime $ProfileName "arquivo" $File.FullName ("arquivo criado na máquina$origin")
    Start-Sleep -Milliseconds $PauseMs
}

try {
    $seen = @{}
    $found = New-Object System.Collections.Generic.List[object]
    $pi = 0
    foreach ($p in $profiles) {
        $pi++
        Write-SubProgress "arquivos" ("procurando em perfil {0} ({1}/{2})" -f $p.Name, $pi, $profiles.Count) $pi ($profiles.Count * 2)
        foreach ($f in @("*.pfx", "*.p12")) {
            foreach ($x in (Get-FilesSafe $p.FullName $f 8)) { $found.Add(@($x, $p.Name)) }
        }
        foreach ($folder in @("Desktop", "Documents", "Downloads", "OneDrive")) {
            foreach ($f in @("*.cer", "*.crt", "*.pem", "*.key")) {
                foreach ($x in (Get-FilesSafe (Join-Path $p.FullName $folder) $f 5)) { $found.Add(@($x, $p.Name)) }
            }
        }
    }
    # Pastas na raiz dos discos fixos (C:\Certificados, D:\...), fora das pastas do sistema.
    $skipRoot = @("Windows", "Program Files", "Program Files (x86)", "ProgramData", "Users", '$Recycle.Bin',
        "System Volume Information", "Recovery", "PerfLogs")
    foreach ($drive in (Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" -ErrorAction SilentlyContinue)) {
        $root = "$($drive.DeviceID)\"
        foreach ($dir in (Get-ChildItem -LiteralPath $root -Directory -Force -ErrorAction SilentlyContinue |
                Where-Object { $skipRoot -notcontains $_.Name })) {
            foreach ($f in @("*.pfx", "*.p12")) {
                foreach ($x in (Get-FilesSafe $dir.FullName $f 4)) { $found.Add(@($x, "_disco")) }
            }
        }
        foreach ($f in @("*.pfx", "*.p12")) {
            foreach ($x in (Get-ChildItem -LiteralPath $root -Filter $f -File -Force -ErrorAction SilentlyContinue)) { $found.Add(@($x, "_disco")) }
        }
    }
    $fi = 0
    foreach ($item in $found) {
        $fi++
        Write-SubProgress "arquivos" ("analisando arquivos {0}/{1}" -f $fi, $found.Count) ($found.Count + $fi) ($found.Count * 2)
        $key = $item[0].FullName.ToLowerInvariant()
        if ($seen.ContainsKey($key)) { continue }
        $seen[$key] = $true
        try { Add-CertFile $item[0] $item[1] } catch { }
    }
    Write-Step "arquivos" "ok" ("arquivos={0}" -f $seen.Count)
} catch { Write-Step "arquivos" "erro" $_.Exception.Message }

# --- 3. Aberturas recentes (atalhos em "Recentes") ------------------------------------------
try {
    $shell = New-Object -ComObject WScript.Shell
    $n = 0
    foreach ($p in $profiles) {
        $recent = Join-Path $p.FullName "AppData\Roaming\Microsoft\Windows\Recent"
        foreach ($lnk in (Get-ChildItem -LiteralPath $recent -Filter "*.lnk" -File -Force -ErrorAction SilentlyContinue)) {
            $target = ""
            try { $target = $shell.CreateShortcut($lnk.FullName).TargetPath } catch { }
            if (($lnk.Name -match $CertExtPattern) -or ($target -match $CertExtPattern)) {
                $path = $(if ($target) { $target } else { $lnk.FullName })
                Add-Activity "lnk_aberto" $lnk.LastWriteTime $p.Name "recentes" $path `
                    ("aberto pelo usuário; primeira abertura {0}, última {1}" -f $lnk.CreationTimeUtc.ToString("o"), $lnk.LastWriteTimeUtc.ToString("o")) `
                    @{ first_opened = $lnk.CreationTimeUtc.ToString("o"); last_opened = $lnk.LastWriteTimeUtc.ToString("o") }
                $n++
            }
        }
    }
    Write-Step "recentes" "ok" "aberturas=$n"
} catch { Write-Step "recentes" "erro" $_.Exception.Message }

# --- 4. Comandos no histórico do PowerShell --------------------------------------------------
try {
    $n = 0
    $cmdPattern = "(?i)pfx|p12|certutil|Export-PfxCertificate|Import-PfxCertificate|Import-Certificate|Cert:\\"
    foreach ($p in $profiles) {
        $hist = Join-Path $p.FullName "AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine"
        foreach ($h in (Get-ChildItem -LiteralPath $hist -Filter "*.txt" -File -Force -ErrorAction SilentlyContinue)) {
            foreach ($m in (Select-String -LiteralPath $h.FullName -Pattern $cmdPattern -ErrorAction SilentlyContinue)) {
                Add-Activity "historico_comando" $h.LastWriteTime $p.Name "psreadline" $h.FullName $m.Line
                $n++
            }
        }
    }
    Write-Step "historico" "ok" "comandos=$n"
} catch { Write-Step "historico" "erro" $_.Exception.Message }

# --- 5. Transferências por acesso remoto ----------------------------------------------------
try {
    $n = 0
    $remoteLogs = New-Object System.Collections.Generic.List[object]
    foreach ($p in $profiles) {
        foreach ($spec in @(@("AppData\Roaming\AnyDesk", "*.trace", "anydesk"), @("AppData\Roaming\AnyDesk", "*.txt", "anydesk"),
                @("AppData\Roaming\TeamViewer", "*.log", "teamviewer"), @("AppData\Roaming\TeamViewer", "*.txt", "teamviewer"),
                @("AppData\Roaming\RustDesk\log", "*", "rustdesk"))) {
            foreach ($f in (Get-FilesSafe (Join-Path $p.FullName $spec[0]) $spec[1] 3)) { $remoteLogs.Add(@($f, $spec[2], $p.Name)) }
        }
    }
    foreach ($spec in @(@("C:\ProgramData\AnyDesk", "*.trace", "anydesk"), @("C:\Program Files\TeamViewer", "*.log", "teamviewer"),
            @("C:\Program Files (x86)\TeamViewer", "*.log", "teamviewer"), @("C:\ProgramData\RustDesk", "*", "rustdesk"),
            @("C:\Windows\ServiceProfiles\LocalService\AppData\Roaming\RustDesk\log", "*", "rustdesk"))) {
        foreach ($f in (Get-FilesSafe $spec[0] $spec[1] 3)) { $remoteLogs.Add(@($f, $spec[2], "_system")) }
    }
    $li = 0
    foreach ($item in $remoteLogs) {
        $li++
        Write-SubProgress "acesso_remoto" ("lendo log {0} ({1}/{2})" -f $item[0].Name, $li, $remoteLogs.Count) $li $remoteLogs.Count
        if ($item[0].Length -gt 500MB) { continue }
        foreach ($m in (Select-String -LiteralPath $item[0].FullName -Pattern $CertExtPattern -ErrorAction SilentlyContinue)) {
            Add-Activity "acesso_remoto_arquivo" $item[0].LastWriteTime $item[2] $item[1] $item[0].FullName $m.Line.Trim()
            $n++
        }
        Start-Sleep -Milliseconds $PauseMs
    }
    Write-Step "acesso_remoto" "ok" ("logs={0} linhas={1}" -f $remoteLogs.Count, $n)
} catch { Write-Step "acesso_remoto" "erro" $_.Exception.Message }

# --- 6. Lixeira ($I: caminho original e data em que foi apagado) ----------------------------
try {
    $n = 0
    foreach ($drive in (Get-CimInstance Win32_LogicalDisk -Filter "DriveType=3" -ErrorAction SilentlyContinue)) {
        $bin = "$($drive.DeviceID)\`$Recycle.Bin"
        foreach ($i in (Get-ChildItem -LiteralPath $bin -Filter '$I*' -File -Recurse -Force -ErrorAction SilentlyContinue)) {
            try {
                $b = [IO.File]::ReadAllBytes($i.FullName)
                if ($b.Length -lt 28) { continue }
                $version = [BitConverter]::ToInt64($b, 0)
                $deleted = [DateTime]::FromFileTimeUtc([BitConverter]::ToInt64($b, 16))
                if ($version -eq 2) {
                    $chars = [BitConverter]::ToInt32($b, 24)
                    $orig = [Text.Encoding]::Unicode.GetString($b, 28, [Math]::Min($chars * 2, $b.Length - 28)).TrimEnd([char]0)
                } else {
                    $orig = [Text.Encoding]::Unicode.GetString($b, 24, [Math]::Min(520, $b.Length - 24)).TrimEnd([char]0)
                }
                if ($orig -match $CertExtPattern) {
                    $sid = Split-Path -Leaf $i.DirectoryName
                    $stillThere = Test-Path -LiteralPath ($i.FullName -replace '\\\$I', '\$R')
                    Add-Activity "cert_na_lixeira" $deleted $sid "lixeira" $orig `
                        ("apagado em {0}; ainda recuperável na lixeira: {1}" -f $deleted.ToString("o"), $stillThere)
                    $n++
                }
            } catch { }
        }
    }
    Write-Step "lixeira" "ok" "apagados=$n"
} catch { Write-Step "lixeira" "erro" $_.Exception.Message }

# --- 7. Eventos do Windows -------------------------------------------------------------------
try {
    $n = 0
    $sources = @(
        @{ LogName = "Microsoft-Windows-CertificateServicesClient-Lifecycle-User/Operational" },
        @{ LogName = "Microsoft-Windows-CertificateServicesClient-Lifecycle-System/Operational" },
        @{ LogName = "Security"; Id = 5058, 5059, 5061 },
        @{ LogName = "Microsoft-Windows-CAPI2/Operational" }
    )
    foreach ($filter in $sources) {
        try {
            $events = @(Get-WinEvent -FilterHashtable $filter -MaxEvents 1000 -ErrorAction Stop)
        } catch { continue }   # log desabilitado, vazio ou auditoria desligada
        foreach ($e in $events) {
            $msg = ""
            try { $msg = ($e.Message -replace "\s+", " ") } catch { }
            # The message often just says "see Details": the certificate (subject, thumbprint,
            # key name, operation) is in the event's EventData/UserData fields.
            try {
                $xml = [xml]$e.ToXml()
                $pairs = New-Object System.Collections.Generic.List[string]
                foreach ($node in $xml.SelectNodes("//*[local-name()='EventData' or local-name()='UserData']//*[not(*)]")) {
                    $name = $(if ($node.Attributes -and $node.Attributes["Name"]) { $node.Attributes["Name"].Value } else { $node.LocalName })
                    $val = ([string]$node.InnerText).Trim()
                    if ($val) { $pairs.Add(("{0}={1}" -f $name, $val)) }
                }
                if ($pairs.Count -gt 0) { $msg = ("{0} | dados: {1}" -f $msg, ($pairs -join "; ")) }
            } catch { }
            if ($filter.LogName -like "*CAPI2*" -and $msg -notmatch "(?i)private key|chave privada|pfx|export") { continue }
            Add-Activity "evento_windows" $e.TimeCreated "_system" $filter.LogName $null $msg `
                @{ event_id = $e.Id; record_id = $e.RecordId; user_sid = $(if ($e.UserId) { $e.UserId.Value } else { $null }) }
            $n++
        }
    }
    Write-Step "eventos" "ok" "eventos=$n"
} catch { Write-Step "eventos" "erro" $_.Exception.Message }

# --- 8. Execução de ferramentas de certificado (Prefetch) -----------------------------------
try {
    $n = 0
    foreach ($tool in @("CERTUTIL.EXE", "CERTMGR.EXE", "CERTLM.EXE", "MMC.EXE", "CERTREQ.EXE")) {
        foreach ($pf in (Get-ChildItem -LiteralPath "C:\Windows\Prefetch" -Filter "$tool-*.pf" -File -ErrorAction SilentlyContinue)) {
            Add-Activity "execucao_ferramenta" $pf.LastWriteTime "_system" "prefetch" $pf.FullName `
                ("{0}: primeira execução registrada {1}, última {2}" -f $tool, $pf.CreationTimeUtc.ToString("o"), $pf.LastWriteTimeUtc.ToString("o"))
            $n++
        }
    }
    Write-Step "execucao" "ok" "registros=$n"
} catch { Write-Step "execucao" "erro" $_.Exception.Message }

# --- 9. Chaves privadas do usuário (data de chegada) -----------------------------------------
try {
    $n = 0
    foreach ($p in $profiles) {
        foreach ($sub in @("AppData\Roaming\Microsoft\Crypto\RSA", "AppData\Roaming\Microsoft\Crypto\Keys")) {
            foreach ($k in (Get-FilesSafe (Join-Path $p.FullName $sub) "*" 2)) {
                Add-Activity "chave_privada_criada" $k.CreationTime $p.Name "crypto_keys" $k.FullName `
                    ("chave privada criada {0}, alterada {1}" -f $k.CreationTimeUtc.ToString("o"), $k.LastWriteTimeUtc.ToString("o"))
                $n++
            }
        }
    }
    Write-Step "chaves" "ok" "chaves=$n"
} catch { Write-Step "chaves" "erro" $_.Exception.Message }

# --- Pacote ----------------------------------------------------------------------------------
$stamp = (Get-Date).ToUniversalTime().ToString("yyyyMMddTHHmmssZ")
$runDir = Join-Path $StagingRoot "cert-run-$stamp"
New-Item -ItemType Directory -Path $runDir -Force | Out-Null
[IO.File]::WriteAllText((Join-Path $runDir "manifest.json"), "[]", $Utf8)
[string]$certsJson = "[" + ($Certs -join ",") + "]"
[string]$activityJson = "[" + ($Activity -join ",") + "]"
if ($JsonSkipped -gt 0) { Write-Step "json" "erro" ("{0} registro(s) ignorado(s) por erro de conversão" -f $JsonSkipped) }
[IO.File]::WriteAllText((Join-Path $runDir "certs.json"), $certsJson, $Utf8)
[IO.File]::WriteAllText((Join-Path $runDir "cert_activity.json"), $activityJson, $Utf8)
$custody = [ordered]@{
    hostname = $env:COMPUTERNAME
    operator = [Security.Principal.WindowsIdentity]::GetCurrent().Name
    collected_at = (Get-Date).ToUniversalTime().ToString("o")
    collector_version = $CollectorVersion
    run_id = $RunId
    certificates = $Certs.Count
    activities = $Activity.Count
    json_skipped = $JsonSkipped
}
[IO.File]::WriteAllText((Join-Path $runDir "custody.json"), [string](ConvertTo-Json (New-Object PSObject -Property $custody) -Depth 3), $Utf8)
Add-Type -AssemblyName System.IO.Compression.FileSystem
$bundle = Join-Path $StagingRoot "CorpDFIR-CERT-$($env:COMPUTERNAME)-$stamp.zip"
[IO.Compression.ZipFile]::CreateFromDirectory($runDir, $bundle, [IO.Compression.CompressionLevel]::Optimal, $false)
Remove-Item -LiteralPath $runDir -Recurse -Force -ErrorAction SilentlyContinue
Write-Step "pacote" "ok" ("certificados={0} atividades={1} arquivo={2}" -f $Certs.Count, $Activity.Count, $bundle)

if ($DryRun) {
    foreach ($t in $ActivityCounts.Keys) { Write-Output ("  {0}: {1}" -f $t, $ActivityCounts[$t]) }
    Write-Step "fim" "ok" "DryRun: pacote mantido em $StagingRoot, nada enviado"
    exit 0
}

# --- Envio (pacote atual + pendentes de execuções anteriores) -------------------------------
function Send-Bundle([string]$Path) {
    $sha = Get-Sha256OfFile $Path
    $boundary = [Guid]::NewGuid().ToString("N")
    $name = [IO.Path]::GetFileName($Path)
    $head = $Utf8.GetBytes("--$boundary`r`nContent-Disposition: form-data; name=""file""; filename=""$name""`r`nContent-Type: application/zip`r`n`r`n")
    $tail = $Utf8.GetBytes("`r`n--$boundary--`r`n")
    $req = [Net.HttpWebRequest]::Create("$BaseUrl/api/v1/upload")
    $req.Method = "POST"
    $req.ContentType = "multipart/form-data; boundary=$boundary"
    $req.Headers.Add("X-DFIR-Token", $Token)
    $req.Headers.Add("X-DFIR-SHA256", $sha)
    $req.ContentLength = $head.Length + (Get-Item -LiteralPath $Path).Length + $tail.Length
    $req.AllowWriteStreamBuffering = $false
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

$sent = 0; $failed = 0
foreach ($zip in (Get-ChildItem -LiteralPath $StagingRoot -Filter "CorpDFIR-*.zip" -File -ErrorAction SilentlyContinue)) {
    Send-Progress "envio" "info" 90 ("enviando {0} ({1:N1} MB)" -f $zip.Name, ($zip.Length / 1MB))
    try {
        $code = Send-Bundle $zip.FullName
        if ($code -eq 200 -or $code -eq 201) {
            Remove-Item -LiteralPath $zip.FullName -Force
            $sent++
            Write-Step "envio" "ok" "$($zip.Name) HTTP $code"
        } else { $failed++; Write-Step "envio" "erro" "$($zip.Name) HTTP $code" }
    } catch {
        $failed++
        $detail = $_.Exception.Message
        if ($_.Exception.InnerException) { $detail += " | " + $_.Exception.InnerException.Message }
        Write-Step "envio" "erro" "$($zip.Name): $detail"
    }
}
Get-ChildItem -LiteralPath $StagingRoot -Directory -Filter "*run-*" -ErrorAction SilentlyContinue |
    Remove-Item -Recurse -Force -ErrorAction SilentlyContinue

Write-Step "fim" $(if ($failed) { "erro" } else { "ok" }) ("enviados={0} pendentes={1} log={2}" -f $sent, $failed, $LogFile)
if ($failed -gt 0) { exit 2 }
exit 0
