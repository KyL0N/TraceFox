[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [ValidateSet("start", "stop", "status", "bootstrap", "supervise")]
    [string]$Command = "start"
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

$script:Root = [System.IO.Path]::GetFullPath((Split-Path -Parent $PSScriptRoot))
$script:WorkRoot = Join-Path $script:Root ".tracefox"
$script:RuntimeRoot = Join-Path $script:WorkRoot "runtime"
$script:CacheRoot = Join-Path $script:WorkRoot "cache"
$script:DataRoot = Join-Path $script:WorkRoot "data"
$script:LogRoot = Join-Path $script:WorkRoot "logs"
$script:StateRoot = Join-Path $script:WorkRoot "state"
$script:ConfigFile = Join-Path $script:WorkRoot "config.env"
$script:StateFile = Join-Path $script:StateRoot "state.json"
$script:StopRequestFile = Join-Path $script:StateRoot "stop.request"
$script:SupervisorLog = Join-Path $script:LogRoot "supervisor.log"
$script:ManifestPath = Join-Path $PSScriptRoot "runtime-manifest.psd1"

$normalizedRoot = $script:Root.TrimEnd([char[]]@(92, 47)).ToLowerInvariant()
$sha = [System.Security.Cryptography.SHA256]::Create()
try {
    $rootHashBytes = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($normalizedRoot))
} finally {
    $sha.Dispose()
}
$rootHash = ([System.BitConverter]::ToString($rootHashBytes)).Replace("-", "").Substring(0, 16)
$script:MutexName = "Local\TraceFoxPortable-$rootHash"

function Initialize-TraceFoxDirectories {
    foreach ($path in @(
        $script:WorkRoot,
        $script:RuntimeRoot,
        $script:CacheRoot,
        $script:DataRoot,
        $script:LogRoot,
        $script:StateRoot,
        (Join-Path $script:DataRoot "victoriametrics"),
        (Join-Path $script:DataRoot "grafana"),
        (Join-Path $script:DataRoot "grafana-plugins"),
        (Join-Path $script:LogRoot "grafana")
    )) {
        if (-not (Test-Path -LiteralPath $path)) {
            New-Item -ItemType Directory -Path $path -Force | Out-Null
        }
    }
}

function Write-TraceFoxLog {
    param([string]$Message)

    $line = "{0} {1}" -f (Get-Date -Format "yyyy-MM-dd HH:mm:ss.fff"), $Message
    Add-Content -LiteralPath $script:SupervisorLog -Value $line -Encoding UTF8
}

function Assert-WindowsAmd64 {
    if ($env:OS -ne "Windows_NT") {
        throw "The portable server currently supports Windows only."
    }
    if (-not [System.Environment]::Is64BitOperatingSystem) {
        throw "The portable server requires 64-bit Windows."
    }
}

function Read-EnvFile {
    param([string]$Path)

    $values = @{}
    if (-not (Test-Path -LiteralPath $Path)) {
        return $values
    }

    foreach ($line in [System.IO.File]::ReadAllLines($Path)) {
        $trimmed = $line.Trim()
        if (-not $trimmed -or $trimmed.StartsWith("#")) {
            continue
        }
        $parts = $trimmed -split "=", 2
        if ($parts.Count -ne 2) {
            continue
        }
        $key = $parts[0].Trim()
        $value = $parts[1].Trim()
        if ($value.Length -ge 2) {
            if (($value.StartsWith('"') -and $value.EndsWith('"')) -or
                ($value.StartsWith("'") -and $value.EndsWith("'"))) {
                $value = $value.Substring(1, $value.Length - 2)
            }
        }
        if ($key) {
            $values[$key] = $value
        }
    }
    return $values
}

function ConvertTo-Port {
    param(
        [string]$Name,
        [object]$Value
    )

    $port = 0
    if (-not [int]::TryParse([string]$Value, [ref]$port) -or $port -lt 1 -or $port -gt 65535) {
        throw "$Name must be an integer between 1 and 65535."
    }
    return $port
}

function Get-TraceFoxConfig {
    $values = @{
        TRACEFOX_UDP_HOST = "0.0.0.0"
        TRACEFOX_UDP_PORT = "9000"
        TRACEFOX_VM_PORT = "8428"
        TRACEFOX_GRAFANA_PORT = "3000"
        TRACEFOX_VERBOSE = "0"
        TRACEFOX_QUEUE_SIZE = "1000"
        GRAFANA_PASSWORD = ""
    }

    foreach ($path in @($script:ConfigFile, (Join-Path $script:Root ".env"))) {
        $fileValues = Read-EnvFile -Path $path
        foreach ($key in $fileValues.Keys) {
            $values[$key] = $fileValues[$key]
        }
    }

    foreach ($key in @($values.Keys)) {
        $environmentValue = [System.Environment]::GetEnvironmentVariable($key)
        if ($null -ne $environmentValue -and $environmentValue -ne "") {
            $values[$key] = $environmentValue
        }
    }

    if (-not $values["GRAFANA_PASSWORD"]) {
        $values["GRAFANA_PASSWORD"] = ([System.Guid]::NewGuid().ToString("N")).Substring(0, 20)
        $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
        [System.IO.File]::WriteAllText(
            $script:ConfigFile,
            "GRAFANA_PASSWORD=$($values['GRAFANA_PASSWORD'])`r`n",
            $utf8NoBom
        )
    }

    return [PSCustomObject]@{
        UdpHost = [string]$values["TRACEFOX_UDP_HOST"]
        UdpPort = ConvertTo-Port -Name "TRACEFOX_UDP_PORT" -Value $values["TRACEFOX_UDP_PORT"]
        VmPort = ConvertTo-Port -Name "TRACEFOX_VM_PORT" -Value $values["TRACEFOX_VM_PORT"]
        GrafanaPort = ConvertTo-Port -Name "TRACEFOX_GRAFANA_PORT" -Value $values["TRACEFOX_GRAFANA_PORT"]
        Verbose = [string]$values["TRACEFOX_VERBOSE"]
        QueueSize = [string]$values["TRACEFOX_QUEUE_SIZE"]
        GrafanaPassword = [string]$values["GRAFANA_PASSWORD"]
    }
}

function Test-ArchiveHash {
    param(
        [string]$Path,
        [string]$ExpectedSha256
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        return $false
    }
    $actual = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
    return $actual -eq $ExpectedSha256.ToLowerInvariant()
}

function Get-Artifact {
    param(
        [string]$Name,
        [hashtable]$Artifact
    )

    $archivePath = Join-Path $script:CacheRoot $Artifact.FileName
    if (Test-ArchiveHash -Path $archivePath -ExpectedSha256 $Artifact.Sha256) {
        return $archivePath
    }
    if (Test-Path -LiteralPath $archivePath) {
        Remove-Item -LiteralPath $archivePath -Force
    }

    $downloadPath = "$archivePath.download"
    if (Test-Path -LiteralPath $downloadPath) {
        Remove-Item -LiteralPath $downloadPath -Force
    }

    Write-Host "[TraceFox] Downloading $Name $($Artifact.Version)..."
    [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
    Invoke-WebRequest -Uri $Artifact.Url -OutFile $downloadPath -UseBasicParsing

    if (-not (Test-ArchiveHash -Path $downloadPath -ExpectedSha256 $Artifact.Sha256)) {
        Remove-Item -LiteralPath $downloadPath -Force -ErrorAction SilentlyContinue
        throw "SHA256 verification failed for $Name."
    }
    Move-Item -LiteralPath $downloadPath -Destination $archivePath -Force
    return $archivePath
}

function Set-EmbeddedPythonPath {
    param([string]$PythonRoot)

    $pth = Get-ChildItem -LiteralPath $PythonRoot -Filter "python*._pth" | Select-Object -First 1
    if ($null -eq $pth) {
        throw "The embedded Python _pth file was not found."
    }

    $serverPath = "..\..\..\server"
    $lines = [System.Collections.Generic.List[string]]::new()
    foreach ($line in [System.IO.File]::ReadAllLines($pth.FullName)) {
        $lines.Add($line)
    }
    if (-not $lines.Contains($serverPath)) {
        $lines.Add($serverPath)
    }
    $utf8NoBom = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllLines($pth.FullName, $lines, $utf8NoBom)
}

function Install-RuntimeComponent {
    param(
        [string]$Name,
        [hashtable]$Artifact
    )

    $destination = Join-Path $script:RuntimeRoot $Artifact.Destination
    $expectedExecutable = Join-Path $destination $Artifact.Executable
    if (Test-Path -LiteralPath $expectedExecutable) {
        if ($Name -eq "Python") {
            Set-EmbeddedPythonPath -PythonRoot $destination
        }
        return
    }

    $archivePath = Get-Artifact -Name $Name -Artifact $Artifact
    $extractPath = Join-Path $script:CacheRoot ("extract-" + [System.Guid]::NewGuid().ToString("N"))
    New-Item -ItemType Directory -Path $extractPath -Force | Out-Null

    try {
        Write-Host "[TraceFox] Extracting $Name..."
        switch ($Artifact.ArchiveType) {
            "zip" {
                Expand-Archive -LiteralPath $archivePath -DestinationPath $extractPath -Force
            }
            "tar.gz" {
                $tar = Get-Command tar.exe -ErrorAction SilentlyContinue
                if ($null -eq $tar) {
                    throw "tar.exe is required to extract the Grafana runtime."
                }
                & $tar.Source -xzf $archivePath -C $extractPath
                if ($LASTEXITCODE -ne 0) {
                    throw "tar.exe failed while extracting $Name."
                }
            }
            default {
                throw "Unsupported archive type: $($Artifact.ArchiveType)"
            }
        }

        if (Test-Path -LiteralPath $destination) {
            Remove-Item -LiteralPath $destination -Recurse -Force
        }
        if ($Artifact.ContainsKey("RootDirectory")) {
            $source = Join-Path $extractPath $Artifact.RootDirectory
            if (-not (Test-Path -LiteralPath $source)) {
                throw "Expected directory $($Artifact.RootDirectory) was not found in $Name."
            }
            Move-Item -LiteralPath $source -Destination $destination
        } else {
            Move-Item -LiteralPath $extractPath -Destination $destination
            $extractPath = $null
        }
    } finally {
        if ($extractPath -and (Test-Path -LiteralPath $extractPath)) {
            Remove-Item -LiteralPath $extractPath -Recurse -Force
        }
    }

    if (-not (Test-Path -LiteralPath $expectedExecutable)) {
        throw "$Name was extracted, but its executable was not found."
    }
    if ($Name -eq "Python") {
        Set-EmbeddedPythonPath -PythonRoot $destination
    }
    Remove-Item -LiteralPath $archivePath -Force -ErrorAction SilentlyContinue
}

function Ensure-Runtime {
    Assert-WindowsAmd64
    if (-not (Test-Path -LiteralPath $script:ManifestPath)) {
        throw "Runtime manifest not found: $script:ManifestPath"
    }
    $manifest = Import-PowerShellDataFile -LiteralPath $script:ManifestPath
    if ($manifest.SchemaVersion -ne 1) {
        throw "Unsupported runtime manifest version."
    }

    Install-RuntimeComponent -Name "Python" -Artifact $manifest.Python
    Install-RuntimeComponent -Name "VictoriaMetrics" -Artifact $manifest.VictoriaMetrics
    Install-RuntimeComponent -Name "Grafana" -Artifact $manifest.Grafana
}

function Test-SupervisorRunning {
    try {
        $mutex = [System.Threading.Mutex]::OpenExisting($script:MutexName)
        $mutex.Dispose()
        return $true
    } catch [System.Threading.WaitHandleCannotBeOpenedException] {
        return $false
    } catch {
        return $false
    }
}

function Test-TcpPortAvailable {
    param([int]$Port)

    $listener = New-Object System.Net.Sockets.TcpListener -ArgumentList @(
        [System.Net.IPAddress]::Any,
        $Port
    )
    try {
        $listener.Start()
        return $true
    } catch {
        return $false
    } finally {
        $listener.Stop()
    }
}

function Test-UdpPortAvailable {
    param([int]$Port)

    $client = New-Object System.Net.Sockets.UdpClient
    try {
        $client.ExclusiveAddressUse = $true
        $endpoint = New-Object System.Net.IPEndPoint -ArgumentList @(
            [System.Net.IPAddress]::Any,
            $Port
        )
        $client.Client.Bind($endpoint)
        return $true
    } catch {
        return $false
    } finally {
        $client.Dispose()
    }
}

function Assert-PortsAvailable {
    param([PSCustomObject]$Config)

    if (-not (Test-TcpPortAvailable -Port $Config.VmPort)) {
        throw "TCP port $($Config.VmPort) is already in use (VictoriaMetrics)."
    }
    if (-not (Test-TcpPortAvailable -Port $Config.GrafanaPort)) {
        throw "TCP port $($Config.GrafanaPort) is already in use (Grafana)."
    }
    if (-not (Test-UdpPortAvailable -Port $Config.UdpPort)) {
        throw "UDP port $($Config.UdpPort) is already in use (TraceFox forwarder)."
    }
}

function Test-HttpEndpoint {
    param([string]$Url)

    try {
        $response = Invoke-WebRequest -Uri $Url -UseBasicParsing -TimeoutSec 2
        return $response.StatusCode -ge 200 -and $response.StatusCode -lt 300
    } catch {
        return $false
    }
}

function Wait-ForCondition {
    param(
        [scriptblock]$Condition,
        [int]$TimeoutSeconds,
        [int]$PollMilliseconds = 500
    )

    $timer = [System.Diagnostics.Stopwatch]::StartNew()
    while ($timer.Elapsed.TotalSeconds -lt $TimeoutSeconds) {
        if (& $Condition) {
            return $true
        }
        Start-Sleep -Milliseconds $PollMilliseconds
    }
    return $false
}

function Quote-ProcessArgument {
    param([string]$Value)
    return '"' + $Value.Replace('"', '\"') + '"'
}

function Remove-OldComponentLogs {
    param([string]$Name)

    Get-ChildItem -LiteralPath $script:LogRoot -Filter "$Name-*.log" -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending |
        Select-Object -Skip 20 |
        Remove-Item -Force -ErrorAction SilentlyContinue
}

function Start-LoggedProcess {
    param(
        [string]$Name,
        [string]$FilePath,
        [string[]]$Arguments,
        [string]$WorkingDirectory
    )

    Remove-OldComponentLogs -Name $Name
    $stamp = Get-Date -Format "yyyyMMdd-HHmmss-fff"
    $stdout = Join-Path $script:LogRoot "$Name-$stamp.out.log"
    $stderr = Join-Path $script:LogRoot "$Name-$stamp.err.log"
    $process = Start-Process `
        -FilePath $FilePath `
        -ArgumentList ($Arguments -join " ") `
        -WorkingDirectory $WorkingDirectory `
        -RedirectStandardOutput $stdout `
        -RedirectStandardError $stderr `
        -WindowStyle Hidden `
        -PassThru
    Write-TraceFoxLog "$Name started with PID $($process.Id)."
    return $process
}

function Set-ChildEnvironment {
    param([PSCustomObject]$Config)

    $vmUrl = "http://127.0.0.1:$($Config.VmPort)"
    $dashboardPath = (Join-Path $script:Root "grafana\dashboards").Replace("\", "/")
    $defaultDashboard = (Join-Path $script:Root "grafana\dashboards\tracefox-overview.json").Replace("\", "/")

    $env:TRACEFOX_UDP_HOST = $Config.UdpHost
    $env:TRACEFOX_UDP_PORT = [string]$Config.UdpPort
    $env:TRACEFOX_VM_URL = $vmUrl
    $env:TRACEFOX_VERBOSE = $Config.Verbose
    $env:TRACEFOX_QUEUE_SIZE = $Config.QueueSize
    $env:TRACEFOX_DASHBOARD_PATH = $dashboardPath

    $env:GF_PATHS_DATA = Join-Path $script:DataRoot "grafana"
    $env:GF_PATHS_LOGS = Join-Path $script:LogRoot "grafana"
    $env:GF_PATHS_PLUGINS = Join-Path $script:DataRoot "grafana-plugins"
    $env:GF_PATHS_PROVISIONING = Join-Path $script:Root "grafana\provisioning"
    $env:GF_SECURITY_ADMIN_USER = "admin"
    $env:GF_SECURITY_ADMIN_PASSWORD = $Config.GrafanaPassword
    $env:GF_USERS_ALLOW_SIGN_UP = "false"
    $env:GF_AUTH_ANONYMOUS_ENABLED = "false"
    $env:GF_SERVER_HTTP_ADDR = "0.0.0.0"
    $env:GF_SERVER_HTTP_PORT = [string]$Config.GrafanaPort
    $env:GF_DASHBOARDS_DEFAULT_HOME_DASHBOARD_PATH = $defaultDashboard
}

function Start-Component {
    param(
        [ValidateSet("victoriametrics", "forwarder", "grafana")]
        [string]$Name,
        [PSCustomObject]$Config
    )

    switch ($Name) {
        "victoriametrics" {
            $home = Join-Path $script:RuntimeRoot "victoriametrics"
            $exe = Join-Path $home "victoria-metrics-windows-amd64-prod.exe"
            $data = Join-Path $script:DataRoot "victoriametrics"
            $process = Start-LoggedProcess `
                -Name $Name `
                -FilePath $exe `
                -Arguments @(
                    (Quote-ProcessArgument "-storageDataPath=$data"),
                    "-retentionPeriod=30d",
                    "-httpListenAddr=127.0.0.1:$($Config.VmPort)"
                ) `
                -WorkingDirectory $home
            return $process
        }
        "forwarder" {
            $pythonHome = Join-Path $script:RuntimeRoot "python"
            $python = Join-Path $pythonHome "python.exe"
            $serverHome = Join-Path $script:Root "server"
            $forwarder = Join-Path $serverHome "metrics_forwarder.py"
            $process = Start-LoggedProcess `
                -Name $Name `
                -FilePath $python `
                -Arguments @("-u", (Quote-ProcessArgument $forwarder)) `
                -WorkingDirectory $serverHome
            return $process
        }
        "grafana" {
            $home = Join-Path $script:RuntimeRoot "grafana"
            $exe = Join-Path $home "bin\grafana.exe"
            $process = Start-LoggedProcess `
                -Name $Name `
                -FilePath $exe `
                -Arguments @("server", "--homepath", (Quote-ProcessArgument $home)) `
                -WorkingDirectory $home
            return $process
        }
    }
}

function Write-State {
    param([hashtable]$Processes)

    $state = [ordered]@{
        supervisor_pid = $PID
        victoriametrics_pid = [int]$Processes["victoriametrics"].Id
        forwarder_pid = [int]$Processes["forwarder"].Id
        grafana_pid = [int]$Processes["grafana"].Id
        updated_at = (Get-Date).ToString("o")
    }
    $state | ConvertTo-Json | Set-Content -LiteralPath $script:StateFile -Encoding UTF8
}

function Stop-ChildProcess {
    param(
        [string]$Name,
        [System.Diagnostics.Process]$Process
    )

    if ($null -eq $Process -or $Process.HasExited) {
        return
    }
    Write-TraceFoxLog "Stopping $Name PID $($Process.Id)."
    Stop-Process -Id $Process.Id -ErrorAction SilentlyContinue
    try {
        $Process.WaitForExit(5000) | Out-Null
    } catch {
        # Fall through to the forced stop below.
    }
    if (-not $Process.HasExited) {
        Stop-Process -Id $Process.Id -Force -ErrorAction SilentlyContinue
    }
}

function Invoke-Supervisor {
    $createdNew = $false
    $mutex = New-Object System.Threading.Mutex($true, $script:MutexName, [ref]$createdNew)
    if (-not $createdNew) {
        $mutex.Dispose()
        return
    }

    $processes = @{}
    try {
        $config = Get-TraceFoxConfig
        Ensure-Runtime
        Assert-PortsAvailable -Config $config
        Set-ChildEnvironment -Config $config
        Remove-Item -LiteralPath $script:StopRequestFile -Force -ErrorAction SilentlyContinue

        Write-TraceFoxLog "Supervisor started with PID $PID."
        $processes["victoriametrics"] = Start-Component -Name "victoriametrics" -Config $config
        $vmHealth = "http://127.0.0.1:$($Config.VmPort)/health"
        if (-not (Wait-ForCondition -Condition { Test-HttpEndpoint -Url $vmHealth } -TimeoutSeconds 30)) {
            Write-TraceFoxLog "VictoriaMetrics did not become healthy within 30 seconds."
        }
        $processes["forwarder"] = Start-Component -Name "forwarder" -Config $config
        $processes["grafana"] = Start-Component -Name "grafana" -Config $config
        Write-State -Processes $processes

        while (-not (Test-Path -LiteralPath $script:StopRequestFile)) {
            foreach ($name in @("victoriametrics", "forwarder", "grafana")) {
                $process = $processes[$name]
                if ($process.HasExited) {
                    Write-TraceFoxLog "$name exited with code $($process.ExitCode); restarting in 2 seconds."
                    Start-Sleep -Seconds 2
                    $processes[$name] = Start-Component -Name $name -Config $config
                }
            }
            Write-State -Processes $processes
            Start-Sleep -Seconds 2
        }
        Write-TraceFoxLog "Stop requested."
    } finally {
        foreach ($name in @("grafana", "forwarder", "victoriametrics")) {
            if ($processes.ContainsKey($name)) {
                Stop-ChildProcess -Name $name -Process $processes[$name]
            }
        }
        Remove-Item -LiteralPath $script:StateFile -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $script:StopRequestFile -Force -ErrorAction SilentlyContinue
        Write-TraceFoxLog "Supervisor stopped."
        if ($createdNew) {
            $mutex.ReleaseMutex()
        }
        $mutex.Dispose()
    }
}

function Show-RecentLogs {
    Write-Host "[TraceFox] Recent supervisor log:"
    if (Test-Path -LiteralPath $script:SupervisorLog) {
        Get-Content -LiteralPath $script:SupervisorLog -Tail 20 | ForEach-Object { Write-Host "  $_" }
    }
    foreach ($name in @("victoriametrics", "forwarder", "grafana")) {
        $log = Get-ChildItem -LiteralPath $script:LogRoot -Filter "$name-*.err.log" -ErrorAction SilentlyContinue |
            Sort-Object LastWriteTime -Descending |
            Select-Object -First 1
        if ($null -ne $log -and $log.Length -gt 0) {
            Write-Host "[TraceFox] Recent $name errors:"
            Get-Content -LiteralPath $log.FullName -Tail 20 | ForEach-Object { Write-Host "  $_" }
        }
    }
}

function Invoke-Start {
    Assert-WindowsAmd64
    if (Test-SupervisorRunning) {
        Write-Host "[TraceFox] Already running."
        $null = Invoke-Status
        return
    }

    Ensure-Runtime
    $config = Get-TraceFoxConfig
    Assert-PortsAvailable -Config $config
    Remove-Item -LiteralPath $script:StopRequestFile -Force -ErrorAction SilentlyContinue

    $powershell = (Get-Process -Id $PID).Path
    $arguments = @(
        "-NoLogo",
        "-NoProfile",
        "-ExecutionPolicy", "Bypass",
        "-File", (Quote-ProcessArgument $PSCommandPath),
        "supervise"
    )
    $supervisor = Start-Process `
        -FilePath $powershell `
        -ArgumentList ($arguments -join " ") `
        -WorkingDirectory $script:Root `
        -WindowStyle Hidden `
        -PassThru

    if (-not (Wait-ForCondition -Condition { Test-SupervisorRunning } -TimeoutSeconds 15)) {
        throw "The TraceFox supervisor failed to start."
    }

    $vmHealth = "http://127.0.0.1:$($Config.VmPort)/health"
    $grafanaHealth = "http://127.0.0.1:$($Config.GrafanaPort)/api/health"
    $healthy = Wait-ForCondition -Condition {
        if ($supervisor.HasExited) {
            throw "The TraceFox supervisor exited during startup."
        }
        (Test-HttpEndpoint -Url $vmHealth) -and
        (Test-HttpEndpoint -Url $grafanaHealth) -and
        (Test-Path -LiteralPath $script:StateFile)
    } -TimeoutSeconds 120 -PollMilliseconds 1000

    if (-not $healthy) {
        New-Item -ItemType File -Path $script:StopRequestFile -Force | Out-Null
        Show-RecentLogs
        throw "TraceFox did not become healthy within 120 seconds."
    }

    Write-Host ""
    Write-Host "TraceFox is running in portable mode."
    Write-Host "  Grafana:          http://127.0.0.1:$($Config.GrafanaPort)"
    Write-Host "  VictoriaMetrics:  http://127.0.0.1:$($Config.VmPort)"
    Write-Host "  Agent target:     <this-windows-ip>:$($Config.UdpPort)/udp"
    Write-Host "  Grafana login:    admin / $($Config.GrafanaPassword)"
    Write-Host "  Data:             $script:DataRoot"
    Write-Host "  Logs:             $script:LogRoot"
    Write-Host ""
    Write-Host "No Windows service was installed. TraceFox stops at logout or reboot."
}

function Invoke-Status {
    $running = Test-SupervisorRunning
    if (-not $running) {
        Write-Host "TraceFox is stopped."
        return $false
    }

    $config = Get-TraceFoxConfig
    $vmHealthy = Test-HttpEndpoint -Url "http://127.0.0.1:$($Config.VmPort)/health"
    $grafanaHealthy = Test-HttpEndpoint -Url "http://127.0.0.1:$($Config.GrafanaPort)/api/health"
    Write-Host "TraceFox supervisor: running"
    Write-Host "VictoriaMetrics:     $(if ($vmHealthy) { 'healthy' } else { 'unhealthy' })"
    Write-Host "Grafana:             $(if ($grafanaHealthy) { 'healthy' } else { 'unhealthy' })"
    Write-Host "Forwarder:           UDP $($Config.UdpHost):$($Config.UdpPort)"
    return ($vmHealthy -and $grafanaHealthy)
}

function Invoke-Stop {
    if (-not (Test-SupervisorRunning)) {
        Remove-Item -LiteralPath $script:StateFile -Force -ErrorAction SilentlyContinue
        Write-Host "TraceFox is already stopped."
        return
    }

    New-Item -ItemType File -Path $script:StopRequestFile -Force | Out-Null
    if (-not (Wait-ForCondition -Condition { -not (Test-SupervisorRunning) } -TimeoutSeconds 20)) {
        throw "TraceFox did not stop within 20 seconds. See $script:SupervisorLog"
    }
    Write-Host "TraceFox stopped."
}

Initialize-TraceFoxDirectories

try {
    switch ($Command.ToLowerInvariant()) {
        "start" {
            Invoke-Start
        }
        "stop" {
            Invoke-Stop
        }
        "status" {
            if (-not (Invoke-Status)) {
                exit 1
            }
        }
        "bootstrap" {
            Ensure-Runtime
            Write-Host "TraceFox Windows runtime is ready."
        }
        "supervise" {
            Invoke-Supervisor
        }
    }
} catch {
    Write-TraceFoxLog "ERROR: $($_.Exception.Message)"
    Write-Error $_.Exception.Message
    exit 1
}
