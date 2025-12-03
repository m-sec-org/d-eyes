param(
    [int]$DurationSeconds = 60,
    [string[]]$Providers = @(
        "{9E814AAD-3204-11D2-9A82-006008A86939}", # Kernel Process/Thread provider
        "{54849625-5478-4994-A5BA-3E3B0328C30D}"  # Security provider
    ),
    [string]$AgentBinary = ".\bin\agent.exe",
    [string]$OutputPath = ".\artifacts\etw-events.jsonl",
    [string]$ReportPath = ".\artifacts\etw-report.json",
    [int]$MinEvents = 100,
    [double]$MaxAvgLatencyMs = 500,
    [double]$MaxMaxLatencyMs = 2000,
    [switch]$EnforceThresholds = $true
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Ensure-AgentBinary {
    param([string]$Path)
    if (Test-Path $Path) {
        return $Path
    }
    Write-Host "agent binary not found at $Path, building..."
    $binDir = Split-Path -Parent $Path
    if (-not (Test-Path $binDir)) {
        New-Item -ItemType Directory -Path $binDir | Out-Null
    }
    go build -o $Path ./agent
    if (-not (Test-Path $Path)) {
        throw "failed to build agent binary at $Path"
    }
    return $Path
}

function Write-CollectorConfig {
    param(
        [string]$Path,
        [string[]]$Providers
    )
    $providerYaml = ($Providers | ForEach-Object { "      - ""$_""" }) -join "`n"
    $yaml = @"
collectors:
  - name: etw-perf
    kind: etw
    providers:
$providerYaml
    output:
      mode: stdout
"@
    $dir = Split-Path -Parent $Path
    if (-not (Test-Path $dir)) {
        New-Item -ItemType Directory -Path $dir | Out-Null
    }
    Set-Content -Path $Path -Value $yaml -Encoding UTF8
    return $Path
}

function Start-Collect {
    param(
        [string]$Agent,
        [string]$ConfigPath,
        [int]$DurationSeconds,
        [string]$OutputPath
    )
    $durationArg = "{0}s" -f $DurationSeconds
    $outputDir = Split-Path -Parent $OutputPath
    if (-not (Test-Path $outputDir)) {
        New-Item -ItemType Directory -Path $outputDir -Force | Out-Null
    }
    if (Test-Path $OutputPath) {
        Remove-Item $OutputPath -Force
    }
    $latencies = New-Object System.Collections.Generic.List[double]
    $events = 0
    & $Agent collect --config $ConfigPath --duration $durationArg |
        ForEach-Object {
            $line = $_.Trim()
            if (-not $line.StartsWith("{")) {
                Write-Host $line
                return
            }
            $receivedAt = Get-Date
            $obj = $line | ConvertFrom-Json
            $events++
            $eventTime = [datetime]::Parse($obj.timestamp)
            $latencies.Add(($receivedAt - $eventTime).TotalMilliseconds)
            $line | Out-File -Append -FilePath $OutputPath -Encoding UTF8
        }
    return [pscustomobject]@{
        EventCount = $events
        Latencies  = $latencies
    }
}

function Write-Report {
    param(
        [pscustomobject]$Stats,
        [string]$ReportPath,
        [int]$DurationSeconds
    )
    $latencies = $Stats.Latencies
    $eventCount = $Stats.EventCount
    $avgLatency = if ($latencies.Count -gt 0) { [Math]::Round(($latencies | Measure-Object -Average).Average, 2) } else { 0 }
    $maxLatency = if ($latencies.Count -gt 0) { [Math]::Round(($latencies | Measure-Object -Maximum).Maximum, 2) } else { 0 }
    $throughput = if ($DurationSeconds -gt 0) { [Math]::Round($eventCount / $DurationSeconds, 2) } else { 0 }
    $report = [pscustomobject]@{
         events      = $eventCount
         duration_s  = $DurationSeconds
         throughput  = $throughput
         avg_latency_ms = $avgLatency
         max_latency_ms = $maxLatency
    }
    $reportDir = Split-Path -Parent $ReportPath
    if (-not (Test-Path $reportDir)) {
        New-Item -ItemType Directory -Path $reportDir | Out-Null
    }
    $report | ConvertTo-Json -Depth 3 | Set-Content -Path $ReportPath -Encoding UTF8
    Write-Host "`n=== ETW PERF SUMMARY ==="
    $report | Format-Table | Out-String | Write-Host
    return $report
}

$agentExe = Ensure-AgentBinary -Path $AgentBinary
$configPath = Join-Path ([System.IO.Path]::GetTempPath()) ("etw-perf-{0}.yaml" -f ([System.Guid]::NewGuid().ToString("N")))
try {
    Write-CollectorConfig -Path $configPath -Providers $Providers | Out-Null
    $stats = Start-Collect -Agent $agentExe -ConfigPath $configPath -DurationSeconds $DurationSeconds -OutputPath $OutputPath
    if ($stats.EventCount -eq 0) {
        throw "collection produced zero events; check providers or permissions"
    }
    $report = Write-Report -Stats $stats -ReportPath $ReportPath -DurationSeconds $DurationSeconds
    $violations = @()
    if ($EnforceThresholds) {
        if ($report.events -lt $MinEvents) {
            $violations += "event count $($report.events) < min $MinEvents"
        }
        if ($report.avg_latency_ms -gt $MaxAvgLatencyMs) {
            $violations += "avg latency $($report.avg_latency_ms)ms > max $MaxAvgLatencyMs ms"
        }
        if ($report.max_latency_ms -gt $MaxMaxLatencyMs) {
            $violations += "max latency $($report.max_latency_ms)ms > max $MaxMaxLatencyMs ms"
        }
    }
    if ($violations.Count -gt 0) {
        Write-Error "Threshold violations:`n - $($violations -join "`n - ")"
        exit 1
    }
}
finally {
    if (Test-Path $configPath) {
        Remove-Item $configPath -Force
    }
}
