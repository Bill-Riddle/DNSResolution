# Copilot Instructions

## Project Purpose

PowerShell scripts for auditing, diagnosing, and reporting on DNS configuration on Windows machines in an Active Directory environment. Primary script: `Invoke-DnsDiagnostics.ps1`.

## Lint

```powershell
Invoke-ScriptAnalyzer -Path . -Recurse
```

## Architecture

`Invoke-DnsDiagnostics.ps1` is structured in four layers:

1. **Data collection** (`Get-TargetDnsData`) — runs a `$collectBlock` scriptblock either locally or via `Invoke-Command` for remote targets. All DNS tests (resolution, PTR lookups, per-server connectivity) run **on the target machine**, not the admin workstation.
2. **Analysis** (`Invoke-DnsAnalysis`) — pure logic; consumes the collected hashtable, returns `@{ Issues, Fixes }` arrays of `[PSCustomObject]`.
3. **Report** (`Write-DnsReport`) — renders color-coded console output, returns the health status string.
4. **Entry point** — wires the three layers together, emits a structured `[PSCustomObject]` via `Write-Output`, and calls `exit 0/1/2` for PDQ.

## Key Conventions

**PS 5.1 target** — no `??`, `?.`, or `?:` operators. Use explicit `if/else`. Script starts with `#Requires -Version 5.1`.

**DNS queries always in try/catch** — `Resolve-DnsName` throws on NXDOMAIN and timeouts rather than returning null.

**Use fixed logical keys for resolution tests**, not query strings as hashtable keys. Hostname and FQDN can be identical on non-domain machines, causing silent overwrites:
```powershell
# Correct
$data.ResolutionTests = @{
    HostShort = @{ QueryName = $hostname; ... }
    HostFqdn  = @{ QueryName = $fqdn;    ... }
    Localhost = @{ QueryName = 'localhost'; ... }
}
```

**Build FQDN from `Win32_ComputerSystem.Domain`**, not `$env:USERDNSDOMAIN`. The env var is unreliable under WinRM, PDQ, and LocalSystem contexts.

**DNS query is the authoritative server health indicator** — ping and TCP/53 are informational only. A server that fails ping but answers DNS queries is healthy.

**Filter local IPs before PTR tests** — exclude loopback (`127.x`), APIPA (`169.254.x`), and addresses from adapters that are not `Status=Up` to avoid false PTR findings on VMware/VPN/Bluetooth adapters.

**Scope severity constants explicitly** — reference as `$script:SEV_CRITICAL`, `$script:SEV_WARN` inside functions.

**PDQ exit codes**: `exit 0` = Healthy, `exit 1` = Warnings, `exit 2` = Critical. Do not dot-source scripts that call `exit`.

**Structured output via `Write-Output`** — emit a `[PSCustomObject]` with `ComputerName`, `DNSHealthStatus`, `IssuesFound`, `RecommendedFixes`, `RawData` (populated only with `-Detailed`).

**Color output via `Write-Host`** — auto-disabled when `PDQ_DEPLOY_PACKAGE_ID` or `PDQ_INVENTORY_CUSTOM_COLUMN_ID` env vars are set, or when `[System.Environment]::UserInteractive` is false.

## Module Dependencies

Built-in Windows modules only — no `Install-Module` required:
- `DnsClient` — `Resolve-DnsName`, `Get-DnsClientServerAddress`, `Get-DnsClient`, `Get-DnsClientGlobalSetting`
- `NetAdapter` / `NetTCPIP` — `Get-NetAdapter`, `Get-NetIPAddress`, `Get-NetIPConfiguration`
- `CimCmdlets` — `Get-CimInstance Win32_ComputerSystem`

All available on Windows 8.1+ / Server 2012 R2+ with PowerShell 5.1.
