# DNS Diagnostics

PowerShell script for auditing and diagnosing DNS configuration issues on Windows machines. Designed for interactive troubleshooting and automated deployment via **PDQ Inventory**.

## Requirements

| Requirement | Minimum |
|---|---|
| PowerShell | 5.1 |
| OS | Windows 8.1 / Server 2012 R2 or later |
| Modules | Built-in only (DnsClient, NetAdapter, NetTCPIP, CimCmdlets) |
| Remote targets | WinRM enabled on target (`winrm quickconfig`) |

## Usage

```powershell
# Local machine
.\Invoke-DnsDiagnostics.ps1

# Remote machine
.\Invoke-DnsDiagnostics.ps1 -ComputerName WORKSTATION01

# With log file
.\Invoke-DnsDiagnostics.ps1 -LogFile C:\Logs\dns-audit.txt

# Include raw collected data in output object
.\Invoke-DnsDiagnostics.ps1 -Detailed

# Suppress color (auto-set in PDQ; use for scripted pipelines)
.\Invoke-DnsDiagnostics.ps1 -NoColor
```

Full parameter help:
```powershell
Get-Help .\Invoke-DnsDiagnostics.ps1 -Full
```

## What It Checks

| Category | Check |
|---|---|
| **Adapter** | No active (Up) network adapters |
| **DNS Config** | No DNS servers configured on any adapter |
| **DNS Config** | Multiple adapters with conflicting DNS server lists |
| **DNS Server** | DNS server unreachable (ping + TCP/53 + query tested from target) |
| **DNS Server** | Server reachable but not responding to queries |
| **Resolution** | Machine cannot resolve its own hostname or FQDN |
| **Resolution** | Machine cannot resolve `localhost` |
| **Stale Record** | DNS A record returns an IP that doesn't match the machine's current IP |
| **PTR Record** | No reverse (PTR) record exists for a local IP |
| **PTR Record** | PTR record points to the wrong hostname |
| **Hosts File** | Non-loopback entries that override DNS |
| **Hosts File** | Domain names in hosts file (bypasses AD DNS — security risk) |
| **DNS Suffix** | Domain not in the global DNS suffix search list |
| **DNS Suffix** | Adapter connection-specific suffix doesn't match the domain |
| **DNS Registration** | Dynamic DNS registration disabled on an adapter |
| **Security** | Public DNS servers (8.8.8.8, 1.1.1.1, etc.) on a domain-joined machine |

> **Note:** All DNS tests run on the *target machine*, not the admin workstation. This ensures results reflect the target's actual network path and DNS configuration.

## Output

### Console (interactive)

Color-coded sections: adapters → DNS config → server health → resolution tests → reverse lookups → hosts file → issues → recommended fixes.

### Structured object (pipeline / PDQ)

```
ComputerName     : WORKSTATION01
DNSHealthStatus  : Warning
IssuesFound      : [@{Severity=Warning; Category=DNS Config; Description=...}, ...]
RecommendedFixes : [@{Category=DNS Config; Fix=...}, ...]
RawData          : (null unless -Detailed is used)
```

Pipe to `Export-Csv` for bulk auditing:
```powershell
'PC01','PC02','PC03' | ForEach-Object {
    .\Invoke-DnsDiagnostics.ps1 -ComputerName $_ -NoColor
} | Select-Object ComputerName, DNSHealthStatus |
    Export-Csv -Path dns-audit-$(Get-Date -Format yyyyMMdd).csv -NoTypeInformation
```

### Exit codes

| Code | Meaning |
|---|---|
| `0` | Healthy — no issues found |
| `1` | Warnings — non-critical issues found |
| `2` | Critical — one or more critical issues found |

## PDQ Inventory Setup

1. In PDQ Inventory, create a new **PowerShell** scanner.
2. Set the script to `Invoke-DnsDiagnostics.ps1` (or paste the contents).
3. PDQ automatically detects the non-interactive context and suppresses color output.
4. Use the exit code to drive a health status column:
   - `0` → Healthy
   - `1` → Warning
   - `2` → Critical

> **Do not dot-source this script.** It calls `exit` at the end to return the exit code. Dot-sourcing will terminate your PowerShell session.

## Log Files

Pass `-LogFile` to write a timestamped plain-text log alongside console output:

```powershell
.\Invoke-DnsDiagnostics.ps1 -LogFile "C:\Logs\dns-$env:COMPUTERNAME-$(Get-Date -Format yyyyMMdd).txt"
```

The log directory is created automatically if it doesn't exist.
