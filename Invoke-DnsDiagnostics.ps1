#Requires -Version 5.1
<#
.SYNOPSIS
    Audits and diagnoses DNS configuration issues on a Windows machine.

.DESCRIPTION
    Collects DNS settings, tests resolution, validates PTR records, checks the hosts
    file, and tests each configured DNS server for reachability and query capability.
    Classifies findings by severity and provides root-cause explanations with
    remediation steps.

    Suitable for interactive troubleshooting and PDQ Inventory deployments.
    PDQ exit codes: 0 = Healthy, 1 = Warnings, 2 = Critical issues.

    NOTE: Do not dot-source this script. It calls 'exit' at the end to return
    an exit code to PDQ and other automation runners.

.PARAMETER ComputerName
    Target machine to audit. Defaults to the local machine.

.PARAMETER Detailed
    Include the full raw collected data in the structured output object's RawData property.

.PARAMETER NoColor
    Suppress color-coded output. Automatically enabled in PDQ and other
    non-interactive environments.

.PARAMETER LogFile
    Path to write a plain-text log file of the diagnostic run.

.EXAMPLE
    .\Invoke-DnsDiagnostics.ps1
    Runs diagnostics on the local machine with color output.

.EXAMPLE
    .\Invoke-DnsDiagnostics.ps1 -ComputerName WORKSTATION01 -Detailed
    Runs diagnostics against a remote machine and includes raw data in output.

.EXAMPLE
    .\Invoke-DnsDiagnostics.ps1 -LogFile C:\Logs\dns-$(hostname).txt
    Runs locally and writes output to a log file.
#>

[CmdletBinding()]
param(
    [Parameter(Position = 0)]
    [string]$ComputerName = $env:COMPUTERNAME,

    [switch]$Detailed,
    [switch]$NoColor,
    [string]$LogFile
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Continue'

# ── Severity constants (referenced via $script: inside functions) ──────────────
$script:SEV_INFO     = 'Info'
$script:SEV_WARN     = 'Warning'
$script:SEV_CRITICAL = 'Critical'

# Well-known public DNS IPs — flagged on domain-joined machines
$script:PUBLIC_DNS = @(
    '8.8.8.8', '8.8.4.4',                    # Google
    '1.1.1.1', '1.0.0.1',                    # Cloudflare
    '9.9.9.9', '149.112.112.112',             # Quad9
    '208.67.222.222', '208.67.220.220',       # OpenDNS
    '4.2.2.1', '4.2.2.2'                     # Level3
)

# Auto-detect non-interactive / PDQ execution context
$script:IsNonInteractive = (
    ($env:PDQ_DEPLOY_PACKAGE_ID -ne $null)        -or
    ($env:PDQ_INVENTORY_CUSTOM_COLUMN_ID -ne $null) -or
    (-not [System.Environment]::UserInteractive)
)
if ($script:IsNonInteractive) { $NoColor = $true }

# ── Output helper ─────────────────────────────────────────────────────────────

function Write-Status {
    param(
        [string]$Message,
        [ValidateSet('Info', 'Success', 'Warning', 'Critical', 'Section', 'Detail')]
        [string]$Level = 'Info'
    )

    $timestamp = Get-Date -Format 'HH:mm:ss'
    $prefix = switch ($Level) {
        'Success'  { '[OK]  ' }
        'Warning'  { '[WARN]' }
        'Critical' { '[CRIT]' }
        default    { '[INFO]' }
    }
    $line = "[$timestamp] $prefix $Message"

    if ($LogFile) {
        Add-Content -Path $LogFile -Value $line -ErrorAction SilentlyContinue
    }

    if ($NoColor) {
        Write-Host $line
        return
    }

    $color = switch ($Level) {
        'Success'  { 'Green'    }
        'Warning'  { 'Yellow'   }
        'Critical' { 'Red'      }
        'Section'  { 'Cyan'     }
        'Detail'   { 'DarkGray' }
        default    { 'White'    }
    }
    Write-Host $line -ForegroundColor $color
}

function Write-Section {
    param([string]$Title)
    Write-Status '' -Level Info
    Write-Status ('-' * 65) -Level Section
    Write-Status "  $Title" -Level Section
    Write-Status ('-' * 65) -Level Section
}

# ── Remote data collection ────────────────────────────────────────────────────

function Get-TargetDnsData {
    <#
    .SYNOPSIS
        Runs all data collection and DNS tests on the target machine.
        For remote targets, executes via Invoke-Command (requires WinRM).
        Returns a hashtable of raw diagnostic data.
    #>
    param([string]$Target)

    $isLocal = (
        $Target -eq $env:COMPUTERNAME -or
        $Target -eq 'localhost'        -or
        $Target -eq '127.0.0.1'        -or
        $Target -eq '.'
    )

    # All collection and per-server DNS tests run ON the target machine so that
    # reachability results reflect the target's network path, not the admin's.
    $collectBlock = {
        $data = @{}

        # ── Network adapters ──────────────────────────────────────────────
        $data.Adapters = @(
            Get-NetAdapter -ErrorAction SilentlyContinue |
                Select-Object Name, InterfaceIndex, Status, MediaConnectionState,
                    LinkSpeed, MacAddress
        )

        # ── DNS server assignments (IPv4) ─────────────────────────────────
        $data.DnsServers = @(
            Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
                Select-Object InterfaceIndex, InterfaceAlias, ServerAddresses
        )

        # ── Per-adapter DNS client settings ───────────────────────────────
        $data.DnsClient = @(
            Get-DnsClient -ErrorAction SilentlyContinue |
                Select-Object InterfaceIndex, InterfaceAlias,
                    ConnectionSpecificSuffix, RegisterThisConnectionsAddress,
                    UseSuffixWhenRegistering
        )

        # ── Global DNS suffix search list ─────────────────────────────────
        try {
            $g = Get-DnsClientGlobalSetting -ErrorAction Stop
            $data.GlobalDns = @{
                SuffixSearchList = [string[]]$g.SuffixSearchList
                UseDevolution    = [bool]$g.UseDevolution
            }
        } catch {
            $data.GlobalDns = @{ SuffixSearchList = @(); UseDevolution = $false }
        }

        # ── Computer / domain info (machine-level, reliable under WinRM) ──
        try {
            $cs = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
            $data.ComputerSystem = @{
                Name         = [string]$cs.Name
                Domain       = [string]$cs.Domain
                PartOfDomain = [bool]$cs.PartOfDomain
                Workgroup    = [string]$cs.Workgroup
            }
        } catch {
            $data.ComputerSystem = @{
                Name         = $env:COMPUTERNAME
                Domain       = $env:USERDOMAIN
                PartOfDomain = $false
                Workgroup    = $env:USERDOMAIN
            }
        }

        # ── Local operational IP addresses ────────────────────────────────
        # Exclude: loopback, APIPA (169.254.x.x), link-local, and tunnel adapters.
        # Only consider addresses from adapters that are Up.
        $upIndexes = @(
            Get-NetAdapter -ErrorAction SilentlyContinue |
                Where-Object { $_.Status -eq 'Up' } |
                Select-Object -ExpandProperty InterfaceIndex
        )
        $data.LocalIPs = @(
            Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
                Where-Object {
                    $_.IPAddress -ne '127.0.0.1'             -and
                    $_.IPAddress -notmatch '^169\.254\.'      -and
                    $_.PrefixOrigin -ne 'WellKnown'           -and
                    $upIndexes -contains $_.InterfaceIndex
                } |
                Select-Object -ExpandProperty IPAddress
        )

        # ── Hosts file ────────────────────────────────────────────────────
        $hostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"
        $data.HostsFile = @{
            Path    = $hostsPath
            Exists  = (Test-Path $hostsPath)
            Entries = @()
        }
        if ($data.HostsFile.Exists) {
            $data.HostsFile.Entries = @(
                Get-Content $hostsPath -ErrorAction SilentlyContinue |
                    Where-Object { $_ -notmatch '^\s*#' -and $_ -match '\S' } |
                    ForEach-Object {
                        $rawLine = $_
                        # Split on whitespace; tokens starting with '#' begin an inline comment
                        $tokens = ($rawLine -split '\s+') | Where-Object { $_ -ne '' }
                        if ($tokens.Count -ge 2 -and $tokens[0] -notmatch '^#') {
                            $ip = $tokens[0].Trim()
                            # Collect all alias tokens up to (but not including) any inline comment
                            $aliases = @()
                            for ($i = 1; $i -lt $tokens.Count; $i++) {
                                if ($tokens[$i] -match '^#') { break }
                                $aliases += $tokens[$i].Trim()
                            }
                            foreach ($alias in $aliases) {
                                [PSCustomObject]@{
                                    IPAddress = $ip
                                    Hostname  = $alias
                                    RawLine   = $rawLine
                                }
                            }
                        }
                    } | Where-Object { $_ -ne $null }
            )
        }

        # ── Name resolution tests ─────────────────────────────────────────
        # Use machine-level domain from Win32_ComputerSystem, not $env:USERDNSDOMAIN,
        # because env vars are unreliable under WinRM / LocalSystem / PDQ contexts.
        $hostname = $data.ComputerSystem.Name
        $domain   = $data.ComputerSystem.Domain
        $fqdn     = if ($data.ComputerSystem.PartOfDomain -and $domain) {
            "$hostname.$domain"
        } else {
            $hostname
        }

        # Use fixed logical keys so hostname == fqdn on non-domain machines doesn't
        # cause a hashtable key collision.
        $data.ResolutionTests = @{
            HostShort = @{ QueryName = $hostname;  Success = $false; Records = @(); Error = $null }
            HostFqdn  = @{ QueryName = $fqdn;      Success = $false; Records = @(); Error = $null }
            Localhost = @{ QueryName = 'localhost'; Success = $false; Records = @(); Error = $null }
        }

        foreach ($key in @('HostShort', 'HostFqdn', 'Localhost')) {
            $name = $data.ResolutionTests[$key].QueryName
            try {
                $r = Resolve-DnsName -Name $name -ErrorAction Stop
                $data.ResolutionTests[$key].Success = $true
                $data.ResolutionTests[$key].Records = @(
                    $r | Select-Object Name, Type, IPAddress, NameHost, TTL
                )
            } catch {
                $data.ResolutionTests[$key].Error = $_.Exception.Message
            }
        }

        # ── PTR (reverse) lookups for each local operational IP ───────────
        $data.ReverseLookups = @{}
        foreach ($ip in $data.LocalIPs) {
            try {
                $ptr = Resolve-DnsName -Name $ip -Type PTR -ErrorAction Stop
                $data.ReverseLookups[$ip] = @{
                    Success  = $true
                    NameHost = [string]($ptr | Where-Object { $_.Type -eq 'PTR' } |
                                    Select-Object -First 1 -ExpandProperty NameHost)
                    Error    = $null
                }
            } catch {
                $data.ReverseLookups[$ip] = @{
                    Success  = $false
                    NameHost = $null
                    Error    = $_.Exception.Message
                }
            }
        }

        # ── DNS server connectivity tests (run from target) ───────────────
        # DNS query is the authoritative pass/fail; ping and TCP/53 are informational.
        $allServers = @(
            $data.DnsServers | ForEach-Object { $_.ServerAddresses } | Select-Object -Unique
        )

        # Choose a test name relevant to the machine's context.
        # For domain-joined machines, use the AD domain name (resolvable by any internal DNS server).
        # For workgroup machines, use the machine's own hostname rather than an internet name —
        # internal-only resolvers (Pi-hole, split-horizon, air-gapped) cannot resolve
        # dns.msftncsi.com and would be incorrectly flagged as unhealthy.
        $testName = if ($data.ComputerSystem.PartOfDomain -and $data.ComputerSystem.Domain) {
            $data.ComputerSystem.Domain
        } else {
            $data.ComputerSystem.Name
        }

        $data.ServerTests = @{}
        foreach ($server in $allServers) {
            $st = @{
                Server    = $server
                Ping      = $false
                Port53TCP = $false
                Query     = $false
                Error     = $null
            }

            # ICMP ping (informational)
            try {
                $st.Ping = [bool](Test-Connection -ComputerName $server -Count 1 -Quiet -ErrorAction Stop)
            } catch {
                $st.Ping = $false
            }

            # TCP port 53 (informational — works even when ICMP is blocked)
            try {
                $tcp = New-Object System.Net.Sockets.TcpClient
                $ar  = $tcp.BeginConnect($server, 53, $null, $null)
                $ok  = $ar.AsyncWaitHandle.WaitOne(2000, $false)
                if ($ok -and $tcp.Connected) { $st.Port53TCP = $true }
                $tcp.Close()
            } catch {
                $st.Port53TCP = $false
            }

            # Actual DNS query — this is the authoritative health indicator
            try {
                $q = Resolve-DnsName -Name $testName -Server $server -ErrorAction Stop
                $st.Query = ($null -ne $q -and $q.Count -gt 0)
            } catch {
                $st.Query = $false
                $st.Error = $_.Exception.Message
            }

            $data.ServerTests[$server] = $st
        }

        return $data
    }

    if ($isLocal) {
        return (& $collectBlock)
    }

    try {
        return Invoke-Command -ComputerName $Target -ScriptBlock $collectBlock -ErrorAction Stop
    } catch {
        throw "Unable to connect to '$Target' via PowerShell remoting: $($_.Exception.Message)"
    }
}

# ── Analysis ──────────────────────────────────────────────────────────────────

function Invoke-DnsAnalysis {
    <#
    .SYNOPSIS
        Inspects collected data and classifies DNS issues with root-cause descriptions
        and remediation steps. Returns @{ Issues, Fixes }.
    #>
    param([hashtable]$Data)

    $issues = New-Object System.Collections.Generic.List[PSCustomObject]
    $fixes  = New-Object System.Collections.Generic.List[PSCustomObject]

    function Add-Finding {
        param(
            [string]$Severity,
            [string]$Category,
            [string]$Description,
            [string]$Fix
        )
        $issues.Add([PSCustomObject]@{
            Severity    = $Severity
            Category    = $Category
            Description = $Description
        })
        if ($Fix) {
            $fixes.Add([PSCustomObject]@{
                Category = $Category
                Fix      = $Fix
            })
        }
    }

    # ── Active adapter check ──────────────────────────────────────────────────
    $activeAdapters = @($Data.Adapters | Where-Object { $_.Status -eq 'Up' })
    if ($activeAdapters.Count -eq 0) {
        Add-Finding $script:SEV_CRITICAL 'Adapter' `
            'No active (Up) network adapters found. The machine has no network connectivity.' `
            'Open Device Manager and enable or repair the network adapter.'
    }

    # ── DNS server assignment check ───────────────────────────────────────────
    $adaptersWithDns = @($Data.DnsServers | Where-Object { $_.ServerAddresses.Count -gt 0 })
    if ($adaptersWithDns.Count -eq 0) {
        Add-Finding $script:SEV_CRITICAL 'DNS Config' `
            'No DNS servers are configured on any network adapter.' `
            'Configure DNS server IPs via Network Adapter settings, or verify that DHCP is delivering option 6 (DNS Servers).'
    }

    # ── Conflicting DNS configs across adapters ───────────────────────────────
    # Only warn if multiple adapters (that have DNS) disagree — common in multihomed
    # machines and VPN setups but still worth surfacing.
    $fingerprints = @{}
    foreach ($entry in $adaptersWithDns) {
        $fp = ($entry.ServerAddresses | Sort-Object) -join ','
        if (-not $fingerprints.ContainsKey($fp)) { $fingerprints[$fp] = [System.Collections.ArrayList]@() }
        [void]$fingerprints[$fp].Add($entry.InterfaceAlias)
    }
    if ($fingerprints.Count -gt 1) {
        $detail = ($fingerprints.Keys | ForEach-Object {
            "$($fingerprints[$_] -join ', ') -> [$_]"
        }) -join '  |  '
        Add-Finding $script:SEV_WARN 'DNS Config' `
            "Multiple adapters have different DNS server configurations: $detail. Resolution may differ depending on which adapter handles a query." `
            'Ensure all active adapters use the same DNS servers, or disable/unbind adapters not required for domain connectivity.'
    }

    # ── Public DNS on domain-joined machine ───────────────────────────────────
    if ($Data.ComputerSystem.PartOfDomain) {
        $allServers = @($Data.DnsServers | ForEach-Object { $_.ServerAddresses } | Select-Object -Unique)
        $publicFound = @($allServers | Where-Object { $script:PUBLIC_DNS -contains $_ })
        if ($publicFound.Count -gt 0) {
            Add-Finding $script:SEV_WARN 'Security' `
                "Public DNS servers configured on domain-joined machine: $($publicFound -join ', '). Public resolvers cannot answer internal Active Directory queries (DC lookups, SRV records, internal FQDNs)." `
                "Remove public DNS entries ($($publicFound -join ', ')) and replace with internal AD DNS server IPs. Verify DHCP option 6."
        }
    }

    # ── DNS server health (from on-machine tests) ─────────────────────────────
    foreach ($server in $Data.ServerTests.Keys) {
        $t = $Data.ServerTests[$server]
        if (-not $t.Query) {
            $reachable = $t.Ping -or $t.Port53TCP
            $sev       = if ($reachable) { $script:SEV_WARN } else { $script:SEV_CRITICAL }
            $desc = if ($reachable) {
                "DNS server $server is reachable (Ping=$($t.Ping) TCP53=$($t.Port53TCP)) but did not respond to a DNS query. The DNS service may be stopped or misconfigured on that server."
            } else {
                "DNS server $server is unreachable from this machine (Ping=$($t.Ping) TCP53=$($t.Port53TCP)). All resolution relying on this server will fail."
            }
            $fix = if ($reachable) {
                "Verify the DNS Server service is running on $server. Check firewall rules allow inbound UDP/TCP 53."
            } else {
                "Verify $server is online and reachable. Confirm network routing and firewall rules allow UDP/TCP 53 from this machine to $server."
            }
            Add-Finding $sev 'DNS Server' $desc $fix
        }
    }

    # ── Hosts file overrides ──────────────────────────────────────────────────
    $nonLoopback = @($Data.HostsFile.Entries | Where-Object {
        $_.IPAddress -notmatch '^127\.' -and $_.IPAddress -ne '::1'
    })
    if ($nonLoopback.Count -gt 0) {
        $entries = ($nonLoopback | ForEach-Object { "$($_.IPAddress) $($_.Hostname)" }) -join '; '
        Add-Finding $script:SEV_WARN 'Hosts File' `
            "Non-loopback hosts file entries override DNS for those names: $entries. Stale entries cause hard-to-diagnose resolution failures." `
            "Review %SystemRoot%\System32\drivers\etc\hosts. Remove stale or unauthorized entries."
    }

    # Flag domain-related entries in hosts (potential DNS hijack / split-brain indicator)
    if ($Data.ComputerSystem.PartOfDomain -and $Data.ComputerSystem.Domain) {
        $domain       = $Data.ComputerSystem.Domain
        $domainInHosts = @($nonLoopback | Where-Object { $_.Hostname -match "(?i)(^|\.)$([regex]::Escape($domain))$" })
        if ($domainInHosts.Count -gt 0) {
            $names = ($domainInHosts | ForEach-Object { $_.Hostname }) -join ', '
            Add-Finding $script:SEV_CRITICAL 'Hosts File' `
                "Domain names in hosts file will bypass DNS for critical AD lookups: $names. This breaks domain authentication, Group Policy, and Kerberos." `
                "Remove domain-related entries ($names) from the hosts file immediately. These override Active Directory DNS and are a security risk."
        }
    }

    # ── Name resolution results ───────────────────────────────────────────────
    $hostname = $Data.ComputerSystem.Name
    $localIPs = @($Data.LocalIPs)

    foreach ($key in @('HostShort', 'HostFqdn', 'Localhost')) {
        $test = $Data.ResolutionTests[$key]
        $name = $test.QueryName

        if (-not $test.Success) {
            if ($key -eq 'Localhost') {
                Add-Finding $script:SEV_WARN 'Resolution' `
                    "Failed to resolve 'localhost': $($test.Error). The loopback entry may be missing from the hosts file." `
                    "Verify the hosts file contains '127.0.0.1  localhost' and '::1  localhost'."
            } else {
                Add-Finding $script:SEV_CRITICAL 'Resolution' `
                    "Failed to resolve '$name': $($test.Error). The machine cannot look up its own name, breaking many Windows services (Kerberos, RPC, SMB)." `
                    "Verify an A record for '$name' exists in DNS. Run 'ipconfig /registerdns' and check DNS server health."
            }
            continue
        }

        # IP mismatch: DNS A record returns an address not held by this machine
        if ($key -ne 'Localhost' -and $localIPs.Count -gt 0) {
            $resolvedIPs = @($test.Records | Where-Object { $_.Type -eq 'A' } |
                                Select-Object -ExpandProperty IPAddress)
            $mismatch = @($resolvedIPs | Where-Object { $localIPs -notcontains $_ })
            if ($mismatch.Count -gt 0 -and $resolvedIPs.Count -gt 0) {
                Add-Finding $script:SEV_WARN 'Stale Record' `
                    "DNS A record for '$name' resolves to [$($mismatch -join ', ')] but this machine's IPs are [$($localIPs -join ', ')]. Likely a stale record from a previous IP address." `
                    "Run 'ipconfig /registerdns' to force re-registration. If the stale record persists, delete it manually in DNS Manager and verify scavenging is configured."
            }
        }
    }

    # ── PTR / reverse lookup ──────────────────────────────────────────────────
    foreach ($ip in $Data.ReverseLookups.Keys) {
        $ptr = $Data.ReverseLookups[$ip]
        if (-not $ptr.Success) {
            Add-Finding $script:SEV_WARN 'PTR Record' `
                "No PTR (reverse DNS) record found for $ip. Missing PTR records cause failures in some applications, SMTP, and security auditing tools." `
                "Create a PTR record in the reverse lookup zone for $ip, or run 'ipconfig /registerdns' if dynamic DNS updates are enabled."
        } elseif ($ptr.NameHost -and ($ptr.NameHost -notmatch "(?i)^$([regex]::Escape($hostname))(\.|\s*$)")) {
            Add-Finding $script:SEV_WARN 'PTR Record' `
                "PTR record for $ip resolves to '$($ptr.NameHost)', not '$hostname'. This is a stale or incorrect reverse record." `
                "Delete the PTR record for $ip and run 'ipconfig /registerdns' to re-register the correct reverse record."
        }
    }

    # ── DNS suffix / domain mismatch ──────────────────────────────────────────
    if ($Data.ComputerSystem.PartOfDomain -and $Data.ComputerSystem.Domain) {
        $domain     = $Data.ComputerSystem.Domain
        $searchList = @($Data.GlobalDns.SuffixSearchList)

        if ($searchList.Count -gt 0 -and ($searchList -notcontains $domain)) {
            Add-Finding $script:SEV_WARN 'DNS Suffix' `
                "Domain '$domain' is not in the DNS suffix search list: [$($searchList -join ', ')]. Short-name queries will not automatically resolve internal domain resources." `
                'Update the DNS suffix search list via Group Policy (Computer Configuration > DNS Client) to include the domain suffix.'
        }

        $wrongSuffix = @($Data.DnsClient | Where-Object {
            $_.ConnectionSpecificSuffix -and
            $_.ConnectionSpecificSuffix -ne $domain
        })
        if ($wrongSuffix.Count -gt 0) {
            $detail = ($wrongSuffix | ForEach-Object {
                "$($_.InterfaceAlias)=$($_.ConnectionSpecificSuffix)"
            }) -join ', '
            Add-Finding $script:SEV_WARN 'DNS Suffix' `
                "Adapter(s) have a connection-specific suffix different from the domain '$domain': $detail. DHCP option 15 may be misconfigured." `
                "Verify DHCP scope option 15 is set to '$domain', or correct the connection-specific suffix manually on the affected adapters."
        }
    }

    # ── Dynamic registration flags ────────────────────────────────────────────
    $notRegistering = @($Data.DnsClient | Where-Object {
        $_.RegisterThisConnectionsAddress -eq $false
    })
    if ($notRegistering.Count -gt 0) {
        $names = ($notRegistering | ForEach-Object { $_.InterfaceAlias }) -join ', '
        Add-Finding $script:SEV_WARN 'DNS Registration' `
            "DNS dynamic registration is disabled on adapter(s): $names. The machine will not self-update its DNS A record on IP change." `
            "Enable 'Register this connection''s addresses in DNS' on the affected adapters, or verify this is intentional for the adapter type."
    }

    return @{
        Issues = $issues.ToArray()
        Fixes  = $fixes.ToArray()
    }
}

# ── Report ────────────────────────────────────────────────────────────────────

function Write-DnsReport {
    <#
    .SYNOPSIS
        Renders a human-readable diagnostic report to the host.
        Returns the overall health status string: 'Healthy', 'Warning', or 'Critical'.
    #>
    param(
        [string]$Target,
        [hashtable]$Data,
        [hashtable]$Analysis
    )

    $critCount   = @($Analysis.Issues | Where-Object { $_.Severity -eq $script:SEV_CRITICAL }).Count
    $warnCount   = @($Analysis.Issues | Where-Object { $_.Severity -eq $script:SEV_WARN }).Count
    $healthStatus = if ($critCount -gt 0) { 'Critical' } elseif ($warnCount -gt 0) { 'Warning' } else { 'Healthy' }
    $healthLevel  = if ($critCount -gt 0) { 'Critical' } elseif ($warnCount -gt 0) { 'Warning' } else { 'Success' }

    # ── Header ────────────────────────────────────────────────────────────────
    Write-Section "DNS Diagnostic Report  --  $Target"
    Write-Status "Computer   : $($Data.ComputerSystem.Name)" -Level Info
    Write-Status "Domain     : $(if ($Data.ComputerSystem.PartOfDomain) { $Data.ComputerSystem.Domain } else { "(Workgroup: $($Data.ComputerSystem.Workgroup))" })" -Level Info
    Write-Status "DNS Status : $healthStatus  ($critCount critical, $warnCount warnings)" -Level $healthLevel

    # ── Network adapters ──────────────────────────────────────────────────────
    Write-Section 'Network Adapters'
    foreach ($a in $Data.Adapters) {
        $lvl = if ($a.Status -eq 'Up') { 'Success' } else { 'Warning' }
        Write-Status ("  {0,-32} Status={1,-10}  Speed={2}" -f $a.Name, $a.Status, $a.LinkSpeed) -Level $lvl
    }

    # ── DNS server configuration ──────────────────────────────────────────────
    Write-Section 'DNS Server Configuration (IPv4)'
    $hasDns = $false
    foreach ($entry in $Data.DnsServers) {
        if ($entry.ServerAddresses.Count -gt 0) {
            Write-Status ("  {0,-32} {1}" -f $entry.InterfaceAlias, ($entry.ServerAddresses -join ', ')) -Level Info
            $hasDns = $true
        }
    }
    if (-not $hasDns) {
        Write-Status '  No DNS servers configured on any adapter.' -Level Critical
    }

    # ── DNS server health (tested from target machine) ────────────────────────
    Write-Section 'DNS Server Health  (tested from target machine)'
    foreach ($server in ($Data.ServerTests.Keys | Sort-Object)) {
        $t = $Data.ServerTests[$server]
        $lvl    = if ($t.Query) { 'Success' } elseif ($t.Ping -or $t.Port53TCP) { 'Warning' } else { 'Critical' }
        $status = if ($t.Query) { 'Responding' } elseif ($t.Ping -or $t.Port53TCP) { 'Reachable / No DNS Response' } else { 'UNREACHABLE' }
        Write-Status ("  {0,-20}  {1,-30}  Ping={2}  TCP53={3}  Query={4}" -f
            $server, $status, $t.Ping, $t.Port53TCP, $t.Query) -Level $lvl
    }

    # ── Name resolution ───────────────────────────────────────────────────────
    Write-Section 'Name Resolution Tests'
    foreach ($key in @('HostShort', 'HostFqdn', 'Localhost')) {
        $test  = $Data.ResolutionTests[$key]
        $label = "{0,-12} ({1})" -f $key, $test.QueryName
        if ($test.Success) {
            $ips = @($test.Records | Where-Object { $_.Type -eq 'A' } |
                        Select-Object -ExpandProperty IPAddress)
            $resolved = if ($ips.Count -gt 0) { $ips -join ', ' } else { '(no A records)' }
            Write-Status ("  {0,-45}  -> {1}" -f $label, $resolved) -Level Success
        } else {
            Write-Status ("  {0,-45}  -> FAILED: {1}" -f $label, $test.Error) -Level Critical
        }
    }

    # ── Reverse lookups ───────────────────────────────────────────────────────
    Write-Section 'Reverse Lookups (PTR)'
    if ($Data.ReverseLookups.Count -eq 0) {
        Write-Status '  No operational local IPs found to test.' -Level Warning
    }
    foreach ($ip in ($Data.ReverseLookups.Keys | Sort-Object)) {
        $ptr = $Data.ReverseLookups[$ip]
        if ($ptr.Success) {
            Write-Status ("  {0,-20}  -> {1}" -f $ip, $ptr.NameHost) -Level Success
        } else {
            Write-Status ("  {0,-20}  -> NO PTR RECORD" -f $ip) -Level Warning
        }
    }

    # ── Hosts file ────────────────────────────────────────────────────────────
    Write-Section 'Hosts File  (non-loopback entries)'
    $nonLoopback = @($Data.HostsFile.Entries | Where-Object {
        $_.IPAddress -notmatch '^127\.' -and $_.IPAddress -ne '::1'
    })
    if ($nonLoopback.Count -eq 0) {
        Write-Status '  None found (only standard loopback entries present).' -Level Success
    } else {
        foreach ($e in $nonLoopback) {
            Write-Status ("  {0,-20}  {1}" -f $e.IPAddress, $e.Hostname) -Level Warning
        }
    }

    # ── Issues ────────────────────────────────────────────────────────────────
    Write-Section "Issues Found  ($($Analysis.Issues.Count) total  --  $critCount critical, $warnCount warnings)"
    if ($Analysis.Issues.Count -eq 0) {
        Write-Status '  No issues detected. DNS configuration appears healthy.' -Level Success
    } else {
        foreach ($issue in $Analysis.Issues) {
            $lvl = switch ($issue.Severity) {
                $script:SEV_CRITICAL { 'Critical' }
                $script:SEV_WARN     { 'Warning'  }
                default              { 'Info'     }
            }
            Write-Status "  [$($issue.Severity.ToUpper().PadRight(8))] [$($issue.Category)]  $($issue.Description)" -Level $lvl
        }
    }

    # ── Recommended fixes ─────────────────────────────────────────────────────
    if ($Analysis.Fixes.Count -gt 0) {
        Write-Section 'Recommended Fixes'
        $n = 1
        foreach ($fix in $Analysis.Fixes) {
            Write-Status "  $n. [$($fix.Category)]  $($fix.Fix)" -Level Info
            $n++
        }
    }

    return $healthStatus
}

# ── Entry point ───────────────────────────────────────────────────────────────

if ($LogFile) {
    $logDir = Split-Path $LogFile -Parent
    if ($logDir -and -not (Test-Path $logDir)) {
        New-Item -ItemType Directory -Path $logDir -Force | Out-Null
    }
    Add-Content -Path $LogFile -Value "=== DNS Diagnostic: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')  Target: $ComputerName ===" `
        -ErrorAction SilentlyContinue
}

Write-Status "Invoke-DnsDiagnostics  --  Target: $ComputerName" -Level Section

$exitCode = 2   # default to critical; overwritten on success
try {
    Write-Status 'Step 1/3 — Collecting DNS configuration and running resolution tests on target...' -Level Info
    $dnsData = Get-TargetDnsData -Target $ComputerName

    Write-Status 'Step 2/3 — Analyzing results...' -Level Info
    $analysis = Invoke-DnsAnalysis -Data $dnsData

    Write-Status 'Step 3/3 — Generating report...' -Level Info
    $healthStatus = Write-DnsReport -Target $ComputerName -Data $dnsData -Analysis $analysis

    # Structured output object — pipe-friendly and PDQ-collectable
    $result = [PSCustomObject]@{
        ComputerName     = $ComputerName
        DNSHealthStatus  = $healthStatus
        IssuesFound      = $analysis.Issues
        RecommendedFixes = $analysis.Fixes
        RawData          = if ($Detailed) { $dnsData } else { $null }
    }
    Write-Output $result

    $exitCode = switch ($healthStatus) {
        'Critical' { 2 }
        'Warning'  { 1 }
        default    { 0 }
    }
} catch {
    Write-Status "FATAL ERROR: $($_.Exception.Message)" -Level Critical
    Write-Status $_.ScriptStackTrace -Level Detail

    $result = [PSCustomObject]@{
        ComputerName     = $ComputerName
        DNSHealthStatus  = 'Error'
        IssuesFound      = @([PSCustomObject]@{
            Severity    = $script:SEV_CRITICAL
            Category    = 'Script Error'
            Description = $_.Exception.Message
        })
        RecommendedFixes = @()
        RawData          = $null
    }
    Write-Output $result
    $exitCode = 2
}

exit $exitCode
