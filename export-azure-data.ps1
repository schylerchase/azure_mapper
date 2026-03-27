#Requires -Version 7.0
<#
.SYNOPSIS
    Azure Network Mapper — Data Export Script (PowerShell)
.DESCRIPTION
    Exports Azure resource data as JSON files for import into the mapper.
    Supports parallel execution, retry on throttling, and all cloud environments.
    Outputs individual JSON files into a timestamped directory.
.PARAMETER Subscription
    Azure subscription name or ID (required)
.PARAMETER ResourceGroup
    Filter exports to a single resource group
.PARAMETER Location
    Filter results by Azure region/location (case-insensitive)
.PARAMETER Cloud
    Cloud environment: commercial, gcc, gcc-high, dod
.PARAMETER TenantId
    Tenant ID for cross-tenant / Lighthouse access
.PARAMETER OutputDir
    Output directory (optional, creates timestamped dir)
.PARAMETER Lighthouse
    Enable Azure Lighthouse delegated access mode
.PARAMETER MaxParallel
    Maximum parallel az CLI calls (default: 8)
.EXAMPLE
    ./export-azure-data.ps1 -Subscription "My Sub"
    ./export-azure-data.ps1 -s "sub-id" -g "my-rg" -l eastus
    ./export-azure-data.ps1 -s "sub-id" -Cloud gcc-high -MaxParallel 12
    ./export-azure-data.ps1 -s "sub-id" -TenantId "tenant-guid" -Lighthouse
#>
[CmdletBinding()]
param(
    [Alias("s")][Parameter(Mandatory)][string]$Subscription,
    [Alias("g")][string]$ResourceGroup,
    [Alias("l")][string]$Location,
    [Alias("c")][string]$Cloud,
    [Alias("t")][string]$TenantId,
    [Alias("o")][string]$OutputDir,
    [switch]$Lighthouse,
    [int]$MaxParallel = 8
)

$ErrorActionPreference = "Stop"
$totalTimer = [Diagnostics.Stopwatch]::StartNew()

# ─── Validation ───────────────────────────────────────────────

if (-not (Get-Command az -ErrorAction SilentlyContinue)) {
    Write-Error "Azure CLI (az) not found. Install from https://aka.ms/install-az-cli"
    exit 1
}

if ($Cloud) {
    switch ($Cloud) {
        { $_ -in "commercial", "AzureCloud" } {
            az cloud set --name AzureCloud --only-show-errors 2>$null
            Write-Host "  Cloud: Azure Commercial"
        }
        "gcc" {
            az cloud set --name AzureCloud --only-show-errors 2>$null
            Write-Host "  Cloud: Azure GCC (Commercial endpoints, policy-restricted)"
        }
        { $_ -in "gcc-high", "AzureUSGovernment" } {
            az cloud set --name AzureUSGovernment --only-show-errors 2>$null
            Write-Host "  Cloud: Azure GCC High"
        }
        "dod" {
            az cloud set --name AzureUSGovernment --only-show-errors 2>$null
            Write-Host "  Cloud: Azure DoD"
        }
        default {
            Write-Error "Unknown cloud '$Cloud'. Use: commercial, gcc, gcc-high, dod"
            exit 1
        }
    }
}

if ($TenantId) {
    Write-Host "  Tenant: $TenantId"
    if ($Lighthouse) { Write-Host "  Mode: Azure Lighthouse (delegated access)" }
}

$loginCheck = az account show --only-show-errors 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Error "Not logged in. Run 'az login' first.$(if ($TenantId) { " For tenant access: az login --tenant $TenantId" })"
    exit 1
}

Write-Host "  Setting subscription to: $Subscription"
az account set --subscription $Subscription --only-show-errors 2>$null
if ($LASTEXITCODE -ne 0) {
    Write-Error "Could not set subscription '$Subscription'. Run 'az account list -o table' to see available subscriptions."
    exit 1
}

# ─── Output directory ─────────────────────────────────────────

if (-not $OutputDir) {
    $ts = Get-Date -Format "yyyyMMdd-HHmmss"
    $subSafe = $Subscription -replace '[\s/:]', '-'
    $OutputDir = "./azure-export-${subSafe}-${ts}"
}
New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null

# ─── Common flags ─────────────────────────────────────────────

$commonFlags = @("--subscription", $Subscription, "--only-show-errors")
$commonRgFlags = @("--subscription", $Subscription, "--only-show-errors")
if ($ResourceGroup) {
    $commonRgFlags += @("-g", $ResourceGroup)
}

# ─── Banner ───────────────────────────────────────────────────

Write-Host ""
Write-Host "  ╔══════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "  ║     Azure Network Mapper — Data Export (PS)          ║" -ForegroundColor Cyan
Write-Host "  ╚══════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Subscription : $Subscription"
if ($ResourceGroup) { Write-Host "  Resource Group: $ResourceGroup" }
if ($Location)      { Write-Host "  Location      : $Location" }
Write-Host "  Parallel     : $MaxParallel concurrent calls"
Write-Host "  Output       : $OutputDir"
Write-Host ""

# ─── Retry helper ─────────────────────────────────────────────

function Invoke-AzWithRetry {
    param([string[]]$Cmd, [int]$MaxRetry = 3)
    for ($i = 0; $i -lt $MaxRetry; $i++) {
        $result = & az @Cmd 2>&1
        if ($LASTEXITCODE -eq 0) { return $result }
        $errStr = $result | Out-String
        if ($errStr -match '429|Too Many Requests|throttl') {
            $wait = [Math]::Pow(2, $i + 1)
            Start-Sleep -Seconds $wait
            continue
        }
        return $result
    }
    return $result
}

# ─── Export definitions (simple list commands) ────────────────
# Each: Label, File, Cmd (array of az CLI args), UseRg (bool)

$exports = @(
    # == Network ==
    @{ Label="Virtual Networks";         File="vnets.json";                Cmd=@("network","vnet","list");                              UseRg=$true  },
    @{ Label="NSGs";                     File="nsgs.json";                 Cmd=@("network","nsg","list");                               UseRg=$true  },
    @{ Label="Route Tables";             File="route-tables.json";         Cmd=@("network","route-table","list");                       UseRg=$true  },
    @{ Label="NICs";                     File="nics.json";                 Cmd=@("network","nic","list");                               UseRg=$true  },
    @{ Label="Public IPs";               File="public-ips.json";           Cmd=@("network","public-ip","list");                         UseRg=$true  },
    @{ Label="ASGs";                     File="asgs.json";                 Cmd=@("network","asg","list");                               UseRg=$true  },
    @{ Label="CDN Profiles";             File="cdn-profiles.json";         Cmd=@("cdn","profile","list");                               UseRg=$true  },
    @{ Label="Traffic Manager";          File="traffic-manager.json";      Cmd=@("network","traffic-manager","profile","list");          UseRg=$true  },
    @{ Label="Private Link Services";    File="private-link-services.json";Cmd=@("network","private-link-service","list");              UseRg=$true  },
    @{ Label="DDoS Protection Plans";    File="ddos-protection.json";      Cmd=@("network","ddos-protection","list");                   UseRg=$true  },
    # == Gateways ==
    @{ Label="NAT Gateways";             File="nat-gateways.json";         Cmd=@("network","nat","gateway","list");                     UseRg=$true  },
    @{ Label="Private Endpoints";        File="private-endpoints.json";    Cmd=@("network","private-endpoint","list");                  UseRg=$true  },
    @{ Label="Azure Firewalls";          File="firewalls.json";            Cmd=@("network","firewall","list");                          UseRg=$true  },
    @{ Label="Bastions";                 File="bastions.json";             Cmd=@("network","bastion","list");                           UseRg=$true  },
    # == Compute ==
    @{ Label="VMs";                      File="vms.json";                  Cmd=@("vm","list","--show-details");                         UseRg=$true  },
    @{ Label="Function Apps";            File="function-apps.json";        Cmd=@("functionapp","list");                                 UseRg=$true  },
    @{ Label="Container Instances";      File="container-instances.json";  Cmd=@("container","list");                                   UseRg=$true  },
    @{ Label="AKS Clusters";             File="aks-clusters.json";         Cmd=@("aks","list");                                         UseRg=$true  },
    @{ Label="App Service Plans";        File="app-service-plans.json";    Cmd=@("appservice","plan","list");                           UseRg=$true  },
    @{ Label="Web Apps";                 File="web-apps.json";             Cmd=@("webapp","list");                                      UseRg=$true  },
    @{ Label="Container Registries";     File="container-registries.json"; Cmd=@("acr","list");                                         UseRg=$true  },
    @{ Label="Batch Accounts";           File="batch-accounts.json";       Cmd=@("batch","account","list");                             UseRg=$true  },
    @{ Label="Virtual Desktop";          File="virtual-desktop.json";      Cmd=@("desktopvirtualization","hostpool","list");             UseRg=$true  },
    # == Load Balancing ==
    @{ Label="App Gateways";             File="app-gateways.json";         Cmd=@("network","application-gateway","list");               UseRg=$true  },
    @{ Label="Load Balancers";           File="load-balancers.json";       Cmd=@("network","lb","list");                                UseRg=$true  },
    # == Connectivity ==
    @{ Label="VPN Connections";          File="vpn-connections.json";      Cmd=@("network","vpn-connection","list");                    UseRg=$true  },
    @{ Label="vWANs";                    File="vwans.json";                Cmd=@("network","vwan","list");                              UseRg=$true  },
    @{ Label="Virtual Hubs";             File="vhubs.json";                Cmd=@("network","vhub","list");                              UseRg=$true  },
    @{ Label="VNet Gateways";            File="vnet-gateways.json";        Cmd=@("network","vnet-gateway","list");                      UseRg=$true  },
    @{ Label="Express Route Circuits";   File="express-routes.json";       Cmd=@("network","express-route","list");                     UseRg=$true  },
    # == Storage ==
    @{ Label="Disks";                    File="disks.json";                Cmd=@("disk","list");                                        UseRg=$true  },
    @{ Label="Snapshots";                File="snapshots.json";            Cmd=@("snapshot","list");                                    UseRg=$true  },
    @{ Label="Storage Accounts";         File="storage-accounts.json";     Cmd=@("storage","account","list");                           UseRg=$true  },
    @{ Label="NetApp Files";             File="netapp-accounts.json";      Cmd=@("netappfiles","account","list");                       UseRg=$true  },
    # == DNS ==
    @{ Label="DNS Zones";                File="dns-zones.json";            Cmd=@("network","dns","zone","list");                        UseRg=$true  },
    @{ Label="Private DNS Zones";        File="private-dns-zones.json";    Cmd=@("network","private-dns","zone","list");                UseRg=$true  },
    # == Security & Edge ==
    @{ Label="Front Doors";              File="front-doors.json";          Cmd=@("network","front-door","list");                        UseRg=$true  },
    @{ Label="WAF Policies";             File="waf-policies.json";         Cmd=@("network","application-gateway","waf-policy","list");  UseRg=$true  },
    @{ Label="Key Vaults";               File="key-vaults.json";           Cmd=@("keyvault","list");                                    UseRg=$true  },
    # == Database ==
    @{ Label="SQL Servers";              File="sql-servers.json";          Cmd=@("sql","server","list");                                UseRg=$true  },
    @{ Label="Redis Caches";             File="redis-caches.json";         Cmd=@("redis","list");                                       UseRg=$true  },
    @{ Label="Cosmos DB Accounts";       File="cosmos-accounts.json";      Cmd=@("cosmosdb","list");                                    UseRg=$true  },
    @{ Label="Synapse Workspaces";       File="synapse-workspaces.json";   Cmd=@("synapse","workspace","list");                         UseRg=$true  },
    @{ Label="MySQL Flexible Servers";   File="mysql-servers.json";        Cmd=@("mysql","flexible-server","list");                     UseRg=$true  },
    @{ Label="PostgreSQL Flexible Servers"; File="postgres-servers.json";  Cmd=@("postgres","flexible-server","list");                  UseRg=$true  },
    # == Integration ==
    @{ Label="Service Bus";              File="service-bus.json";          Cmd=@("servicebus","namespace","list");                      UseRg=$true  },
    @{ Label="Event Hubs";               File="event-hubs.json";           Cmd=@("eventhubs","namespace","list");                       UseRg=$true  },
    @{ Label="API Management";           File="api-management.json";       Cmd=@("apim","list");                                        UseRg=$true  },
    @{ Label="Logic Apps";               File="logic-apps.json";           Cmd=@("logic","workflow","list");                             UseRg=$true  },
    @{ Label="SignalR Services";         File="signalr.json";              Cmd=@("signalr","list");                                     UseRg=$true  },
    @{ Label="Relay Namespaces";         File="relay-namespaces.json";     Cmd=@("relay","namespace","list");                           UseRg=$true  },
    @{ Label="Data Factories";           File="data-factories.json";       Cmd=@("datafactory","list");                                 UseRg=$true  },
    @{ Label="IoT Hubs";                 File="iot-hubs.json";             Cmd=@("iot","hub","list");                                   UseRg=$true  },
    # == Observability ==
    @{ Label="Application Insights";     File="app-insights.json";         Cmd=@("monitor","app-insights","component","list");          UseRg=$true  },
    @{ Label="Log Analytics Workspaces"; File="log-analytics.json";        Cmd=@("monitor","log-analytics","workspace","list");         UseRg=$true  },
    @{ Label="Monitor Action Groups";    File="action-groups.json";        Cmd=@("monitor","action-group","list");                      UseRg=$true  },
    @{ Label="Monitor Metric Alerts";    File="metric-alerts.json";        Cmd=@("monitor","metrics","alert","list");                   UseRg=$true  },
    @{ Label="Automation Accounts";      File="automation-accounts.json";  Cmd=@("automation","account","list");                        UseRg=$true  },
    # == AI & Cognitive ==
    @{ Label="Cognitive Services";       File="cognitive-services.json";   Cmd=@("cognitiveservices","account","list");                 UseRg=$true  },
    @{ Label="ML Workspaces";            File="ml-workspaces.json";        Cmd=@("ml","workspace","list");                              UseRg=$true  },
    @{ Label="Purview Accounts";         File="purview-accounts.json";     Cmd=@("purview","account","list");                           UseRg=$true  },
    # == Identity ==
    @{ Label="Role Assignments";         File="role-assignments.json";     Cmd=@("role","assignment","list","--all");                   UseRg=$false },
    @{ Label="Role Definitions";         File="role-definitions.json";     Cmd=@("role","definition","list");                           UseRg=$false },
    @{ Label="Managed Identities";       File="managed-identities.json";   Cmd=@("identity","list");                                   UseRg=$true  },
    @{ Label="Policy Assignments";       File="policy-assignments.json";   Cmd=@("policy","assignment","list");                         UseRg=$false },
    # == Infrastructure ==
    @{ Label="Resource Groups";          File="resource-groups.json";      Cmd=@("group","list");                                       UseRg=$false },
    @{ Label="Network Watchers";         File="network-watchers.json";     Cmd=@("network","watcher","list");                           UseRg=$false },
    @{ Label="Azure Arc Machines";       File="arc-machines.json";         Cmd=@("connectedmachine","list");                            UseRg=$true  },
    @{ Label="Recovery Services Vaults"; File="recovery-vaults.json";      Cmd=@("backup","vault","list");                              UseRg=$true  },
    @{ Label="Managed Applications";     File="managed-apps.json";         Cmd=@("managedapp","list");                                  UseRg=$true  },
    @{ Label="Azure Maps";               File="maps-accounts.json";        Cmd=@("maps","account","list");                              UseRg=$true  }
)

# ─── Parallel export runner ───────────────────────────────────

Write-Host "  Running $($exports.Count) exports (parallel x$MaxParallel)..." -ForegroundColor Cyan
Write-Host ""

$results = $exports | ForEach-Object -ThrottleLimit $MaxParallel -Parallel {
    $export    = $_
    $outDir    = $using:OutputDir
    $subFlags  = $using:commonFlags
    $rgFlags   = $using:commonRgFlags
    $locFilter = $using:Location
    $maxRetry  = 3

    $flags = if ($export.UseRg) { $rgFlags } else { $subFlags }
    $fullCmd = @($export.Cmd) + @($flags) + @("-o", "json")
    $filePath = Join-Path $outDir $export.File
    $sw = [Diagnostics.Stopwatch]::StartNew()

    # Retry loop for throttling
    $rawResult = $null
    $succeeded = $false
    for ($i = 0; $i -lt $maxRetry; $i++) {
        $rawResult = & az @fullCmd 2>&1
        if ($LASTEXITCODE -eq 0) { $succeeded = $true; break }
        $errStr = $rawResult | Out-String
        if ($errStr -match '429|Too Many Requests|throttl') {
            Start-Sleep -Seconds ([Math]::Pow(2, $i + 1))
            continue
        }
        break
    }
    $sw.Stop()
    $elapsed = "{0:N1}s" -f $sw.Elapsed.TotalSeconds

    if ($succeeded) {
        try {
            $json = ($rawResult | Out-String) | ConvertFrom-Json
            $items = if ($json -is [System.Array]) { $json } else { @($json) }

            # Apply location filter if specified
            if ($locFilter -and $items.Count -gt 0) {
                $items = @($items | Where-Object { $_.location -and $_.location -ieq $locFilter })
            }

            if ($items.Count -eq 0) {
                "[]" | Out-File -FilePath $filePath -Encoding utf8
                @{ Label=$export.Label; File=$export.File; Status="EMPTY"; Items=0; Elapsed=$elapsed }
            } else {
                $items | ConvertTo-Json -Depth 20 -AsArray | Out-File -FilePath $filePath -Encoding utf8
                $size = (Get-Item $filePath).Length
                @{ Label=$export.Label; File=$export.File; Status="OK"; Items=$items.Count; Bytes=$size; Elapsed=$elapsed }
            }
        } catch {
            $rawResult | Out-File -FilePath $filePath -Encoding utf8
            $size = (Get-Item $filePath).Length
            @{ Label=$export.Label; File=$export.File; Status="OK"; Bytes=$size; Elapsed=$elapsed; Items="?" }
        }
    } else {
        "[]" | Out-File -FilePath $filePath -Encoding utf8
        $errMsg = ($rawResult | Out-String).Trim()
        if ($errMsg.Length -gt 80) { $errMsg = $errMsg.Substring(0, 80) }
        @{ Label=$export.Label; File=$export.File; Status="SKIP"; Detail=$errMsg; Elapsed=$elapsed }
    }
}

# Print results sorted by status
$okCount = 0; $emptyCount = 0; $skipCount = 0
foreach ($r in $results | Sort-Object { switch($_.Status){ "OK"{0} "EMPTY"{1} "SKIP"{2} } }, Label) {
    $color = switch ($r.Status) { "OK" { "Green" } "EMPTY" { "Yellow" } "SKIP" { "Red" } default { "Gray" } }
    $detail = switch ($r.Status) {
        "OK"    { "$($r.Items) items, $([Math]::Round($r.Bytes/1KB,1))KB" }
        "EMPTY" { "no resources" }
        "SKIP"  { $r.Detail }
    }
    $line = "  {0,-38} {1,-6} ({2})  {3}" -f $r.Label, $r.Status, $detail, $r.Elapsed
    Write-Host $line -ForegroundColor $color
    switch ($r.Status) { "OK" { $okCount++ } "EMPTY" { $emptyCount++ } "SKIP" { $skipCount++ } }
}

# ─── Multi-step exports (sequential — depend on prior outputs) ─

Write-Host ""
Write-Host "  Multi-step exports:" -ForegroundColor Cyan

function Get-JsonArray([string]$FilePath) {
    if (-not (Test-Path $FilePath)) { return @() }
    $content = Get-Content $FilePath -Raw | ConvertFrom-Json
    if ($content -is [System.Array]) { return $content } else { return @($content) }
}

function Export-IteratedResource {
    param(
        [string]$Label,
        [string]$OutFile,
        [array]$Parents,
        [scriptblock]$CommandBuilder
    )
    Write-Host "    $Label..." -NoNewline
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $all = @()
    $parentCount = 0
    foreach ($parent in $Parents) {
        $name = $parent.name
        $rg = $parent.resourceGroup
        if (-not $name -or -not $rg) { continue }
        $parentCount++
        try {
            $cmd = & $CommandBuilder $name $rg
            $result = Invoke-AzWithRetry -Cmd $cmd
            if ($LASTEXITCODE -eq 0 -and $result) {
                $parsed = ($result | Out-String) | ConvertFrom-Json
                if ($parsed -is [System.Array]) { $all += $parsed } else { $all += @($parsed) }
            }
        } catch { }
    }
    $sw.Stop()
    $elapsed = "{0:N1}s" -f $sw.Elapsed.TotalSeconds
    $filePath = Join-Path $OutputDir $OutFile
    $all | ConvertTo-Json -Depth 20 -AsArray | Out-File -FilePath $filePath -Encoding utf8
    if ($all.Count -eq 0) {
        Write-Host " EMPTY (0 from $parentCount parents) $elapsed" -ForegroundColor Yellow
        $script:emptyCount++
    } else {
        $size = (Get-Item $filePath).Length
        Write-Host " OK ($($all.Count) items from $parentCount parents, $([Math]::Round($size/1KB,1))KB) $elapsed" -ForegroundColor Green
        $script:okCount++
    }
}

# Load parent resources for iteration
$vnets = Get-JsonArray (Join-Path $OutputDir "vnets.json")
$dnsZones = Get-JsonArray (Join-Path $OutputDir "dns-zones.json")
$pdnsZones = Get-JsonArray (Join-Path $OutputDir "private-dns-zones.json")
$sqlServers = Get-JsonArray (Join-Path $OutputDir "sql-servers.json")

# Subnets (per VNet)
Export-IteratedResource -Label "Subnets" -OutFile "subnets.json" -Parents $vnets -CommandBuilder {
    param($name, $rg)
    @("network","vnet","subnet","list","--vnet-name",$name,"-g",$rg) + $commonFlags + @("-o","json")
}

# VNet Peerings (per VNet)
Export-IteratedResource -Label "VNet Peerings" -OutFile "peerings.json" -Parents $vnets -CommandBuilder {
    param($name, $rg)
    @("network","vnet","peering","list","--vnet-name",$name,"-g",$rg) + $commonFlags + @("-o","json")
}

# DNS Record Sets (public zones)
Export-IteratedResource -Label "DNS Records (public)" -OutFile "dns-records-public.json" -Parents $dnsZones -CommandBuilder {
    param($name, $rg)
    @("network","dns","record-set","list","--zone-name",$name,"-g",$rg) + $commonFlags + @("-o","json")
}

# DNS Record Sets (private zones)
Export-IteratedResource -Label "DNS Records (private)" -OutFile "dns-records-private.json" -Parents $pdnsZones -CommandBuilder {
    param($name, $rg)
    @("network","private-dns","record-set","list","--zone-name",$name,"-g",$rg) + $commonFlags + @("-o","json")
}

# Merge public + private DNS records into one file
$pubRecords = Get-JsonArray (Join-Path $OutputDir "dns-records-public.json")
$privRecords = Get-JsonArray (Join-Path $OutputDir "dns-records-private.json")
$allDnsRecords = @($pubRecords) + @($privRecords)
$allDnsRecords | ConvertTo-Json -Depth 20 -AsArray | Out-File -FilePath (Join-Path $OutputDir "dns-records.json") -Encoding utf8
Remove-Item (Join-Path $OutputDir "dns-records-public.json") -ErrorAction SilentlyContinue
Remove-Item (Join-Path $OutputDir "dns-records-private.json") -ErrorAction SilentlyContinue

# Private DNS Zone VNet Links (per private zone)
Export-IteratedResource -Label "Private DNS Zone Links" -OutFile "private-dns-links.json" -Parents $pdnsZones -CommandBuilder {
    param($name, $rg)
    @("network","private-dns","link","vnet","list","--zone-name",$name,"-g",$rg) + $commonFlags + @("-o","json")
}

# SQL Databases (per server)
Export-IteratedResource -Label "SQL Databases" -OutFile "sql-databases.json" -Parents $sqlServers -CommandBuilder {
    param($name, $rg)
    @("sql","db","list","-s",$name,"-g",$rg) + $commonFlags + @("-o","json")
}

# ─── Export log ───────────────────────────────────────────────

$logEntries = @($results | ForEach-Object {
    $entry = [ordered]@{ label = $_.Label; file = $_.File; status = $_.Status; elapsed = $_.Elapsed }
    if ($_.Bytes)  { $entry.bytes = $_.Bytes }
    if ($_.Items)  { $entry.items = $_.Items }
    if ($_.Detail) { $entry.detail = $_.Detail }
    $entry
})
$logEntries | ConvertTo-Json -Depth 3 |
    Out-File -FilePath (Join-Path $OutputDir "_export-log.json") -Encoding utf8

# ─── Summary ─────────────────────────────────────────────────

$totalTimer.Stop()
$allFiles = Get-ChildItem -Path $OutputDir -Filter "*.json" -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -ne "_export-log.json" }
$fileCount = ($allFiles | Measure-Object).Count
$totalBytes = ($allFiles | Measure-Object -Property Length -Sum).Sum
$totalSize = if ($totalBytes -gt 1MB) { "{0:N1} MB" -f ($totalBytes / 1MB) }
             elseif ($totalBytes -gt 1KB) { "{0:N0} KB" -f ($totalBytes / 1KB) }
             else { "$totalBytes bytes" }
$totalTime = "{0:N1}s" -f $totalTimer.Elapsed.TotalSeconds

Write-Host ""
Write-Host "  ═══════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host "  Export complete in $totalTime (parallel x$MaxParallel)" -ForegroundColor Green
Write-Host "  $fileCount files ($totalSize)" -ForegroundColor Green
Write-Host "    OK:      $okCount" -ForegroundColor Green
Write-Host "    Empty:   $emptyCount" -ForegroundColor Yellow
if ($skipCount -gt 0) {
    Write-Host "    Skipped: $skipCount (extensions not installed or no permissions)" -ForegroundColor Red
}
Write-Host ""
Write-Host "  Output: $OutputDir"
Write-Host "  Log:    $OutputDir/_export-log.json"
Write-Host ""
Write-Host "  To load: Use 'Upload JSON Files' in Azure Network Mapper"
Write-Host "           and select all files from $OutputDir/"
Write-Host "  ═══════════════════════════════════════════════════════" -ForegroundColor Cyan
Write-Host ""
