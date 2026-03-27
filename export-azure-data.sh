#!/usr/bin/env bash
# Azure Network Mapper - Data Export Script
# Usage: ./export-azure-data.sh -s <subscription> [-g <resource-group>] [-l <location>] [-c <cloud>] [-t <tenant-id>] [--lighthouse]
#
# Exports Azure resource data as JSON files for import into the mapper.
# Supports: Commercial, GCC, GCC High, DoD cloud environments.
# Supports: Azure Lighthouse delegated access (--lighthouse flag).

set -euo pipefail

SUB=""
RG=""
LOC=""
CLOUD=""
TENANT=""
LIGHTHOUSE=false
EXPORTED=0
EMPTY=0
SKIPPED=0
EXPORT_LOG="["

usage() {
  cat >&2 <<EOF
Usage: $0 -s <subscription> [-g <resource-group>] [-l <location>] [-c <cloud>] [-t <tenant-id>] [--lighthouse]

Options:
  -s  Subscription name or ID (required)
  -g  Resource group filter
  -l  Location/region filter (case-insensitive)
  -c  Cloud environment: commercial, gcc, gcc-high, dod
  -t  Tenant ID (for cross-tenant / Lighthouse access)
  --lighthouse  Enable Lighthouse delegated access mode
  --help, -h    Show this help
EOF
  exit 1
}

# Parse long options first, collect short options for getopts
ARGS=()
while [[ $# -gt 0 ]]; do
  case $1 in
    --lighthouse) LIGHTHOUSE=true; shift ;;
    --cloud)
      if [[ $# -lt 2 || "$2" == -* ]]; then
        echo "ERROR: --cloud requires a value" >&2; exit 1
      fi
      CLOUD="$2"; shift 2 ;;
    --tenant)
      if [[ $# -lt 2 || "$2" == -* ]]; then
        echo "ERROR: --tenant requires a value" >&2; exit 1
      fi
      TENANT="$2"; shift 2 ;;
    --help) usage ;;
    *) ARGS+=("$1"); shift ;;
  esac
done

# Reset positional params (bash 3.2-safe: avoids unbound variable on empty array)
if (( ${#ARGS[@]} > 0 )); then
  set -- "${ARGS[@]}"
else
  set --
fi

while getopts "s:g:l:c:t:h" opt; do
  case $opt in
    s) SUB="$OPTARG" ;;
    g) RG="$OPTARG" ;;
    l) LOC="$OPTARG" ;;
    c) CLOUD="$OPTARG" ;;
    t) TENANT="$OPTARG" ;;
    h) usage ;;
    *) usage ;;
  esac
done

if [ -z "$SUB" ]; then
  echo "ERROR: Subscription (-s) is required" >&2
  usage
fi

# --- Dependency checks ---

if ! command -v az &>/dev/null; then
  echo "ERROR: Azure CLI (az) not found. Install from https://aka.ms/install-az-cli" >&2
  exit 1
fi

if ! command -v python3 &>/dev/null; then
  echo "ERROR: python3 not found (required for JSON processing)." >&2
  exit 1
fi

# --- Cloud environment ---

if [ -n "$CLOUD" ]; then
  case "$CLOUD" in
    commercial|AzureCloud)
      az cloud set --name AzureCloud --only-show-errors
      echo "Cloud: Azure Commercial" ;;
    gcc)
      az cloud set --name AzureCloud --only-show-errors
      echo "Cloud: Azure GCC (Commercial endpoints, policy-restricted)" ;;
    gcc-high|AzureUSGovernment)
      az cloud set --name AzureUSGovernment --only-show-errors
      echo "Cloud: Azure GCC High" ;;
    dod)
      az cloud set --name AzureUSGovernment --only-show-errors
      echo "Cloud: Azure DoD" ;;
    *)
      echo "ERROR: Unknown cloud '$CLOUD'. Use: commercial, gcc, gcc-high, dod" >&2
      exit 1 ;;
  esac
fi

# --- Login / tenant verification ---

if [ -n "$TENANT" ]; then
  echo "Tenant: $TENANT"
  if [ "$LIGHTHOUSE" = true ]; then
    echo "Mode: Azure Lighthouse (delegated access)"
  fi
fi

if ! az account show --only-show-errors &>/dev/null; then
  echo "ERROR: Not logged in. Run 'az login' first." >&2
  if [ -n "$TENANT" ]; then
    echo "  For tenant access: az login --tenant $TENANT" >&2
  fi
  exit 1
fi

# --- Set subscription ---

echo "Setting subscription to: $SUB"
az account set --subscription "$SUB" --only-show-errors || {
  echo "ERROR: Could not set subscription '$SUB'" >&2
  echo "  Run 'az account list -o table' to see available subscriptions." >&2
  exit 1
}

# --- Output directory ---

TIMESTAMP=$(date +%Y%m%d-%H%M%S)
SUB_SAFE=$(echo "$SUB" | tr ' /:' '---')
OUTDIR="azure-export-${SUB_SAFE}-${TIMESTAMP}"
ERRLOG="$OUTDIR/.export-errors.log"
mkdir -p "$OUTDIR"
echo "Output directory: $OUTDIR"

# --- Build common args ---
# COMMON: base flags for ALL commands (always non-empty, avoids bash 3.2 empty-array issue)
# COMMON_RG: base flags + resource group filter (for commands that support -g)
COMMON=(--subscription "$SUB" --only-show-errors)
COMMON_RG=("${COMMON[@]}")
if [ -n "$RG" ]; then
  COMMON_RG+=(-g "$RG")
  echo "Resource Group filter: $RG"
fi
if [ -n "$LOC" ]; then
  echo "Location filter: $LOC"
fi

# --- Helper: log entry for export log ---

log_entry() {
  local label="$1" file="$2" status="$3"
  shift 3
  local extra=""
  if [ "$#" -ge 1 ]; then extra=",\"bytes\":$1"; fi
  if [ "$#" -ge 2 ]; then extra="$extra,\"items\":$2"; fi
  if [ "$#" -ge 3 ]; then
    local escaped
    escaped=$(echo "$3" | sed 's/"/\\"/g' | head -c 120)
    extra="$extra,\"detail\":\"$escaped\""
  fi
  EXPORT_LOG="${EXPORT_LOG}{\"label\":\"$label\",\"file\":\"$file\",\"status\":\"$status\"${extra}},"
}

# --- Helper: export az command output with error capture, empty detection, and location filter ---

run_cmd() {
  local desc="$1"
  local outfile="$2"
  shift 2
  printf "  %-40s" "$desc..."

  local tmpfile="$OUTDIR/.$outfile.tmp"
  local errfile="$OUTDIR/.$outfile.err"

  if "$@" > "$tmpfile" 2>"$errfile"; then
    # Apply location filter if specified (case-insensitive)
    if [ -n "$LOC" ]; then
      python3 -c "
import json, sys
with open(sys.argv[1]) as f:
    data = json.load(f)
loc = sys.argv[2].lower()
if isinstance(data, list):
    data = [r for r in data if r.get('location', '').lower() == loc]
with open(sys.argv[3], 'w') as f:
    json.dump(data, f, indent=2)
" "$tmpfile" "$LOC" "$OUTDIR/$outfile" 2>/dev/null || mv "$tmpfile" "$OUTDIR/$outfile"
    else
      mv "$tmpfile" "$OUTDIR/$outfile"
    fi
    rm -f "$errfile"

    local count size
    count=$(python3 -c "
import json, sys
with open(sys.argv[1]) as f:
    d = json.load(f)
print(len(d) if isinstance(d, list) else 1)
" "$OUTDIR/$outfile" 2>/dev/null || echo "?")
    size=$(wc -c < "$OUTDIR/$outfile" | tr -d ' ')

    if [ "$count" = "0" ]; then
      echo "EMPTY (no resources)"
      EMPTY=$((EMPTY + 1))
      log_entry "$desc" "$outfile" "EMPTY"
    else
      echo "OK ($count items, ${size} bytes)"
      EXPORTED=$((EXPORTED + 1))
      log_entry "$desc" "$outfile" "OK" "$size" "$count"
    fi
  else
    local err_detail=""
    if [ -s "$errfile" ]; then
      err_detail=$(head -1 "$errfile")
      echo "--- $desc ($outfile) ---" >> "$ERRLOG"
      cat "$errfile" >> "$ERRLOG"
      echo "" >> "$ERRLOG"
    fi
    echo "SKIP${err_detail:+ ($err_detail)}"
    echo "[]" > "$OUTDIR/$outfile"
    rm -f "$tmpfile" "$errfile"
    SKIPPED=$((SKIPPED + 1))
    log_entry "$desc" "$outfile" "SKIPPED" "" "" "$err_detail"
  fi
  rm -f "$tmpfile"
}

# --- Helper: merge JSON arrays (used by iteration loops) ---

merge_json() {
  python3 -c "
import json, sys
a = json.loads(sys.argv[1])
b = json.loads(sys.argv[2])
print(json.dumps(a + b))
" "$1" "$2"
}

# --- Helper: iterate-and-merge export (for per-VNet, per-zone, per-server resources) ---

iterate_export() {
  local desc="$1"
  local outfile="$2"
  local list_json="$3"
  shift 3
  # Remaining args: the az command template with __NAME__ and __RG__ placeholders

  printf "  %-40s" "$desc..."
  local merged="[]"
  local item_count=0

  while IFS=$'\t' read -r iname irg; do
    [ -z "$iname" ] && continue
    # Build command by replacing placeholders
    local cmd_str="$*"
    cmd_str="${cmd_str//__NAME__/$iname}"
    cmd_str="${cmd_str//__RG__/$irg}"
    local result
    result=$(eval "$cmd_str" 2>/dev/null || echo "[]")
    merged=$(merge_json "$merged" "$result" 2>/dev/null || echo "$merged")
    item_count=$((item_count + 1))
  done < <(echo "$list_json" | python3 -c "
import json, sys
data = json.load(sys.stdin)
for r in (data if isinstance(data, list) else []):
    name = r.get('name', '')
    rg = r.get('resourceGroup', '')
    if name and rg:
        print(f'{name}\t{rg}')
" 2>/dev/null || true)

  echo "$merged" > "$OUTDIR/$outfile"
  local count
  count=$(python3 -c "import json,sys;d=json.loads(sys.argv[1]);print(len(d) if isinstance(d,list) else 0)" "$merged" 2>/dev/null || echo "0")

  if [ "$count" = "0" ]; then
    echo "EMPTY (0 items from $item_count parents)"
    EMPTY=$((EMPTY + 1))
    log_entry "$desc" "$outfile" "EMPTY"
  else
    local size
    size=$(wc -c < "$OUTDIR/$outfile" | tr -d ' ')
    echo "OK ($count items from $item_count parents, ${size} bytes)"
    EXPORTED=$((EXPORTED + 1))
    log_entry "$desc" "$outfile" "OK" "$size" "$count"
  fi
}

# --- Write export log ---

write_export_log() {
  # Remove trailing comma and close the array
  EXPORT_LOG="${EXPORT_LOG%,}]"
  echo "$EXPORT_LOG" | python3 -m json.tool > "$OUTDIR/_export-log.json" 2>/dev/null \
    || echo "$EXPORT_LOG" > "$OUTDIR/_export-log.json"
}

# ==========================================
# Export resources
# ==========================================

echo ""
echo "== Network ======================================"
run_cmd "Virtual Networks" "vnets.json" az network vnet list "${COMMON_RG[@]}" -o json
run_cmd "NSGs" "nsgs.json" az network nsg list "${COMMON_RG[@]}" -o json
run_cmd "Route Tables" "route-tables.json" az network route-table list "${COMMON_RG[@]}" -o json
run_cmd "NICs" "nics.json" az network nic list "${COMMON_RG[@]}" -o json
run_cmd "Public IPs" "public-ips.json" az network public-ip list "${COMMON_RG[@]}" -o json
run_cmd "ASGs" "asgs.json" az network asg list "${COMMON_RG[@]}" -o json
run_cmd "CDN Profiles" "cdn-profiles.json" az cdn profile list "${COMMON_RG[@]}" -o json
run_cmd "Traffic Manager" "traffic-manager.json" az network traffic-manager profile list "${COMMON_RG[@]}" -o json
run_cmd "Private Link Services" "private-link-services.json" az network private-link-service list "${COMMON_RG[@]}" -o json
run_cmd "DDoS Protection Plans" "ddos-protection.json" az network ddos-protection list "${COMMON_RG[@]}" -o json

# Subnets (per VNet — requires iterating)
VNET_JSON=$(cat "$OUTDIR/vnets.json" 2>/dev/null || echo "[]")
iterate_export "Subnets" "subnets.json" "$VNET_JSON" \
  "az network vnet subnet list --vnet-name __NAME__ -g __RG__ ${COMMON[*]} -o json"

echo ""
echo "== Gateways ====================================="
run_cmd "NAT Gateways" "nat-gateways.json" az network nat gateway list "${COMMON_RG[@]}" -o json
run_cmd "Private Endpoints" "private-endpoints.json" az network private-endpoint list "${COMMON_RG[@]}" -o json
run_cmd "Azure Firewalls" "firewalls.json" az network firewall list "${COMMON_RG[@]}" -o json
run_cmd "Bastions" "bastions.json" az network bastion list "${COMMON_RG[@]}" -o json

echo ""
echo "== Compute ======================================"
run_cmd "VMs (with details)" "vms.json" az vm list --show-details "${COMMON_RG[@]}" -o json
run_cmd "Function Apps" "function-apps.json" az functionapp list "${COMMON_RG[@]}" -o json
run_cmd "Container Instances" "container-instances.json" az container list "${COMMON_RG[@]}" -o json
run_cmd "AKS Clusters" "aks-clusters.json" az aks list "${COMMON_RG[@]}" -o json
run_cmd "App Service Plans" "app-service-plans.json" az appservice plan list "${COMMON_RG[@]}" -o json
run_cmd "Web Apps" "web-apps.json" az webapp list "${COMMON_RG[@]}" -o json
run_cmd "Container Registries" "container-registries.json" az acr list "${COMMON_RG[@]}" -o json
run_cmd "Batch Accounts" "batch-accounts.json" az batch account list "${COMMON_RG[@]}" -o json
run_cmd "Virtual Desktop Host Pools" "virtual-desktop.json" az desktopvirtualization hostpool list "${COMMON_RG[@]}" -o json

echo ""
echo "== Load Balancing ==============================="
run_cmd "App Gateways" "app-gateways.json" az network application-gateway list "${COMMON_RG[@]}" -o json
run_cmd "Load Balancers" "load-balancers.json" az network lb list "${COMMON_RG[@]}" -o json

echo ""
echo "== Connectivity ================================="

# VNet Peerings (per VNet)
iterate_export "VNet Peerings" "peerings.json" "$VNET_JSON" \
  "az network vnet peering list --vnet-name __NAME__ -g __RG__ ${COMMON[*]} -o json"

run_cmd "VPN Connections" "vpn-connections.json" az network vpn-connection list "${COMMON_RG[@]}" -o json
run_cmd "vWANs" "vwans.json" az network vwan list "${COMMON_RG[@]}" -o json
run_cmd "Virtual Hubs" "vhubs.json" az network vhub list "${COMMON_RG[@]}" -o json
run_cmd "VNet Gateways" "vnet-gateways.json" az network vnet-gateway list "${COMMON_RG[@]}" -o json
run_cmd "Express Route Circuits" "express-routes.json" az network express-route list "${COMMON_RG[@]}" -o json

echo ""
echo "== Storage ======================================"
run_cmd "Disks" "disks.json" az disk list "${COMMON_RG[@]}" -o json
run_cmd "Snapshots" "snapshots.json" az snapshot list "${COMMON_RG[@]}" -o json
run_cmd "Storage Accounts" "storage-accounts.json" az storage account list "${COMMON_RG[@]}" -o json
run_cmd "NetApp Files Accounts" "netapp-accounts.json" az netappfiles account list "${COMMON_RG[@]}" -o json

echo ""
echo "== DNS =========================================="
run_cmd "DNS Zones" "dns-zones.json" az network dns zone list "${COMMON_RG[@]}" -o json
run_cmd "Private DNS Zones" "private-dns-zones.json" az network private-dns zone list "${COMMON_RG[@]}" -o json

# DNS Record Sets (iterate public + private zones)
DNS_ZONE_JSON=$(cat "$OUTDIR/dns-zones.json" 2>/dev/null || echo "[]")
PDNS_ZONE_JSON=$(cat "$OUTDIR/private-dns-zones.json" 2>/dev/null || echo "[]")

printf "  %-40s" "DNS Record Sets..."
DNS_RECORDS="[]"
DNS_REC_PARENTS=0
# Public DNS zones
while IFS=$'\t' read -r zname zrg; do
  [ -z "$zname" ] && continue
  result=$(az network dns record-set list --zone-name "$zname" -g "$zrg" "${COMMON[@]}" -o json 2>/dev/null || echo "[]")
  DNS_RECORDS=$(merge_json "$DNS_RECORDS" "$result" 2>/dev/null || echo "$DNS_RECORDS")
  DNS_REC_PARENTS=$((DNS_REC_PARENTS + 1))
done < <(echo "$DNS_ZONE_JSON" | python3 -c "
import json, sys
for r in json.load(sys.stdin):
    print(f'{r.get(\"name\",\"\")}\t{r.get(\"resourceGroup\",\"\")}')
" 2>/dev/null || true)
# Private DNS zones
while IFS=$'\t' read -r zname zrg; do
  [ -z "$zname" ] && continue
  result=$(az network private-dns record-set list --zone-name "$zname" -g "$zrg" "${COMMON[@]}" -o json 2>/dev/null || echo "[]")
  DNS_RECORDS=$(merge_json "$DNS_RECORDS" "$result" 2>/dev/null || echo "$DNS_RECORDS")
  DNS_REC_PARENTS=$((DNS_REC_PARENTS + 1))
done < <(echo "$PDNS_ZONE_JSON" | python3 -c "
import json, sys
for r in json.load(sys.stdin):
    print(f'{r.get(\"name\",\"\")}\t{r.get(\"resourceGroup\",\"\")}')
" 2>/dev/null || true)
echo "$DNS_RECORDS" > "$OUTDIR/dns-records.json"
DNS_REC_COUNT=$(python3 -c "import json,sys;d=json.loads(sys.argv[1]);print(len(d) if isinstance(d,list) else 0)" "$DNS_RECORDS" 2>/dev/null || echo "0")
if [ "$DNS_REC_COUNT" = "0" ]; then
  echo "EMPTY (0 records from $DNS_REC_PARENTS zones)"
  EMPTY=$((EMPTY + 1))
  log_entry "DNS Record Sets" "dns-records.json" "EMPTY"
else
  DNS_REC_SIZE=$(wc -c < "$OUTDIR/dns-records.json" | tr -d ' ')
  echo "OK ($DNS_REC_COUNT records from $DNS_REC_PARENTS zones, ${DNS_REC_SIZE} bytes)"
  EXPORTED=$((EXPORTED + 1))
  log_entry "DNS Record Sets" "dns-records.json" "OK" "$DNS_REC_SIZE" "$DNS_REC_COUNT"
fi

# Private DNS Zone VNet Links (iterate private zones)
iterate_export "Private DNS Zone Links" "private-dns-links.json" "$PDNS_ZONE_JSON" \
  "az network private-dns link vnet list --zone-name __NAME__ -g __RG__ ${COMMON[*]} -o json"

echo ""
echo "== Security & Edge =============================="
run_cmd "Front Doors" "front-doors.json" az network front-door list "${COMMON_RG[@]}" -o json
run_cmd "WAF Policies" "waf-policies.json" az network application-gateway waf-policy list "${COMMON_RG[@]}" -o json
run_cmd "Key Vaults" "key-vaults.json" az keyvault list "${COMMON_RG[@]}" -o json

echo ""
echo "== Database ====================================="
run_cmd "SQL Servers" "sql-servers.json" az sql server list "${COMMON_RG[@]}" -o json

# SQL Databases (per server)
SQL_SERVER_JSON=$(cat "$OUTDIR/sql-servers.json" 2>/dev/null || echo "[]")
iterate_export "SQL Databases" "sql-databases.json" "$SQL_SERVER_JSON" \
  "az sql db list -s __NAME__ -g __RG__ ${COMMON[*]} -o json"

run_cmd "Redis Caches" "redis-caches.json" az redis list "${COMMON_RG[@]}" -o json
run_cmd "Cosmos DB Accounts" "cosmos-accounts.json" az cosmosdb list "${COMMON_RG[@]}" -o json
run_cmd "Synapse Workspaces" "synapse-workspaces.json" az synapse workspace list "${COMMON_RG[@]}" -o json
run_cmd "MySQL Flexible Servers" "mysql-servers.json" az mysql flexible-server list "${COMMON_RG[@]}" -o json
run_cmd "PostgreSQL Flexible Servers" "postgres-servers.json" az postgres flexible-server list "${COMMON_RG[@]}" -o json

echo ""
echo "== Integration =================================="
run_cmd "Service Bus Namespaces" "service-bus.json" az servicebus namespace list "${COMMON_RG[@]}" -o json
run_cmd "Event Hub Namespaces" "event-hubs.json" az eventhubs namespace list "${COMMON_RG[@]}" -o json
run_cmd "API Management" "api-management.json" az apim list "${COMMON_RG[@]}" -o json
run_cmd "Logic Apps" "logic-apps.json" az logic workflow list "${COMMON_RG[@]}" -o json
run_cmd "SignalR Services" "signalr.json" az signalr list "${COMMON_RG[@]}" -o json
run_cmd "Relay Namespaces" "relay-namespaces.json" az relay namespace list "${COMMON_RG[@]}" -o json
run_cmd "Data Factories" "data-factories.json" az datafactory list "${COMMON_RG[@]}" -o json
run_cmd "IoT Hubs" "iot-hubs.json" az iot hub list "${COMMON_RG[@]}" -o json

echo ""
echo "== Observability ================================"
run_cmd "Application Insights" "app-insights.json" az monitor app-insights component list "${COMMON_RG[@]}" -o json
run_cmd "Log Analytics Workspaces" "log-analytics.json" az monitor log-analytics workspace list "${COMMON_RG[@]}" -o json
run_cmd "Monitor Action Groups" "action-groups.json" az monitor action-group list "${COMMON_RG[@]}" -o json
run_cmd "Monitor Metric Alerts" "metric-alerts.json" az monitor metrics alert list "${COMMON_RG[@]}" -o json
run_cmd "Automation Accounts" "automation-accounts.json" az automation account list "${COMMON_RG[@]}" -o json

echo ""
echo "== Identity ====================================="
run_cmd "Role Assignments" "role-assignments.json" az role assignment list "${COMMON[@]}" --all -o json
run_cmd "Role Definitions" "role-definitions.json" az role definition list "${COMMON[@]}" -o json
run_cmd "Managed Identities" "managed-identities.json" az identity list "${COMMON_RG[@]}" -o json
run_cmd "Policy Assignments" "policy-assignments.json" az policy assignment list -o json

echo ""
echo "== Azure Resources =============================="
run_cmd "Resource Groups" "resource-groups.json" az group list "${COMMON[@]}" -o json
run_cmd "Network Watchers" "network-watchers.json" az network watcher list "${COMMON[@]}" -o json
run_cmd "Azure Arc Machines" "arc-machines.json" az connectedmachine list "${COMMON_RG[@]}" -o json
run_cmd "Recovery Services Vaults" "recovery-vaults.json" az backup vault list "${COMMON_RG[@]}" -o json
run_cmd "Managed Applications" "managed-apps.json" az managedapp list "${COMMON_RG[@]}" -o json
run_cmd "Azure Maps Accounts" "maps-accounts.json" az maps account list "${COMMON_RG[@]}" -o json

echo ""
echo "== AI & Cognitive ==============================="
run_cmd "Cognitive Services" "cognitive-services.json" az cognitiveservices account list "${COMMON_RG[@]}" -o json
run_cmd "ML Workspaces" "ml-workspaces.json" az ml workspace list "${COMMON_RG[@]}" -o json
run_cmd "Purview Accounts" "purview-accounts.json" az purview account list "${COMMON_RG[@]}" -o json

# ==========================================
# Export log + Summary
# ==========================================

write_export_log

echo ""
echo "================================================="
TOTAL=$((EXPORTED + EMPTY + SKIPPED))
echo "  Export complete: $OUTDIR"
echo "  Total: $TOTAL resource types"
echo "    OK:      $EXPORTED (with data)"
echo "    Empty:   $EMPTY (no resources found)"
if [ "$SKIPPED" -gt 0 ]; then
  echo "    Skipped: $SKIPPED (see $ERRLOG)"
fi
echo ""
echo "Files:"
for f in "$OUTDIR"/*.json; do
  [ -f "$f" ] || continue
  fname=$(basename "$f")
  [ "$fname" = "_export-log.json" ] && continue
  size=$(wc -c < "$f" | tr -d ' ')
  echo "  $fname (${size} bytes)"
done
echo ""
echo "  Export log: $OUTDIR/_export-log.json"
echo ""
echo "To load: Use 'Upload JSON Files' in Azure Network Mapper"
echo "         and select all files from $OUTDIR/"
echo "================================================="
