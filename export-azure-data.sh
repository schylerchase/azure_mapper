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
SKIPPED=0

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

# --- Helper: export az command output with error capture and location filter ---

run_cmd() {
  local desc="$1"
  local outfile="$2"
  shift 2
  echo "Exporting: $desc..."

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

    local count
    count=$(python3 -c "
import json, sys
with open(sys.argv[1]) as f:
    d = json.load(f)
print(len(d) if isinstance(d, list) else 1)
" "$OUTDIR/$outfile" 2>/dev/null || echo "?")
    echo "  -> $outfile ($count items)"
    EXPORTED=$((EXPORTED + 1))
  else
    local err_detail=""
    if [ -s "$errfile" ]; then
      err_detail=$(head -1 "$errfile")
      echo "--- $desc ($outfile) ---" >> "$ERRLOG"
      cat "$errfile" >> "$ERRLOG"
      echo "" >> "$ERRLOG"
    fi
    echo "  -> SKIPPED: $desc${err_detail:+ ($err_detail)}" >&2
    echo "[]" > "$OUTDIR/$outfile"
    rm -f "$tmpfile" "$errfile"
    SKIPPED=$((SKIPPED + 1))
  fi
  rm -f "$tmpfile"
}

# --- Helper: merge JSON arrays (used by peerings/SQL loops) ---

merge_json() {
  python3 -c "
import json, sys
a = json.loads(sys.argv[1])
b = json.loads(sys.argv[2])
print(json.dumps(a + b))
" "$1" "$2"
}

# ==========================================
# Export resources
# ==========================================

# Core Networking
run_cmd "Virtual Networks" "vnets.json" az network vnet list "${COMMON_RG[@]}" -o json
run_cmd "NSGs" "nsgs.json" az network nsg list "${COMMON_RG[@]}" -o json
run_cmd "Route Tables" "route-tables.json" az network route-table list "${COMMON_RG[@]}" -o json
run_cmd "NICs" "nics.json" az network nic list "${COMMON_RG[@]}" -o json
run_cmd "Public IPs" "public-ips.json" az network public-ip list "${COMMON_RG[@]}" -o json
run_cmd "NAT Gateways" "nat-gateways.json" az network nat gateway list "${COMMON_RG[@]}" -o json
run_cmd "Private Endpoints" "private-endpoints.json" az network private-endpoint list "${COMMON_RG[@]}" -o json
run_cmd "ASGs" "asgs.json" az network asg list "${COMMON_RG[@]}" -o json

# Compute
run_cmd "VMs (with details)" "vms.json" az vm list --show-details "${COMMON_RG[@]}" -o json
run_cmd "Function Apps" "function-apps.json" az functionapp list "${COMMON_RG[@]}" -o json
run_cmd "Container Instances" "container-instances.json" az container list "${COMMON_RG[@]}" -o json
run_cmd "AKS Clusters" "aks-clusters.json" az aks list "${COMMON_RG[@]}" -o json

# Load Balancing
run_cmd "App Gateways" "app-gateways.json" az network application-gateway list "${COMMON_RG[@]}" -o json
run_cmd "Load Balancers" "load-balancers.json" az network lb list "${COMMON_RG[@]}" -o json

# VNet Peerings (per VNet — requires iterating)
echo "Exporting: VNet Peerings..."
PEERINGS="[]"
while IFS=$'\t' read -r vname vrg; do
  [ -z "$vname" ] && continue
  result=$(az network vnet peering list --vnet-name "$vname" -g "$vrg" "${COMMON[@]}" -o json 2>/dev/null || echo "[]")
  PEERINGS=$(merge_json "$PEERINGS" "$result" 2>/dev/null || echo "$PEERINGS")
done < <(az network vnet list "${COMMON_RG[@]}" --query '[].{n:name,rg:resourceGroup}' -o tsv 2>/dev/null || true)
echo "$PEERINGS" > "$OUTDIR/peerings.json"
EXPORTED=$((EXPORTED + 1))
echo "  -> peerings.json"

# Connectivity
run_cmd "VPN Connections" "vpn-connections.json" az network vpn-connection list "${COMMON_RG[@]}" -o json
run_cmd "vWANs" "vwans.json" az network vwan list "${COMMON_RG[@]}" -o json
run_cmd "Virtual Hubs" "vhubs.json" az network vhub list "${COMMON_RG[@]}" -o json

# Storage
run_cmd "Disks" "disks.json" az disk list "${COMMON_RG[@]}" -o json
run_cmd "Snapshots" "snapshots.json" az snapshot list "${COMMON_RG[@]}" -o json
run_cmd "Storage Accounts" "storage-accounts.json" az storage account list "${COMMON_RG[@]}" -o json

# DNS
run_cmd "DNS Zones" "dns-zones.json" az network dns zone list "${COMMON_RG[@]}" -o json
run_cmd "Private DNS Zones" "private-dns-zones.json" az network private-dns zone list "${COMMON_RG[@]}" -o json

# Security & Edge
run_cmd "Front Doors" "front-doors.json" az network front-door list "${COMMON_RG[@]}" -o json
run_cmd "WAF Policies" "waf-policies.json" az network application-gateway waf-policy list "${COMMON_RG[@]}" -o json

# Database
run_cmd "SQL Servers" "sql-servers.json" az sql server list "${COMMON_RG[@]}" -o json

# SQL Databases (per server — requires iterating)
echo "Exporting: SQL Databases..."
SQL_DBS="[]"
while IFS=$'\t' read -r sname srg; do
  [ -z "$sname" ] && continue
  result=$(az sql db list -s "$sname" -g "$srg" "${COMMON[@]}" -o json 2>/dev/null || echo "[]")
  SQL_DBS=$(merge_json "$SQL_DBS" "$result" 2>/dev/null || echo "$SQL_DBS")
done < <(az sql server list "${COMMON_RG[@]}" --query '[].{n:name,rg:resourceGroup}' -o tsv 2>/dev/null || true)
echo "$SQL_DBS" > "$OUTDIR/sql-databases.json"
EXPORTED=$((EXPORTED + 1))
echo "  -> sql-databases.json"

run_cmd "Redis Caches" "redis-caches.json" az redis list "${COMMON_RG[@]}" -o json
run_cmd "Synapse Workspaces" "synapse-workspaces.json" az synapse workspace list "${COMMON_RG[@]}" -o json

# Identity (no RG filter — these are subscription-scoped)
run_cmd "Role Assignments" "role-assignments.json" az role assignment list "${COMMON[@]}" --all -o json
run_cmd "Role Definitions" "role-definitions.json" az role definition list "${COMMON[@]}" -o json

# Azure-Specific
run_cmd "Resource Groups" "resource-groups.json" az group list "${COMMON[@]}" -o json
run_cmd "Bastions" "bastions.json" az network bastion list "${COMMON_RG[@]}" -o json
run_cmd "Network Watchers" "network-watchers.json" az network watcher list "${COMMON[@]}" -o json
run_cmd "Firewalls" "firewalls.json" az network firewall list "${COMMON_RG[@]}" -o json

# ==========================================
# Summary
# ==========================================

echo ""
echo "Export complete: $OUTDIR"
echo "  Exported: $EXPORTED resource types"
if [ "$SKIPPED" -gt 0 ]; then
  echo "  Skipped:  $SKIPPED resource types (see $ERRLOG for details)"
fi
echo ""
echo "Files:"
for f in "$OUTDIR"/*.json; do
  [ -f "$f" ] || continue
  size=$(wc -c < "$f" | tr -d ' ')
  echo "  $(basename "$f") (${size} bytes)"
done
echo ""
echo "To load: Use 'Upload JSON Files' in Azure Network Mapper and select all files from $OUTDIR/"
