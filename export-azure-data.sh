#!/usr/bin/env bash
# Azure Network Mapper - Data Export Script
# Usage: ./export-azure-data.sh -s <subscription-name-or-id> [-g <resource-group>] [-l <location>]
#
# Exports Azure resource data as JSON files for import into the mapper.

set -euo pipefail

SUB=""
RG=""
LOC=""

while getopts "s:g:l:" opt; do
  case $opt in
    s) SUB="$OPTARG" ;;
    g) RG="$OPTARG" ;;
    l) LOC="$OPTARG" ;;
    *) echo "Usage: $0 -s <subscription> [-g <resource-group>] [-l <location>]" >&2; exit 1 ;;
  esac
done

if [ -z "$SUB" ]; then
  echo "ERROR: Subscription (-s) is required" >&2
  echo "Usage: $0 -s <subscription> [-g <resource-group>] [-l <location>]" >&2
  exit 1
fi

# Check az CLI is installed and logged in
if ! command -v az &>/dev/null; then
  echo "ERROR: Azure CLI (az) not found. Install from https://aka.ms/install-azure-cli" >&2
  exit 1
fi

if ! az account show &>/dev/null; then
  echo "ERROR: Not logged in. Run 'az login' first." >&2
  exit 1
fi

# Set subscription
echo "Setting subscription to: $SUB"
az account set --subscription "$SUB" 2>/dev/null || {
  echo "ERROR: Could not set subscription '$SUB'" >&2
  exit 1
}

# Create output directory
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
SUB_SAFE=$(echo "$SUB" | tr ' /:' '---')
OUTDIR="azure-export-${SUB_SAFE}-${TIMESTAMP}"
mkdir -p "$OUTDIR"
echo "Output directory: $OUTDIR"

# Build common args (arrays prevent word-splitting on names with spaces)
COMMON=(--subscription "$SUB")
if [ -n "$RG" ]; then
  RG_FILTER=(-g "$RG")
else
  RG_FILTER=()
fi

# Helper function for running az commands
run_cmd() {
  local desc="$1"
  local outfile="$2"
  shift 2
  echo "Exporting: $desc..."
  if "$@" > "$OUTDIR/$outfile" 2>/dev/null; then
    local count
    count=$(python3 -c "import json,sys; d=json.load(open(sys.argv[1])); print(len(d) if isinstance(d,list) else 1)" "$OUTDIR/$outfile" 2>/dev/null || echo "?")
    echo "  -> $outfile ($count items)"
  else
    echo "  -> SKIPPED (command failed)" >&2
    echo "[]" > "$OUTDIR/$outfile"
  fi
}

# Core Networking
run_cmd "Virtual Networks" "vnets.json" az network vnet list "${COMMON[@]}" "${RG_FILTER[@]}" -o json
run_cmd "NSGs" "nsgs.json" az network nsg list "${COMMON[@]}" "${RG_FILTER[@]}" -o json
run_cmd "Route Tables" "route-tables.json" az network route-table list "${COMMON[@]}" "${RG_FILTER[@]}" -o json
run_cmd "NICs" "nics.json" az network nic list "${COMMON[@]}" "${RG_FILTER[@]}" -o json
run_cmd "Public IPs" "public-ips.json" az network public-ip list "${COMMON[@]}" "${RG_FILTER[@]}" -o json
run_cmd "NAT Gateways" "nat-gateways.json" az network nat gateway list "${COMMON[@]}" "${RG_FILTER[@]}" -o json
run_cmd "Private Endpoints" "private-endpoints.json" az network private-endpoint list "${COMMON[@]}" "${RG_FILTER[@]}" -o json
run_cmd "ASGs" "asgs.json" az network asg list "${COMMON[@]}" "${RG_FILTER[@]}" -o json

# Compute
run_cmd "VMs (with details)" "vms.json" az vm list --show-details "${COMMON[@]}" "${RG_FILTER[@]}" -o json
run_cmd "Function Apps" "function-apps.json" az functionapp list "${COMMON[@]}" "${RG_FILTER[@]}" -o json
run_cmd "Container Instances" "container-instances.json" az container list "${COMMON[@]}" "${RG_FILTER[@]}" -o json
run_cmd "AKS Clusters" "aks-clusters.json" az aks list "${COMMON[@]}" "${RG_FILTER[@]}" -o json

# Load Balancing
run_cmd "App Gateways" "app-gateways.json" az network application-gateway list "${COMMON[@]}" "${RG_FILTER[@]}" -o json
run_cmd "Load Balancers" "load-balancers.json" az network lb list "${COMMON[@]}" "${RG_FILTER[@]}" -o json

# Peerings (per VNet)
echo "Exporting: VNet Peerings..."
PEERINGS="[]"
while IFS=$'\t' read -r vname vrg; do
  [ -z "$vname" ] && continue
  result=$(az network vnet peering list --vnet-name "$vname" -g "$vrg" "${COMMON[@]}" -o json 2>/dev/null || echo "[]")
  PEERINGS=$(python3 -c "
import json,sys
a=json.loads(sys.argv[1])
b=json.loads(sys.argv[2])
print(json.dumps(a+b))
" "$PEERINGS" "$result" 2>/dev/null || echo "$PEERINGS")
done < <(az network vnet list "${COMMON[@]}" --query '[].{n:name,rg:resourceGroup}' -o tsv 2>/dev/null)
echo "$PEERINGS" > "$OUTDIR/peerings.json"
echo "  -> peerings.json"

# Connectivity
run_cmd "VPN Connections" "vpn-connections.json" az network vpn-connection list "${COMMON[@]}" "${RG_FILTER[@]}" -o json
run_cmd "vWANs" "vwans.json" az network vwan list "${COMMON[@]}" "${RG_FILTER[@]}" -o json
run_cmd "Virtual Hubs" "vhubs.json" az network vhub list "${COMMON[@]}" "${RG_FILTER[@]}" -o json

# Storage
run_cmd "Disks" "disks.json" az disk list "${COMMON[@]}" "${RG_FILTER[@]}" -o json
run_cmd "Snapshots" "snapshots.json" az snapshot list "${COMMON[@]}" "${RG_FILTER[@]}" -o json
run_cmd "Storage Accounts" "storage-accounts.json" az storage account list "${COMMON[@]}" "${RG_FILTER[@]}" -o json

# DNS
run_cmd "DNS Zones" "dns-zones.json" az network dns zone list "${COMMON[@]}" "${RG_FILTER[@]}" -o json
run_cmd "Private DNS Zones" "private-dns-zones.json" az network private-dns zone list "${COMMON[@]}" "${RG_FILTER[@]}" -o json

# Security & Edge
run_cmd "Front Doors" "front-doors.json" az network front-door list "${COMMON[@]}" "${RG_FILTER[@]}" -o json
run_cmd "WAF Policies" "waf-policies.json" az network application-gateway waf-policy list "${COMMON[@]}" "${RG_FILTER[@]}" -o json

# Database
run_cmd "SQL Servers" "sql-servers.json" az sql server list "${COMMON[@]}" "${RG_FILTER[@]}" -o json

# SQL Databases (per server)
echo "Exporting: SQL Databases..."
SQL_DBS="[]"
while IFS=$'\t' read -r sname srg; do
  [ -z "$sname" ] && continue
  result=$(az sql db list -s "$sname" -g "$srg" "${COMMON[@]}" -o json 2>/dev/null || echo "[]")
  SQL_DBS=$(python3 -c "
import json,sys
a=json.loads(sys.argv[1])
b=json.loads(sys.argv[2])
print(json.dumps(a+b))
" "$SQL_DBS" "$result" 2>/dev/null || echo "$SQL_DBS")
done < <(az sql server list "${COMMON[@]}" --query '[].{n:name,rg:resourceGroup}' -o tsv 2>/dev/null)
echo "$SQL_DBS" > "$OUTDIR/sql-databases.json"
echo "  -> sql-databases.json"

run_cmd "Redis Caches" "redis-caches.json" az redis list "${COMMON[@]}" "${RG_FILTER[@]}" -o json
run_cmd "Synapse Workspaces" "synapse-workspaces.json" az synapse workspace list "${COMMON[@]}" "${RG_FILTER[@]}" -o json

# Identity
run_cmd "Role Assignments" "role-assignments.json" az role assignment list "${COMMON[@]}" --all -o json
run_cmd "Role Definitions" "role-definitions.json" az role definition list "${COMMON[@]}" -o json

# Azure-Specific
run_cmd "Resource Groups" "resource-groups.json" az group list "${COMMON[@]}" -o json
run_cmd "Bastions" "bastions.json" az network bastion list "${COMMON[@]}" "${RG_FILTER[@]}" -o json
run_cmd "Network Watchers" "network-watchers.json" az network watcher list "${COMMON[@]}" -o json
run_cmd "Firewalls" "firewalls.json" az network firewall list "${COMMON[@]}" "${RG_FILTER[@]}" -o json

echo ""
echo "Export complete: $OUTDIR"
echo "Files:"
ls -la "$OUTDIR"/*.json | awk '{print "  " $NF " (" $5 " bytes)"}'
echo ""
echo "To load: Use 'Upload JSON Files' in Azure Network Mapper and select all files from $OUTDIR/"
