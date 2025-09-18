#!/usr/bin/env bash
#
# Kubernetes cluster orchestrator
#
# This script runs on a single control machine with passwordless SSH access to
# all cluster nodes. It coordinates the installation of an external etcd
# server, control plane nodes, and worker nodes by downloading a per‑node
# installation script from a GitHub repository and executing it remotely.
#
# Features:
#   * Prompts you for node IP addresses and roles (etcd, control plane, workers)
#     if not provided via environment variables.
#   * Pings and SSHs to each node to check connectivity, reporting status in
#     colour (green for OK, yellow for warning, red for down).
#   * Executes installation sequentially: etcd first, then first control
#     plane, then additional control planes, then workers.
#   * Automatically retrieves join commands from the first control plane and
#     passes them to subsequent nodes.
#   * Uses curl to pull the node installation script from a specified GitHub
#     raw URL. You must upload k8s‑complete.sh to your repository and
#     provide its raw URL when prompted.
#   * Logs all operations to /var/log/k8s-controller.log.

set -euo pipefail

# Where to write logs
LOG="/var/log/k8s-controller.log"

# Colours for status output
CLR_GREEN="\033[32m"
CLR_YELLOW="\033[33m"
CLR_RED="\033[31m"
CLR_RESET="\033[0m"

# Write a message to stdout and append to log
log_info() {
  echo "[+] $1" | tee -a "$LOG"
}

# Prompt for a variable if it's unset. Accepts variable name, prompt text,
# and optional default. When non‑interactive, falls back to default.
prompt_if_empty() {
  local var="$1" prompt="$2" default="${3:-}" input
  if [ -z "${!var:-}" ]; then
    if [ -t 0 ]; then
      read -rp "$prompt ${default:+[$default]}: " input
      if [ -z "$input" ] && [ -n "$default" ]; then
        input="$default"
      fi
    else
      input="$default"
    fi
    # shellcheck disable=SC2163
    printf -v "$var" '%s' "$input"
  fi
}

# Verify we are root or have sufficient privileges
require_root() {
  if [ "$(id -u)" -ne 0 ]; then
    echo "This script must be run as root (or with sudo)." >&2
    exit 1
  fi
}

# Check ping and ssh connectivity to a node. Sets two global variables:
# PING_STATUS and SSH_STATUS. 0=OK, 1=warning/unreachable.
check_node() {
  local ip="$1"
  # Ping (ICMP). If ping fails, it's unreachable.
  if ping -c 1 -W 2 "$ip" >/dev/null 2>&1; then
    PING_STATUS=0
  else
    PING_STATUS=1
  fi
  # Test SSH. If ssh returns 0, it's OK. We pass -o BatchMode=yes to avoid
  # password prompts and -o StrictHostKeyChecking=no to accept new keys.
  if ssh -o BatchMode=yes -o ConnectTimeout=3 -o StrictHostKeyChecking=no \
      -o UserKnownHostsFile=/dev/null root@"$ip" true >/dev/null 2>&1; then
    SSH_STATUS=0
  else
    SSH_STATUS=1
  fi
}

# Print a status table for all nodes. Accepts arrays of names and IPs.
print_status_table() {
  local names=("${NAMES[@]}") ips=("${IPS[@]}") roles=("${ROLES[@]}")
  echo
  echo "Cluster node status:"
  echo "-----------------------------------------------------------------"
  printf "%-20s %-15s %-10s %-10s\n" "Node" "IP" "Ping" "SSH"
  echo "-----------------------------------------------------------------"
  for i in "${!ips[@]}"; do
    local name="${names[$i]}" ip="${ips[$i]}" role="${roles[$i]}"
    check_node "$ip"
    local ping_col ssh_col
    ping_col=$([ $PING_STATUS -eq 0 ] && echo "${CLR_GREEN}OK${CLR_RESET}" || echo "${CLR_RED}DOWN${CLR_RESET}")
    ssh_col=$([ $SSH_STATUS -eq 0 ] && echo "${CLR_GREEN}OK${CLR_RESET}" || echo "${CLR_YELLOW}WARN${CLR_RESET}")
    printf "%-20s %-15s %-10s %-10s\n" "$name ($role)" "$ip" "$ping_col" "$ssh_col"
  done
  echo "-----------------------------------------------------------------"
}

# Execute installation on a remote node. Arguments: IP, role, env vars (string)
install_remote() {
  local ip="$1" role="$2" envs="$3"
  log_info "Installing role $role on $ip..."
  # Compose remote command: download script and execute it with env vars.
  # We wrap commands in single quotes; variables are expanded on local side.
  # Use curl to download script to a temp file. Use bash -s to run it.
  ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null root@"$ip" bash -c \
    "\"${envs}\" curl -fsSL \"${GITHUB_URL}\" -o /tmp/k8s-install.sh && chmod +x /tmp/k8s-install.sh && /tmp/k8s-install.sh" >>"$LOG" 2>&1
  if [ $? -ne 0 ]; then
    die "Installation failed on $ip ($role). Check $LOG for details."
  fi
  log_info "Installation completed on $ip ($role)."
}

# Parse join commands from cp1. Expects cp1 IP.
get_join_cmds() {
  local cp_ip="$1"
  log_info "Fetching join commands from $cp_ip..."
  # Wait up to 10 minutes for the file to appear.
  local timeout=600 elapsed=0
  while ! ssh -o BatchMode=yes -o ConnectTimeout=3 -o StrictHostKeyChecking=no \
             -o UserKnownHostsFile=/dev/null root@"$cp_ip" test -f /root/join-commands.txt >/dev/null 2>&1; do
    if [ $elapsed -ge $timeout ]; then
      die "Timed out waiting for join-commands.txt on $cp_ip"
    fi
    sleep 5
    elapsed=$((elapsed+5))
  done
  # Fetch file
  local join_file
  join_file=$(ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null root@"$cp_ip" cat /root/join-commands.txt)
  # Parse cp join and worker join commands
  CP_JOIN_CMD=$(echo "$join_file" | awk '/control-plane join/ {getline; print}')
  WORKER_JOIN_CMD=$(echo "$join_file" | awk '/Worker join/ {getline; print}')
  if [ -z "$CP_JOIN_CMD" ] || [ -z "$WORKER_JOIN_CMD" ]; then
    die "Failed to parse join commands from $cp_ip"
  fi
  log_info "Parsed control-plane join and worker join commands."
}

# Main orchestrator
main() {
  require_root
  # Ensure log file exists
  mkdir -p "$(dirname "$LOG")"
  touch "$LOG"
  log_info "Starting Kubernetes cluster orchestrator..."
  # Prompt for GitHub URL for node installation script
  prompt_if_empty GITHUB_URL "Enter raw GitHub URL of node install script (k8s-complete.sh)" ""
  if [ -z "$GITHUB_URL" ]; then
    die "GitHub URL is required to download node script."
  fi
  # Prompt for etcd IP and control plane IPs
  prompt_if_empty ETCD_IP "Enter etcd node IP" "10.176.44.19"
  # Ask for control plane IPs space-separated, first is first control plane
  prompt_if_empty CP_IPS_STR "Enter space-separated control plane IPs (first will be first control plane)" "10.176.44.20 10.176.44.21"
  # Ask for worker IPs space-separated
  prompt_if_empty WORKER_IPS_STR "Enter space-separated worker node IPs" "10.176.44.22 10.176.44.23 10.176.44.24 10.176.44.25"
  # Ask for VIP
  prompt_if_empty VIP "Enter cluster VIP for API server" "10.176.44.10"
  # Convert CP_IPS_STR and WORKER_IPS_STR to arrays
  IFS=' ' read -ra CP_IPS <<< "$CP_IPS_STR"
  IFS=' ' read -ra WORKER_IPS_ARR <<< "$WORKER_IPS_STR"
  # Build arrays of names, IPs and roles
  NAMES=() IPS=() ROLES=()
  # etcd node
  NAMES+=("etcd1")
  IPS+=("$ETCD_IP")
  ROLES+=("etcd")
  # control planes
  for i in "${!CP_IPS[@]}"; do
    local idx=$((i+1))
    NAMES+=("cp${idx}")
    IPS+=("${CP_IPS[$i]}")
    ROLES+=("cp")
  done
  # workers
  for i in "${!WORKER_IPS_ARR[@]}"; do
    local idx=$((i+1))
    NAMES+=("w${idx}")
    IPS+=("${WORKER_IPS_ARR[$i]}")
    ROLES+=("worker")
  done
  # Show status table and confirm
  print_status_table
  echo
  if [ -t 0 ]; then
    read -rp "Proceed with installation? (yes/no) [yes]: " ANSWER
    if [ -z "$ANSWER" ]; then ANSWER="yes"; fi
    if [[ ! "$ANSWER" =~ ^[Yy](es)?$ ]]; then
      echo "Aborting installation."; exit 0
    fi
  fi
  # Stage 1: install etcd
  install_remote "$ETCD_IP" "etcd" "ROLE=etcd NODE_IP=$ETCD_IP VIP=$VIP ETCD_IP=$ETCD_IP"
  # Stage 2: install first control plane
  first_cp_ip="${CP_IPS[0]}"
  install_remote "$first_cp_ip" "cp1" "ROLE=cp FIRST_CP=yes ETCD_IP=$ETCD_IP VIP=$VIP"
  # Retrieve join commands
  get_join_cmds "$first_cp_ip"
  # Stage 3: install additional control planes
  if [ "${#CP_IPS[@]}" -gt 1 ]; then
    for i in $(seq 1 $(( ${#CP_IPS[@]} - 1 )) ); do
      local cp_ip="${CP_IPS[$i]}"
      install_remote "$cp_ip" "cp$((i+1))" "ROLE=cp FIRST_CP=no ETCD_IP=$ETCD_IP VIP=$VIP JOIN_CMD='${CP_JOIN_CMD}'"
    done
  fi
  # Stage 4: install workers
  for i in "${!WORKER_IPS_ARR[@]}"; do
    local worker_ip="${WORKER_IPS_ARR[$i]}"
    install_remote "$worker_ip" "worker$((i+1))" "ROLE=worker JOIN_CMD='${WORKER_JOIN_CMD}'"
  done
  log_info "All nodes have been configured."
  # Print final status table
  print_status_table
  log_info "Cluster installation complete."
}

main "$@"