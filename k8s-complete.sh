#!/usr/bin/env bash
#
# Kubernetes one‑shot installer and cluster bootstrap script
#
# This script provisions an etcd node, control plane nodes and worker nodes for a
# Kubernetes cluster on Debian‑based systems. It handles prerequisite software,
# container runtime configuration, kubeadm bootstrap, CNI deployment, metrics,
# Helm, Rancher, node labelling, audit logging, log rotation and NTP hardening.
#
# Features:
#   * Idempotent – safe to re‑run on a node when nothing has changed.
#   * Supports single external etcd node and HA control plane via a VIP.
#   * Accepts role (etcd, cp or worker) from the environment or via prompt.
#   * Writes all output to /var/log/k8s-one.log for troubleshooting.
#   * Can run non‑interactively by defining environment variables.
#
# Example usage:
#   ROLE=etcd ./k8s-complete.sh
#   ROLE=cp FIRST_CP=yes ETCD_IP=10.176.44.19 VIP=10.176.44.10 ./k8s-complete.sh
#   ROLE=worker JOIN_CMD="$(cat /root/join-commands.txt | grep 'kubeadm join')" ./k8s-complete.sh
#
# Default values may be overridden by setting environment variables before
# execution. See configuration section below.

set -euo pipefail

# -----------------------------------------------------------------------------
#  Configuration
# -----------------------------------------------------------------------------
# These values can be overridden by exporting variables before running the
# script. For example: ETCD_DEFAULT_IP=192.168.1.100 ./k8s-complete.sh

VIP_DEFAULT="10.176.44.10"
ETCD_DEFAULT_IP="10.176.44.19"
CP1_IP="10.176.44.20"
CP2_IP="10.176.44.21"
WORKER_IPS=("10.176.44.22" "10.176.44.23" "10.176.44.24" "10.176.44.25")

POD_CIDR="${POD_CIDR:-10.244.0.0/16}"
SERVICE_CIDR="${SERVICE_CIDR:-10.96.0.0/12}"
CALICO_MANIFEST="${CALICO_MANIFEST:-https://raw.githubusercontent.com/projectcalico/calico/v3.28.2/manifests/calico.yaml}"
ETCD_VER="${ETCD_VER:-v3.5.15}"
K8S_CHANNEL="${K8S_CHANNEL:-stable}" # e.g., stable or release-1.31
INSTALL_RANCHER_DEFAULT="${INSTALL_RANCHER_DEFAULT:-y}"
RANCHER_HOSTNAME="${RANCHER_HOSTNAME:-rancher.local}"

REG_MIRROR="${REG_MIRROR:-}"       # set to a registry mirror if needed

# Audit log configuration
AUDIT_DIR="/var/log/kubernetes"
AUDIT_FILE="${AUDIT_DIR}/audit.log"
AUDIT_POLICY="/etc/kubernetes/audit-policy.yaml"

# Location of log file for the script
LOG="/var/log/k8s-one.log"

# -----------------------------------------------------------------------------
#  Helper functions
# -----------------------------------------------------------------------------

# Print a message to stdout and append it to the log file.
log_info() {
  echo "[+] $1" | tee -a "$LOG"
}

# Print an error message and exit. This logs the error and exits non‑zero.
die() {
  echo "[x] $1" | tee -a "$LOG" >&2
  exit 1
}

# Ensure we are running as root. Many operations require root privileges.
require_root() {
  if [ "$(id -u)" -ne 0 ]; then
    die "This script must be run as root. Use sudo or log in as root."
  fi
}

# Run a command and capture its output in the log file. On failure the
# script aborts with a helpful message.
run() {
  local cmd="$1"
  log_info "Running: $cmd"
  # shellcheck disable=SC2086
  bash -c "$cmd" >>"$LOG" 2>&1 || die "Command failed: $cmd. See $LOG for details."
}

# Prompt the user for input if a variable is empty. Accepts a prompt message
# and an optional default value. The result is stored in the provided
# variable name. If STDIN is not a TTY, the default value will be used.
prompt_if_empty() {
  local varname="$1" prompt="$2" default="${3:-}" input=""
  # Use indirect reference to determine current value
  local current="${!varname:-}"
  if [ -z "$current" ]; then
    if [ -t 0 ]; then
      read -rp "$prompt ${default:+[$default]}: " input
      # If user hits enter and default exists, use default
      if [ -z "$input" ] && [ -n "$default" ]; then
        input="$default"
      fi
    else
      # Non‑interactive mode: use default or empty
      input="$default"
    fi
    # shellcheck disable=SC2163
    printf -v "$varname" '%s' "$input"
  fi
}

# Detect the primary IPv4 address of this host. Use the first non‑loopback
# address. This is useful for automatically binding etcd or API server.
detect_ip() {
  ip -4 addr show scope global | awk '/inet /{print $2}' | cut -d/ -f1 | head -n1
}

# Determine the home directory of the non‑root user that invoked sudo, if any.
user_home() {
  local usr
  usr="${SUDO_USER:-${USER}}"
  getent passwd "$usr" | cut -d: -f6
}

# Check connectivity to a host and port. Returns 0 on success, 1 on failure.
check_port() {
  local host="$1" port="$2"
  timeout 3 bash -c "/dev/tcp/${host}/${port}" >/dev/null 2>&1
}

# Install system packages if they are not present. Accepts a list of package names.
# Uses apt-get and will not upgrade held packages without permission.
apt_install() {
  local pkgs=("$@")
  # Filter out packages that are already installed
  local to_install=()
  for pkg in "${pkgs[@]}"; do
    if ! dpkg -s "$pkg" >/dev/null 2>&1; then
      to_install+=("$pkg")
    fi
  done
  if [ "${#to_install[@]}" -gt 0 ]; then
    run "DEBIAN_FRONTEND=noninteractive apt-get install -y --allow-change-held-packages ${to_install[*]}"
  else
    log_info "Packages already installed: ${pkgs[*]}"
  fi
}

# Hold Kubernetes packages to prevent unintended upgrades.
hold_kube_packages() {
  run "apt-mark hold kubelet kubeadm kubectl"
}

# Add Kubernetes APT repository and GPG keys if not already present.
setup_kube_repo() {
  if [ ! -f /etc/apt/sources.list.d/kubernetes.list ]; then
    mkdir -p /etc/apt/keyrings
    run "curl -fsSL https://pkgs.k8s.io/core:/${K8S_CHANNEL}:/v1.31/deb/Release.key | gpg --dearmor -o /etc/apt/keyrings/kubernetes-apt-keyring.gpg"
    echo "deb [signed-by=/etc/apt/keyrings/kubernetes-apt-keyring.gpg] https://pkgs.k8s.io/core:${K8S_CHANNEL}:/v1.31/deb/ /" > /etc/apt/sources.list.d/kubernetes.list
    run "apt-get update -y"
  fi
}

# -----------------------------------------------------------------------------
#  Prerequisite installation and system preparation
# -----------------------------------------------------------------------------
prep_os() {
  log_info "Starting OS preparation and prerequisite installation..."
  # Update package lists with retry logic to handle transient network errors
  run "apt-get update -y"

  # Install required packages (skip if already installed)
  apt_install ca-certificates curl gnupg lsb-release apt-transport-https \
              software-properties-common chrony ebtables ethtool jq socat \
              conntrack ipset ipvsadm ufw bash-completion openssh-client

  # Ensure chrony (NTP) is enabled
  if systemctl list-unit-files chrony.service >/dev/null 2>&1; then
    run "systemctl enable --now chrony"
  elif systemctl list-unit-files chronyd.service >/dev/null 2>&1; then
    run "systemctl enable --now chronyd"
  fi

  # Configure UFW (if available) for Kubernetes ports
  if command -v ufw >/dev/null 2>&1; then
    # Only add rules if they don't already exist
    for p in 22 6443 2379 2380 10250 10257 10259; do
      ufw status numbered | grep -q "ALLOW.*${p}/tcp" || run "ufw allow ${p}/tcp"
    done
  fi

  # Load kernel modules and set sysctl parameters
  echo "overlay" >/etc/modules-load.d/containerd.conf
  echo "br_netfilter" >>/etc/modules-load.d/containerd.conf
  modprobe overlay || true
  modprobe br_netfilter || true
  cat >/etc/sysctl.d/99-kubernetes-cri.conf <<EOF
net.bridge.bridge-nf-call-iptables = 1
net.bridge.bridge-nf-call-ip6tables = 1
net.ipv4.ip_forward = 1
EOF
  run "sysctl --system"

  # Disable swap permanently
  run "swapoff -a || true"
  sed -ri 's/^[^#].*\s+swap\s+/#&/' /etc/fstab || true

  # Install containerd
  apt_install containerd
  # Generate default config if missing
  if [ ! -f /etc/containerd/config.toml ]; then
    run "containerd config default >/etc/containerd/config.toml"
  fi
  # Enable systemd cgroup driver
  sed -i 's/SystemdCgroup = false/SystemdCgroup = true/' /etc/containerd/config.toml
  # Configure registry mirror if defined
  if [ -n "$REG_MIRROR" ]; then
    mkdir -p /etc/containerd/certs.d/docker.io
    cat >/etc/containerd/certs.d/docker.io/hosts.toml <<EOF
server = "https://registry-1.docker.io"
[host."${REG_MIRROR}"]
  capabilities = ["pull", "resolve"]
EOF
  fi
  run "systemctl enable --now containerd"

  # Add Kubernetes repo and install kubeadm, kubelet, kubectl
  setup_kube_repo
  apt_install kubeadm kubelet kubectl
  hold_kube_packages
  run "systemctl enable --now kubelet"
  log_info "OS preparation complete."
}

# -----------------------------------------------------------------------------
#  Etcd installation for external cluster
# -----------------------------------------------------------------------------
install_etcd() {
  local node_ip="$1"
  log_info "Installing external etcd on ${node_ip}..."
  # Skip installation if etcd already installed
  if command -v etcd >/dev/null 2>&1; then
    log_info "etcd already installed; skipping download."
  else
    # Download and extract etcd
    local url="https://github.com/etcd-io/etcd/releases/download/${ETCD_VER}/etcd-${ETCD_VER}-linux-amd64.tar.gz"
    run "cd /tmp && curl -L ${url} -o etcd.tgz && tar xzf etcd.tgz"
    run "install -m 0755 /tmp/etcd-${ETCD_VER}-linux-amd64/etcd /usr/local/bin/etcd"
    run "install -m 0755 /tmp/etcd-${ETCD_VER}-linux-amd64/etcdctl /usr/local/bin/etcdctl"
  fi

  # Generate TLS certificates if not present
  mkdir -p /etc/etcd/pki
  pushd /etc/etcd/pki >/dev/null
  if [ ! -f ca.crt ] || [ ! -f server.crt ] || [ ! -f server.key ]; then
    log_info "Generating etcd TLS certificates..."
    run "openssl genrsa -out ca.key 4096"
    run "openssl req -x509 -new -nodes -key ca.key -subj /CN=etcd-ca -days 3650 -out ca.crt"
    cat >openssl.etcd.cnf <<EOF
[ req ]
distinguished_name = req_distinguished_name
x509_extensions = v3_req
prompt = no

[ req_distinguished_name ]
CN = etcd

[ v3_req ]
keyUsage = critical, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth, clientAuth
subjectAltName = @alt_names

[ alt_names ]
DNS.1 = localhost
IP.1 = 127.0.0.1
IP.2 = ${node_ip}
EOF
    run "openssl genrsa -out server.key 4096"
    run "openssl req -new -key server.key -out server.csr -config openssl.etcd.cnf"
    run "openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial -out server.crt -days 3650 -extensions v3_req -extfile openssl.etcd.cnf"
  fi
  popd >/dev/null

  # Create systemd service for etcd
  cat >/etc/systemd/system/etcd.service <<EOF
[Unit]
Description=etcd
Documentation=https://etcd.io
After=network-online.target
Wants=network-online.target

[Service]
Type=notify
ExecStart=/usr/local/bin/etcd \\
  --name=$(hostname -s) \\
  --data-dir=/var/lib/etcd \\
  --advertise-client-urls=https://${node_ip}:2379 \\
  --listen-client-urls=https://${node_ip}:2379,https://127.0.0.1:2379 \\
  --initial-advertise-peer-urls=https://${node_ip}:2380 \\
  --listen-peer-urls=https://${node_ip}:2380 \\
  --initial-cluster=$(hostname -s)=https://${node_ip}:2380 \\
  --initial-cluster-state=new \\
  --client-cert-auth \\
  --trusted-ca-file=/etc/etcd/pki/ca.crt \\
  --cert-file=/etc/etcd/pki/server.crt \\
  --key-file=/etc/etcd/pki/server.key \\
  --peer-client-cert-auth \\
  --peer-trusted-ca-file=/etc/etcd/pki/ca.crt \\
  --peer-cert-file=/etc/etcd/pki/server.crt \\
  --peer-key-file=/etc/etcd/pki/server.key
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
  run "systemctl daemon-reload"
  run "systemctl enable --now etcd"

  # Check etcd health
  log_info "Validating etcd endpoint health..."
  if check_port "$node_ip" 2379 && ETCDCTL_API=3 etcdctl --endpoints="https://${node_ip}:2379" --cacert=/etc/etcd/pki/ca.crt --cert=/etc/etcd/pki/server.crt --key=/etc/etcd/pki/server.key endpoint status >/dev/null 2>&1; then
    log_info "etcd is healthy at https://${node_ip}:2379"
  else
    die "etcd health check failed on ${node_ip}. Review $LOG for details."
  fi

  # Export client certs for kubeadm
  mkdir -p /root/etcd-client-export
  install -m 0644 /etc/etcd/pki/ca.crt /root/etcd-client-export/ca.crt
  install -m 0644 /etc/etcd/pki/server.crt /root/etcd-client-export/client.crt
  install -m 0600 /etc/etcd/pki/server.key /root/etcd-client-export/client.key

  log_info "etcd installation complete. Client certs available in /root/etcd-client-export."
}

# -----------------------------------------------------------------------------
#  Control plane bootstrap and optional HA configuration
# -----------------------------------------------------------------------------

# Copy etcd client certificates from the external etcd node. Requires passwordless SSH.
fetch_etcd_certs() {
  local etcd_ip="$1"
  log_info "Fetching etcd client certs from ${etcd_ip}..."
  mkdir -p /etc/kubernetes/pki/etcd
  # Use scp quietly; ignore host key prompts
  run "scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null root@${etcd_ip}:/root/etcd-client-export/ca.crt /etc/kubernetes/pki/etcd/ca.crt"
  run "scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null root@${etcd_ip}:/root/etcd-client-export/client.crt /etc/kubernetes/pki/etcd/etcd-client.crt"
  run "scp -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null root@${etcd_ip}:/root/etcd-client-export/client.key /etc/kubernetes/pki/etcd/etcd-client.key"
  chmod 600 /etc/kubernetes/pki/etcd/etcd-client.key
  chmod 644 /etc/kubernetes/pki/etcd/ca.crt /etc/kubernetes/pki/etcd/etcd-client.crt
  log_info "etcd client certs copied."
}

# Generate audit log policy file
create_audit_policy() {
  mkdir -p "$AUDIT_DIR"
  cat >"${AUDIT_POLICY}" <<'EOF'
apiVersion: audit.k8s.io/v1
kind: Policy
rules:
  # Log all metadata for pods, secrets, configmaps, etc.
  - level: Metadata
    resources:
      - group: ""
        resources: ["pods", "secrets", "configmaps", "services", "endpoints"]
  # Log request and response for modifications and impersonation
  - level: RequestResponse
    verbs: ["update", "patch", "delete", "create", "impersonate"]
    resources:
      - group: "*"
        resources: ["*"]
  # Drop audit for kube-proxy and job controller to avoid noise
  - level: None
    users: ["system:kube-proxy", "system:serviceaccount:kube-system:job-controller"]
EOF
}

# Initialize the first control plane using kubeadm.
kubeadm_init() {
  local vip="$1" etcd_ip="$2"
  log_info "Initializing the first control plane on VIP ${vip} using external etcd ${etcd_ip}..."
  create_audit_policy
  # Determine Kubernetes version string for kubeadm (e.g., v1.31.x)
  local kv
  kv="$(kubeadm version -o short)"
  # Use kubeadm init with external etcd and audit logging
  run "kubeadm init --control-plane-endpoint ${vip}:6443 \
    --pod-network-cidr ${POD_CIDR} \
    --service-cidr ${SERVICE_CIDR} \
    --kubernetes-version ${kv} \
    --upload-certs \
    --external-etcd endpoints=https://${etcd_ip}:2379,caFile=/etc/kubernetes/pki/etcd/ca.crt,certFile=/etc/kubernetes/pki/etcd/etcd-client.crt,keyFile=/etc/kubernetes/pki/etcd/etcd-client.key \
    --apiserver-extra-args \"--audit-log-path=${AUDIT_FILE} --audit-log-maxage=7 --audit-log-maxbackup=10 --audit-log-maxsize=100 --audit-policy-file=${AUDIT_POLICY}\""

  # Set up kubeconfig for root
  mkdir -p /root/.kube
  cp -f /etc/kubernetes/admin.conf /root/.kube/config
  # Enable kubectl bash completion for root
  grep -q "kubectl completion bash" /root/.bashrc || echo 'source <(kubectl completion bash)' >>/root/.bashrc
  log_info "kubeadm init complete. admin.conf copied to /root/.kube/config."
}

# Join additional control plane nodes
kubeadm_join_cp() {
  local join_cmd="$1"
  log_info "Joining additional control plane node..."
  if [ -z "$join_cmd" ]; then
    die "Join command is empty. Cannot join control plane."
  fi
  run "$join_cmd"
  log_info "Control plane join successful."
}

# Join worker nodes
kubeadm_join_worker() {
  local join_cmd="$1"
  log_info "Joining worker node..."
  if [ -z "$join_cmd" ]; then
    die "Worker join command is empty. Cannot join worker."
  fi
  run "$join_cmd"
  log_info "Worker join successful."
}

# Apply Calico CNI
apply_cni() {
  log_info "Applying Calico CNI plugin..."
  run "KUBECONFIG=/etc/kubernetes/admin.conf kubectl apply -f ${CALICO_MANIFEST}"
  log_info "Calico deployment initiated."
}

# Enable Calico WireGuard encryption
enable_calico_wireguard() {
  log_info "Enabling Calico WireGuard encryption..."
  cat > /tmp/calico-wireguard.yaml <<'EOF'
apiVersion: crd.projectcalico.org/v1
kind: FelixConfiguration
metadata:
  name: default
spec:
  wireguardEnabled: true
EOF
  run "KUBECONFIG=/etc/kubernetes/admin.conf kubectl apply -f /tmp/calico-wireguard.yaml"
  rm -f /tmp/calico-wireguard.yaml
  log_info "WireGuard enabled for Calico."
}

# Install metrics server
install_metrics() {
  log_info "Installing Kubernetes metrics server..."
  run "KUBECONFIG=/etc/kubernetes/admin.conf kubectl apply -f https://github.com/kubernetes-sigs/metrics-server/releases/latest/download/components.yaml"
  log_info "Metrics server deployment initiated."
}

# Install Helm and kubectx/kubens utilities
install_helm() {
  log_info "Installing Helm and kubectx/kubens..."
  if ! command -v helm >/dev/null 2>&1; then
    run "curl -fsSL https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash"
  fi
  # Install kubectx and kubens
  if ! command -v kubens >/dev/null 2>&1; then
    run "curl -fsSL https://raw.githubusercontent.com/ahmetb/kubectx/master/kubens -o /usr/local/bin/kubens && chmod +x /usr/local/bin/kubens"
  fi
  if ! command -v kubectx >/dev/null 2>&1; then
    run "curl -fsSL https://raw.githubusercontent.com/ahmetb/kubectx/master/kubectx -o /usr/local/bin/kubectx && chmod +x /usr/local/bin/kubectx"
  fi
  log_info "Helm, kubectx and kubens installed."
}

# Install Rancher on the first control plane if requested
install_rancher() {
  log_info "Installing Rancher on Kubernetes cluster..."
  # Ensure cert-manager is installed
  run "KUBECONFIG=/etc/kubernetes/admin.conf kubectl apply -f https://github.com/cert-manager/cert-manager/releases/latest/download/cert-manager.yaml"
  # Wait briefly for cert-manager to start
  log_info "Waiting for cert-manager webhook to become available..."
  run "KUBECONFIG=/etc/kubernetes/admin.conf kubectl wait --for=condition=Available --timeout=300s -n cert-manager deploy/cert-manager-webhook || true"
  # Add Rancher repository and install
  run "helm repo add rancher-stable https://releases.rancher.com/server-charts/stable"
  run "helm repo update"
  run "KUBECONFIG=/etc/kubernetes/admin.conf kubectl create namespace cattle-system --dry-run=client -o yaml | kubectl apply -f -"
  run "helm upgrade --install rancher rancher-stable/rancher \
       --namespace cattle-system \
       --set hostname=${RANCHER_HOSTNAME} \
       --set bootstrapPassword=admin \
       --set replicas=1"
  log_info "Rancher installation initiated. Access will be at https://${RANCHER_HOSTNAME}"
}

# Generate join commands and save them for other nodes
generate_join_cmds() {
  log_info "Generating kubeadm join commands for additional nodes..."
  # Upload cluster certificates and capture certificate key from last line
  local cert_key
  cert_key="$(kubeadm init phase upload-certs --upload-certs 2>>"$LOG" | tail -1)"
  local cp_join_cmd worker_join_cmd
  cp_join_cmd="$(kubeadm token create --print-join-command 2>>"$LOG") --control-plane --certificate-key ${cert_key}"
  worker_join_cmd="$(kubeadm token create --print-join-command 2>>"$LOG")"
  cat >/root/join-commands.txt <<EOF
# Control-plane join command (execute on each additional control-plane node):
${cp_join_cmd}

# Worker join command (execute on each worker node):
${worker_join_cmd}
EOF
  log_info "Join commands written to /root/join-commands.txt"
}

# Label and taint nodes appropriately after they join the cluster
label_and_taint_nodes() {
  log_info "Labelling and tainting nodes..."
  if [ -f /etc/kubernetes/admin.conf ]; then
    local K="--kubeconfig=/etc/kubernetes/admin.conf"
    # Label control-plane nodes (existing or new)
    for cp in cp1 cp2; do
      run "kubectl $K label node ${cp} node-role.kubernetes.io/control-plane='' --overwrite || true"
    done
    # Label worker nodes and remove control-plane taint if accidentally set
    for ip in "${WORKER_IPS[@]}"; do
      local node
      node=$(kubectl $K get nodes -o wide 2>>"$LOG" | awk -v IP="$ip" '$0~IP{print $1}') || true
      if [ -n "$node" ]; then
        run "kubectl $K label node ${node} node-role.kubernetes.io/worker='' --overwrite"
        run "kubectl $K taint nodes ${node} node-role.kubernetes.io/control-plane- || true"
      fi
    done
  fi
  log_info "Node labelling and taints updated."
}

# Copy kubeconfig to the invoking non-root user (~/.kube/config)
copy_kubeconfig_to_user() {
  log_info "Copying kubeconfig to invoking user..."
  local usr_home
  usr_home="$(user_home)"
  if [ -f /etc/kubernetes/admin.conf ] && [ "$usr_home" != "/root" ]; then
    mkdir -p "$usr_home/.kube"
    cp -f /etc/kubernetes/admin.conf "$usr_home/.kube/config"
    chown -R "${SUDO_USER:-$USER}":"${SUDO_USER:-$USER}" "$usr_home/.kube"
    log_info "Kubeconfig copied to ${usr_home}/.kube/config."
  fi
}

# Configure audit logging: ensure log directory and policy file exist; restart kubelet to apply
enable_audit_logging() {
  log_info "Enabling Kubernetes API audit logging..."
  mkdir -p "$AUDIT_DIR"
  touch "$AUDIT_FILE"
  chmod 640 "$AUDIT_FILE"
  # Restart kubelet to pick up new apiserver args (if not restarted automatically)
  run "systemctl restart kubelet"
  log_info "Audit logging enabled. Logs will be written to ${AUDIT_FILE}."
}

# Configure log rotation for audit log
configure_logrotate() {
  log_info "Configuring log rotation for Kubernetes audit log..."
  cat >/etc/logrotate.d/k8s-audit <<EOF
${AUDIT_FILE} {
  daily
  rotate 14
  compress
  missingok
  notifempty
  copytruncate
}
EOF
  log_info "Log rotation configured for ${AUDIT_FILE}."
}

# Harden NTP configuration by limiting sources
hardening_ntp() {
  log_info "Hardening chrony NTP configuration..."
  if [ -f /etc/chrony/chrony.conf ]; then
    sed -i 's/^pool .*/pool in.pool.ntp.org iburst maxsources 2/' /etc/chrony/chrony.conf || true
    run "systemctl restart chrony"
  fi
  log_info "NTP configuration hardened."
}

# Set up a local virtual IP using keepalived and haproxy on control plane nodes
setup_local_vip() {
  local vip_ip="$1"
  log_info "Configuring local VIP ${vip_ip} with keepalived and haproxy..."
  apt_install keepalived haproxy
  local iface
  iface="$(ip route show default | awk '/default/ {print $5; exit}')"
  local priority=100
  [[ "$(hostname -s)" =~ cp2$ ]] && priority=90
  cat >/etc/keepalived/keepalived.conf <<EOF
vrrp_instance VI_1 {
  state BACKUP
  interface ${iface}
  virtual_router_id 51
  priority ${priority}
  advert_int 1
  authentication {
    auth_type PASS
    auth_pass 42pass
  }
  virtual_ipaddress {
    ${vip_ip}
  }
  track_script {
    chk_haproxy
  }
}

vrrp_script chk_haproxy {
  script "pidof haproxy"
  interval 2
  weight 2
}
EOF
  cat >/etc/haproxy/haproxy.cfg <<EOF
global
  log /dev/log local0
  maxconn 2048
defaults
  mode tcp
  timeout connect 5s
  timeout client  50s
  timeout server  50s
frontend k8s-api
  bind *:6443
  default_backend k8s-masters
backend k8s-masters
  balance roundrobin
  option tcp-check
  server cp1 ${CP1_IP}:6443 check
  server cp2 ${CP2_IP}:6443 check
EOF
  run "systemctl enable --now haproxy keepalived"
  log_info "Local VIP configuration applied."
}

# -----------------------------------------------------------------------------
#  Main logic
# -----------------------------------------------------------------------------
main() {
  require_root
  # Ensure log file exists
  mkdir -p "$(dirname "$LOG")"
  touch "$LOG"

  # Determine role (etcd, cp, worker) from environment or prompt
  ROLE="${ROLE:-}"  # May be exported from environment
  case "$ROLE" in
    etcd|cp|worker) : ;; # valid roles
    *)
      # Ask user if not provided and interactive
      prompt_if_empty ROLE "Select node role (etcd/cp/worker)" ""
      case "$ROLE" in
        etcd|cp|worker) ;; 
        *) die "Invalid role specified: $ROLE";;
      esac
      ;;
  esac

  log_info "Node role: ${ROLE}"

  # Perform common OS prep for all roles
  prep_os

  if [ "$ROLE" = "etcd" ]; then
    # Determine IP to bind etcd to
    local_ip="$(detect_ip)"
    prompt_if_empty NODE_IP "Enter IP for etcd to bind" "$local_ip"
    install_etcd "$NODE_IP"
    log_info "etcd node provisioning finished."
    return 0
  fi

  # For both control plane and worker roles, we need etcd and VIP information
  prompt_if_empty ETCD_IP "Enter IP of external etcd node" "$ETCD_DEFAULT_IP"
  prompt_if_empty VIP "Enter cluster VIP for API server" "$VIP_DEFAULT"

  if [ "$ROLE" = "cp" ]; then
    # Determine if first control plane
    FIRST_CP="${FIRST_CP:-}"  # Accept from environment or prompt
    prompt_if_empty FIRST_CP "Is this the FIRST control-plane node? (yes/no)" "yes"
    # Ask whether to set up local VIP on this node (only relevant for CP nodes)
    SETUP_VIP="${SETUP_VIP:-}"  # Accept from environment or prompt
    prompt_if_empty SETUP_VIP "Configure local VIP using keepalived/haproxy on this node? (yes/no)" "yes"

    # Optionally set up local VIP
    if [[ "$SETUP_VIP" =~ ^[Yy](es)?$ ]]; then
      setup_local_vip "$VIP"
    fi

    if [[ "$FIRST_CP" =~ ^[Yy](es)?$ ]]; then
      # First control plane: fetch etcd certs, init cluster, install components
      fetch_etcd_certs "$ETCD_IP"
      kubeadm_init "$VIP" "$ETCD_IP"
      apply_cni
      enable_calico_wireguard
      install_metrics
      install_helm
      # Ask about Rancher installation
      INSTALL_RANCHER="${INSTALL_RANCHER:-}"  # Accept from env or prompt
      prompt_if_empty INSTALL_RANCHER "Install Rancher on this control-plane node? (yes/no)" "$INSTALL_RANCHER_DEFAULT"
      if [[ "$INSTALL_RANCHER" =~ ^[Yy](es)?$ ]]; then
        install_rancher
      else
        log_info "Skipping Rancher installation."
      fi
      generate_join_cmds
      label_and_taint_nodes
      copy_kubeconfig_to_user
      enable_audit_logging
      configure_logrotate
      hardening_ntp
      log_info "First control-plane node setup complete."
    else
      # Additional control plane: join via provided join command
      JOIN_CMD="${JOIN_CMD:-}"  # Accept join command via env or prompt
      prompt_if_empty JOIN_CMD "Paste the control-plane join command" ""
      kubeadm_join_cp "$JOIN_CMD"
      # Label nodes after joining
      label_and_taint_nodes
      log_info "Additional control-plane node setup complete."
    fi
  elif [ "$ROLE" = "worker" ]; then
    # Worker node: join via provided join command
    JOIN_CMD="${JOIN_CMD:-}"  # Accept join command via env or prompt
    prompt_if_empty JOIN_CMD "Paste the worker join command" ""
    kubeadm_join_worker "$JOIN_CMD"
    label_and_taint_nodes
    log_info "Worker node setup complete."
  fi
  log_info "Cluster setup finished. See ${LOG} for detailed logs."
}

main "$@"