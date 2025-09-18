# Kubernetes HA Cluster Installer

This project provides a **single-command workflow** to bootstrap a **high-availability Kubernetes cluster** on Debian 12.  
It combines two scripts:

- **`k8s-complete.sh`** → Installs everything required on a single node (etcd / control plane / worker).
- **`k8s-controller.sh`** → Orchestrates the install across all nodes via SSH, with live reachability checks.

---

## Features

- External **etcd** with TLS
- **Control plane HA** with VIP via Keepalived + HAProxy
- **Calico CNI** with WireGuard encryption
- **Metrics Server**
- **Helm** (kubectl plugins included)
- Optional **Rancher** install
- **Audit logging** with logrotate
- **Chrony NTP** hardening
- Full-screen TUI: progress bar, per-task status, color-coded results
- Detailed logs:  
  - `/var/log/k8s-one.log` on nodes  
  - `/var/log/k8s-controller.log` on the orchestrator

```mermaid

flowchart TD
    A["Control Machine\nk8s-controller.sh"] -->|SSH| B["etcd1\nROLE=etcd"];
    A -->|SSH| C["cp1\nROLE=cp (first)"];
    A -->|SSH| D["cp2\nROLE=cp (join)"];
    A -->|SSH| E["w1\nROLE=worker"];
    A -->|SSH| F["w2\nROLE=worker"];
    A -->|SSH| G["w3\nROLE=worker"];
    A -->|SSH| H["w4\nROLE=worker"];

    B --> C;
    C --> D;
    C --> E;
    C --> F;
    C --> G;
    C --> H;
