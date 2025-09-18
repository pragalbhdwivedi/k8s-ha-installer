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

---

## Architecture

```mermaid
flowchart TD
    A[Control Machine<br/>k8s-controller.sh] -->|SSH| B[etcd1<br/>ROLE=etcd]
    A -->|SSH| C[cp1<br/>ROLE=cp (first)]
    A -->|SSH| D[cp2<br/>ROLE=cp (join)]
    A -->|SSH| E[w1<br/>ROLE=worker]
    A -->|SSH| F[w2<br/>ROLE=worker]
    A -->|SSH| G[w3<br/>ROLE=worker]
    A -->|SSH| H[w4<br/>ROLE=worker]

    B --> C
    C --> D
    C --> E
    C --> F
    C --> G
    C --> H
