# TUM-OpenSIEM: Installation & Operations Guide

**Product**: TUM-OpenSIEM Enterprise Appliance v2.0.0  
**Target Environments**: Windows 10/11 x64, Linux (Ubuntu 22.04 LTS / RHEL 9), Kubernetes 1.28+  
**Air-Gap Ready**: Offline bundle `tum-opensiem-appliance-offline.tar.gz` included

---

## 1. Prerequisites

### For Windows Desktop Operator App:
- Windows 10 / 11 64-bit or Windows Server 2022
- 4 GB RAM minimum (8 GB recommended)
- 1 GB free disk space
- No local runtime (.NET or Node.js) required — self-contained runtime included

### For Standalone Hallmark Web HUD:
- Any modern web browser (Edge, Chrome, Firefox, Safari)
- Zero external runtime, library, or internet dependencies

### For Docker Appliance:
- Docker Engine 24.0+ or Podman 4.5+ with Docker Compose v2.20+
- 8 GB RAM minimum (16 GB for high-EPS production)
- Ports 5200, 514 (UDP/TCP), 8123, 9000 available

### For Kubernetes (Helm):
- Kubernetes cluster v1.28+
- Helm v3.12+
- Persistent Volume Claim (PVC) support (Default: 50 Gi)

---

## 2. Deployment Instructions

### Method 1: Standalone Hallmark Console Web HUD (Instant Zero-Dependency)
To immediately visualize security events and telemetry without installing any software or services:
1. Navigate to `hallmark-console/`:
   ```cmd
   cd D:\TUM\setup-product\tum-socs\hallmark-console
   ```
2. Double-click `launch-console.cmd` or run:
   ```powershell
   powershell -ExecutionPolicy Bypass -File .\launch-console.ps1
   ```
3. The dark-theme cybersecurity visualizer opens immediately in your default browser.

---

### Method 2: Standalone Windows Operator Desktop Application
For full-featured desktop operations:
1. Navigate to `desktop-app/`:
   ```powershell
   cd D:\TUM\setup-product\tum-socs\desktop-app
   ```
2. Optional: Run shortcut setup:
   ```powershell
   powershell -ExecutionPolicy Bypass -File .\install-desktop.ps1
   ```
3. Launch the desktop application:
   ```cmd
   launch-desktop.cmd
   ```
   or double-click `TUM-OpenSIEM.exe`.

---

### Method 3: All-in-One Docker Container Appliance
Deploy the complete SIEM engine with ClickHouse columnar storage on a server or workstation:

#### A. Online Deployment (with Docker active):
1. Navigate to `docker-appliance/`:
   ```powershell
   cd D:\TUM\setup-product\tum-socs\docker-appliance
   ```
2. Run the startup script:
   ```powershell
   powershell -ExecutionPolicy Bypass -File .\start-appliance.ps1
   ```
   (On Linux/macOS: `./start-appliance.sh` or `docker compose up -d`)

3. Verify cluster status:
   ```bash
   docker compose ps
   curl http://localhost:5200/health
   curl http://localhost:8123/ping
   ```

#### B. Air-Gapped / Sovereign Offline Deployment:
1. Transfer `tum-opensiem-appliance-offline.tar.gz` to the target server.
2. Unpack the offline archive:
   ```bash
   tar -xzvf tum-opensiem-appliance-offline.tar.gz -C /opt/tum-opensiem
   cd /opt/tum-opensiem
   ```
3. Start the appliance:
   ```bash
   docker compose up -d
   ```

---

### Method 4: Enterprise Kubernetes Deployment (Helm v3)
Deploy into an enterprise Kubernetes cluster:
```bash
cd D:/TUM/setup-product/tum-socs/helm
helm upgrade --install tum-opensiem ./tum-opensiem \
  --namespace tum-security \
  --create-namespace \
  --set clickhouse.persistence.size=100Gi
```

---

## 3. High-Throughput Ingestion Verification & Stress Testing

To simulate 50,000 EPS sustained ingestion against the appliance:
```powershell
cd D:\TUM\setup-product\tum-socs\stress-test
node stress-test-50k-eps.mjs --target http://localhost:5200 --eps 50000 --duration 60s
```

For 24-hour endurance testing:
```powershell
powershell -ExecutionPolicy Bypass -File .\run-24h-stress-test.ps1
```

---

## 4. Troubleshooting & Diagnostics

- **Port 514 Permission Denied on Linux**: Binding to privileged port 514 requires `CAP_NET_BIND_SERVICE`. If running non-root without Docker, configure `setcap 'cap_net_bind_service=+ep' Tum.Siem.Server` or map to port 1514.
- **ClickHouse Healthcheck Timing**: The `clickhouse` container takes 5–8 seconds to initialize data directories on initial cold start. The Compose file includes `condition: service_healthy` so `tum-siem-appliance` starts only after ClickHouse is ready.
- **WORM Ledger Storage**: Verify disk storage for WORM audit logs is mounted to persistent volumes (`tum_worm_storage` volume).
