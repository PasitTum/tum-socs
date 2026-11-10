# TUM OpenSIEM — Turnkey SIEM & SOC Appliance Quickstart Guide
**Product**: TUM OpenSIEM Enterprise Suite v2.0.0  
**Target Environment**: Windows 10/11 (Desktop App), Ubuntu 22.04 LTS / RHEL 9 (Docker Appliance), Kubernetes 1.28+ (Helm)  
**Performance Tier**: 50,000 – 100,000 EPS High-Throughput Ingestion (ClickHouse columnar storage)

---

## 1. Package Contents
```
setup-product/tum-socs/
├── desktop-app/                          # Standalone Windows Electron Desktop Application
│   ├── TUM-OpenSIEM.exe                  # Pre-packaged 238MB desktop executable
│   ├── resources/
│   └── locales/
├── docker-appliance/                     # Turnkey Containerized SOC Appliance
│   ├── docker-compose.yml                # ClickHouse + Vector + TUM-SIEM all-in-one stack
│   ├── Dockerfile                        # Multi-stage security-hardened container spec
│   └── compose-test.ps1                  # Appliance validation test script
├── helm/                                 # Production Kubernetes Deployment
│   └── tum-opensiem/                     # Helm v3 chart (ClickHouse statefulset, SIEM deployments)
├── stress-test/                          # Ingestion & Soak Stress Test Suite
│   ├── stress-test-50k-eps.mjs           # 50,000 EPS sustained load generator
│   ├── run-24h-stress-test.ps1           # 24-hour soak runner with memory leak checks
│   └── stress-test-report.json           # Validated benchmark results
├── smoke-test.ps1                        # Standalone smoke test & verification script
└── INSTALL_AND_QUICKSTART_GUIDE.md       # This document
```

---

## 2. Installation & Quickstart

### Method A: Standalone Windows Operator Desktop App
1. Navigate to `desktop-app/`:
   ```powershell
   cd D:\TUM\setup-product\tum-socs\desktop-app
   ```
2. Double-click or execute `TUM-OpenSIEM.exe`.
3. The SIEM Operator Dashboard will open immediately without requiring local Node.js or .NET runtimes.

### Method B: All-in-One Docker Appliance
1. Navigate to `docker-appliance/`:
   ```bash
   cd D:/TUM/setup-product/tum-socs/docker-appliance
   ```
2. Start the cluster:
   ```bash
   docker compose up -d
   ```
3. Verify cluster health:
   - Web HUD: `http://localhost:5000`
   - Syslog Ingestion: `udp://0.0.0.0:514`
   - ClickHouse Native: `tcp://localhost:9000`

### Method C: Offline Container Image Export & Loading
To deploy on an air-gapped / sovereign government network without internet:
1. Export image from build host:
   ```bash
   docker save tum-opensiem:latest | gzip > tum-opensiem-offline.tar.gz
   ```
2. Import image on target machine:
   ```bash
   docker load < tum-opensiem-offline.tar.gz
   docker compose up -d
   ```

### Method D: Enterprise Kubernetes (Helm)
```bash
helm upgrade --install tum-siem ./helm/tum-opensiem --namespace tum-security --create-namespace
```

### Verification Smoke Test
Run the turnkey package smoke test:
```powershell
cd D:\TUM\setup-product\tum-socs
powershell -ExecutionPolicy Bypass -File .\smoke-test.ps1
```
