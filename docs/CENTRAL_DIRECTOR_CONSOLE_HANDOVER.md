# Handover: TUM Unified Cyber Defense Console -> TUM-OpenSIEM Web Console

- **Source Team:** Central Director Team
- **Destination Team:** TUM-Socs Co., Ltd. (Cyber Defense & SIEM Team)
- **Mandate:** Directive from CEO (1 พฤศจิกายน 2026)
- **Status:** Handed Over & Integrated as Native SIEM Feature 🟢
- **Associated Epic:** [`SCRUM-6`](https://daywakler.atlassian.net/browse/SCRUM-6) / `PasitTum/tum-socs#2`

---

## 1. บริบทและวัตถุประสงค์ของการส่งมอบ (Context & Purpose)

ตามคำสั่งของท่านประธานฯ และ CEO:
> *"สำหรับ Central Director Team ส่วนนี้ให้เป็น feature ของ SIEM ที่เรากำลังจะพัฒนาไปเลย ส่งต่อให้ทีม TUM-Socs จัดการได้เลย"*

ฝ่าย Central Director ได้ส่งมอบหน้าจอ **Interactive Cyber Attack Map & Executive HUD Visualizer** ให้ทีม TUM-Socs บรรจุเป็นฟีเจอร์ Web Console หลักของโปรเจกต์ **TUM-OpenSIEM** เรียบร้อยแล้ว เพื่อให้ทีม SecOps สามารถเชื่อมต่อข้อมูลสดจาก RingBuffer, ClickHouse, และ Sigma Rule Alert เข้าสู่หน้าจอแสดงผลได้โดยตรงในคลังเดียวกัน

---

## 2. อาร์ติแฟกต์ที่ส่งมอบ (Handover Deliverables)

| ไฟล์ที่ส่งมอบ | ตำแหน่งใน tum-socs | คำอธิบาย |
| :--- | :--- | :--- |
| **Executive HUD & Attack Map** | `visualizers/index.html` | หน้าจอแสดงผลแบบ Real-Time WebGL/Canvas สไตล์ Cyberpunk รองรับ Attack Map, Telemetry Graph, Custom Filter, และ One-Click Audit Export |
| **Legacy Telemetry Monitor** | `docs/tumlog_dashboard.html` | แดชบอร์ดตรวจสอบสถานะ RingBuffer และ Ingestion สถิติเดิมของ Tum.Log |

---

## 3. แผนการเชื่อมต่อระบบของ TUM-Socs (Integration Plan with OpenSIEM)

1. **Sprint 2 (Sigma Rule & Alert Dispatcher):**
   - เชื่อม Webhook Dispatcher ของ TUM-Socs ให้ยิง Event สดเข้า WebSocket / SSE ของ `visualizers/index.html`
2. **Sprint 3 (Web Dashboard & Event Explorer):**
   - เชื่อมต่อหน้าจอค้นหา Log (Query Explorer) ให้ดึงข้อมูลจาก **ClickHouse** หรือ **DuckDB**
   - บรรจุ `visualizers/index.html` เข้าเป็นหน้าแรก (Overview Dashboard) ของ TUM-OpenSIEM
   - รองรับการ Export รายงานพยานหลักฐาน (Court-Ready Tamper-Proof Evidence) ร่วมกับ Merkle Hash Ledger
