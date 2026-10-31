# 02_TUM_Socs — Full-Spectrum Cyber Defense & Compliance Log Mesh
## บริษัทที่ 2 ในเครือ TUM Group Holdings Co., Ltd. (วิวัฒนาการจาก TUMLog)

> **คำขวัญ:** *"Active Cyber Defense, Kernel-Level Telemetry & Tamper-Evident Ledger"*  
> **สถานะ:** Active Production Pillar 🟢  
> **ผู้รับผิดชอบหลัก:** Managing Director (Cyber Defense & SOC Operations) & DevOps Security Engineer

---

## 1. ขอบเขตและหน้าที่ความรับผิดชอบ (Company Scope)

**TUMSocs Co., Ltd.** คือศูนย์บัญชาการและโครงข่ายความมั่นคงไซเบอร์เชิงรุก (Active Cyber Defense) ก้าวข้ามการเก็บ Log แบบดั้งเดิม สู่ระบบวิเคราะห์และตัดตอนภัยคุกคามทันที:

1. **Context & Attribution Engine (Where / Why / Risk):**
   - วิเคราะห์เจาะลึกว่าเหตุการณ์ที่เกิดขึ้น **มาจากไหน (Where?)**, **เข้ามาทำไม (Why?)**, และ **มีความเสี่ยงระดับใด (Risk Score)**
   - คำนวณค่าความเสี่ยงแบบไดนามิกระหว่าง 0-100 เพื่อแจ้งเตือน SOC ทันที
2. **Tamper-Evident Cryptographic Ledger (ISO 27001 & พ.ร.บ.คอมพิวเตอร์ฯ):**
   - กลไก **Merkle Hash Tree** และ **SHA-256 Chaining** ป้องกันการแก้ไขหรือลบ Log ย้อนหลัง
   - ออกใบเสร็จรับรองความถูกต้องดิจิทัล (Tamper-Proof Receipt) สำหรับใช้เป็นพยานหลักฐานทางกฎหมาย
3. **Automated Threat Detection & Active Mitigation:**
   - ตรวจจับการโจมตีอัตโนมัติ: Brute Force, Token Replay, Credential Stuffing, PII Data Exfiltration
   - โหมดตอบสนองฉุกเฉิน (Active Mitigation): สั่งตัดเซสชันและขึ้นบัญชีดำ IP อัตโนมัติในระดับ Middleware และ Kernel
4. **Compliance Multi-Sink Ingestion:**
   - ส่งออกข้อมูลไปยังระบบจัดเก็บหลากหลาย: Local Secure File, Splunk, ElasticSearch, AWS CloudWatch, Azure Monitor

---

## 2. โครงสร้างโฟลเดอร์ภายใน (Internal Architecture)

```
02_TUM_Socs/
├── Tum.Log/                     # รหัสต้นฉบับเครื่องยนต์ความปลอดภัยและบันทึกหลักฐาน
│   ├── Core/
│   │   ├── Interfaces/         # ITumLogEngine, ITamperProofLogChain, ITumThreatDetector
│   │   └── Models/             # TumLogEntry, SecurityThreatAlert, TamperProofReceipt
│   ├── Infrastructure/         # RingBuffer, LogSinkDispatcher, PII Sanitizer
│   ├── Extensions/             # ServiceCollection extensions for ASP.NET Core & Workers
│   ├── Tum.Log.csproj          # โปรเจกต์หลัก (.NET 5.0, .NET 8.0, .NET 10.0)
│   └── README.md               # รายละเอียดเชิงลึกของ Tum.Log Engine
├── docs/                        # เอกสารสถาปัตยกรรมและการปฏิบัติตามกฎหมาย
│   ├── 01_URS ถึง 09_ROADMAP   # ข้อกำหนดระบบครบวงจร (URS, SRS, SDD, Test Plan, Changelog)
│   └── tumlog_dashboard.html   # Live Telemetry & Log Monitoring Visualizer
└── README.md                    # เอกสารภาพรวมบริษัท TUMSocs
```

---

## 3. ความเชื่อมโยงกับบริษัทย่อยอื่น (Synergy & Cross-Company Links)

- ⬅️ **รับข้อมูลจาก `01_TUM_Trust_Security`:** รับ Audit Event จากจุดตรวจอัตลักษณ์ บัตรประชาชน และตู้คีออส เพื่อวิเคราะห์พฤติกรรมผิดปกติ
- ➡️ **ประสานงานกับ `03_TUM_Quantum`:** ส่งสถิติรูปแบบการโจมตีจริง (Real-world Attack Telemetry) ให้ TUMQuantum ใช้จำลองการโจมตี และรับ Merkle Tree ที่ทนทานต่อคอมพิวเตอร์ควอนตัมมาใช้งาน
