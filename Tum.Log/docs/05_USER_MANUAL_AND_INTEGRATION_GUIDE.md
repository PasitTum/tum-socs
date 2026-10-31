# TUMLog: User Manual & Integration Guide
**Document Reference:** TUM-LOG-UM-2026-V1.0  
**Classification:** **PUBLIC / CUSTOMER DEVELOPER GUIDE (คู่มือใช้งานสำหรับลูกค้า เผยแพร่สาธารณะได้)**  
**Target Audience:** Software Developers, DevOps Engineers, System Integrators  
**Product:** TUMLog — Sovereign Application Compliance & Threat Defense Mesh (*Powered by TUM*)  
**Version:** 1.0.0  

---

## 🚀 1. การติดตั้งใน 60 วินาที (60-Second Quickstart)

### ขั้นตอนที่ 1: ติดตั้งผ่าน NuGet Package Manager
```bash
dotnet add package Tum.Log
```

### ขั้นตอนที่ 2: ลงทะเบียนใน `Program.cs`
เพิ่มบริการ TUMLog เพียง 1 บรรทัดใน Dependency Injection Container:

```csharp
using Tum.Log;
using Tum.Trust.Security.Core.Models.Logging;

var builder = WebApplication.CreateBuilder(args);

// ลงทะเบียน TUMLog
builder.Services.AddTumLog(options =>
{
    options.ApplicationName = "CoreBankingPortal";
    options.Environment = "Production";
    options.WormRetentionDays = 90;                     // พรบ. คอมพิวเตอร์ ม.26 (อย่างน้อย 90 วัน)
    options.NtpServerHost = "time.navy.mi.th";           // ฐานเวลากองทัพเรือไทย
    options.DefenseMode = ThreatDefenseMode.AuditOnly;   // โหมดนุ่มนวล ไม่ขัดขวางผู้ใช้งาน
    options.ScanOutboundResponses = true;                // สแกนขาออกป้องกันข้อมูลรั่วไหล
});

var app = builder.Build();

// วาง Middleware ไว้ที่ต้น Pipeline (ดักจับทุก Request/Response ทั่วทั้งระบบอัตโนมัติ)
app.UseTumLog();

app.MapControllers();
app.Run();
```

> [!TIP]
> **เพียงเท่านี้ ระบบของคุณจะสอดคล้องตาม พรบ. คอมพิวเตอร์ ม.26 และ PDPA โดยไม่ต้องแก้ไข Controller หรือ Business Logic เดิมเลยแม้แต่บรรทัดเดียว!**

---

## 🛠️ 2. กลยุทธ์การใช้งาน 4 ระดับ (The Four-Tier Ingestion Strategy)

### Tier 1: Zero-Touch Middleware (แนะนำสำหรับ 90% ของระบบ)
เพียงใส่ `app.UseTumLog()` ระบบจะทำการ:
- บันทึก Client IP, User-Agent, HTTP Status Code, และ Latency อัตโนมัติ
- Mask ข้อมูลส่วนบุคคล (เลขบัตร ปชช. Modulo-11, บัตรเครดิต Luhn)
- ดักจับการโจมตีทางเว็บ (SQLi, XSS, Path Traversal)

### Tier 2: Declarative `[TumAudit]` Attribute (สำหรับธุรกรรมธุรกิจที่ต้องการ Audit ละเอียด)
แปะ Attribute เหนือฟังก์ชัน Controller Action หรือ Service Method:

```csharp
[ApiController]
[Route("api/v1/payments")]
public class PaymentController : ControllerBase
{
    [HttpPost("transfer")]
    [TumAudit("PAYMENT.TRANSFER", LogCategory.BusinessTransaction, Severity = "High")]
    public async Task<IActionResult> TransferFunds([FromBody] TransferRequest request)
    {
        // โค้ดโอนเงินปกติ
        return Ok(new { success = true });
    }
}
```

### Tier 3: Fluent Programmatic API (สำหรับเหตุการณ์เฉพาะใน Domain Logic)
สำหรับกรณีที่ต้องการบันทึก Log เองในโค้ด:

```csharp
public class SecurityService
{
    private readonly ITumLogEngine _tumLog;

    public SecurityService(ITumLogEngine tumLog)
    {
        _tumLog = tumLog;
    }

    public async Task RevokeAdminKey(string keyId, string adminUserId)
    {
        // บันทึก Log การเพิกถอนกุญแจสำคัญ
        await _tumLog.LogEventAsync(
            eventName: "SEC.KEY_REVOKE",
            category: LogCategory.SecurityThreat,
            payload: $"API Key {keyId} revoked by administrator",
            userId: adminUserId,
            severity: "Critical");
    }
}
```

### Tier 4: Multi-Destination Configuration (`appsettings.json`)
กำหนดปลายทางจัดเก็บ Log ได้หลากหลายในไฟล์คอนฟิก:

```json
{
  "TumLog": {
    "ApplicationName": "EnterpriseApp",
    "StorageDirectory": "./tum_logs",
    "WormRetentionDays": 90,
    "DefenseMode": "AuditOnly",
    "Destinations": [
      {
        "SinkType": "LocalWormFile",
        "IsEnabled": true
      },
      {
        "SinkType": "SyslogRfc5424",
        "EndpointUri": "syslog://siem.corp.internal:514",
        "IsEnabled": true
      },
      {
        "SinkType": "ElasticsearchOpenSearch",
        "EndpointUri": "https://opensearch.corp.internal:9200",
        "TargetName": "tumlog-audit-events",
        "IsEnabled": true
      }
    ]
  }
}
```

---

## 🖥️ 3. การใช้งาน Dashboard ระดับผู้บริหารและ SOC

เปิดไฟล์ [`tumlog_dashboard.html`](file:///d:/Work/NKS-Kiosk-Config/NKS-Kiosk-Identity-SDK/docs/developer-portal/tumlog_dashboard.html) บนเบราว์เซอร์เพื่อเข้าสู่หน้าจอควบคุม:
1. **Live Stream & Trace:** ดูการบันทึก Log แบบ Real-time พร้อม Correlation ID แกะรอยธุรกรรม
2. **Endpoint PII Mesh:** ดูแผนผังว่า Route ไหนในระบบมีข้อมูลส่วนบุคคลไหลผ่าน และมีประวัติถูกโจมตีเท่าใด
3. **Bidirectional Defense:** ตรวจสอบการโจมตีขาเข้าที่สกัดได้ และข้อมูลรั่วไหลขาออกที่ถูก Mask ทิ้ง
4. **Audit Certificate Button:** กดปุ่ม **"Audit Certificate"** เพื่อพิมพ์เอกสารรับรองสำหรับส่งมอบกระทรวงดิจิทัลฯ (MDES) หรือผู้ตรวจประเมิน ISO 27001
