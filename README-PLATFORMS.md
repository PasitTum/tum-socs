# TUM-OpenSIEM Multi-Platform Operational Guide

**TUM-OpenSIEM** คือ Sovereign Security Information & Event Management (SIEM) ที่ถูกออกแบบตามหลักสถาปัตยกรรม **"ใช้งานง่ายกับทุก Platform (Universal Multi-Platform Defense)"**

---

## 🖥️ 1. Windows Application (Native Desktop Client)
* **ไฟล์โปรแกรม:** `dist/desktop/win-unpacked/TUM-OpenSIEM.exe`
* **ลักษณะการทำงาน:** เป็น Native Windows Application ที่รันผ่าน Electron Shell
* **คุณสมบัติ:**
  * รองรับ Native Windows Notification (แจ้งเตือนเด้งขึ้นหน้าจอเมื่อพบการโจมตีระดับ Critical เช่น SQLi หรือ Ransomware)
  * System Tray ด้านล่างขวาของ Windows
  * ไม่ต้องเปิดผ่านบราวเซอร์ สามารถดับเบิ้ลคลิกเข้าสู่ Cyber Command Console ได้ทันที
* **คำสั่งเปิดโหมด Dev:** `npm --prefix Tum.Siem.Web run desktop:dev`

---

## 🪟 2. Windows Standalone Server (.exe)
* **ไฟล์โปรแกรม:** `dist/win-x64/Tum.Siem.Server.exe`
* **ลักษณะการทำงาน:** Self-contained Single-file Executable ขนาดกะทัดรัด
* **ความสะดวก:** **ไม่ต้องติดตั้ง .NET Runtime หรือ Database เพิ่มเติมใดๆ ทั้งสิ้น** (Zero-Dependency) ดับเบิ้ลคลิกแล้วสตาร์ท Web API + Ingestion Engine + WORM Ledger บนพอร์ต 5000/5001 ทันที

---

## 🐧 3. Linux Application (Ubuntu / Debian / RHEL / CentOS)
* **ไฟล์โปรแกรม:** `dist/linux-x64/Tum.Siem.Server`
* **ลักษณะการทำงาน:** Self-contained ELF Binary ทำงานเป็น Standalone Daemon หรือ Systemd Service
* **การติดตั้งและรัน:**
  ```bash
  chmod +x Tum.Siem.Server
  ./Tum.Siem.Server --urls "http://0.0.0.0:5000;https://0.0.0.0:5001"
  ```
* รองรับการรันเป็น Linux Background Daemon ตลอด 24x7 และรองรับ Ingestion สูงสุด 8.8M EPS

---

## 🍎 4. macOS Application (Apple Silicon & Intel)
* **ไฟล์โปรแกรม:** `dist/osx-arm64/Tum.Siem.Server`
* **ลักษณะการทำงาน:** Native Mach-O Executable คอมไพล์ตรงสำหรับชิป Apple Silicon (M1/M2/M3/M4)
* **การติดตั้งและรัน:**
  ```bash
  chmod +x Tum.Siem.Server
  ./Tum.Siem.Server
  ```

---

## 📱 5. Tablet & Mobile Application (iPadOS, iOS, Android, Galaxy Tab, Surface)
* **การทำงาน:** **Enterprise Progressive Web App (PWA)**
* **คุณสมบัติการใช้งานบนอุปกรณ์พกพา:**
  1. **Add to Home Screen:** เข้าผ่าน Safari หรือ Chrome บนมือถือหรือแท็บเล็ต แล้วกด *"Add to Home Screen (เพิ่มไปยังหน้าจอหลัก)"* จะกลายเป็นแอปพลิเคชันแยกเดี่ยว (Standalone) เต็มหน้าจอโดยไม่มีแถบ URL ของบราวเซอร์
  2. **Tactical Thumb Navigation Bar:** มีแถบเมนูด้านล่างหน้าจอสำหรับการใช้งานด้วยนิ้วโป้งมือเดียวบนมือถือ (`⚡ เรดาร์`, `🔍 ค้นหา`, `🎯 ทดสอบโจมตี`, `🕸️ กราฟ`, `⚖️ ตรวจสอบ ม.26`)
  3. **Responsive Mobile Drawer:** เมนู Sidebar ย่อเก็บเข้าลิ้นชักด้านข้าง และเปิดผ่านปุ่ม Hamburger Menu ได้อย่างสะดวก
  4. **Touch Ergonomics:** ปุ่มและองค์ประกอบทั้งหมดมีขนาดสัมผัสไม่ต่ำกว่า 44x44px ตามมาตรฐาน Apple HIG และ Google Material Design
  5. **Offline Resilience:** มี Service Worker (`sw.js`) ทำการแคชหน้าจอ ช่วยให้เปิดแอปได้เร็วทันใจแม้สัญญาณเน็ตไม่เสถียร

---

## 📦 สรุปคำสั่ง Build ทุก Platform ในคำสั่งเดียว:
```powershell
.\build-all-platforms.ps1
```
