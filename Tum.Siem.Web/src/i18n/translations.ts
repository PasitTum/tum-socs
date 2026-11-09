// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

export type Language = 'th' | 'en';

export const translations = {
  th: {
    // Brand & Navigation
    brandName: 'TUM-OpenSIEM',
    brandSubtitle: 'Sovereign Security Mesh',
    navRadar: 'เรดาร์ภัยคุกคาม',
    navRadarSub: 'Threat Radar & HUD',
    navExplorer: 'ค้นหา Log พยานหลักฐาน',
    navExplorerSub: 'Event Query Explorer',
    navGraph: 'กราฟวิเคราะห์การโจมตี',
    navGraphSub: 'Correlated Attack Graph',
    navRules: 'กฎตรวจจับ SigmaHQ',
    navRulesSub: 'Native Sigma Rules',
    navCompliance: 'รายงาน ม.26 & PDPA',
    navComplianceSub: 'CCA Sec 26 & ISO 27001',

    // Status Card
    engineStatus: 'สถานะเครื่องยนต์',
    wormSeal: 'ตราประทับ WORM:',
    retention: 'ระยะเวลาจัดเก็บ:',
    sigmaRules: 'กฎ Sigma:',
    loaded: 'โหลดแล้ว',
    days: 'วัน',

    // Header & Actions
    btnSimulate: 'จำลองการโจมตี (Red-Team)',
    btnScan: 'สแกนทั้งระบบ',
    btnScanning: 'กำลังสแกน...',
    btnExport: 'ส่งออกรายงานพยานหลักฐาน',
    btnDatasets: 'คลังชุดข้อมูลจริง & ล้างขยะ Prod',
    btnCyberRange: 'สนามจำลองไซเบอร์เสมือนจริง (Cyber Range)',
    btnLogout: 'ออกจากระบบ',

    // View Titles & Subtitles
    radarTitle: 'เรดาร์ตรวจจับ & แดชบอร์ดความมั่นคง (Threat Radar HUD)',
    radarSubtitle: 'การตรวจจับภัยคุกคามแบบเรียลไทม์ พร้อมอัลกอริทึมวิเคราะห์ความเสี่ยงต่อเนื่อง 0-100',
    explorerTitle: 'ตัวสืบค้นและค้นหา Log พยานหลักฐาน (Event Query Explorer)',
    explorerSubtitle: 'ค้นหาด้วยไวยากรณ์ Lucene / SQL พร้อมตรวจสอบความถูกต้องด้วย SHA-256 Merkle Ledger',
    graphTitle: 'กราฟวิเคราะห์ความสัมพันธ์ภัยคุกคาม (Correlated Attack Graph)',
    graphSubtitle: 'วิเคราะห์ความเชื่อมโยงของไอพีผู้โจมตี, เทคนิค MITRE ATT&CK และทรัพยากรเป้าหมาย',
    rulesTitle: 'คลังกฎตรวจจับภัยคุกคามมาตรฐาน SigmaHQ (Sigma Rules Engine)',
    rulesSubtitle: 'คอมไพล์กฎในหน่วยความจำสู่ Expression Trees เพื่อการสแกนความเร็วสูงระดับไมโครวินาที',
    complianceTitle: 'รายงานพยานหลักฐานตามกฎหมาย (CCA Sec 26 & Regulatory Compliance)',
    complianceSubtitle: 'รับรองความสมบูรณ์ตาม พ.ร.บ.คอมพิวเตอร์ฯ ม.26, PDPA, และ ISO/IEC 27001',

    // Metrics Cards
    metricTotalLogs: 'ปริมาณข้อมูล Log รวม',
    metricBlockedThreats: 'ภัยคุกคามที่ถูกสกัดกั้น',
    metricActiveRules: 'กฎตรวจจับ SigmaHQ',
    metricPiiRedacted: 'ข้อมูลส่วนบุคคลที่กำบัง (PDPA)',
    zeroTax: 'Zero Ingestion Tax',
    autoMitigated: 'ตอบสนองอัตโนมัติ',
    openRules: 'กฎเปิด',

    // Chart
    chartTitle: 'ดัชนีวัดระดับความเสี่ยงภัยคุกคามตามเวลาจริง (Continuous Dynamic Risk Index)',
    riskScore: 'คะแนนความเสี่ยง (0 - 100)',

    // Feed
    liveFeedTitle: 'กระแสเหตุการณ์ความมั่นคงสด (Live Telemetry Feed)',
    waitingTelemetry: 'กำลังรอสัญญาณข้อมูลจาก RingBuffer Mesh...',
    simHint: 'กดปุ่ม "คลังชุดข้อมูลจริง" หรือ "จำลองการโจมตี" เพื่อโหลดเหตุการณ์',

    // Login Portal
    loginPortalTitle: 'เข้าสู่ระบบศูนย์ปฏิบัติการความมั่นคง (SOC Console Login)',
    loginPortalDesc: 'ระบบตรวจสอบสิทธิ์ระดับความมั่นคงสูง (Sovereign Role-Based Authentication)',
    lblUsername: 'ชื่อผู้ใช้งาน (Username)',
    lblPassword: 'รหัสผ่าน (Password)',
    btnLogin: 'เข้าสู่ระบบความมั่นคง (Authenticate)',
    btnLoginning: 'กำลังตรวจสอบสิทธิ์...',
    quickDemoLogin: 'เข้าสู่ระบบด่วนสำหรับการสาธิต (Quick Demo Roles):',
    roleAdmin: 'SecOps Director (ผู้ดูแลระบบ)',
    roleAnalyst: 'Threat Analyst (นักวิเคราะห์ภัย)',
    roleAuditor: 'Compliance Auditor (ผู้ตรวจสอบ ม.26)',
    complianceNote: 'รับรองการเข้ารหัสตามมาตรฐาน FIPS 204 และ พ.ร.บ.คอมพิวเตอร์ฯ ม.26',

    // Dataset Manager Modal
    datasetModalTitle: 'คลังชุดข้อมูลภัยคุกคามจริง & การเตรียมขึ้น Production',
    datasetModalDesc: 'นำเข้า Log จริงจากการเจาะระบบในโลกไซเบอร์เพื่อทดสอบ หรือล้างข้อมูลทั้งหมดคืนสู่สถานะ Genesis สะอาด 100%',
    btnLoadDataset: 'นำเข้าข้อมูลนี้',
    btnLoadingDataset: 'กำลังนำเข้า...',
    btnPurgeProd: 'ล้างข้อมูลทดสอบทั้งหมด (Reset to Clean Production)',
    purgeConfirm: 'คุณแน่ใจหรือไม่ว่าต้องการล้างข้อมูลทดสอบทั้งหมด? ข้อมูลในดิสก์จะถูกลบและรีเซ็ตราก Merkle คืนสู่ Genesis เพื่อส่งมอบลูกค้า',
    records: 'รายการ',
  },
  en: {
    // Brand & Navigation
    brandName: 'TUM-OpenSIEM',
    brandSubtitle: 'Sovereign Security Mesh',
    navRadar: 'Threat Radar HUD',
    navRadarSub: 'Real-time Defense',
    navExplorer: 'Event Query Explorer',
    navExplorerSub: 'Forensic Audit Search',
    navGraph: 'Attack Graph',
    navGraphSub: 'Correlated Topology',
    navRules: 'Sigma Rules',
    navRulesSub: 'SigmaHQ Detection Engine',
    navCompliance: 'Legal & PDPA Audit',
    navComplianceSub: 'CCA Sec 26 & ISO 27001',

    // Status Card
    engineStatus: 'Engine Status',
    wormSeal: 'WORM Seal:',
    retention: 'Retention:',
    sigmaRules: 'Sigma Rules:',
    loaded: 'Loaded',
    days: 'Days',

    // Header & Actions
    btnSimulate: 'Simulate Attack (Red-Team)',
    btnScan: 'Full Security Scan',
    btnScanning: 'Scanning...',
    btnExport: 'Export Audit Evidence',
    btnDatasets: 'Real Datasets & Prod Clean',
    btnCyberRange: 'Enterprise Cyber Range',
    btnLogout: 'Sign Out',

    // View Titles & Subtitles
    radarTitle: 'Threat Detection Radar & Security HUD',
    radarSubtitle: 'Real-time threat detection with continuous dynamic risk scoring 0-100',
    explorerTitle: 'Forensic Event Query Explorer',
    explorerSubtitle: 'Search via Lucene / SQL syntax verified by SHA-256 Merkle Ledger',
    graphTitle: 'Correlated Threat Topology Graph',
    graphSubtitle: 'Analyze trajectories between attacker IPs, MITRE techniques, and target assets',
    rulesTitle: 'SigmaHQ Detection Rules Repository',
    rulesSubtitle: 'In-memory compilation into native Expression Trees for microsecond throughput',
    complianceTitle: 'Legal Compliance Audit & Custody Chain',
    complianceSubtitle: 'Guaranteed compliance with Thai CCA Sec 26, PDPA, and ISO/IEC 27001',

    // Metrics Cards
    metricTotalLogs: 'Total Ingested Telemetry',
    metricBlockedThreats: 'Threats Intercepted',
    metricActiveRules: 'Active Sigma Rules',
    metricPiiRedacted: 'PII Elements Masked (PDPA)',
    zeroTax: 'Zero Ingestion Tax',
    autoMitigated: 'Auto-Mitigated',
    openRules: 'Active Rules',

    // Chart
    chartTitle: 'Continuous Dynamic Risk Index (Real-time)',
    riskScore: 'Risk Score (0 - 100)',

    // Feed
    liveFeedTitle: 'Live Security Telemetry Feed',
    waitingTelemetry: 'Awaiting telemetry signals from RingBuffer Mesh...',
    simHint: 'Click "Real Datasets" or "Simulate Attack" to inject telemetry',

    // Login Portal
    loginPortalTitle: 'Security Operations Center (SOC) Console Login',
    loginPortalDesc: 'High-assurance sovereign role-based authentication portal',
    lblUsername: 'Username',
    lblPassword: 'Password',
    btnLogin: 'Authenticate Session',
    btnLoginning: 'Verifying Credentials...',
    quickDemoLogin: 'Quick Demo Access Roles:',
    roleAdmin: 'SecOps Director (Administrator)',
    roleAnalyst: 'Threat Analyst (SOC Analyst)',
    roleAuditor: 'Compliance Auditor (Legal Auditor)',
    complianceNote: 'FIPS 204 Quantum-Ready & Thai CCA Sec 26 Certified',

    // Dataset Manager Modal
    datasetModalTitle: 'Authentic Threat Datasets & Production Cleanup Suite',
    datasetModalDesc: 'Ingest authentic real-world cyber attack logs for demonstration, or execute complete wipe to clean Genesis state for customer delivery.',
    btnLoadDataset: 'Ingest Dataset',
    btnLoadingDataset: 'Ingesting...',
    btnPurgeProd: 'Purge All Test Telemetry (Reset for Production Delivery)',
    purgeConfirm: 'Are you sure you want to purge all test telemetry? All disk records will be wiped and Merkle root reset to pristine Genesis seal for customer delivery.',
    records: 'records',
  },
};
