// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

import http from 'node:http';

/**
 * Layer 3: Database & Honeypot Canary Vault (Port 5030)
 * Simulates SQL storage execution, honeytoken canary files, and Ransomware shadow copy triggers.
 */
export function startVaultService(port = 5030, forwarder = null) {
  const server = http.createServer(async (req, res) => {
    const startTime = Date.now();
    const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '127.0.0.1';
    let body = '';

    req.on('data', (chunk) => {
      body += chunk;
    });

    req.on('end', () => {
      let statusCode = 200;
      let responseData = { status: 'STORED', layer: 'Sovereign-Database-Vault' };
      let eventName = 'DB.LEDGER.QUERY';
      let isThreat = false;
      let severity = 'Information';

      if (req.url === '/health') {
        statusCode = 200;
        responseData = { status: 'healthy', layer: 'DB-Vault', port };
      } else if (req.url.startsWith('/api/v1/vault/query')) {
        eventName = 'DB.QUERY.EXECUTE';
        if (body.includes('UNION SELECT') || body.includes('INFORMATION_SCHEMA')) {
          isThreat = true;
          severity = 'Critical';
          eventName = 'DB.SQL_INJECTION.TRIPPED';
          responseData = { error: 'Malicious SQL AST caught by Sovereign Query Guard' };
        }
      } else if (req.url.startsWith('/api/v1/canary/shadow-copy')) {
        // Ransomware Canary Honeypot
        isThreat = true;
        severity = 'Critical';
        eventName = 'HOST.RANSOMWARE.SHADOW_COPY_DELETED';
        responseData = { alert: 'CANARY_TRIPPED_SYSTEM_LOCKED' };
      } else if (req.url.startsWith('/api/v1/system/lsass')) {
        // Mimikatz memory dump attempt
        isThreat = true;
        severity = 'Critical';
        eventName = 'HOST.CREDENTIAL_ACCESS.LSASS_DUMP';
        responseData = { alert: 'MEMORY_SCRAPING_INTERCEPTED' };
      }

      const duration = Date.now() - startTime;

      // Emit Layer 3 Database/Canary Telemetry to TUM-OpenSIEM Core
      if (forwarder) {
        forwarder.enqueue({
          eventName,
          category: isThreat ? 2 : 1,
          severity,
          applicationName: 'TUM-PostgreSQL-Vault-01',
          environment: 'Production',
          clientIp: clientIp.replace('::ffff:', ''),
          requestPath: req.url,
          httpMethod: req.method,
          statusCode,
          executionDurationMs: duration,
          payloadSanitized: body || `VAULT_OP=${eventName} PATH=${req.url}`,
        });
      }

      res.writeHead(statusCode, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(responseData));
    });
  });

  return new Promise((resolve) => {
    server.listen(port, () => {
      resolve(server);
    });
  });
}
