// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

import http from 'node:http';

/**
 * Layer 2: Core Banking & Transaction Business API (Port 5020)
 * Processes transactions, KYC profiles with Thai National IDs & Credit Cards, emitting business audit telemetry.
 */
export function startBankingService(port = 5020, forwarder = null) {
  const server = http.createServer(async (req, res) => {
    const startTime = Date.now();
    const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '127.0.0.1';
    let body = '';

    req.on('data', (chunk) => {
      body += chunk;
    });

    req.on('end', () => {
      let statusCode = 200;
      let responseData = { status: 'SUCCESS', service: 'CoreBanking-Engine-v2' };
      let eventName = 'BANKING.TRANSACTION.PROCESSED';
      let isThreat = false;

      if (req.url === '/health') {
        statusCode = 200;
        responseData = { status: 'healthy', layer: 'CoreBanking-API', port };
      } else if (req.url.startsWith('/api/v1/auth/login')) {
        eventName = 'BANKING.USER.AUTHENTICATE';
        if (body.includes('UNION SELECT') || body.includes("' OR '1'='1")) {
          isThreat = true;
          eventName = 'BANKING.SQLI.ATTEMPT';
          responseData = { error: 'Authentication rejected by security policy' };
        } else {
          responseData = { authenticated: true, session: 'SEC-SESS-9921' };
        }
      } else if (req.url.startsWith('/api/v1/payments/transfer')) {
        eventName = 'BANKING.PAYMENT.TRANSFER';
        responseData = { transferId: 'TXN-2026-99881', clearance: 'CLEARED' };
      } else if (req.url.startsWith('/api/v1/mcp/tool')) {
        eventName = 'AI.AGENT.MCP_EXECUTION';
        if (body.includes('Ignore previous') || body.includes('system memory')) {
          isThreat = true;
          eventName = 'AI.AGENT.PROMPT_INJECTION';
        }
      }

      const duration = Date.now() - startTime;

      // Emit Layer 2 Application Telemetry to TUM-OpenSIEM Core
      if (forwarder) {
        forwarder.enqueue({
          eventName,
          category: isThreat ? 2 : 1,
          severity: isThreat ? 'Critical' : 'Information',
          applicationName: 'TUM-Banking-Core-API',
          environment: 'Production',
          clientIp: clientIp.replace('::ffff:', ''),
          requestPath: req.url,
          httpMethod: req.method,
          statusCode,
          executionDurationMs: duration,
          payloadSanitized: body || `ACTION=${eventName} URI=${req.url}`,
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
