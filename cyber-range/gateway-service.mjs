// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

import http from 'node:http';

/**
 * Layer 1: Edge Reverse Proxy & API Gateway (Port 5010)
 * Handles incoming Internet traffic, SSL offload simulation, and emits Edge access logs.
 */
export function startGatewayService(port = 5010, forwarder = null) {
  const server = http.createServer(async (req, res) => {
    const startTime = Date.now();
    const clientIp = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '127.0.0.1';
    let body = '';

    req.on('data', (chunk) => {
      body += chunk;
    });

    req.on('end', async () => {
      let statusCode = 200;
      let responseData = { status: 'OK', gateway: 'TUM-Edge-Proxy-v1', path: req.url };

      // Route simulation
      if (req.url === '/health') {
        statusCode = 200;
        responseData = { status: 'healthy', layer: 'Edge-Gateway', port };
      } else if (req.url.startsWith('/api/v1/checkout') || req.url.startsWith('/api/v1/auth')) {
        statusCode = 200;
        responseData = { status: 'forwarded_to_banking_core', latencyMs: 1.4 };
      } else if (req.url.includes('SELECT') || req.url.includes('..') || req.url.includes('jndi')) {
        // Suspicious exploit attempt routed through gateway
        statusCode = 200;
        responseData = { status: 'inspected_and_relayed', threatFlag: true };
      }

      const duration = Date.now() - startTime;

      // Emit Layer 1 Telemetry to TUM-OpenSIEM Core
      if (forwarder) {
        forwarder.enqueue({
          eventName: 'EDGE.GATEWAY.ACCESS',
          category: statusCode >= 400 ? 2 : 1,
          severity: statusCode >= 400 ? 'Warning' : 'Information',
          applicationName: 'TUM-Edge-Gateway-01',
          environment: 'Production',
          clientIp: clientIp.replace('::ffff:', ''),
          requestPath: req.url,
          httpMethod: req.method,
          statusCode,
          executionDurationMs: duration,
          payloadSanitized: body || `METHOD=${req.method} PATH=${req.url} UA=${req.headers['user-agent'] || 'curl'}`,
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
