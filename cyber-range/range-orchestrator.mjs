// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

import http from 'node:http';
import { TelemetryForwarder } from './telemetry-forwarder.mjs';
import { startGatewayService } from './gateway-service.mjs';
import { startBankingService } from './banking-service.mjs';
import { startVaultService } from './vault-service.mjs';
import { AdversaryBot } from './adversary-bot.mjs';

const CONTROL_PORT = 5040;
const GATEWAY_PORT = 5010;
const BANKING_PORT = 5020;
const VAULT_PORT = 5030;
const SIEM_URL = process.env.SIEM_URL || 'http://localhost:5000';

async function main() {
  console.log('\x1b[36m%s\x1b[0m', '==============================================================================');
  console.log('\x1b[36m%s\x1b[0m', '  TUM-OpenSIEM Sovereign Multi-Layer Cyber Range Environment');
  console.log('\x1b[36m%s\x1b[0m', '==============================================================================\n');

  // 1. Initialize Telemetry Forwarder
  console.log('\x1b[33m%s\x1b[0m', '>>> [1/5] Initializing Telemetry Forwarder Agent to ' + SIEM_URL + '...');
  const forwarder = new TelemetryForwarder(SIEM_URL);
  const authed = await forwarder.authenticate();
  if (authed) {
    console.log('\x1b[32m%s\x1b[0m', '  ✔ Connected to TUM-OpenSIEM Core. HMAC-SHA256 Token Acquired.');
  } else {
    console.log('\x1b[31m%s\x1b[0m', '  ✖ Warning: TUM-OpenSIEM Core offline on port 5000. Will retry automatically.');
  }

  // 2. Start Layer 1: Gateway
  console.log('\x1b[33m%s\x1b[0m', '>>> [2/5] Booting Layer 1: Edge Web Gateway on port ' + GATEWAY_PORT + '...');
  await startGatewayService(GATEWAY_PORT, forwarder);
  console.log('\x1b[32m%s\x1b[0m', '  ✔ Layer 1 (Edge Gateway) Active on http://localhost:' + GATEWAY_PORT);

  // 3. Start Layer 2: Core Banking API
  console.log('\x1b[33m%s\x1b[0m', '>>> [3/5] Booting Layer 2: Core Banking Business API on port ' + BANKING_PORT + '...');
  await startBankingService(BANKING_PORT, forwarder);
  console.log('\x1b[32m%s\x1b[0m', '  ✔ Layer 2 (Banking Core) Active on http://localhost:' + BANKING_PORT);

  // 4. Start Layer 3: Database & Vault
  console.log('\x1b[33m%s\x1b[0m', '>>> [4/5] Booting Layer 3: Sovereign Database Vault on port ' + VAULT_PORT + '...');
  await startVaultService(VAULT_PORT, forwarder);
  console.log('\x1b[32m%s\x1b[0m', '  ✔ Layer 3 (Database Vault) Active on http://localhost:' + VAULT_PORT);

  // 5. Initialize Layer 4: Adversary Bot
  const adversary = new AdversaryBot(
    `http://localhost:${GATEWAY_PORT}`,
    `http://localhost:${BANKING_PORT}`,
    `http://localhost:${VAULT_PORT}`
  );

  // 6. Start Cyber Range Controller API (Port 5040)
  const controlServer = http.createServer(async (req, res) => {
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

    if (req.method === 'OPTIONS') {
      res.writeHead(204);
      res.end();
      return;
    }

    if (req.url === '/range/status' && req.method === 'GET') {
      const status = {
        orchestrator: 'TUM Sovereign Cyber Range v2.0',
        active: true,
        layers: {
          gateway: { port: GATEWAY_PORT, status: 'ONLINE', role: 'Edge Reverse Proxy & Load Balancer' },
          banking: { port: BANKING_PORT, status: 'ONLINE', role: 'Core Banking & KYC Business API' },
          vault: { port: VAULT_PORT, status: 'ONLINE', role: 'Sovereign Database & Canary Vault' },
          adversary: { active: adversary.isRunning, role: 'Autonomous Threat Actor & Botnet' },
        },
        telemetryStats: forwarder.stats,
        timestampUtc: new Date().toISOString(),
      };
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(status));
      return;
    }

    if (req.url === '/range/attack' && req.method === 'POST') {
      const attacks = await adversary.executeAptAttackWave();
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ success: true, message: '5-Stage APT Attack Campaign Executed', details: attacks }));
      return;
    }

    if (req.url === '/range/traffic' && req.method === 'POST') {
      const ops = [];
      for (let i = 0; i < 5; i++) {
        ops.push(await adversary.sendLegitimateTransaction());
      }
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ success: true, message: '5 Legitimate Business Transactions Injected', ops }));
      return;
    }

    if (req.url === '/range/continuous/start' && req.method === 'POST') {
      adversary.startContinuousSimulation(2500, (tick) => {
        if (tick.type === 'ATTACK_WAVE') {
          console.log('\x1b[31m%s\x1b[0m', `[CYBER-RANGE ALERT] Injected ${tick.count} Attack Vectors into Layer 1 & 2!`);
        } else {
          console.log('\x1b[32m%s\x1b[0m', `[CYBER-RANGE] Legitimate Transaction Processed for Citizen ID: ${tick.details?.id}`);
        }
      });
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ success: true, message: 'Continuous Live Cyber Range Loop Started (Every 2.5s)' }));
      return;
    }

    if (req.url === '/range/continuous/stop' && req.method === 'POST') {
      adversary.stopContinuousSimulation();
      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ success: true, message: 'Continuous Simulation Stopped' }));
      return;
    }

    res.writeHead(404, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify({ error: 'Endpoint not found' }));
  });

  controlServer.listen(CONTROL_PORT, () => {
    console.log('\x1b[32m%s\x1b[0m', '  ✔ Cyber Range Control API Active on http://localhost:' + CONTROL_PORT + '/range/status');
    console.log('\x1b[36m%s\x1b[0m', '\n==============================================================================');
    console.log('\x1b[32m%s\x1b[0m', '  ALL 4 CYBER RANGE LAYERS ARE RUNNING & STREAMING TO TUM-OPENSIEM!');
    console.log('\x1b[36m%s\x1b[0m', '==============================================================================\n');
  });
}

main().catch(console.error);
