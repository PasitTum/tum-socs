// Copyright (c) 2026 TUM Trust Security. All rights reserved.
// Licensed under the Apache License, Version 2.0. See LICENSE in the project root for license information.

/**
 * High-throughput asynchronous telemetry forwarder streaming multi-layer logs into TUM-OpenSIEM Core.
 */
export class TelemetryForwarder {
  constructor(siemBaseUrl = 'http://localhost:5000') {
    this.siemBaseUrl = siemBaseUrl;
    this.token = null;
    this.tokenExpires = 0;
    this.queue = [];
    this.isFlushing = false;
    this.stats = {
      forwarded: 0,
      threatsDetected: 0,
      piiMasked: 0,
      errors: 0,
    };
  }

  async authenticate() {
    try {
      const res = await fetch(`${this.siemBaseUrl}/api/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: 'admin', password: 'TumAdmin2026!#' }),
      });
      if (!res.ok) throw new Error(`Auth failed: ${res.statusText}`);
      const data = await res.json();
      this.token = data.token;
      this.tokenExpires = Date.now() + 3600 * 1000;
      return true;
    } catch (err) {
      this.stats.errors++;
      return false;
    }
  }

  async ensureAuth() {
    if (!this.token || Date.now() > this.tokenExpires - 60000) {
      await this.authenticate();
    }
  }

  enqueue(event) {
    this.queue.push(event);
    this.flush();
  }

  async flush() {
    if (this.isFlushing || this.queue.length === 0) return;
    this.isFlushing = true;

    try {
      await this.ensureAuth();
      while (this.queue.length > 0) {
        const event = this.queue.shift();
        try {
          const res = await fetch(`${this.siemBaseUrl}/api/logs/ingest`, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              Authorization: `Bearer ${this.token}`,
            },
            body: JSON.stringify(event),
          });

          if (res.ok) {
            const result = await res.json();
            this.stats.forwarded++;
            if (result.sigmaMatchesCount > 0) this.stats.threatsDetected += result.sigmaMatchesCount;
            if (result.piiRedacted > 0) this.stats.piiMasked += result.piiRedacted;
          } else {
            this.stats.errors++;
          }
        } catch {
          this.stats.errors++;
        }
      }
    } finally {
      this.isFlushing = false;
    }
  }
}
