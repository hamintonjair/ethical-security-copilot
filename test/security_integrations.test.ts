import test from "node:test";
import assert from "node:assert/strict";
import { createHmac } from "node:crypto";
import { Store } from "../src/store.js";

test("fuente de eventos: firma HMAC, deduplicación, redacción y auditoría", async () => {
  const store = await Store.open("memory", Buffer.alloc(32, 7));
  try {
    const source = await store.createSecurityIntegration({ name: "EDR de prueba", provider: "generic" }, "admin");
    assert.equal(typeof source.secret, "string");
    assert.equal((await store.listSecurityIntegrations())[0].secretLast4, source.secret.slice(-4));
    assert.equal(JSON.stringify(await store.listSecurityIntegrations()).includes(source.secret), false);

    const timestamp = String(Math.floor(Date.now() / 1000));
    const event = {
      eventId: "external-1", observedAt: new Date().toISOString(), severity: "high", category: "suspicious_login",
      title: "Inicio sospechoso", asset: "persona@example.com", summary: "token: abcdefghijklmnop",
      data: { apiKey: "sensitive", location: "Bogota" },
    };
    const raw = JSON.stringify(event);
    const signature = "sha256=" + createHmac("sha256", source.secret).update(`${timestamp}.${raw}`).digest("hex");
    assert.deepEqual(await store.ingestSecurityEvent(source.id, timestamp, signature, raw, event), { status: "accepted", eventId: (await store.listSecurityEvents())[0].id });
    assert.equal((await store.ingestSecurityEvent(source.id, timestamp, signature, raw, event)).status, "duplicate");
    const stored = (await store.listSecurityEvents())[0];
    assert.equal(stored.asset, "[REDACTED:EMAIL]");
    assert.equal(stored.summary.includes("abcdefghijklmnop"), false);
    assert.equal((await store.verifyAuditChain()).ok, true);

    assert.equal((await store.ingestSecurityEvent(source.id, timestamp, "sha256=" + "0".repeat(64), raw, event)).status, "invalid_signature");
    const old = String(Math.floor(Date.now() / 1000) - 600);
    const oldSig = "sha256=" + createHmac("sha256", source.secret).update(`${old}.${raw}`).digest("hex");
    assert.equal((await store.ingestSecurityEvent(source.id, old, oldSig, raw, event)).status, "invalid_timestamp");
  } finally { await store.close(); }
});
