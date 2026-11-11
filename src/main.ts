#!/usr/bin/env node
// Servidor MCP por stdio. El ROL lo fija quien lanza el proceso (no el cliente/LLM).
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { Store } from "./store.js";
import { createServer } from "./server.js";
import { Role } from "./schemas.js";

const key = process.env.ESC_SIGNING_KEY;
if (!key || key.length < 32) { console.error("ESC_SIGNING_KEY (mín. 32 caracteres) es obligatorio. No hay clave por defecto."); process.exit(1); }
const role = Role.parse(process.env.ESC_ROLE ?? "agent");
const store = new Store(process.env.ESC_DB ?? "esc.db", Buffer.from(key));
const { server } = createServer({ store, role, actor: process.env.ESC_ACTOR ?? `mcp-${role}` });
await server.connect(new StdioServerTransport());
console.error(`Ethical Security Copilot listo (rol: ${role})`);
