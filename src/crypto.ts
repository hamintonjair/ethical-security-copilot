import { createHash, createHmac, randomBytes, timingSafeEqual } from "node:crypto";

/** JSON canónico: claves ordenadas, sin espacios. Base de hashes y firmas. */
export function canonical(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  const o = value as Record<string, unknown>;
  return `{${Object.keys(o).sort().filter(k => o[k] !== undefined).map(k => `${JSON.stringify(k)}:${canonical(o[k])}`).join(",")}}`;
}

export const sha256 = (s: string) => createHash("sha256").update(s).digest("hex");

export function sign(key: Buffer, hash: string): string {
  return createHmac("sha256", key).update(hash).digest("hex");
}

export function verifySignature(key: Buffer, hash: string, signature: string): boolean {
  const expected = Buffer.from(sign(key, hash), "hex");
  const got = Buffer.from(signature, "hex");
  return expected.length === got.length && timingSafeEqual(expected, got);
}

export const newToken = () => randomBytes(32).toString("hex");
