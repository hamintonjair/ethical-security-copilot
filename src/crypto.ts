import { createHash, createHmac, randomBytes, timingSafeEqual, createCipheriv, createDecipheriv } from "node:crypto";

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

/** Cifra un secreto (p. ej. una llave de API de terceros) con AES-256-GCM. `key` debe tener 32 bytes. */
export function encryptSecret(plain: string, key: Buffer): string {
  const iv = randomBytes(12);
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const ct = Buffer.concat([cipher.update(plain, "utf8"), cipher.final()]);
  return `${iv.toString("hex")}:${cipher.getAuthTag().toString("hex")}:${ct.toString("hex")}`;
}

/** Inverso de encryptSecret. Lanza si el formato o la autenticación no son válidos. */
export function decryptSecret(enc: string, key: Buffer): string {
  const [ivHex, tagHex, ctHex] = enc.split(":");
  if (!ivHex || !tagHex || !ctHex) throw new Error("formato de secreto cifrado inválido");
  const decipher = createDecipheriv("aes-256-gcm", key, Buffer.from(ivHex, "hex"));
  decipher.setAuthTag(Buffer.from(tagHex, "hex"));
  return Buffer.concat([decipher.update(Buffer.from(ctHex, "hex")), decipher.final()]).toString("utf8");
}
