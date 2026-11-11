/** Redacción por defecto: se aplica en la ingesta de evidencia y en los logs, no solo en el reporte. */
const RULES: [RegExp, string][] = [
  [/-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g, "[REDACTED:PRIVATE_KEY]"],
  [/\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g, "[REDACTED:JWT]"],
  [/\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g, "[REDACTED:AWS_KEY]"],
  [/\b(authorization|bearer)\s*[:=]?\s*[A-Za-z0-9._~+\/=-]{12,}/gi, "$1 [REDACTED:TOKEN]"],
  [/\b(password|passwd|pwd|secret|api[_-]?key|token)\b(\s*["']?\s*[:=]\s*)["']?[^\s"',;]+["']?/gi, "$1$2[REDACTED]"],
  [/\b(?:\d[ -]?){13,19}\b/g, "[REDACTED:CARD]"],
  [/\b\d{3}-\d{2}-\d{4}\b/g, "[REDACTED:SSN]"],
  [/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/g, "[REDACTED:EMAIL]"],
];

export function redact(input: string, maxLen = 8000): string {
  let out = input;
  for (const [re, rep] of RULES) out = out.replace(re, rep);
  return out.length > maxLen ? out.slice(0, maxLen) + "…[TRUNCATED]" : out;
}
