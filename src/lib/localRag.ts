import type { PhotoContext, SignalFingerprint } from "./fingerprintEngine";
import type { AnalysisResult } from "./types";

export interface RagDocument {
  id: string;
  title: string;
  body: string;
  tags: string[];
}

export interface RagResult {
  document: RagDocument;
  score: number;
  snippet: string;
}

export const localKnowledgeBase: RagDocument[] = [
  {
    id: "safe-boundaries",
    title: "SmolSignal safety boundaries",
    tags: ["safety", "blocked", "replay", "access", "automotive"],
    body:
      "SmolSignal blocks car key cloning, access badge/card cloning, bypass instructions for doors, gates, alarms, or vehicles, replay/transmit workflows for unknown or security-like RF captures, and generic hack-this-device flows. Blocked captures can still receive high-level education and benign documentation advice.",
  },
  {
    id: "consumer-ir",
    title: "Consumer infrared remotes",
    tags: ["ir", "infrared", "remote", "nec", "samsung", "sony"],
    body:
      "Consumer IR remotes usually contain protocol, address, and command fields. Safe workflows include organizing buttons, creating replacement remote files for devices you own, and testing one button at a time. IR generation should stay limited to consumer devices such as TVs, fans, AC units, projectors, speakers, and LED strips.",
  },
  {
    id: "subghz-passive",
    title: "Passive Sub-GHz sensor handling",
    tags: ["subghz", "rf", "sensor", "weather", "telemetry", "433"],
    body:
      "Sub-GHz captures can represent weather sensors, telemetry, remotes, alarms, garage/gate systems, or vehicle systems. Unknown RF should stay passive: label the source, record frequency and protocol hints, compare against public references, and avoid replay or transmit steps unless working with a harmless owned lab device.",
  },
  {
    id: "nfc-rfid",
    title: "NFC/RFID credential caution",
    tags: ["nfc", "rfid", "badge", "mifare", "hid", "em4100", "ibutton"],
    body:
      "NFC, RFID, and iButton files may represent credentials or access tokens. Safe workflows are read-only identification, ownership documentation, and high-level education. SmolSignal does not help copy credentials, recover keys, bypass access, or clone badges.",
  },
  {
    id: "gpio-lab",
    title: "GPIO lab safety",
    tags: ["gpio", "uart", "i2c", "spi", "voltage", "wiring"],
    body:
      "GPIO work should begin with voltage and ground checks. Confirm pin direction, never connect unknown voltages directly, and use owned lab hardware. Safe workflows include wiring checklists, sensor/module identification, and passive serial observation with permission.",
  },
  {
    id: "web-serial",
    title: "Web Serial Flipper connection",
    tags: ["web serial", "usb", "flipper", "chrome", "connection"],
    body:
      "Web Serial works only in supported Chromium-based browsers and secure contexts. It can request a USB serial port and open a connection, but users should still use official Flipper tooling for firmware updates and sensitive operations. SmolSignal's connection panel is for safe import/export assistance and connection status.",
  },
];

function tokenize(text: string) {
  return text
    .toLowerCase()
    .replace(/[^a-z0-9.+-]+/g, " ")
    .split(/\s+/)
    .filter((token) => token.length >= 2);
}

function vector(tokens: string[]) {
  const result = new Map<string, number>();
  tokens.forEach((token) => result.set(token, (result.get(token) ?? 0) + 1));
  return result;
}

function cosine(a: Map<string, number>, b: Map<string, number>) {
  let dot = 0;
  let aNorm = 0;
  let bNorm = 0;
  for (const value of a.values()) aNorm += value * value;
  for (const value of b.values()) bNorm += value * value;
  for (const [key, value] of a) dot += value * (b.get(key) ?? 0);
  if (!aNorm || !bNorm) return 0;
  return dot / Math.sqrt(aNorm * bNorm);
}

function snippet(body: string, queryTokens: string[]) {
  const sentences = body.split(/(?<=[.!?])\s+/);
  const best = sentences
    .map((sentence) => ({ sentence, score: tokenize(sentence).filter((token) => queryTokens.includes(token)).length }))
    .sort((a, b) => b.score - a.score)[0];
  return best?.sentence ?? body.slice(0, 180);
}

export function buildRagQuery(analysis: AnalysisResult, fingerprint: SignalFingerprint, userGoal = "", photo?: PhotoContext) {
  return [
    userGoal,
    analysis.summary,
    analysis.plainEnglish,
    fingerprint.label,
    fingerprint.category,
    fingerprint.features.frequencyBand,
    fingerprint.features.protocols.join(" "),
    photo?.notes ?? "",
  ].join(" ");
}

export function searchLocalKnowledge(query: string, limit = 3): RagResult[] {
  const queryTokens = tokenize(query);
  const queryVector = vector(queryTokens);
  return localKnowledgeBase
    .map((document) => {
      const documentText = `${document.title} ${document.tags.join(" ")} ${document.body}`;
      const score = cosine(queryVector, vector(tokenize(documentText)));
      return { document, score: Number(score.toFixed(3)), snippet: snippet(document.body, queryTokens) };
    })
    .filter((result) => result.score > 0)
    .sort((a, b) => b.score - a.score)
    .slice(0, limit);
}
