import type { AnalysisResult, SafetyLevel } from "./types";
import { categoryLabel, matchProtocolKnowledge, type DeviceCategory, type ProtocolMatch } from "./protocolDatabase";

export interface PhotoContext {
  fileName: string;
  width: number;
  height: number;
  notes: string;
}

export interface RawPulseStats {
  count: number;
  min: number;
  max: number;
  average: number;
}

export interface SignalFingerprint {
  signature: string;
  label: string;
  category: DeviceCategory;
  confidence: number;
  safety: SafetyLevel;
  passiveMode: boolean;
  evidence: string[];
  warnings: string[];
  features: {
    domain: string;
    frequencyBand: string;
    protocols: string[];
    modulation: string;
    rawPulseStats?: RawPulseStats;
    fieldEntropy: number;
    photoContext?: string;
  };
  matches: ProtocolMatch[];
}

function hashText(text: string) {
  let hash = 2_166_136_261;
  for (let index = 0; index < text.length; index += 1) {
    hash ^= text.charCodeAt(index);
    hash = Math.imul(hash, 16_777_619);
  }
  return (hash >>> 0).toString(16).padStart(8, "0");
}

function describeFrequencyBand(frequencies: number[]) {
  const frequency = frequencies[0];
  if (!frequency) return "No frequency field";
  if (frequency >= 300_000_000 && frequency <= 320_000_000) return "315 MHz ISM/security band";
  if (frequency >= 390_000_000 && frequency <= 391_000_000) return "390 MHz security/remote band";
  if (frequency >= 433_000_000 && frequency <= 435_000_000) return "433 MHz ISM sensor/remote band";
  if (frequency >= 868_000_000 && frequency <= 869_000_000) return "868 MHz ISM band";
  if (frequency >= 902_000_000 && frequency <= 928_000_000) return "915 MHz ISM band";
  return `${(frequency / 1_000_000).toFixed(3)} MHz`;
}

function getField(analysis: AnalysisResult, key: string) {
  return analysis.parsed.fields[key]?.[0] ?? "";
}

function extractRawNumbers(analysis: AnalysisResult) {
  return analysis.parsed.fieldEntries
    .filter((entry) => /raw|data/i.test(entry.key))
    .flatMap((entry) => entry.value.match(/-?\d+/g) ?? [])
    .map((value) => Number.parseInt(value, 10))
    .filter((value) => Number.isFinite(value));
}

function pulseStats(values: number[]): RawPulseStats | undefined {
  if (!values.length) return undefined;
  const min = Math.min(...values);
  const max = Math.max(...values);
  const average = values.reduce((sum, value) => sum + value, 0) / values.length;
  return { count: values.length, min, max, average: Number(average.toFixed(1)) };
}

function entropyForText(text: string) {
  if (!text) return 0;
  const counts = new Map<string, number>();
  for (const character of text) counts.set(character, (counts.get(character) ?? 0) + 1);
  let entropy = 0;
  for (const count of counts.values()) {
    const probability = count / text.length;
    entropy -= probability * Math.log2(probability);
  }
  return Number(entropy.toFixed(2));
}

function chooseCategory(analysis: AnalysisResult, matches: ProtocolMatch[]): DeviceCategory {
  const blocked = matches.find((match) => match.entry.safety === "blocked" && match.score >= 0.4);
  if (blocked) return blocked.entry.category;

  const strongest = matches[0];
  if (strongest?.score >= 0.3) return strongest.entry.category;

  if (analysis.parsed.domain === "infrared") return "consumer_ir";
  if (analysis.parsed.domain === "subghz") return "unknown_rf";
  if (analysis.parsed.domain === "gpio") return "gpio_lab";
  if (analysis.parsed.domain === "nfc" || analysis.parsed.domain === "rfid" || analysis.parsed.domain === "ibutton") {
    return analysis.level === "blocked" ? "access_control" : "credential_tag";
  }
  return "unknown";
}

function confidenceFor(analysis: AnalysisResult, matches: ProtocolMatch[], category: DeviceCategory) {
  const topScore = matches[0]?.score ?? 0;
  let confidence = 0.24 + topScore;
  if (analysis.parsed.protocols.length) confidence += 0.08;
  if (analysis.parsed.frequencies.length) confidence += 0.06;
  if (analysis.parsed.fieldEntries.length >= 4) confidence += 0.05;
  if (category === "unknown" || category === "unknown_rf") confidence = Math.min(confidence, 0.58);
  return Math.min(0.96, Number(confidence.toFixed(2)));
}

function safetyFor(analysis: AnalysisResult, matches: ProtocolMatch[]): SafetyLevel {
  if (analysis.level === "blocked") return "blocked";
  if (matches.some((match) => match.entry.safety === "blocked" && match.score >= 0.4)) return "blocked";
  if (analysis.level === "caution" || matches.some((match) => match.entry.safety === "caution")) return "caution";
  return analysis.level;
}

export function fingerprintAnalysis(analysis: AnalysisResult, userGoal = "", photo?: PhotoContext): SignalFingerprint {
  const matches = matchProtocolKnowledge(analysis.parsed, userGoal, photo?.notes ?? "");
  const category = chooseCategory(analysis, matches);
  const safety = safetyFor(analysis, matches);
  const confidence = confidenceFor(analysis, matches, category);
  const stats = analysis.signalFeatures.timing
    ? {
        count: analysis.signalFeatures.timing.count,
        min: analysis.signalFeatures.timing.min,
        max: analysis.signalFeatures.timing.max,
        average: analysis.signalFeatures.timing.average,
      }
    : undefined;
  const modulation = getField(analysis, "preset") || getField(analysis, "modulation") || "Not specified";
  const frequencyBand = analysis.signalFeatures.primaryFrequencyBand;
  const signatureSeed = [
    analysis.parsed.domain,
    analysis.parsed.fileType,
    analysis.parsed.frequencies.map((frequency) => Math.round(frequency / 1000)).join(","),
    analysis.parsed.protocols.slice().sort().join(","),
    analysis.signalFeatures.entropy.rawValueNormalizedEntropy,
    analysis.signalFeatures.entropy.hexByteNormalizedEntropy,
    analysis.parsed.fieldEntries.length,
  ].join("|");

  const evidence = [
    `Parsed as ${analysis.parsed.domain}.`,
    `Safety gate decision: ${analysis.decision}.`,
    ...matches.slice(0, 3).flatMap((match) => match.evidence),
  ];

  if (stats) evidence.push(`Raw/data fields contain ${stats.count} numeric timing/value tokens.`);
  evidence.push(
    `Gate entropy: field ${analysis.signalFeatures.entropy.fieldShannonBitsPerChar} bits/char, raw ${analysis.signalFeatures.entropy.rawValueNormalizedEntropy}, hex ${analysis.signalFeatures.entropy.hexByteNormalizedEntropy}.`,
  );
  if (photo?.fileName) evidence.push(`Photo context attached: ${photo.fileName} (${photo.width}x${photo.height}).`);

  const warnings = [
    ...(analysis.lab?.enabled ? ["Authorized Lab Mode is active; keep all work inside the documented owned/simulated scope."] : []),
    ...(analysis.decision !== "allow" ? ["Keep this workflow passive/explanation-only unless the source is clearly safe and authorized."] : []),
    ...(safety === "blocked" ? ["Do not replay, clone, transmit, unlock, or bypass this signal."] : []),
  ];

  return {
    signature: `smol-${hashText(signatureSeed)}`,
    label: categoryLabel(category),
    category,
    confidence,
    safety,
    passiveMode: category === "passive_sensor" || category === "unknown_rf" || analysis.decision === "explain-only",
    evidence: Array.from(new Set(evidence)).slice(0, 10),
    warnings: Array.from(new Set(warnings)),
    features: {
      domain: analysis.parsed.domain,
      frequencyBand,
      protocols: analysis.parsed.protocols,
      modulation,
      rawPulseStats: stats,
      fieldEntropy: analysis.signalFeatures.entropy.fieldShannonBitsPerChar,
      photoContext: photo ? `${photo.fileName}; ${photo.notes || "no notes"}` : undefined,
    },
    matches,
  };
}
