import type { ParsedCapture, SignalFeatureSummary } from "./types";

function round(value: number, digits = 3) {
  return Number(value.toFixed(digits));
}

function shannonEntropy(values: string[]) {
  if (!values.length) return 0;
  const counts = new Map<string, number>();
  values.forEach((value) => counts.set(value, (counts.get(value) ?? 0) + 1));
  let entropy = 0;
  for (const count of counts.values()) {
    const probability = count / values.length;
    entropy -= probability * Math.log2(probability);
  }
  return entropy;
}

function normalizedEntropy(values: string[]) {
  if (values.length <= 1) return 0;
  const unique = new Set(values).size;
  if (unique <= 1) return 0;
  return shannonEntropy(values) / Math.log2(unique);
}

function frequencyBandLabel(frequency?: number) {
  if (!frequency) return "No frequency field";
  if (frequency >= 300_000_000 && frequency <= 320_000_000) return "315 MHz ISM/security band";
  if (frequency >= 390_000_000 && frequency <= 391_000_000) return "390 MHz security/remote band";
  if (frequency >= 433_000_000 && frequency <= 435_000_000) return "433 MHz ISM sensor/remote band";
  if (frequency >= 868_000_000 && frequency <= 869_000_000) return "868 MHz ISM band";
  if (frequency >= 902_000_000 && frequency <= 928_000_000) return "915 MHz ISM band";
  return `${(frequency / 1_000_000).toFixed(3)} MHz`;
}

function rawNumericValues(parsed: ParsedCapture) {
  return parsed.fieldEntries
    .filter((entry) => /raw|data/i.test(entry.key))
    .flatMap((entry) => entry.value.match(/-?\d+/g) ?? [])
    .map((value) => Number.parseInt(value, 10))
    .filter((value) => Number.isFinite(value));
}

function hexBytes(parsed: ParsedCapture) {
  return parsed.fieldEntries
    .filter((entry) => /key|data|raw|uid|address|command|credential/i.test(entry.key))
    .flatMap((entry) => entry.value.match(/[a-fA-F0-9]{2}/g) ?? [])
    .map((value) => value.toUpperCase());
}

function timingSummary(values: number[]): SignalFeatureSummary["timing"] {
  if (!values.length) return undefined;
  const min = Math.min(...values);
  const max = Math.max(...values);
  const average = values.reduce((sum, value) => sum + value, 0) / values.length;
  const variance = values.reduce((sum, value) => sum + (value - average) ** 2, 0) / values.length;
  const signs = values.map((value) => Math.sign(value)).filter((value) => value !== 0);
  const signChanges = signs.slice(1).filter((sign, index) => sign !== signs[index]).length;

  return {
    count: values.length,
    min,
    max,
    average: round(average, 1),
    standardDeviation: round(Math.sqrt(variance), 1),
    uniqueRatio: round(new Set(values.map((value) => Math.round(Math.abs(value) / 25) * 25)).size / values.length),
    signAlternationRatio: signs.length > 1 ? round(signChanges / (signs.length - 1)) : 0,
  };
}

export function extractSignalFeatures(parsed: ParsedCapture): SignalFeatureSummary {
  const rawValues = rawNumericValues(parsed);
  const bytes = hexBytes(parsed);
  const fieldText = parsed.fieldEntries.map((entry) => `${entry.key}:${entry.value}`).join("|");
  const rawBuckets = rawValues.map((value) => String(Math.round(Math.abs(value) / 50) * 50));

  return {
    primaryFrequencyHz: parsed.frequencies[0],
    primaryFrequencyBand: frequencyBandLabel(parsed.frequencies[0]),
    entropy: {
      fieldShannonBitsPerChar: round(shannonEntropy(Array.from(fieldText)), 2),
      rawValueShannonBits: round(shannonEntropy(rawBuckets), 2),
      rawValueNormalizedEntropy: round(normalizedEntropy(rawBuckets), 3),
      hexByteShannonBits: round(shannonEntropy(bytes), 2),
      hexByteNormalizedEntropy: round(normalizedEntropy(bytes), 3),
      rawTokenCount: rawValues.length,
      hexByteCount: bytes.length,
    },
    timing: timingSummary(rawValues),
  };
}
