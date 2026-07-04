import type { FieldEntry, ParsedCapture, SignalDomain } from "./types";

const FIELD_LINE = /^\s*([^:#][^:]{1,80}):\s*(.*?)\s*$/;

function normalizeKey(key: string) {
  return key.trim().toLowerCase().replace(/\s+/g, "_");
}

function extensionOf(fileName?: string) {
  const ext = fileName?.split(".").pop()?.toLowerCase();
  return ext && ext !== fileName ? ext : undefined;
}

function unique(values: string[]) {
  return Array.from(new Set(values.filter(Boolean)));
}

function getFirst(fields: Record<string, string[]>, key: string) {
  return fields[normalizeKey(key)]?.[0] ?? "";
}

function inferDomain(
  text: string,
  fields: Record<string, string[]>,
  fileName?: string,
): SignalDomain {
  const ext = extensionOf(fileName);
  const fileType = getFirst(fields, "filetype").toLowerCase();
  const lower = text.toLowerCase();

  if (ext === "ir" || fileType.includes("ir signal") || lower.includes("filetype: ir")) {
    return "infrared";
  }
  if (ext === "sub" || fileType.includes("subghz") || lower.includes("frequency:")) {
    return "subghz";
  }
  if (ext === "nfc" || fileType.includes("nfc")) {
    return "nfc";
  }
  if (ext === "rfid" || fileType.includes("rfid") || lower.includes("em4100")) {
    return "rfid";
  }
  if (ext === "ibtn" || ext === "ibutton" || fileType.includes("ibutton")) {
    return "ibutton";
  }
  if (ext === "ble" || fileType.includes("ble") || fileType.includes("bluetooth")) {
    return "ble";
  }
  if (ext === "gpio" || fileType.includes("gpio")) {
    return "gpio";
  }

  return "unknown";
}

function extractFrequencies(fields: Record<string, string[]>) {
  const candidates = [
    ...(fields.frequency ?? []),
    ...(fields.frequency_analyzer ?? []),
    ...(fields.hopper_frequency ?? []),
  ];

  return candidates
    .map((value) => Number.parseInt(value.replace(/[^0-9]/g, ""), 10))
    .filter((value) => Number.isFinite(value) && value > 0);
}

function extractProtocols(fields: Record<string, string[]>, text: string) {
  const knownProtocolHints = [
    "NEC",
    "NECext",
    "Samsung32",
    "RC5",
    "RC6",
    "Sony",
    "SIRC",
    "RAW",
    "Princeton",
    "KeeLoq",
    "HCS",
    "Security+",
    "CAME",
    "NICE",
    "Hormann",
    "Mifare Classic",
    "Mifare Ultralight",
    "NTAG",
    "EM4100",
    "HID Prox",
  ];

  const fromFields = [
    ...(fields.protocol ?? []),
    ...(fields.type ?? []),
    ...(fields.card_type ?? []),
    ...(fields.device_type ?? []),
  ];

  const lower = text.toLowerCase();
  const fromHints = knownProtocolHints.filter((hint) => lower.includes(hint.toLowerCase()));

  return unique([...fromFields, ...fromHints]);
}

export function parseFlipperCapture(content: string, fileName?: string): ParsedCapture {
  const clean = content.replace(/^\uFEFF/, "").replace(/\r\n/g, "\n");
  const lines = clean.split("\n");
  const fields: Record<string, string[]> = {};
  const fieldEntries: FieldEntry[] = [];
  let rawDataLines = 0;

  lines.forEach((line, index) => {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#")) return;

    const match = FIELD_LINE.exec(line);
    if (!match) return;

    const [, rawKey, rawValue] = match;
    const key = normalizeKey(rawKey);
    const value = rawValue.trim();
    fields[key] = [...(fields[key] ?? []), value];
    fieldEntries.push({ key: rawKey.trim(), value, line: index + 1 });

    if (key.includes("raw") || key === "data" || key === "key") {
      rawDataLines += 1;
    }
  });

  const domain = inferDomain(clean, fields, fileName);
  const fileType = getFirst(fields, "filetype") || `${domain} capture`;
  const names = unique([...(fields.name ?? []), ...(fields.remote ?? [])]);
  const frequencies = extractFrequencies(fields);
  const protocols = extractProtocols(fields, clean);

  return {
    fileName,
    fileType,
    domain,
    fields,
    fieldEntries,
    frequencies,
    protocols,
    names,
    rawDataLines,
    lineCount: lines.length,
    contentPreview: clean.slice(0, 900),
  };
}

export function getFieldValues(parsed: ParsedCapture, key: string) {
  return parsed.fields[normalizeKey(key)] ?? [];
}
