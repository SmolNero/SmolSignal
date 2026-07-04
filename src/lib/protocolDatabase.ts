import type { ParsedCapture, SafetyLevel, SignalDomain } from "./types";

export type DeviceCategory =
  | "consumer_ir"
  | "passive_sensor"
  | "access_control"
  | "automotive_security"
  | "security_replay"
  | "gpio_lab"
  | "credential_tag"
  | "unknown_rf"
  | "unknown";

export interface ProtocolKnowledgeEntry {
  id: string;
  name: string;
  category: DeviceCategory;
  safety: SafetyLevel;
  domains: SignalDomain[];
  protocols: string[];
  terms: string[];
  frequencyRanges?: Array<[number, number]>;
  description: string;
  safeUse: string;
  blockedUse: string;
}

export interface ProtocolMatch {
  entry: ProtocolKnowledgeEntry;
  score: number;
  evidence: string[];
}

export const protocolKnowledgeBase: ProtocolKnowledgeEntry[] = [
  {
    id: "consumer-ir-parsed",
    name: "Consumer infrared remote",
    category: "consumer_ir",
    safety: "safe",
    domains: ["infrared"],
    protocols: ["NEC", "NECext", "Samsung32", "RC5", "RC6", "Sony", "SIRC", "Panasonic", "JVC"],
    terms: ["ir signals", "infrared", "remote", "power", "volume", "tv", "projector", "fan", "led", "ac"],
    description: "Common parsed infrared remote-control data for consumer devices.",
    safeUse: "Organize buttons, build replacement remote files, and document known device controls.",
    blockedUse: "Do not use IR workflows to interfere with devices you do not own or have permission to control.",
  },
  {
    id: "weather-telemetry-433",
    name: "Passive weather/sensor telemetry",
    category: "passive_sensor",
    safety: "caution",
    domains: ["subghz"],
    protocols: ["Oregon", "Acurite", "Ambient", "ThermoPro", "LaCrosse", "Nexus", "Fine Offset"],
    terms: ["weather", "temperature", "humidity", "sensor", "telemetry", "oregon", "acurite", "thermopro"],
    frequencyRanges: [
      [433_000_000, 435_000_000],
      [915_000_000, 916_500_000],
      [868_000_000, 869_000_000],
    ],
    description: "Low-power environmental sensors often broadcast simple telemetry frames.",
    safeUse: "Passive labeling, documentation, and comparison against sensor protocol references.",
    blockedUse: "Do not replay or spoof telemetry into systems you do not own or control.",
  },
  {
    id: "tpms-passive",
    name: "TPMS-style passive sensor",
    category: "passive_sensor",
    safety: "caution",
    domains: ["subghz"],
    protocols: ["TPMS"],
    terms: ["tpms", "tire pressure", "pressure sensor"],
    frequencyRanges: [
      [314_000_000, 316_000_000],
      [432_000_000, 435_000_000],
    ],
    description: "Tire-pressure or similar telemetry can expose identifying sensor data.",
    safeUse: "Passive education and documentation of your own sensors.",
    blockedUse: "Do not track, spoof, or replay telemetry for vehicles or property you do not own.",
  },
  {
    id: "rolling-code-security",
    name: "Rolling-code security remote",
    category: "security_replay",
    safety: "blocked",
    domains: ["subghz"],
    protocols: ["KeeLoq", "HCS", "Security+", "SecPlus"],
    terms: ["rolling code", "keeloq", "hcs", "security+", "secplus", "garage", "gate", "barrier", "alarm"],
    frequencyRanges: [
      [300_000_000, 320_000_000],
      [390_000_000, 391_000_000],
      [433_000_000, 435_000_000],
    ],
    description: "Security remotes can protect garages, gates, alarms, barriers, and similar systems.",
    safeUse: "High-level explanation of rolling codes and why replay/cloning is blocked.",
    blockedUse: "Cloning, replaying, unlocking, bypassing, or generating transmit steps.",
  },
  {
    id: "automotive-keyfob",
    name: "Automotive/key-fob signal",
    category: "automotive_security",
    safety: "blocked",
    domains: ["subghz", "nfc", "rfid", "ble"],
    protocols: ["KeeLoq", "HCS", "Hitag", "Keyless"],
    terms: ["automotive", "vehicle", "car key", "key fob", "keyfob", "tesla", "toyota", "honda", "ford"],
    frequencyRanges: [
      [300_000_000, 320_000_000],
      [432_000_000, 435_000_000],
      [868_000_000, 869_000_000],
    ],
    description: "Vehicle key and remote systems are high-risk and out of scope for SmolSignal workflows.",
    safeUse: "High-level education and owner-support guidance only.",
    blockedUse: "Cloning, unlock flows, replay, key recovery, bypass, or procedural attack steps.",
  },
  {
    id: "access-credential",
    name: "Access-control credential/tag",
    category: "access_control",
    safety: "blocked",
    domains: ["nfc", "rfid", "ibutton"],
    protocols: ["Mifare Classic", "HID Prox", "iClass", "Seos", "EM4100", "T5577", "Dallas", "iButton"],
    terms: ["access", "badge", "prox", "hid", "mifare classic", "em4100", "t5577", "ibutton", "dallas key"],
    description: "Tags and credentials can control access to doors, buildings, lockers, or infrastructure.",
    safeUse: "Identify tag family at a high level and document ownership/authorization boundaries.",
    blockedUse: "Cloning, bypass, sector/key recovery, credential copying, or access instructions.",
  },
  {
    id: "benign-nfc-tag",
    name: "General NFC tag",
    category: "credential_tag",
    safety: "caution",
    domains: ["nfc"],
    protocols: ["NTAG", "Mifare Ultralight", "ISO14443"],
    terms: ["ntag", "ultralight", "ndef", "url", "amiibo", "tag"],
    description: "General NFC tags may hold URLs, NDEF records, or product metadata.",
    safeUse: "Read-only identification, documentation, and NDEF learning on tags you own.",
    blockedUse: "Do not copy credentials, payment media, transit passes, or access badges.",
  },
  {
    id: "gpio-lab",
    name: "GPIO/lab hardware workflow",
    category: "gpio_lab",
    safety: "safe",
    domains: ["gpio"],
    protocols: ["UART", "I2C", "SPI", "GPIO"],
    terms: ["gpio", "uart", "i2c", "spi", "sensor", "module", "breadboard"],
    description: "Lab hardware and module workflows are useful when voltage and pin direction are respected.",
    safeUse: "Wiring checklists, passive identification, and educational lab notes.",
    blockedUse: "Do not connect unknown voltages or interact with equipment without authorization.",
  },
];

function normalize(text: string) {
  return text.toLowerCase().replace(/[_-]+/g, " ");
}

function protocolMatches(parsed: ParsedCapture, protocols: string[]) {
  return protocols.filter((known) =>
    parsed.protocols.some((protocol) => normalize(protocol).includes(normalize(known)) || normalize(known).includes(normalize(protocol))),
  );
}

function termsInText(text: string, terms: string[]) {
  const lower = normalize(text);
  return terms.filter((term) => lower.includes(normalize(term)));
}

function frequencyMatches(parsed: ParsedCapture, ranges: Array<[number, number]> = []) {
  return parsed.frequencies.filter((frequency) => ranges.some(([min, max]) => frequency >= min && frequency <= max));
}

function combinedText(parsed: ParsedCapture, userGoal = "", photoNotes = "") {
  const fields = parsed.fieldEntries.map((entry) => `${entry.key}: ${entry.value}`).join("\n");
  return `${parsed.fileName ?? ""}\n${parsed.fileType}\n${parsed.domain}\n${parsed.protocols.join(" ")}\n${fields}\n${userGoal}\n${photoNotes}`;
}

export function matchProtocolKnowledge(parsed: ParsedCapture, userGoal = "", photoNotes = ""): ProtocolMatch[] {
  const text = combinedText(parsed, userGoal, photoNotes);

  return protocolKnowledgeBase
    .map((entry) => {
      const evidence: string[] = [];
      let score = 0;

      if (entry.domains.includes(parsed.domain)) {
        score += 0.14;
        evidence.push(`Domain matches ${parsed.domain}.`);
      }

      const matchedProtocols = protocolMatches(parsed, entry.protocols);
      if (matchedProtocols.length) {
        score += Math.min(0.46, matchedProtocols.length * 0.23);
        evidence.push(`Protocol hint matched: ${matchedProtocols.join(", ")}.`);
      }

      const matchedTerms = termsInText(text, entry.terms);
      if (matchedTerms.length) {
        score += Math.min(0.28, matchedTerms.length * 0.08);
        evidence.push(`Text hint matched: ${matchedTerms.slice(0, 5).join(", ")}.`);
      }

      const matchedFrequencies = frequencyMatches(parsed, entry.frequencyRanges);
      if (matchedFrequencies.length) {
        score += 0.16;
        evidence.push("Frequency is in a known range for this category.");
      }

      return { entry, score: Number(score.toFixed(3)), evidence };
    })
    .filter((match) => match.score >= 0.14)
    .sort((a, b) => b.score - a.score);
}

export function categoryLabel(category: DeviceCategory) {
  switch (category) {
    case "consumer_ir":
      return "Consumer IR remote";
    case "passive_sensor":
      return "Passive sensor/telemetry";
    case "access_control":
      return "Access-control credential";
    case "automotive_security":
      return "Automotive/key-fob security";
    case "security_replay":
      return "Security replay risk";
    case "gpio_lab":
      return "GPIO/lab hardware";
    case "credential_tag":
      return "General NFC/tag workflow";
    case "unknown_rf":
      return "Unknown RF capture";
    default:
      return "Unknown signal";
  }
}
