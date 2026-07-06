export type SignalDomain =
  | "infrared"
  | "subghz"
  | "nfc"
  | "rfid"
  | "ibutton"
  | "ble"
  | "gpio"
  | "unknown";

export type SafetyLevel = "safe" | "caution" | "blocked" | "unknown";

export type SafetyDecision = "allow" | "explain-only" | "blocked";

export type GateEvidenceSource = "domain" | "frequency" | "protocol" | "entropy" | "timing" | "intent" | "lab_scope";

export interface GateEvidence {
  source: GateEvidenceSource;
  level: SafetyLevel;
  weight: number;
  message: string;
}

export interface GateScore {
  safe: number;
  caution: number;
  blocked: number;
}

export interface FieldEntry {
  key: string;
  value: string;
  line: number;
}

export interface ParsedCapture {
  fileName?: string;
  fileType: string;
  domain: SignalDomain;
  fields: Record<string, string[]>;
  fieldEntries: FieldEntry[];
  frequencies: number[];
  protocols: string[];
  names: string[];
  rawDataLines: number;
  lineCount: number;
  contentPreview: string;
}

export interface SignalFeatureSummary {
  primaryFrequencyHz?: number;
  primaryFrequencyBand: string;
  entropy: {
    fieldShannonBitsPerChar: number;
    rawValueShannonBits: number;
    rawValueNormalizedEntropy: number;
    hexByteShannonBits: number;
    hexByteNormalizedEntropy: number;
    rawTokenCount: number;
    hexByteCount: number;
  };
  timing?: {
    count: number;
    min: number;
    max: number;
    average: number;
    standardDeviation: number;
    uniqueRatio: number;
    signAlternationRatio: number;
  };
}

export interface SafetyFinding {
  level: SafetyLevel;
  title: string;
  detail: string;
  matched?: string;
}

export interface AnalysisResult {
  parsed: ParsedCapture;
  level: SafetyLevel;
  decision: SafetyDecision;
  summary: string;
  plainEnglish: string;
  findings: SafetyFinding[];
  gateEvidence: GateEvidence[];
  gateScore: GateScore;
  signalFeatures: SignalFeatureSummary;
  safeActions: string[];
  blockedActions: string[];
  nextSteps: string[];
  lab?: {
    enabled: boolean;
    scope: string;
    effect: string;
    constraints: string[];
  };
}

export interface IrButton {
  name: string;
  protocol: string;
  address: string;
  command: string;
}

export interface IrBuildResult {
  ok: boolean;
  fileName: string;
  content: string;
  errors: string[];
}
