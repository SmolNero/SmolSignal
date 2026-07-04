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
  safeActions: string[];
  blockedActions: string[];
  nextSteps: string[];
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
