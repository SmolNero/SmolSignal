import { parseFlipperCapture } from "./flipperParser";
import { extractSignalFeatures } from "./signalFeatures";
import type {
  AnalysisResult,
  GateEvidence,
  GateEvidenceSource,
  GateScore,
  ParsedCapture,
  SafetyDecision,
  SafetyFinding,
  SafetyLevel,
  SignalFeatureSummary,
} from "./types";

export interface LabAuthorizationOptions {
  enabled: boolean;
  scope: string;
}

const AUTOMOTIVE_TERMS = [
  "automotive",
  "vehicle",
  "car key",
  "key fob",
  "keyfob",
  "tesla",
  "toyota",
  "honda",
  "ford",
  "bmw",
  "mercedes",
  "volkswagen",
  "subaru",
];

const ACCESS_TERMS = [
  "access control",
  "door access",
  "badge",
  "prox card",
  "hid prox",
  "iclass",
  "seos",
  "indala",
  "mifare classic",
  "sector key",
  "mfkey",
  "t5577",
  "em4100",
  "ibutton",
  "dallas key",
];

const SECURITY_REPLAY_TERMS = [
  "rolling code",
  "keeloq",
  "hcs",
  "security+",
  "secplus",
  "garage",
  "gate opener",
  "barrier",
  "alarm",
  "unlock",
  "bypass",
  "clone",
  "replay attack",
];

const SENSOR_TERMS = [
  "weather",
  "oregon",
  "acurite",
  "ambient weather",
  "thermopro",
  "temperature",
  "humidity",
  "tpms",
  "sensor",
];

const SAFE_IR_PROTOCOLS = ["nec", "necext", "samsung32", "rc5", "rc6", "sony", "sirc", "panasonic", "jvc"];

function normalize(text: string) {
  return text.toLowerCase().replace(/[_-]+/g, " ");
}

function findTerm(text: string, terms: string[]) {
  const lower = normalize(text);
  return terms.find((term) => lower.includes(normalize(term)));
}

function combinedText(parsed: ParsedCapture, userGoal = "") {
  const fields = parsed.fieldEntries.map((entry) => `${entry.key}: ${entry.value}`).join("\n");
  return `${parsed.fileName ?? ""}\n${parsed.fileType}\n${parsed.domain}\n${parsed.protocols.join(" ")}\n${fields}\n${userGoal}`;
}

function addFinding(
  findings: SafetyFinding[],
  level: SafetyLevel,
  title: string,
  detail: string,
  matched?: string,
) {
  findings.push({ level, title, detail, matched });
}

function addEvidence(
  evidence: GateEvidence[],
  source: GateEvidenceSource,
  level: SafetyLevel,
  weight: number,
  message: string,
) {
  evidence.push({ source, level, weight: Number(weight.toFixed(2)), message });
}

function strongestLevel(findings: SafetyFinding[], fallback: SafetyLevel): SafetyLevel {
  if (findings.some((finding) => finding.level === "blocked")) return "blocked";
  if (findings.some((finding) => finding.level === "caution")) return "caution";
  if (findings.some((finding) => finding.level === "safe")) return "safe";
  return fallback;
}

function decisionFor(level: SafetyLevel): SafetyDecision {
  if (level === "blocked") return "blocked";
  if (level === "caution" || level === "unknown") return "explain-only";
  return "allow";
}

function scoreGateEvidence(evidence: GateEvidence[]): GateScore {
  return evidence.reduce(
    (score, item) => {
      if (item.level === "safe") score.safe += item.weight;
      if (item.level === "caution" || item.level === "unknown") score.caution += item.weight;
      if (item.level === "blocked") score.blocked += item.weight;
      return score;
    },
    { safe: 0, caution: 0, blocked: 0 },
  );
}

function levelFromGateScore(score: GateScore): SafetyLevel {
  if (score.blocked >= 2.0) return "blocked";
  if (score.caution >= 0.75) return "caution";
  if (score.safe >= 0.85 && score.caution < 0.75) return "safe";
  return "unknown";
}

function describeFrequency(hz: number) {
  if (hz > 1_000_000) return `${(hz / 1_000_000).toFixed(3)} MHz`;
  if (hz > 1_000) return `${(hz / 1_000).toFixed(1)} kHz`;
  return `${hz} Hz`;
}

function summarizeParsed(parsed: ParsedCapture) {
  const bits = [`Detected ${parsed.domain === "unknown" ? "an unknown" : `a ${parsed.domain}`} capture`];
  if (parsed.protocols.length) bits.push(`protocol hints: ${parsed.protocols.slice(0, 4).join(", ")}`);
  if (parsed.frequencies.length) bits.push(`frequency: ${parsed.frequencies.map(describeFrequency).join(", ")}`);
  if (parsed.names.length) bits.push(`named signals: ${parsed.names.slice(0, 4).join(", ")}`);
  return `${bits.join("; ")}.`;
}

function protocolText(parsed: ParsedCapture) {
  return parsed.protocols.map((protocol) => normalize(protocol)).join(" ");
}

function buildSignalGateEvidence(
  parsed: ParsedCapture,
  text: string,
  features: SignalFeatureSummary,
): GateEvidence[] {
  const evidence: GateEvidence[] = [];
  const protocols = protocolText(parsed);
  const lower = normalize(text);

  if (parsed.domain === "infrared") {
    addEvidence(evidence, "domain", "safe", 0.35, "Capture domain is infrared, which is usually suitable for owned consumer remote workflows.");
  }

  if (parsed.domain === "subghz") {
    addEvidence(evidence, "domain", "caution", 0.35, "Capture domain is Sub-GHz RF, so the gate starts conservative until protocol and intent are clearer.");
  }

  if (parsed.domain === "nfc" || parsed.domain === "rfid" || parsed.domain === "ibutton") {
    addEvidence(evidence, "domain", "caution", 0.55, "Tag/credential-capable domains require caution until the tag family and purpose are clear.");
  }

  if (parsed.domain === "gpio") {
    addEvidence(evidence, "domain", "safe", 0.45, "GPIO/lab notes are allowed when voltage, ownership, and pin direction are documented.");
  }

  if (features.primaryFrequencyHz) {
    const band = features.primaryFrequencyBand;
    if (band.includes("315") || band.includes("390")) {
      addEvidence(evidence, "frequency", "caution", 0.45, `${band} is commonly used by remotes and security-like devices. Frequency alone does not block or allow.`);
    } else if (band.includes("433") || band.includes("868") || band.includes("915")) {
      addEvidence(evidence, "frequency", "caution", 0.25, `${band} is a mixed ISM band used by harmless sensors and riskier remotes. Frequency alone does not decide.`);
    } else {
      addEvidence(evidence, "frequency", "unknown", 0.12, `${band} is not in SmolSignal's common band table.`);
    }
  }

  if (parsed.domain === "infrared" && parsed.protocols.some((protocol) => SAFE_IR_PROTOCOLS.includes(protocol.toLowerCase()))) {
    addEvidence(evidence, "protocol", "safe", 0.9, "Known parsed consumer IR protocol matched.");
  }

  if (/oregon|acurite|ambient|thermopro|lacrosse|weather|temperature|humidity|sensor/.test(`${protocols} ${lower}`)) {
    addEvidence(evidence, "protocol", "caution", 0.35, "Sensor/telemetry hints matched; passive documentation is appropriate, transmit/replay is not generated.");
  }

  if (/keeloq|\bhcs\b|security\+|secplus|rolling code/.test(`${protocols} ${lower}`)) {
    addEvidence(evidence, "protocol", "blocked", 2.3, "Rolling-code/security protocol indicators matched.");
  }

  if (/mifare classic|hid prox|iclass|seos|em4100|t5577|ibutton|dallas/.test(`${protocols} ${lower}`)) {
    addEvidence(evidence, "protocol", "blocked", 2.1, "Access credential or clonable tag-family indicators matched.");
  }

  if (/clone|bypass|unlock|replay attack|car key|key fob|keyfob|badge|access control/.test(lower)) {
    addEvidence(evidence, "intent", "blocked", 2.0, "User intent contains cloning, bypass, unlock, key-fob, badge, or access-control language.");
  } else if (/replay|transmit|send/.test(lower) && parsed.domain === "subghz") {
    addEvidence(evidence, "intent", "caution", 0.65, "User intent mentions transmit/replay-like action on RF; SmolSignal keeps unknown/security-like RF passive.");
  }

  const entropy = features.entropy;
  if (entropy.rawTokenCount >= 12 && entropy.rawValueNormalizedEntropy >= 0.78) {
    addEvidence(
      evidence,
      "entropy",
      "caution",
      0.45,
      `Raw timing/value entropy is high (${entropy.rawValueNormalizedEntropy}); treat unknown RF as encoded/random-like until identified.`,
    );
  }

  if (entropy.hexByteCount >= 8 && entropy.hexByteNormalizedEntropy >= 0.72 && parsed.domain !== "infrared") {
    addEvidence(
      evidence,
      "entropy",
      "caution",
      0.35,
      `Hex-byte entropy is elevated (${entropy.hexByteNormalizedEntropy}); this can indicate IDs, counters, keys, or encoded payloads, so keep workflows passive unless clearly safe.`,
    );
  }

  if (features.timing && parsed.domain === "subghz") {
    addEvidence(
      evidence,
      "timing",
      "caution",
      Math.min(0.55, 0.2 + features.timing.count / 100),
      `Raw RF timing data detected (${features.timing.count} values, unique ratio ${features.timing.uniqueRatio}); raw RF remains passive unless clearly scoped to a harmless lab device.`,
    );
  }

  return evidence;
}

function signalFindingFromEvidence(findings: SafetyFinding[], evidence: GateEvidence[], score: GateScore) {
  if (score.blocked >= 2.0) {
    addFinding(
      findings,
      "blocked",
      "Signal-aware gate hard block",
      "Frequency, protocol, entropy, timing, and/or intent evidence crossed the hard-block threshold.",
    );
    return;
  }

  if (score.caution >= 0.75) {
    const details = evidence
      .filter((item) => item.level === "caution" || item.level === "unknown")
      .map((item) => item.message)
      .slice(0, 2)
      .join(" ");
    addFinding(findings, "caution", "Signal-aware gate caution", details || "Signal features require passive handling.");
  }
}

function domainFinding(parsed: ParsedCapture, text: string, findings: SafetyFinding[]) {
  if (parsed.domain === "infrared") {
    const safeProtocol = parsed.protocols.some((protocol) => SAFE_IR_PROTOCOLS.includes(protocol.toLowerCase()));
    addFinding(
      findings,
      "safe",
      "Consumer IR workflow",
      safeProtocol
        ? "This looks like normal infrared remote-control data. SmolSignal can help organize or generate Flipper .ir files."
        : "This looks like infrared data. IR is usually appropriate for remote-control learning and repair workflows.",
    );
    return;
  }

  if (parsed.domain === "subghz") {
    const sensorTerm = findTerm(text, SENSOR_TERMS);
    if (sensorTerm) {
      addFinding(
        findings,
        "caution",
        "Sub-GHz sensor-like capture",
        "This may be a low-power sensor or telemetry signal. SmolSignal can explain and label it, but will not generate replay/transmit steps.",
        sensorTerm,
      );
      return;
    }

    addFinding(
      findings,
      "caution",
      "Unknown Sub-GHz capture",
      "Sub-GHz captures can include security devices. SmolSignal keeps this in explain-only mode unless the source is clearly safe.",
    );
    return;
  }

  if (parsed.domain === "nfc" || parsed.domain === "rfid" || parsed.domain === "ibutton") {
    addFinding(
      findings,
      "caution",
      "Credential-like technology",
      "NFC, RFID, and iButton files may represent badges, tags, or credentials. SmolSignal can identify and explain, but not clone or bypass access systems.",
    );
    return;
  }

  if (parsed.domain === "gpio") {
    addFinding(
      findings,
      "safe",
      "GPIO learning workflow",
      "GPIO notes are suitable for wiring, sensor identification, and lab workflows. Check voltage and pinout before connecting hardware.",
    );
    return;
  }

  addFinding(
    findings,
    "unknown",
    "Unknown format",
    "SmolSignal could not confidently identify this capture. It will only provide high-level explanation and labeling.",
  );
}

function highRiskFindings(text: string, findings: SafetyFinding[]) {
  const automotive = findTerm(text, AUTOMOTIVE_TERMS);
  if (automotive) {
    addFinding(
      findings,
      "blocked",
      "Automotive/key-fob risk",
      "Vehicle and key-fob workflows are blocked. SmolSignal will not help clone, replay, unlock, or bypass automotive systems.",
      automotive,
    );
  }

  const access = findTerm(text, ACCESS_TERMS);
  if (access) {
    addFinding(
      findings,
      "blocked",
      "Access-control risk",
      "Access-control credential workflows are blocked. SmolSignal can explain the category, but will not assist with cloning or bypass.",
      access,
    );
  }

  const replay = findTerm(text, SECURITY_REPLAY_TERMS);
  if (replay) {
    addFinding(
      findings,
      "blocked",
      "Security replay/bypass risk",
      "Replay, cloning, bypass, garage/gate, rolling-code, and alarm workflows are blocked to keep the project safe and legitimate.",
      replay,
    );
  }
}

function hasHardBlock(findings: SafetyFinding[]) {
  return findings.some((finding) => finding.level === "blocked");
}

function isLabEligible(options?: LabAuthorizationOptions) {
  return Boolean(options?.enabled && options.scope.trim().length >= 12);
}

function labContext(options?: LabAuthorizationOptions) {
  if (!options?.enabled) return undefined;
  const scope = options.scope.trim();
  return {
    enabled: true,
    scope,
    effect:
      scope.length >= 12
        ? "Authorized Lab Mode is active for non-blocked captures. SmolSignal enables richer documentation, report, RAG, and AI explanation workflows while preserving hard blockers."
        : "Authorized Lab Mode was requested, but scope notes are too short to change the safety decision.",
    constraints: [
      "Hard-blocked categories remain blocked regardless of lab mode.",
      "No car key, access credential, gate, garage, alarm, vehicle, cloning, bypass, unlock, or unknown-security replay workflows are generated.",
      "Use only owned, simulated, toy, or intentionally isolated lab fixtures described in the scope notes.",
      "Generated output remains for documentation, labeling, reports, local RAG, and safe AI explanations.",
    ],
  };
}

function makePlainEnglish(parsed: ParsedCapture, level: SafetyLevel, lab?: AnalysisResult["lab"]) {
  if (level === "blocked") {
    return "This capture overlaps with systems that can protect vehicles, doors, gates, alarms, or credentials. SmolSignal will explain what category it appears to be, but it will not provide cloning, replay, bypass, unlock, or attack steps.";
  }

  if (lab?.enabled && parsed.domain !== "infrared") {
    return "Authorized Lab Mode is active for this non-blocked capture. SmolSignal can provide richer lab documentation, reports, RAG context, and AI explanations while still refusing cloning, bypass, unlock, credential, vehicle, alarm, gate, garage, or unknown-security replay workflows.";
  }

  if (parsed.domain === "infrared") {
    return "This appears to be a consumer infrared remote capture. That is the best fit for SmolSignal today: you can label buttons, clean up names, and generate a safe Flipper .ir remote file.";
  }

  if (parsed.domain === "subghz") {
    return "This appears to be a radio-frequency capture. Because RF can include security systems, SmolSignal keeps it in explain-only mode unless it is clearly a harmless lab or sensor workflow.";
  }

  if (parsed.domain === "nfc" || parsed.domain === "rfid" || parsed.domain === "ibutton") {
    return "This appears to involve a tag or credential technology. SmolSignal can explain the type and suggest documentation steps, but it will not help copy or bypass access credentials.";
  }

  if (parsed.domain === "gpio") {
    return "This appears to be a hardware/GPIO workflow. SmolSignal can help turn notes into a safe checklist, with extra attention to voltage, ground, and pin direction.";
  }

  return "SmolSignal does not recognize this format yet. It can still summarize visible fields and suggest safe documentation steps.";
}

function makeActions(parsed: ParsedCapture, level: SafetyLevel, lab?: AnalysisResult["lab"]) {
  const blockedActions = [
    "Car key cloning or unlock flows",
    "Access badge/card cloning",
    "Bypass instructions for doors, gates, alarms, or vehicles",
    "Replay/transmit workflows for unknown or security-like RF captures",
    "Generic 'hack this device' instructions",
  ];

  if (level === "blocked") {
    return {
      safeActions: [
        "Give a high-level category explanation",
        "Help write a benign lab note",
        "Suggest manufacturer documentation or authorized support paths",
      ],
      blockedActions,
    };
  }

  if (parsed.domain === "infrared") {
    return {
      safeActions: [
        "Generate a Flipper .ir file for consumer remotes",
        "Rename and organize IR buttons",
        "Create a troubleshooting checklist for TVs, fans, projectors, LED strips, or AC remotes",
      ],
      blockedActions,
    };
  }

  if (lab?.enabled) {
    return {
      safeActions: [
        "Create scoped lab documentation and exportable reports",
        "Ask the AI explainer for richer beginner-friendly lab context",
        "Compare metadata, timing features, protocol hints, and local RAG references",
        "Build passive notes for owned sensors or simulated lab fixtures",
        "Record authorization scope and constraints alongside the analysis",
      ],
      blockedActions,
    };
  }

  return {
    safeActions: [
      "Classify the capture type",
      "Explain visible metadata",
      "Suggest safe labeling and documentation steps",
      "Recommend using a controlled lab device for deeper testing",
    ],
    blockedActions,
  };
}

function makeNextSteps(parsed: ParsedCapture, level: SafetyLevel, lab?: AnalysisResult["lab"]) {
  if (level === "blocked") {
    return [
      "Do not replay, transmit, clone, or use this capture against a real-world system.",
      "If this is an authorized lab, replace the capture with a toy/demo protocol and document the lab scope.",
      "Use SmolSignal only for labeling, learning, and safe notes for this item.",
    ];
  }

  if (lab?.enabled && parsed.domain !== "infrared") {
    return [
      "Keep the capture inside the scoped owned/simulated lab described in Authorized Lab Mode.",
      "Export a Markdown or JSON report so the scope, constraints, and safety decision stay attached to the analysis.",
      "Use local RAG and the AI explainer for learning and documentation, not for replay, cloning, bypass, or unlock steps.",
    ];
  }

  if (parsed.domain === "infrared") {
    return [
      "Confirm the target is a consumer IR device you own or are allowed to control.",
      "Use the IR Builder below to create a .ir file with clean button names.",
      "Load the .ir file into Flipper under the infrared folder and test one button at a time.",
    ];
  }

  if (parsed.domain === "subghz") {
    return [
      "Label the source and location of the capture.",
      "Keep analysis passive unless you are using a clearly owned lab transmitter/receiver.",
      "For sensors, record frequency, protocol hint, and timing; avoid replay/transmit actions.",
    ];
  }

  return [
    "Document what device you own and why you are analyzing it.",
    "Keep the workflow passive unless the system is a harmless lab setup.",
    "Add more metadata or a file name if SmolSignal could not classify it confidently.",
  ];
}

export function analyzeCapture(content: string, fileName?: string, userGoal = "", labOptions?: LabAuthorizationOptions): AnalysisResult {
  const parsed = parseFlipperCapture(content, fileName);
  const text = combinedText(parsed, userGoal);
  const signalFeatures = extractSignalFeatures(parsed);
  const gateEvidence = buildSignalGateEvidence(parsed, text, signalFeatures);
  if (labOptions?.enabled && labOptions.scope.trim().length >= 12) {
    addEvidence(
      gateEvidence,
      "lab_scope",
      "safe",
      0.85,
      "Authorized Lab Mode scope notes are present; this can upgrade only non-blocked captures into richer lab documentation workflows.",
    );
  } else if (labOptions?.enabled) {
    addEvidence(gateEvidence, "lab_scope", "caution", 0.35, "Authorized Lab Mode was enabled, but scope notes are too short to affect the decision.");
  }
  const gateScore = scoreGateEvidence(gateEvidence);
  const findings: SafetyFinding[] = [];

  domainFinding(parsed, text, findings);
  highRiskFindings(text, findings);
  signalFindingFromEvidence(findings, gateEvidence, gateScore);

  const lab = labContext(labOptions);
  const labEligible = isLabEligible(labOptions) && !hasHardBlock(findings);

  if (labOptions?.enabled) {
    addFinding(
      findings,
      labEligible ? "safe" : hasHardBlock(findings) ? "blocked" : "caution",
      labEligible ? "Authorized lab scope accepted" : "Authorized lab scope not applied",
      labEligible
        ? "The user provided scoped lab/ownership notes. Non-blocked caution/unknown captures can use richer lab documentation and AI explanation workflows."
        : hasHardBlock(findings)
          ? "Hard-blocked categories remain blocked even when Authorized Lab Mode is enabled."
          : "Add clearer scope notes describing the owned, simulated, toy, or isolated lab fixture.",
    );
  }

  const signalLevel = levelFromGateScore(gateScore);
  const fallbackLevel = signalLevel === "unknown" ? (parsed.domain === "unknown" ? "unknown" : "caution") : signalLevel;
  const baseLevel = strongestLevel(findings, fallbackLevel);
  const level = labEligible && baseLevel !== "blocked" ? "safe" : baseLevel;
  const decision = decisionFor(level);
  const actions = makeActions(parsed, level, labEligible ? lab : undefined);

  return {
    parsed,
    level,
    decision,
    summary: summarizeParsed(parsed),
    plainEnglish: makePlainEnglish(parsed, level, labEligible ? lab : undefined),
    findings,
    gateEvidence,
    gateScore,
    signalFeatures,
    safeActions: actions.safeActions,
    blockedActions: actions.blockedActions,
    nextSteps: makeNextSteps(parsed, level, labEligible ? lab : undefined),
    lab,
  };
}
