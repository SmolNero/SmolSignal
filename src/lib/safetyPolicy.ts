import { parseFlipperCapture } from "./flipperParser";
import type { AnalysisResult, ParsedCapture, SafetyDecision, SafetyFinding, SafetyLevel } from "./types";

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

function makePlainEnglish(parsed: ParsedCapture, level: SafetyLevel) {
  if (level === "blocked") {
    return "This capture overlaps with systems that can protect vehicles, doors, gates, alarms, or credentials. SmolSignal will explain what category it appears to be, but it will not provide cloning, replay, bypass, unlock, or attack steps.";
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

function makeActions(parsed: ParsedCapture, level: SafetyLevel) {
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

function makeNextSteps(parsed: ParsedCapture, level: SafetyLevel) {
  if (level === "blocked") {
    return [
      "Do not replay, transmit, clone, or use this capture against a real-world system.",
      "If this is an authorized lab, replace the capture with a toy/demo protocol and document the lab scope.",
      "Use SmolSignal only for labeling, learning, and safe notes for this item.",
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

export function analyzeCapture(content: string, fileName?: string, userGoal = ""): AnalysisResult {
  const parsed = parseFlipperCapture(content, fileName);
  const text = combinedText(parsed, userGoal);
  const findings: SafetyFinding[] = [];

  domainFinding(parsed, text, findings);
  highRiskFindings(text, findings);

  const level = strongestLevel(findings, parsed.domain === "unknown" ? "unknown" : "caution");
  const decision = decisionFor(level);
  const actions = makeActions(parsed, level);

  return {
    parsed,
    level,
    decision,
    summary: summarizeParsed(parsed),
    plainEnglish: makePlainEnglish(parsed, level),
    findings,
    safeActions: actions.safeActions,
    blockedActions: actions.blockedActions,
    nextSteps: makeNextSteps(parsed, level),
  };
}
