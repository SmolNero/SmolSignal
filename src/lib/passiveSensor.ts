import type { SignalFingerprint } from "./fingerprintEngine";
import type { AnalysisResult } from "./types";

export interface PassiveSensorGuide {
  enabled: boolean;
  title: string;
  summary: string;
  observations: string[];
  safeSteps: string[];
  neverDo: string[];
  markdown: string;
}

export function buildPassiveSensorGuide(analysis: AnalysisResult, fingerprint: SignalFingerprint): PassiveSensorGuide {
  const enabled = fingerprint.category === "passive_sensor" || fingerprint.category === "unknown_rf";
  const frequency = analysis.parsed.frequencies[0]
    ? `${(analysis.parsed.frequencies[0] / 1_000_000).toFixed(3)} MHz`
    : "unknown frequency";
  const protocols = analysis.parsed.protocols.length ? analysis.parsed.protocols.join(", ") : "no protocol hint";

  const observations = [
    `Frequency: ${frequency}`,
    `Protocol hints: ${protocols}`,
    `Modulation/preset: ${fingerprint.features.modulation}`,
    `Signature: ${fingerprint.signature}`,
  ];

  if (fingerprint.features.rawPulseStats) {
    observations.push(
      `Raw numeric tokens: ${fingerprint.features.rawPulseStats.count}, avg ${fingerprint.features.rawPulseStats.average}`,
    );
  }

  const safeSteps = [
    "Label the capture with source, location, time, and device ownership.",
    "Compare only metadata and timing patterns against public sensor references.",
    "Use passive listening or documentation workflows; do not transmit back to the device.",
    "If this is your own lab sensor, create a separate lab note that states scope and authorization.",
  ];

  const neverDo = [
    "Do not replay or transmit unknown RF captures.",
    "Do not spoof telemetry into systems you do not own.",
    "Do not use this workflow for garage, gate, alarm, vehicle, or access systems.",
  ];

  const markdown = [
    "# Passive Sensor Note",
    "",
    `**Enabled:** ${enabled ? "yes" : "no"}`,
    `**Likely category:** ${fingerprint.label}`,
    `**Safety:** ${fingerprint.safety}`,
    "",
    "## Observations",
    ...observations.map((item) => `- ${item}`),
    "",
    "## Safe Steps",
    ...safeSteps.map((item) => `- ${item}`),
    "",
    "## Never Do",
    ...neverDo.map((item) => `- ${item}`),
    "",
  ].join("\n");

  return {
    enabled,
    title: enabled ? "Passive sensor mode" : "Passive mode not recommended for this capture",
    summary: enabled
      ? "This capture can be handled as a passive documentation workflow. SmolSignal will not generate replay/transmit steps."
      : "This capture is not classified as a passive sensor workflow.",
    observations,
    safeSteps,
    neverDo,
    markdown,
  };
}
