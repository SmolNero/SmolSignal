import type { AiExplanation } from "./aiClient";
import type { CommunityMatch } from "./communityLibrary";
import type { PhotoContext, SignalFingerprint } from "./fingerprintEngine";
import type { RagResult } from "./localRag";
import type { PassiveSensorGuide } from "./passiveSensor";
import type { AnalysisResult } from "./types";

export interface ReportInput {
  analysis: AnalysisResult;
  fingerprint: SignalFingerprint;
  passiveGuide: PassiveSensorGuide;
  ragResults: RagResult[];
  communityMatches: CommunityMatch[];
  aiExplanation?: AiExplanation;
  photo?: PhotoContext;
  userGoal: string;
}

const REDACTED = "[redacted by SmolSignal report exporter]";
const SENSITIVE_KEY_PATTERN = /key|data|raw|uid|password|sector|address|command|token|secret|credential/i;

function list(items: string[]) {
  return items.length ? items.map((item) => `- ${item}`).join("\n") : "- None";
}

function redactValue(key: string, value: string) {
  return SENSITIVE_KEY_PATTERN.test(key) ? REDACTED : value;
}

function sanitizeAnalysisForReport(analysis: AnalysisResult): AnalysisResult {
  const fields = Object.fromEntries(
    Object.entries(analysis.parsed.fields).map(([key, values]) => [key, values.map((value) => redactValue(key, value))]),
  );

  return {
    ...analysis,
    parsed: {
      ...analysis.parsed,
      fields,
      fieldEntries: analysis.parsed.fieldEntries.map((entry) => ({
        ...entry,
        value: redactValue(entry.key, entry.value),
      })),
      contentPreview: "[omitted from exported report]",
    },
  };
}

function sanitizeCommunityMatches(matches: CommunityMatch[]) {
  return matches.map((match) => ({
    score: match.score,
    reason: match.reason,
    profile: {
      id: match.profile.id,
      name: match.profile.name,
      kind: match.profile.kind,
      safety: match.profile.safety,
      description: match.profile.description,
      tags: match.profile.tags,
      buttonCount: match.profile.buttons?.length ?? 0,
      note: match.profile.note,
    },
  }));
}

export function buildMarkdownReport(input: ReportInput) {
  const { analysis, fingerprint, passiveGuide, ragResults, communityMatches, aiExplanation, photo, userGoal } = input;
  return [
    "# SmolSignal Analysis Report",
    "",
    `Generated: ${new Date().toISOString()}`,
    "",
    "## User Goal",
    userGoal || "Not provided.",
    "",
    "## Shazam-Style Fingerprint",
    `- Likely category: ${fingerprint.label}`,
    `- Confidence: ${Math.round(fingerprint.confidence * 100)}%`,
    `- Safety: ${fingerprint.safety}`,
    `- Decision: ${analysis.decision}`,
    `- Signature: ${fingerprint.signature}`,
    "",
    "## Evidence",
    list(fingerprint.evidence),
    "",
    "## Warnings",
    list(fingerprint.warnings),
    "",
    "## Signal-Aware Gate Evidence",
    `- Score: safe ${analysis.gateScore.safe.toFixed(2)}, caution ${analysis.gateScore.caution.toFixed(2)}, blocked ${analysis.gateScore.blocked.toFixed(2)}`,
    `- Frequency band: ${analysis.signalFeatures.primaryFrequencyBand}`,
    `- Entropy: field ${analysis.signalFeatures.entropy.fieldShannonBitsPerChar} bits/char, raw ${analysis.signalFeatures.entropy.rawValueNormalizedEntropy}, hex ${analysis.signalFeatures.entropy.hexByteNormalizedEntropy}`,
    list(analysis.gateEvidence.map((item) => `${item.level} +${item.weight} (${item.source}): ${item.message}`)),
    "",
    "## Parsed Capture",
    `- File: ${analysis.parsed.fileName ?? "unknown"}`,
    `- File type: ${analysis.parsed.fileType}`,
    `- Domain: ${analysis.parsed.domain}`,
    `- Protocols: ${analysis.parsed.protocols.join(", ") || "none"}`,
    `- Frequency band: ${fingerprint.features.frequencyBand}`,
    `- Modulation/preset: ${fingerprint.features.modulation}`,
    "",
    analysis.lab?.enabled
      ? [
          "## Authorized Lab Mode",
          `- Effect: ${analysis.lab.effect}`,
          `- Scope: ${analysis.lab.scope}`,
          "- Constraints:",
          ...analysis.lab.constraints.map((constraint) => `  - ${constraint}`),
          "",
        ].join("\n")
      : "",
    photo
      ? ["## Photo Context", `- File: ${photo.fileName}`, `- Size: ${photo.width}x${photo.height}`, `- Notes: ${photo.notes || "none"}`, ""].join("\n")
      : "",
    "## Safety Findings",
    list(analysis.findings.map((finding) => `${finding.level}: ${finding.title} - ${finding.detail}`)),
    "",
    "## Safe Next Steps",
    list(analysis.nextSteps),
    "",
    "## Passive Sensor Mode",
    passiveGuide.markdown,
    "",
    "## Local Knowledge Matches",
    list(ragResults.map((result) => `${result.document.title} (${result.score}): ${result.snippet}`)),
    "",
    "## Safe Community Matches",
    list(communityMatches.map((match) => `${match.profile.name} (${match.profile.kind}): ${match.reason}`)),
    "",
    aiExplanation ? ["## AI Explanation", `Provider/model: ${aiExplanation.provider} / ${aiExplanation.model}`, "", aiExplanation.text, ""].join("\n") : "",
    "## Blocked Actions",
    list(analysis.blockedActions),
    "",
  ].join("\n");
}

export function buildJsonReport(input: ReportInput) {
  return JSON.stringify(
    {
      schema: "smolsignal.analysis-report.v1",
      generatedAt: new Date().toISOString(),
      userGoal: input.userGoal,
      analysis: sanitizeAnalysisForReport(input.analysis),
      fingerprint: input.fingerprint,
      passiveGuide: input.passiveGuide,
      ragResults: input.ragResults,
      communityMatches: sanitizeCommunityMatches(input.communityMatches),
      aiExplanation: input.aiExplanation,
      photo: input.photo,
      safetyNotice:
        "This report is for learning, labeling, documentation, and safe owned-device workflows. It does not authorize replay, cloning, bypass, or access attempts.",
    },
    null,
    2,
  );
}
