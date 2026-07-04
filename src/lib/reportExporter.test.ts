import { describe, expect, it } from "vitest";
import { findCommunityMatches } from "./communityLibrary";
import { fingerprintAnalysis } from "./fingerprintEngine";
import { buildRagQuery, searchLocalKnowledge } from "./localRag";
import { buildPassiveSensorGuide } from "./passiveSensor";
import { buildJsonReport, buildMarkdownReport } from "./reportExporter";
import { analyzeCapture } from "./safetyPolicy";

describe("reportExporter", () => {
  it("exports markdown and JSON reports", () => {
    const analysis = analyzeCapture("Filetype: IR signals file\nprotocol: NEC\naddress: 00 FF 00 00\ncommand: 12 ED 00 00", "remote.ir", "explain");
    const fingerprint = fingerprintAnalysis(analysis, "explain");
    const passiveGuide = buildPassiveSensorGuide(analysis, fingerprint);
    const ragResults = searchLocalKnowledge(buildRagQuery(analysis, fingerprint, "explain"));
    const communityMatches = findCommunityMatches(analysis, fingerprint, "explain");
    const input = { analysis, fingerprint, passiveGuide, ragResults, communityMatches, userGoal: "explain" };

    expect(buildMarkdownReport(input)).toContain("SmolSignal Analysis Report");
    const json = buildJsonReport(input);
    expect(JSON.parse(json).schema).toBe("smolsignal.analysis-report.v1");
    expect(json).not.toContain("12 ED 00 00");
    expect(json).toContain("redacted by SmolSignal report exporter");
  });
});
