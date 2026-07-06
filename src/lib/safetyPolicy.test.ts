import { describe, expect, it } from "vitest";
import { analyzeCapture } from "./safetyPolicy";

describe("analyzeCapture", () => {
  it("allows normal IR remote workflows", () => {
    const result = analyzeCapture(
      `Filetype: IR signals file
name: Power
protocol: NEC
address: 00 FF 00 00
command: 12 ED 00 00`,
      "remote.ir",
      "Build a remote for my TV",
    );

    expect(result.level).toBe("safe");
    expect(result.decision).toBe("allow");
  });

  it("blocks automotive key-fob workflows", () => {
    const result = analyzeCapture(
      `Filetype: Flipper SubGhz Key File
Frequency: 315000000
Protocol: KeeLoq
Manufacture: automotive key fob`,
      "car.sub",
      "clone my car key fob",
    );

    expect(result.level).toBe("blocked");
    expect(result.decision).toBe("blocked");
  });

  it("keeps unknown Sub-GHz captures explain-only", () => {
    const result = analyzeCapture(
      `Filetype: Flipper SubGhz RAW File
Frequency: 433920000
Protocol: RAW
RAW_Data: 1 2 3`,
      "unknown.sub",
      "What is this?",
    );

    expect(result.level).toBe("caution");
    expect(result.decision).toBe("explain-only");
    expect(result.gateEvidence.some((item) => item.source === "frequency")).toBe(true);
    expect(result.gateEvidence.some((item) => item.source === "timing")).toBe(true);
  });

  it("uses frequency as weighted context without blocking by itself", () => {
    const result = analyzeCapture(
      `Filetype: Flipper SubGhz RAW File
Frequency: 433920000
Preset: FuriHalSubGhzPresetOok650Async`,
      "frequency-only.sub",
      "Identify this capture",
    );

    expect(result.decision).toBe("explain-only");
    expect(result.gateScore.blocked).toBe(0);
    expect(result.signalFeatures.primaryFrequencyBand).toContain("433 MHz");
  });

  it("uses protocol and intent with frequency to block high-risk captures", () => {
    const result = analyzeCapture(
      `Filetype: Flipper SubGhz Key File
Frequency: 315000000
Protocol: KeeLoq
Manufacture: key fob`,
      "keyfob.sub",
      "replay this key fob",
    );

    expect(result.decision).toBe("blocked");
    expect(result.gateScore.blocked).toBeGreaterThanOrEqual(2);
    expect(result.gateEvidence.some((item) => item.source === "protocol" && item.level === "blocked")).toBe(true);
    expect(result.gateEvidence.some((item) => item.source === "intent" && item.level === "blocked")).toBe(true);
  });

  it("computes Shannon entropy features for raw and hex-like payloads", () => {
    const result = analyzeCapture(
      `Filetype: Flipper SubGhz RAW File
Frequency: 433920000
Protocol: RAW
RAW_Data: -1200 480 -380 920 -410 930 -1200 500 -390 910 -405 925 -1210 515
Key: A1 B2 C3 D4 E5 F6 12 34`,
      "entropy.sub",
      "Analyze my owned lab sensor capture",
    );

    expect(result.signalFeatures.entropy.rawTokenCount).toBeGreaterThan(10);
    expect(result.signalFeatures.entropy.rawValueNormalizedEntropy).toBeGreaterThan(0.5);
    expect(result.signalFeatures.entropy.hexByteCount).toBeGreaterThan(4);
    expect(result.gateEvidence.some((item) => item.source === "entropy")).toBe(true);
  });

  it("allows richer workflows for scoped authorized lab captures", () => {
    const result = analyzeCapture(
      `Filetype: Flipper SubGhz RAW File
Frequency: 433920000
Protocol: RAW
RAW_Data: 1 2 3`,
      "unknown.sub",
      "Document my toy RF lab transmitter",
      {
        enabled: true,
        scope: "Owned toy transmitter connected to an isolated test receiver on my bench; no real access systems.",
      },
    );

    expect(result.level).toBe("safe");
    expect(result.decision).toBe("allow");
    expect(result.lab?.enabled).toBe(true);
    expect(result.safeActions.join(" ")).toContain("lab documentation");
    expect(result.gateEvidence.some((item) => item.source === "lab_scope" && item.level === "safe")).toBe(true);
  });

  it("keeps hard-blocked categories blocked even in lab mode", () => {
    const result = analyzeCapture(
      `Filetype: Flipper SubGhz Key File
Frequency: 315000000
Protocol: KeeLoq
Manufacture: automotive key fob`,
      "car.sub",
      "authorized lab test",
      {
        enabled: true,
        scope: "Owned vehicle fob in my lab with permission, requesting analysis only.",
      },
    );

    expect(result.level).toBe("blocked");
    expect(result.decision).toBe("blocked");
    expect(result.findings.some((finding) => finding.title === "Authorized lab scope not applied")).toBe(true);
  });
});
