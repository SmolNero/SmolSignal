import { describe, expect, it } from "vitest";
import { fingerprintAnalysis } from "./fingerprintEngine";
import { analyzeCapture } from "./safetyPolicy";

describe("fingerprintAnalysis", () => {
  it("classifies safe consumer IR", () => {
    const analysis = analyzeCapture(
      `Filetype: IR signals file
name: Power
protocol: NEC
address: 00 FF 00 00
command: 12 ED 00 00`,
      "remote.ir",
      "build a TV remote",
    );

    const fingerprint = fingerprintAnalysis(analysis, "build a TV remote");

    expect(fingerprint.category).toBe("consumer_ir");
    expect(fingerprint.safety).toBe("safe");
    expect(fingerprint.confidence).toBeGreaterThan(0.5);
  });

  it("classifies weather sensor captures as passive", () => {
    const analysis = analyzeCapture(
      `Filetype: Flipper SubGhz RAW File
Frequency: 433920000
Protocol: Oregon Weather Sensor
RAW_Data: -1200 480 -380 920`,
      "weather.sub",
      "identify weather sensor",
    );

    const fingerprint = fingerprintAnalysis(analysis, "identify weather sensor");

    expect(fingerprint.category).toBe("passive_sensor");
    expect(fingerprint.passiveMode).toBe(true);
    expect(fingerprint.features.rawPulseStats?.count).toBeGreaterThan(0);
  });
});
