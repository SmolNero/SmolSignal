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
  });
});
