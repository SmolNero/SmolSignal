import { describe, expect, it } from "vitest";
import { parseFlipperCapture } from "./flipperParser";

describe("parseFlipperCapture", () => {
  it("detects IR captures", () => {
    const parsed = parseFlipperCapture(
      `Filetype: IR signals file
Version: 1
name: Power
protocol: NEC
address: 00 FF 00 00
command: 12 ED 00 00`,
      "remote.ir",
    );

    expect(parsed.domain).toBe("infrared");
    expect(parsed.fileType).toBe("IR signals file");
    expect(parsed.protocols).toContain("NEC");
    expect(parsed.names).toContain("Power");
  });

  it("extracts Sub-GHz frequencies", () => {
    const parsed = parseFlipperCapture(
      `Filetype: Flipper SubGhz RAW File
Frequency: 433920000
Protocol: RAW
RAW_Data: 1 2 3`,
      "capture.sub",
    );

    expect(parsed.domain).toBe("subghz");
    expect(parsed.frequencies).toEqual([433920000]);
    expect(parsed.rawDataLines).toBe(1);
  });
});
