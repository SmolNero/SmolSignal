import { describe, expect, it } from "vitest";
import { buildIrFile } from "./irBuilder";

describe("buildIrFile", () => {
  it("builds valid Flipper IR files", () => {
    const result = buildIrFile("Living Room TV", [
      { name: "Power", protocol: "NEC", address: "00ff0000", command: "12 ed 00 00" },
    ]);

    expect(result.ok).toBe(true);
    expect(result.fileName).toBe("Living_Room_TV.ir");
    expect(result.content).toContain("Filetype: IR signals file");
    expect(result.content).toContain("address: 00 FF 00 00");
    expect(result.content).toContain("command: 12 ED 00 00");
  });

  it("rejects unsafe or unknown protocols", () => {
    const result = buildIrFile("Bad", [
      { name: "Open", protocol: "KeeLoq", address: "00", command: "01" },
    ]);

    expect(result.ok).toBe(false);
    expect(result.errors.join(" ")).toContain("choose one of");
  });
});
