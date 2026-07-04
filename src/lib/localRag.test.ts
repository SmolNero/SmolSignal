import { describe, expect, it } from "vitest";
import { searchLocalKnowledge } from "./localRag";

describe("searchLocalKnowledge", () => {
  it("returns relevant local RAG snippets", () => {
    const results = searchLocalKnowledge("433 weather sensor passive subghz telemetry", 2);

    expect(results.length).toBeGreaterThan(0);
    expect(results[0].document.id).toBe("subghz-passive");
  });
});
