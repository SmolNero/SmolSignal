import { describe, expect, it } from "vitest";
import { aiEndpointPresets, buildAiMessages, generateAiExplanation, type AiProviderConfig } from "./aiClient";
import { analyzeCapture } from "./safetyPolicy";

function jsonResponse(payload: unknown, status = 200) {
  return new Response(JSON.stringify(payload), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

const baseConfig: AiProviderConfig = {
  provider: "openai-compatible",
  bridgeProvider: "custom",
  endpoint: aiEndpointPresets.llamaCpp,
  model: "test-model",
  apiKey: "",
  temperature: 0.2,
};

describe("buildAiMessages", () => {
  it("redacts raw data and enforces blocked decisions", () => {
    const analysis = analyzeCapture(
      `Filetype: Flipper SubGhz Key File
Frequency: 315000000
Protocol: KeeLoq
Manufacture: automotive key fob
Key: ABCD1234`,
      "car.sub",
      "clone this car key",
    );

    const messages = buildAiMessages(analysis, "clone this car key");
    const combined = messages.map((message) => message.content).join("\n");

    expect(combined).toContain("BLOCKED");
    expect(combined).toContain("redacted by SmolSignal safety gate");
    expect(combined).not.toContain("ABCD1234");
  });

  it("includes safe deterministic context for IR", () => {
    const analysis = analyzeCapture(
      `Filetype: IR signals file
name: Power
protocol: NEC
address: 00 FF 00 00
command: 12 ED 00 00`,
      "remote.ir",
      "build a TV remote",
    );

    const messages = buildAiMessages(analysis, "build a TV remote");
    const combined = messages.map((message) => message.content).join("\n");

    expect(combined).toContain("ALLOW");
    expect(combined).toContain("Consumer IR workflow");
    expect(combined).not.toContain("12 ED 00 00");
  });
});

describe("generateAiExplanation", () => {
  it("calls OpenAI-compatible chat completions", async () => {
    const analysis = analyzeCapture("Filetype: IR signals file\nprotocol: NEC", "remote.ir", "explain");
    const requests: RequestInit[] = [];

    const result = await generateAiExplanation(analysis, "explain", baseConfig, async (_input, init) => {
      requests.push(init ?? {});
      return jsonResponse({ choices: [{ message: { content: "Plain English: safe IR." } }] });
    });

    expect(result.text).toBe("Plain English: safe IR.");
    expect(JSON.stringify(requests[0].body)).toContain("test-model");
  });

  it("calls Ollama chat", async () => {
    const analysis = analyzeCapture("Filetype: IR signals file\nprotocol: NEC", "remote.ir", "explain");
    const config: AiProviderConfig = {
      ...baseConfig,
      provider: "ollama",
      endpoint: aiEndpointPresets.ollama,
    };

    const result = await generateAiExplanation(analysis, "explain", config, async () => {
      return jsonResponse({ message: { content: "Ollama says safe." } });
    });

    expect(result.text).toBe("Ollama says safe.");
  });

  it("calls the local AI bridge", async () => {
    const analysis = analyzeCapture("Filetype: IR signals file\nprotocol: NEC", "remote.ir", "explain");
    const config: AiProviderConfig = {
      ...baseConfig,
      provider: "bridge",
      bridgeProvider: "deepseek",
      endpoint: aiEndpointPresets.bridge,
    };

    const result = await generateAiExplanation(analysis, "explain", config, async () => {
      return jsonResponse({ text: "Bridge says safe.", provider: "deepseek", model: "test-model" });
    });

    expect(result.text).toBe("Bridge says safe.");
  });
});
