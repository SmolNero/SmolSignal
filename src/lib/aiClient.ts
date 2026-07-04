import type { PhotoContext, SignalFingerprint } from "./fingerprintEngine";
import type { RagResult } from "./localRag";
import type { AnalysisResult, SafetyDecision } from "./types";

export type AiProvider = "ollama" | "openai-compatible" | "bridge";
export type BridgeProvider = "ollama" | "openai" | "deepseek" | "qwen" | "custom";

export interface AiProviderConfig {
  provider: AiProvider;
  bridgeProvider: BridgeProvider;
  endpoint: string;
  model: string;
  apiKey: string;
  temperature: number;
}

export interface AiMessage {
  role: "system" | "user" | "assistant";
  content: string;
}

export interface AiExplanation {
  text: string;
  provider: AiProvider;
  model: string;
}

export interface AiExtraContext {
  fingerprint?: SignalFingerprint;
  photo?: PhotoContext;
  ragResults?: RagResult[];
}

type FetchLike = (input: RequestInfo | URL, init?: RequestInit) => Promise<Response>;

const REDACTED_VALUE = "[redacted by SmolSignal safety gate]";
const SAFE_FIELD_KEYS = new Set([
  "filetype",
  "version",
  "frequency",
  "preset",
  "protocol",
  "type",
  "name",
  "device_type",
  "card_type",
  "modulation",
]);

const SENSITIVE_KEY_PATTERN = /key|data|raw|uid|password|sector|address|command|token|secret|credential/i;

function redactFieldValue(key: string, value: string) {
  const normalized = key.trim().toLowerCase().replace(/\s+/g, "_");
  if (SAFE_FIELD_KEYS.has(normalized) && !SENSITIVE_KEY_PATTERN.test(normalized)) return value;
  return REDACTED_VALUE;
}

function sanitizeAnalysisForPrompt(analysis: AnalysisResult) {
  return {
    deterministicSafetyGate: {
      level: analysis.level,
      decision: analysis.decision,
      summary: analysis.summary,
      plainEnglish: analysis.plainEnglish,
      lab: analysis.lab,
    },
    parsedCapture: {
      fileName: analysis.parsed.fileName,
      fileType: analysis.parsed.fileType,
      domain: analysis.parsed.domain,
      frequencies: analysis.parsed.frequencies,
      protocols: analysis.parsed.protocols,
      names: analysis.parsed.names,
      rawDataLines: analysis.parsed.rawDataLines,
      lineCount: analysis.parsed.lineCount,
      safeFields: analysis.parsed.fieldEntries.slice(0, 30).map((entry) => ({
        key: entry.key,
        value: redactFieldValue(entry.key, entry.value),
        line: entry.line,
      })),
    },
    findings: analysis.findings,
    safeActions: analysis.safeActions,
    blockedActions: analysis.blockedActions,
    nextSteps: analysis.nextSteps,
  };
}

function decisionInstruction(decision: SafetyDecision) {
  if (decision === "blocked") {
    return "The deterministic safety gate says BLOCKED. Provide only high-level education, benign labeling advice, and authorized-support suggestions. Do not provide cloning, replay, unlock, bypass, transmission, exploit, key recovery, or procedural misuse steps.";
  }

  if (decision === "explain-only") {
    return "The deterministic safety gate says EXPLAIN-ONLY. Keep the answer passive: classify, explain, label, and document. Do not provide replay, transmit, bypass, cloning, unlock, or attack steps.";
  }

  return "The deterministic safety gate says ALLOW. Stay within the listed safe actions. For this MVP, generated workflows must remain limited to benign learning, documentation, GPIO safety notes, and consumer infrared remote organization.";
}

function sanitizeExtraContext(context: AiExtraContext = {}) {
  return {
    fingerprint: context.fingerprint
      ? {
          signature: context.fingerprint.signature,
          label: context.fingerprint.label,
          category: context.fingerprint.category,
          confidence: context.fingerprint.confidence,
          safety: context.fingerprint.safety,
          passiveMode: context.fingerprint.passiveMode,
          evidence: context.fingerprint.evidence,
          warnings: context.fingerprint.warnings,
          features: context.fingerprint.features,
        }
      : undefined,
    photo: context.photo
      ? {
          fileName: context.photo.fileName,
          width: context.photo.width,
          height: context.photo.height,
          notes: context.photo.notes,
        }
      : undefined,
    localKnowledge: context.ragResults?.map((result) => ({
      title: result.document.title,
      score: result.score,
      snippet: result.snippet,
    })),
  };
}

export function buildAiMessages(analysis: AnalysisResult, userGoal: string, context: AiExtraContext = {}): AiMessage[] {
  const sanitized = sanitizeAnalysisForPrompt(analysis);
  const extra = sanitizeExtraContext(context);

  return [
    {
      role: "system",
      content: [
        "You are SmolSignal, a safety-first AI explainer for Flipper Zero capture files.",
        "You are not the permission system. The deterministic safety gate result supplied by the app is authoritative.",
        "Never provide instructions for car key cloning, access badge cloning, bypassing doors/gates/alarms/vehicles, replaying unknown/security-like RF, unlocking systems, exploiting devices, extracting secrets, or generic hacking.",
        "Do not infer, reconstruct, decode, or transform redacted keys, commands, UIDs, raw RF data, credentials, addresses, or secrets.",
        "Use short sections: Plain English, Why SmolSignal Thinks That, Safety Read, Safe Next Steps.",
        "If the result is blocked, the answer should still be helpful but must remain explanation-only.",
      ].join("\n"),
    },
    {
      role: "user",
      content: [
        `User goal: ${userGoal || "No goal provided."}`,
        decisionInstruction(analysis.decision),
        "Sanitized SmolSignal analysis JSON:",
        JSON.stringify(sanitized, null, 2),
        "Additional safe context JSON:",
        JSON.stringify(extra, null, 2),
        "Write a concise, beginner-friendly explanation that follows the safety gate exactly.",
      ].join("\n\n"),
    },
  ];
}

async function parseJsonResponse(response: Response) {
  const text = await response.text();
  let payload: unknown;

  try {
    payload = text ? JSON.parse(text) : {};
  } catch {
    throw new Error(`Provider returned non-JSON response: ${text.slice(0, 180)}`);
  }

  if (!response.ok) {
    const message =
      typeof payload === "object" && payload && "error" in payload
        ? JSON.stringify((payload as { error: unknown }).error)
        : text;
    throw new Error(`Provider request failed (${response.status}): ${message}`);
  }

  return payload;
}

function extractOpenAiText(payload: unknown) {
  const choice = (payload as { choices?: Array<{ message?: { content?: string }; text?: string }> }).choices?.[0];
  return choice?.message?.content ?? choice?.text ?? "";
}

function extractOllamaText(payload: unknown) {
  const ollama = payload as { message?: { content?: string }; response?: string };
  return ollama.message?.content ?? ollama.response ?? "";
}

function headersForConfig(config: AiProviderConfig) {
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (config.provider === "openai-compatible" && config.apiKey.trim()) {
    headers.Authorization = `Bearer ${config.apiKey.trim()}`;
  }
  return headers;
}

export async function generateAiExplanation(
  analysis: AnalysisResult,
  userGoal: string,
  config: AiProviderConfig,
  context: AiExtraContext = {},
  fetchImpl: FetchLike = fetch,
): Promise<AiExplanation> {
  const model = config.model.trim();
  const endpoint = config.endpoint.trim();

  if (!model) throw new Error("Choose a model before asking the AI explainer.");
  if (!endpoint) throw new Error("Choose an endpoint before asking the AI explainer.");

  const messages = buildAiMessages(analysis, userGoal, context);

  if (config.provider === "ollama") {
    const response = await fetchImpl(endpoint, {
      method: "POST",
      headers: headersForConfig(config),
      body: JSON.stringify({
        model,
        messages,
        stream: false,
        options: { temperature: config.temperature },
      }),
    });
    const payload = await parseJsonResponse(response);
    const text = extractOllamaText(payload);
    if (!text) throw new Error("Ollama returned an empty response.");
    return { text, provider: config.provider, model };
  }

  if (config.provider === "bridge") {
    const response = await fetchImpl(endpoint, {
      method: "POST",
      headers: headersForConfig(config),
      body: JSON.stringify({
        provider: config.bridgeProvider,
        model,
        messages,
        temperature: config.temperature,
      }),
    });
    const payload = (await parseJsonResponse(response)) as { text?: string; provider?: string; model?: string };
    if (!payload.text) throw new Error("AI bridge returned an empty response.");
    return { text: payload.text, provider: config.provider, model: payload.model ?? model };
  }

  const response = await fetchImpl(endpoint, {
    method: "POST",
    headers: headersForConfig(config),
    body: JSON.stringify({
      model,
      messages,
      temperature: config.temperature,
    }),
  });
  const payload = await parseJsonResponse(response);
  const text = extractOpenAiText(payload);
  if (!text) throw new Error("OpenAI-compatible provider returned an empty response.");
  return { text, provider: config.provider, model };
}

export const aiEndpointPresets = {
  ollama: "http://localhost:11434/api/chat",
  bridge: "http://localhost:8787/api/ai",
  llamaCpp: "http://localhost:8080/v1/chat/completions",
  vllm: "http://localhost:8000/v1/chat/completions",
  openai: "https://api.openai.com/v1/chat/completions",
  deepseek: "https://api.deepseek.com/chat/completions",
  qwen: "https://dashscope.aliyuncs.com/compatible-mode/v1/chat/completions",
};
