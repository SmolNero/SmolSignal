import { createServer } from "node:http";

const PORT = Number(process.env.SMOLSIGNAL_AI_BRIDGE_PORT || 8787);
const DEFAULT_ALLOWED_ORIGINS = new Set([
  "http://localhost:5173",
  "http://127.0.0.1:5173",
  "http://localhost:4173",
  "http://127.0.0.1:4173",
]);

function allowedOrigins() {
  const extra = (process.env.SMOLSIGNAL_ALLOWED_ORIGINS || "")
    .split(",")
    .map((origin) => origin.trim())
    .filter(Boolean);
  return new Set([...DEFAULT_ALLOWED_ORIGINS, ...extra]);
}

function writeJson(response, status, payload, origin) {
  const headers = {
    "Content-Type": "application/json; charset=utf-8",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Vary": "Origin",
  };
  if (origin) headers["Access-Control-Allow-Origin"] = origin;
  response.writeHead(status, headers);
  response.end(JSON.stringify(payload));
}

function isOriginAllowed(origin) {
  if (!origin) return true;
  return allowedOrigins().has(origin);
}

async function readJsonRequest(request) {
  const chunks = [];
  for await (const chunk of request) chunks.push(chunk);
  const text = Buffer.concat(chunks).toString("utf8");
  if (!text) return {};
  return JSON.parse(text);
}

function providerConfig(provider, endpoint) {
  switch (provider) {
    case "ollama":
      return {
        kind: "ollama",
        endpoint: endpoint || `${process.env.OLLAMA_HOST || "http://localhost:11434"}/api/chat`,
        apiKey: "",
      };
    case "openai":
      return {
        kind: "openai-compatible",
        endpoint: endpoint || "https://api.openai.com/v1/chat/completions",
        apiKey: process.env.OPENAI_API_KEY || "",
      };
    case "deepseek":
      return {
        kind: "openai-compatible",
        endpoint: endpoint || "https://api.deepseek.com/chat/completions",
        apiKey: process.env.DEEPSEEK_API_KEY || "",
      };
    case "qwen":
      return {
        kind: "openai-compatible",
        endpoint: endpoint || "https://dashscope.aliyuncs.com/compatible-mode/v1/chat/completions",
        apiKey: process.env.DASHSCOPE_API_KEY || "",
      };
    case "custom":
      return {
        kind: "openai-compatible",
        endpoint: endpoint || process.env.OPENAI_COMPATIBLE_ENDPOINT || "",
        apiKey: process.env.OPENAI_COMPATIBLE_API_KEY || "",
      };
    default:
      throw new Error(`Unsupported provider: ${provider}`);
  }
}

async function callProvider({ provider, endpoint, model, messages, temperature }) {
  if (!model || typeof model !== "string") throw new Error("Missing model.");
  if (!Array.isArray(messages)) throw new Error("Missing messages array.");

  const selected = providerConfig(provider, endpoint);
  if (!selected.endpoint) throw new Error("Missing provider endpoint.");

  if (selected.kind === "ollama") {
    const upstream = await fetch(selected.endpoint, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        model,
        messages,
        stream: false,
        options: { temperature: Number.isFinite(temperature) ? temperature : 0.2 },
      }),
    });
    const payload = await upstream.json();
    if (!upstream.ok) throw new Error(JSON.stringify(payload));
    return payload.message?.content || payload.response || "";
  }

  if (!selected.apiKey && provider !== "custom") {
    throw new Error(`Missing API key environment variable for provider: ${provider}`);
  }

  const headers = { "Content-Type": "application/json" };
  if (selected.apiKey) headers.Authorization = `Bearer ${selected.apiKey}`;

  const upstream = await fetch(selected.endpoint, {
    method: "POST",
    headers,
    body: JSON.stringify({
      model,
      messages,
      temperature: Number.isFinite(temperature) ? temperature : 0.2,
    }),
  });
  const payload = await upstream.json();
  if (!upstream.ok) throw new Error(JSON.stringify(payload.error || payload));
  return payload.choices?.[0]?.message?.content || payload.choices?.[0]?.text || "";
}

const server = createServer(async (request, response) => {
  const origin = request.headers.origin;

  if (!isOriginAllowed(origin)) {
    writeJson(response, 403, { error: `Origin not allowed: ${origin}` }, undefined);
    return;
  }

  if (request.method === "OPTIONS") {
    writeJson(response, 204, {}, origin);
    return;
  }

  if (request.method === "GET" && request.url === "/api/health") {
    writeJson(response, 200, { ok: true, name: "SmolSignal AI Bridge" }, origin);
    return;
  }

  if (request.method !== "POST" || request.url !== "/api/ai") {
    writeJson(response, 404, { error: "Not found" }, origin);
    return;
  }

  try {
    const body = await readJsonRequest(request);
    const text = await callProvider(body);
    if (!text) throw new Error("Provider returned an empty response.");
    writeJson(response, 200, { text, provider: body.provider, model: body.model }, origin);
  } catch (error) {
    writeJson(response, 500, { error: error instanceof Error ? error.message : String(error) }, origin);
  }
});

server.listen(PORT, () => {
  console.log(`SmolSignal AI Bridge listening on http://localhost:${PORT}`);
  console.log("Allowed browser origins:", Array.from(allowedOrigins()).join(", "));
});
