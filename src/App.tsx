import { ChangeEvent, useState } from "react";
import {
  aiEndpointPresets,
  generateAiExplanation,
  type AiExplanation,
  type AiProviderConfig,
} from "./lib/aiClient";
import { exportCommunityProfile, findCommunityMatches, type CommunityProfile } from "./lib/communityLibrary";
import { fingerprintAnalysis, type PhotoContext } from "./lib/fingerprintEngine";
import { buildIrFile, parseIrButtonsFromCapture, safeIrProtocols } from "./lib/irBuilder";
import { buildRagQuery, searchLocalKnowledge } from "./lib/localRag";
import { buildPassiveSensorGuide } from "./lib/passiveSensor";
import { buildJsonReport, buildMarkdownReport } from "./lib/reportExporter";
import { analyzeCapture } from "./lib/safetyPolicy";
import { samples } from "./lib/samples";
import type { IrButton, SafetyLevel } from "./lib/types";

interface SerialPortLike {
  open(options: { baudRate: number }): Promise<void>;
  close(): Promise<void>;
  getInfo?: () => { usbVendorId?: number; usbProductId?: number };
}

type NavigatorWithSerial = Navigator & {
  serial?: {
    requestPort(): Promise<SerialPortLike>;
  };
};

const emptyButton: IrButton = {
  name: "Power",
  protocol: "NEC",
  address: "00 FF 00 00",
  command: "12 ED 00 00",
};

const levelLabels: Record<SafetyLevel, string> = {
  safe: "Safe",
  caution: "Explain-only",
  blocked: "Blocked",
  unknown: "Unknown",
};

const defaultAiConfig: AiProviderConfig = {
  provider: "ollama",
  bridgeProvider: "ollama",
  endpoint: aiEndpointPresets.ollama,
  model: "qwen2.5:7b",
  apiKey: "",
  temperature: 0.2,
};

function RiskBadge({ level }: { level: SafetyLevel }) {
  return <span className={`risk-badge risk-${level}`}>{levelLabels[level]}</span>;
}

function downloadTextFile(fileName: string, content: string) {
  const blob = new Blob([content], { type: "text/plain;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = fileName;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

export default function App() {
  const [captureText, setCaptureText] = useState(samples[0].content);
  const [fileName, setFileName] = useState(samples[0].fileName);
  const [goal, setGoal] = useState(samples[0].goal);
  const [remoteName, setRemoteName] = useState("SmolSignal Remote");
  const [buttons, setButtons] = useState<IrButton[]>([emptyButton]);
  const [dropActive, setDropActive] = useState(false);
  const [aiConfig, setAiConfig] = useState<AiProviderConfig>(defaultAiConfig);
  const [aiExplanation, setAiExplanation] = useState<AiExplanation>();
  const [aiError, setAiError] = useState("");
  const [aiLoading, setAiLoading] = useState(false);
  const [labEnabled, setLabEnabled] = useState(false);
  const [labScope, setLabScope] = useState("Owned/simulated lab fixture only; no vehicles, credentials, access systems, gates, garages, or alarms.");
  const [photoContext, setPhotoContext] = useState<PhotoContext>();
  const [photoPreview, setPhotoPreview] = useState("");
  const [irImportMessage, setIrImportMessage] = useState("");
  const [serialPort, setSerialPort] = useState<SerialPortLike>();
  const [serialStatus, setSerialStatus] = useState("Not connected");
  const [serialLog, setSerialLog] = useState("Use Chrome or Edge on desktop for Web Serial. Connect Flipper over USB, then click Connect.");

  const analysis = captureText.trim() ? analyzeCapture(captureText, fileName, goal, { enabled: labEnabled, scope: labScope }) : undefined;
  const fingerprint = analysis ? fingerprintAnalysis(analysis, goal, photoContext) : undefined;
  const passiveGuide = analysis && fingerprint ? buildPassiveSensorGuide(analysis, fingerprint) : undefined;
  const ragResults = analysis && fingerprint ? searchLocalKnowledge(buildRagQuery(analysis, fingerprint, goal, photoContext), 3) : [];
  const communityMatches = analysis && fingerprint ? findCommunityMatches(analysis, fingerprint, goal) : [];
  const buildResult = buildIrFile(remoteName, buttons);

  async function loadFile(file?: File) {
    if (!file) return;
    const text = await file.text();
    setCaptureText(text);
    setFileName(file.name);
    setAiExplanation(undefined);
    setAiError("");
  }

  async function loadPhoto(file?: File) {
    if (!file) return;
    const url = URL.createObjectURL(file);
    const image = new Image();
    image.onload = () => {
      setPhotoContext({ fileName: file.name, width: image.naturalWidth, height: image.naturalHeight, notes: photoContext?.notes ?? "" });
      setPhotoPreview(url);
    };
    image.onerror = () => {
      URL.revokeObjectURL(url);
      setPhotoContext(undefined);
      setPhotoPreview("");
    };
    image.src = url;
  }

  function onFileChange(event: ChangeEvent<HTMLInputElement>) {
    void loadFile(event.target.files?.[0]);
  }

  function onPhotoChange(event: ChangeEvent<HTMLInputElement>) {
    void loadPhoto(event.target.files?.[0]);
  }

  function updateButton(index: number, patch: Partial<IrButton>) {
    setButtons((current) => current.map((button, itemIndex) => (itemIndex === index ? { ...button, ...patch } : button)));
  }

  function removeButton(index: number) {
    setButtons((current) => current.filter((_, itemIndex) => itemIndex !== index));
  }

  function loadSample(index: number) {
    const sample = samples[index];
    setCaptureText(sample.content);
    setFileName(sample.fileName);
    setGoal(sample.goal);
    setAiExplanation(undefined);
    setAiError("");
    setIrImportMessage("");
  }

  function copyIrFile() {
    if (!buildResult.ok) return;
    void navigator.clipboard.writeText(buildResult.content);
  }

  function importIrButtonsFromCapture() {
    const parsed = parseIrButtonsFromCapture(captureText);
    if (!parsed.buttons.length) {
      setIrImportMessage(parsed.errors.length ? parsed.errors.join(" ") : "No parsed IR buttons found in the current capture.");
      return;
    }
    setButtons(parsed.buttons);
    setRemoteName(fileName.replace(/\.[^.]+$/, "") || "Imported_IR_Remote");
    setIrImportMessage(`Imported ${parsed.buttons.length} IR button${parsed.buttons.length === 1 ? "" : "s"}.`);
  }

  function loadCommunityProfile(profile: CommunityProfile) {
    if (profile.buttons?.length) {
      setButtons(profile.buttons);
      setRemoteName(profile.name);
      setIrImportMessage(`Loaded safe community profile: ${profile.name}. Replace placeholder commands with owned captures if needed.`);
      return;
    }
    if (profile.note) {
      void navigator.clipboard.writeText(profile.note);
      setIrImportMessage(`Copied note for ${profile.name}.`);
    }
  }

  function downloadAnalysisReport(format: "md" | "json") {
    if (!analysis || !fingerprint || !passiveGuide) return;
    const reportInput = {
      analysis,
      fingerprint,
      passiveGuide,
      ragResults,
      communityMatches,
      aiExplanation,
      photo: photoContext,
      userGoal: goal,
    };
    const content = format === "md" ? buildMarkdownReport(reportInput) : buildJsonReport(reportInput);
    downloadTextFile(`smolsignal-report-${fingerprint.signature}.${format}`, content);
  }

  function downloadCommunityProfile(profile: CommunityProfile) {
    downloadTextFile(`${profile.id}.smolsignal-profile.json`, exportCommunityProfile(profile));
  }

  async function connectFlipperSerial() {
    const nav = navigator as NavigatorWithSerial;
    if (!nav.serial) {
      setSerialStatus("Web Serial not supported");
      setSerialLog("Use Chrome or Edge on desktop. Safari and Firefox do not currently support Web Serial.");
      return;
    }

    try {
      const port = await nav.serial.requestPort();
      await port.open({ baudRate: 115200 });
      const info = port.getInfo?.();
      setSerialPort(port);
      setSerialStatus("Connected over Web Serial");
      setSerialLog(
        `Connected. Vendor: ${info?.usbVendorId ?? "unknown"}; Product: ${info?.usbProductId ?? "unknown"}. Use this panel for safe connection status while importing/exporting files through Flipper storage workflows.`,
      );
    } catch (error) {
      setSerialStatus("Connection failed");
      setSerialLog(error instanceof Error ? error.message : String(error));
    }
  }

  async function disconnectFlipperSerial() {
    if (!serialPort) return;
    try {
      await serialPort.close();
      setSerialPort(undefined);
      setSerialStatus("Disconnected");
      setSerialLog("Serial port closed.");
    } catch (error) {
      setSerialLog(error instanceof Error ? error.message : String(error));
    }
  }

  function updateAiConfig(patch: Partial<AiProviderConfig>) {
    setAiConfig((current) => ({ ...current, ...patch }));
  }

  function chooseProvider(provider: AiProviderConfig["provider"]) {
    if (provider === "ollama") {
      setAiConfig((current) => ({
        ...current,
        provider,
        bridgeProvider: "ollama",
        endpoint: aiEndpointPresets.ollama,
        model: current.model || "qwen2.5:7b",
        apiKey: "",
      }));
      return;
    }

    if (provider === "bridge") {
      setAiConfig((current) => ({
        ...current,
        provider,
        endpoint: aiEndpointPresets.bridge,
        apiKey: "",
      }));
      return;
    }

    setAiConfig((current) => ({
      ...current,
      provider,
      bridgeProvider: "custom",
      endpoint: aiEndpointPresets.llamaCpp,
    }));
  }

  function chooseEndpointPreset(preset: keyof typeof aiEndpointPresets) {
    updateAiConfig({ endpoint: aiEndpointPresets[preset] });
  }

  async function askAi() {
    if (!analysis) return;
    setAiLoading(true);
    setAiError("");
    setAiExplanation(undefined);

    try {
      const explanation = await generateAiExplanation(analysis, goal, aiConfig, {
        fingerprint,
        photo: photoContext,
        ragResults,
      });
      setAiExplanation(explanation);
    } catch (error) {
      setAiError(error instanceof Error ? error.message : String(error));
    } finally {
      setAiLoading(false);
    }
  }

  return (
    <main>
      <section className="hero">
        <div className="hero-copy">
          <p className="eyebrow">SmolSignal</p>
          <h1>AI-style signal copilot for Flipper Zero.</h1>
          <p>
            Drop a Flipper capture, describe what you want to do, and SmolSignal classifies risk with a deterministic
            safety gate. Then use Ollama, Qwen, GPT, DeepSeek, llama.cpp, or vLLM for a richer AI explanation.
          </p>
          <div className="hero-actions">
            <a href="#analyzer" className="primary-link">
              Analyze a capture
            </a>
            <a href="#ir-builder" className="secondary-link">
              Build an IR file
            </a>
            <a href="#magic-console" className="secondary-link">
              Connect Flipper
            </a>
          </div>
        </div>
        <div className="hero-card">
          <span className="pulse" />
          <h2>Safety engine</h2>
          <p>Blocks car keys, access bypass, unknown security replay, and generic hack flows.</p>
          <p>The AI is the explainer, not the permission system. Safe IR tooling stays local and deterministic.</p>
        </div>
      </section>

      <section id="analyzer" className="grid two-columns">
        <div className="panel">
          <div className="section-heading">
            <p className="eyebrow">Analyzer</p>
            <h2>Drop or paste a Flipper file</h2>
          </div>

          <div className="sample-row">
            {samples.map((sample, index) => (
              <button key={sample.label} type="button" onClick={() => loadSample(index)}>
                {sample.label}
              </button>
            ))}
          </div>

          <label className="field-label" htmlFor="goal">
            What are you trying to do?
          </label>
          <input
            id="goal"
            value={goal}
            onChange={(event) => setGoal(event.target.value)}
            placeholder="Example: build a replacement remote for my TV"
          />

          <div className="lab-box">
            <div className="section-heading compact-heading horizontal">
              <div>
                <p className="eyebrow">Authorized Lab Mode</p>
                <h3>Scoped owned/simulated work</h3>
              </div>
              <label className="switch-label">
                <input type="checkbox" checked={labEnabled} onChange={(event) => setLabEnabled(event.target.checked)} />
                <span>{labEnabled ? "On" : "Off"}</span>
              </label>
            </div>
            <p className="muted">
              Enables richer lab documentation and AI explanation for non-blocked captures when scope is provided. It does
              not unlock car keys, access credentials, gates, garages, alarms, bypass, cloning, or unknown-security replay.
            </p>
            <label className="field-label" htmlFor="labScope">
              Scope / authorization notes
            </label>
            <textarea
              id="labScope"
              className="scope-textarea"
              value={labScope}
              onChange={(event) => setLabScope(event.target.value)}
              placeholder="Describe the owned toy/demo device, simulated protocol, or isolated lab fixture."
            />
          </div>

          <div className="photo-box">
            <div className="section-heading compact-heading">
              <p className="eyebrow">Photo + capture</p>
              <h3>Add device context</h3>
            </div>
            <input type="file" accept="image/*" onChange={onPhotoChange} />
            {photoPreview ? <img className="photo-preview" src={photoPreview} alt="Device context preview" /> : null}
            {photoContext ? (
              <>
                <p className="muted">
                  {photoContext.fileName} · {photoContext.width}x{photoContext.height}
                </p>
                <label className="field-label" htmlFor="photoNotes">
                  What does the photo show?
                </label>
                <input
                  id="photoNotes"
                  value={photoContext.notes}
                  onChange={(event) => setPhotoContext({ ...photoContext, notes: event.target.value })}
                  placeholder="Example: hotel AC unit, Samsung TV, LED strip controller"
                />
                <button
                  type="button"
                  className="ghost-button inline-button"
                  onClick={() => {
                    setPhotoContext(undefined);
                    setPhotoPreview("");
                  }}
                >
                  Remove photo
                </button>
              </>
            ) : (
              <p className="muted">Optional. SmolSignal uses image metadata and your notes, not raw image data, unless you choose to send context to an AI provider.</p>
            )}
          </div>

          <div
            className={`drop-zone ${dropActive ? "drop-active" : ""}`}
            onDragOver={(event) => {
              event.preventDefault();
              setDropActive(true);
            }}
            onDragLeave={() => setDropActive(false)}
            onDrop={(event) => {
              event.preventDefault();
              setDropActive(false);
              void loadFile(event.dataTransfer.files[0]);
            }}
          >
            <input type="file" accept=".ir,.sub,.nfc,.rfid,.ibtn,.txt" onChange={onFileChange} />
            <span>Drop .ir, .sub, .nfc, .rfid, or .txt files here</span>
          </div>

          <label className="field-label" htmlFor="fileName">
            File name
          </label>
          <input id="fileName" value={fileName} onChange={(event) => setFileName(event.target.value)} />

          <label className="field-label" htmlFor="captureText">
            Capture contents
          </label>
          <textarea
            id="captureText"
            value={captureText}
            onChange={(event) => setCaptureText(event.target.value)}
            spellCheck={false}
          />
        </div>

        <div className="panel result-panel">
          <div className="section-heading horizontal">
            <div>
              <p className="eyebrow">Result</p>
              <h2>SmolSignal readout</h2>
            </div>
            {analysis ? <RiskBadge level={analysis.level} /> : null}
          </div>

          {analysis ? (
            <>
              {fingerprint ? (
                <div className="signal-identity-card">
                  <div>
                    <p className="eyebrow">Shazam for signals</p>
                    <h3>{fingerprint.label}</h3>
                    <p>{Math.round(fingerprint.confidence * 100)}% confidence · {fingerprint.signature}</p>
                  </div>
                  <RiskBadge level={fingerprint.safety} />
                </div>
              ) : null}

              <div className="readout-card">
                <h3>{analysis.summary}</h3>
                <p>{analysis.plainEnglish}</p>
              </div>

              {analysis.lab?.enabled ? (
                <div className="lab-readout">
                  <div>
                    <p className="eyebrow">Authorized Lab Mode</p>
                    <strong>{analysis.lab.effect}</strong>
                  </div>
                  <ul>
                    {analysis.lab.constraints.map((constraint) => (
                      <li key={constraint}>{constraint}</li>
                    ))}
                  </ul>
                </div>
              ) : null}

              <div className="fact-grid">
                <div>
                  <span>Decision</span>
                  <strong>{analysis.decision}</strong>
                </div>
                <div>
                  <span>Domain</span>
                  <strong>{analysis.parsed.domain}</strong>
                </div>
                <div>
                  <span>File type</span>
                  <strong>{analysis.parsed.fileType}</strong>
                </div>
                <div>
                  <span>Fields</span>
                  <strong>{analysis.parsed.fieldEntries.length}</strong>
                </div>
                {fingerprint ? (
                  <>
                    <div>
                      <span>Frequency band</span>
                      <strong>{fingerprint.features.frequencyBand}</strong>
                    </div>
                    <div>
                      <span>Modulation</span>
                      <strong>{fingerprint.features.modulation}</strong>
                    </div>
                  </>
                ) : null}
              </div>

              {fingerprint ? (
                <div className="list-block">
                  <h3>Fingerprint evidence</h3>
                  <ul>
                    {fingerprint.evidence.map((item) => (
                      <li key={item}>{item}</li>
                    ))}
                  </ul>
                  {fingerprint.warnings.length ? (
                    <div className="warning-text">
                      {fingerprint.warnings.map((warning) => (
                        <p key={warning}>{warning}</p>
                      ))}
                    </div>
                  ) : null}
                </div>
              ) : null}

              {fingerprint && passiveGuide ? (
                <div className="report-actions">
                  <button type="button" onClick={() => downloadAnalysisReport("md")}>Download Markdown report</button>
                  <button type="button" onClick={() => downloadAnalysisReport("json")}>Download JSON report</button>
                </div>
              ) : null}

              <div className="list-block">
                <h3>Findings</h3>
                {analysis.findings.map((finding) => (
                  <div className="finding" key={`${finding.title}-${finding.matched ?? "none"}`}>
                    <RiskBadge level={finding.level} />
                    <div>
                      <strong>{finding.title}</strong>
                      <p>{finding.detail}</p>
                      {finding.matched ? <small>Matched: {finding.matched}</small> : null}
                    </div>
                  </div>
                ))}
              </div>

              <div className="list-block">
                <h3>Next steps</h3>
                <ul>
                  {analysis.nextSteps.map((step) => (
                    <li key={step}>{step}</li>
                  ))}
                </ul>
              </div>

              <div className="split-list">
                <div>
                  <h3>Allowed</h3>
                  <ul>
                    {analysis.safeActions.map((action) => (
                      <li key={action}>{action}</li>
                    ))}
                  </ul>
                </div>
                <div>
                  <h3>Never generated</h3>
                  <ul>
                    {analysis.blockedActions.map((action) => (
                      <li key={action}>{action}</li>
                    ))}
                  </ul>
                </div>
              </div>

              {passiveGuide ? (
                <div className={`mode-card ${passiveGuide.enabled ? "mode-enabled" : ""}`}>
                  <div className="section-heading horizontal">
                    <div>
                      <p className="eyebrow">Passive sensor mode</p>
                      <h3>{passiveGuide.title}</h3>
                    </div>
                    <span className="risk-badge risk-caution">No transmit</span>
                  </div>
                  <p>{passiveGuide.summary}</p>
                  <div className="split-list">
                    <div>
                      <h3>Observe</h3>
                      <ul>
                        {passiveGuide.observations.map((item) => (
                          <li key={item}>{item}</li>
                        ))}
                      </ul>
                    </div>
                    <div>
                      <h3>Safe steps</h3>
                      <ul>
                        {passiveGuide.safeSteps.map((item) => (
                          <li key={item}>{item}</li>
                        ))}
                      </ul>
                    </div>
                  </div>
                </div>
              ) : null}

              {ragResults.length ? (
                <div className="list-block rag-panel">
                  <p className="eyebrow">Local vector/RAG</p>
                  <h3>Relevant built-in knowledge</h3>
                  {ragResults.map((result) => (
                    <div className="knowledge-card" key={result.document.id}>
                      <strong>{result.document.title}</strong>
                      <span>score {result.score}</span>
                      <p>{result.snippet}</p>
                    </div>
                  ))}
                </div>
              ) : null}

              {communityMatches.length ? (
                <div className="list-block community-panel">
                  <p className="eyebrow">Safe community library</p>
                  <h3>Matching safe profiles</h3>
                  {communityMatches.map((match) => (
                    <div className="community-card" key={match.profile.id}>
                      <div>
                        <strong>{match.profile.name}</strong>
                        <p>{match.profile.description}</p>
                        <small>{match.reason}</small>
                      </div>
                      <div className="community-actions">
                        <button type="button" onClick={() => loadCommunityProfile(match.profile)}>
                          {match.profile.buttons?.length ? "Load" : "Copy note"}
                        </button>
                        <button type="button" className="ghost-button" onClick={() => downloadCommunityProfile(match.profile)}>
                          Export
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              ) : null}

              <div className="ai-panel" id="ai-explainer">
                <div className="section-heading horizontal">
                  <div>
                    <p className="eyebrow">Phase 1 AI</p>
                    <h2>Ask a real model</h2>
                  </div>
                  <span className="risk-badge risk-safe">Safety-gated</span>
                </div>

                <p className="muted">
                  The model receives a sanitized analysis and must follow the safety decision above. For cloud models,
                  use the local AI bridge so API keys stay out of the browser.
                </p>

                <div className="ai-grid">
                  <label>
                    <span>Provider</span>
                    <select value={aiConfig.provider} onChange={(event) => chooseProvider(event.target.value as AiProviderConfig["provider"])}>
                      <option value="ollama">Ollama direct</option>
                      <option value="bridge">Local AI bridge</option>
                      <option value="openai-compatible">OpenAI-compatible direct</option>
                    </select>
                  </label>

                  {aiConfig.provider === "bridge" ? (
                    <label>
                      <span>Bridge upstream</span>
                      <select
                        value={aiConfig.bridgeProvider}
                        onChange={(event) => updateAiConfig({ bridgeProvider: event.target.value as AiProviderConfig["bridgeProvider"] })}
                      >
                        <option value="ollama">Ollama</option>
                        <option value="openai">OpenAI / GPT</option>
                        <option value="deepseek">DeepSeek</option>
                        <option value="qwen">Qwen / DashScope</option>
                        <option value="custom">Custom OpenAI-compatible</option>
                      </select>
                    </label>
                  ) : null}

                  <label>
                    <span>Model</span>
                    <input
                      value={aiConfig.model}
                      onChange={(event) => updateAiConfig({ model: event.target.value })}
                      placeholder="qwen2.5:7b, gpt-4o-mini, deepseek-chat"
                    />
                  </label>

                  <label>
                    <span>Temperature</span>
                    <input
                      type="number"
                      min="0"
                      max="1.5"
                      step="0.1"
                      value={aiConfig.temperature}
                      onChange={(event) => updateAiConfig({ temperature: Number(event.target.value) })}
                    />
                  </label>
                </div>

                <div className="preset-row">
                  <button type="button" onClick={() => chooseEndpointPreset("ollama")}>Ollama</button>
                  <button type="button" onClick={() => chooseEndpointPreset("bridge")}>Bridge</button>
                  <button type="button" onClick={() => chooseEndpointPreset("llamaCpp")}>llama.cpp</button>
                  <button type="button" onClick={() => chooseEndpointPreset("vllm")}>vLLM</button>
                  <button type="button" onClick={() => chooseEndpointPreset("openai")}>OpenAI</button>
                  <button type="button" onClick={() => chooseEndpointPreset("deepseek")}>DeepSeek</button>
                  <button type="button" onClick={() => chooseEndpointPreset("qwen")}>Qwen</button>
                </div>

                <label className="field-label" htmlFor="aiEndpoint">
                  Endpoint
                </label>
                <input
                  id="aiEndpoint"
                  value={aiConfig.endpoint}
                  onChange={(event) => updateAiConfig({ endpoint: event.target.value })}
                />

                {aiConfig.provider === "openai-compatible" ? (
                  <>
                    <label className="field-label" htmlFor="aiApiKey">
                      API key for direct browser mode
                    </label>
                    <input
                      id="aiApiKey"
                      value={aiConfig.apiKey}
                      onChange={(event) => updateAiConfig({ apiKey: event.target.value })}
                      placeholder="Only use direct keys locally. Prefer the bridge for cloud providers."
                      type="password"
                    />
                    <p className="warning-text">
                      Direct browser mode can expose API keys and may hit provider CORS limits. For GPT, DeepSeek, and
                      Qwen on a public/demo page, run <code>npm run ai:bridge</code> instead.
                    </p>
                  </>
                ) : null}

                <div className="builder-actions">
                  <button type="button" className="primary-button" disabled={aiLoading} onClick={askAi}>
                    {aiLoading ? "Asking model..." : "Ask AI explainer"}
                  </button>
                </div>

                {aiError ? <div className="error-box"><p>{aiError}</p></div> : null}
                {aiExplanation ? (
                  <div className="ai-answer">
                    <div className="answer-meta">
                      {aiExplanation.provider} · {aiExplanation.model}
                    </div>
                    <pre>{aiExplanation.text}</pre>
                  </div>
                ) : null}
              </div>
            </>
          ) : (
            <p>Paste a Flipper capture to see a safety readout.</p>
          )}
        </div>
      </section>

      <section id="magic-console" className="grid two-columns magic-console">
        <div className="panel">
          <div className="section-heading">
            <p className="eyebrow">Phase 3</p>
            <h2>Web Serial Flipper connection</h2>
          </div>
          <p className="muted">
            Connect status for supported browsers. SmolSignal does not perform firmware updates, cloning, replay, or bypass
            actions over serial.
          </p>
          <div className="serial-status-card">
            <strong>{serialStatus}</strong>
            <p>{serialLog}</p>
          </div>
          <div className="builder-actions">
            <button type="button" onClick={connectFlipperSerial} disabled={Boolean(serialPort)}>
              Connect via Web Serial
            </button>
            <button type="button" className="ghost-button" onClick={disconnectFlipperSerial} disabled={!serialPort}>
              Disconnect
            </button>
          </div>
        </div>

        <div className="panel">
          <div className="section-heading">
            <p className="eyebrow">Magic UX</p>
            <h2>Signal identity pipeline</h2>
          </div>
          <div className="pipeline-list">
            <div><span>1</span> Parse Flipper capture</div>
            <div><span>2</span> Match protocol/device database</div>
            <div><span>3</span> Fingerprint signal shape</div>
            <div><span>4</span> Add photo context and local RAG</div>
            <div><span>5</span> Generate safe reports, profiles, and AI explanations</div>
          </div>
        </div>
      </section>

      <section id="ir-builder" className="panel ir-builder">
        <div className="section-heading horizontal">
          <div>
            <p className="eyebrow">Safe generator</p>
            <h2>Build a consumer IR remote file</h2>
          </div>
          <span className="risk-badge risk-safe">IR only</span>
        </div>

        <p className="muted">
          This creates Flipper-compatible <code>.ir</code> files for consumer infrared devices such as TVs, fans,
          projectors, LED strips, and AC remotes. It does not generate Sub-GHz, NFC, RFID, access, vehicle, or replay
          workflows.
        </p>

        <label className="field-label" htmlFor="remoteName">
          Remote name
        </label>
        <input id="remoteName" value={remoteName} onChange={(event) => setRemoteName(event.target.value)} />

        <div className="button-table">
          {buttons.map((button, index) => (
            <div className="button-row" key={`${index}-${button.name}`}>
              <input
                aria-label="Button name"
                value={button.name}
                onChange={(event) => updateButton(index, { name: event.target.value })}
                placeholder="Button name"
              />
              <select
                aria-label="Protocol"
                value={button.protocol}
                onChange={(event) => updateButton(index, { protocol: event.target.value })}
              >
                {safeIrProtocols.map((protocol) => (
                  <option key={protocol} value={protocol}>
                    {protocol}
                  </option>
                ))}
              </select>
              <input
                aria-label="Address"
                value={button.address}
                onChange={(event) => updateButton(index, { address: event.target.value })}
                placeholder="Address hex"
              />
              <input
                aria-label="Command"
                value={button.command}
                onChange={(event) => updateButton(index, { command: event.target.value })}
                placeholder="Command hex"
              />
              <button type="button" className="ghost-button" onClick={() => removeButton(index)} disabled={buttons.length === 1}>
                Remove
              </button>
            </div>
          ))}
        </div>

        <div className="builder-actions">
          <button type="button" onClick={importIrButtonsFromCapture} disabled={analysis?.parsed.domain !== "infrared"}>
            Import current IR capture
          </button>
          <button type="button" onClick={() => setButtons((current) => [...current, { ...emptyButton, name: `Button_${current.length + 1}` }])}>
            Add button
          </button>
          <button type="button" disabled={!buildResult.ok} onClick={copyIrFile}>
            Copy .ir text
          </button>
          <button
            type="button"
            className="primary-button"
            disabled={!buildResult.ok}
            onClick={() => downloadTextFile(buildResult.fileName, buildResult.content)}
          >
            Download .ir
          </button>
        </div>

        {irImportMessage ? <p className="warning-text">{irImportMessage}</p> : null}

        {buildResult.errors.length ? (
          <div className="error-box">
            {buildResult.errors.map((error) => (
              <p key={error}>{error}</p>
            ))}
          </div>
        ) : (
          <pre className="ir-preview">{buildResult.content}</pre>
        )}
      </section>
    </main>
  );
}
