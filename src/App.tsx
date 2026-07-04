import { ChangeEvent, useState } from "react";
import { buildIrFile, safeIrProtocols } from "./lib/irBuilder";
import { analyzeCapture } from "./lib/safetyPolicy";
import { samples } from "./lib/samples";
import type { IrButton, SafetyLevel } from "./lib/types";

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

  const analysis = captureText.trim() ? analyzeCapture(captureText, fileName, goal) : undefined;
  const buildResult = buildIrFile(remoteName, buttons);

  async function loadFile(file?: File) {
    if (!file) return;
    const text = await file.text();
    setCaptureText(text);
    setFileName(file.name);
  }

  function onFileChange(event: ChangeEvent<HTMLInputElement>) {
    void loadFile(event.target.files?.[0]);
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
  }

  function copyIrFile() {
    if (!buildResult.ok) return;
    void navigator.clipboard.writeText(buildResult.content);
  }

  return (
    <main>
      <section className="hero">
        <div className="hero-copy">
          <p className="eyebrow">SmolSignal</p>
          <h1>AI-style signal copilot for Flipper Zero.</h1>
          <p>
            Drop a Flipper capture, describe what you want to do, and SmolSignal explains the signal in plain English,
            classifies risk, and only enables safe workflows like consumer IR remote generation.
          </p>
          <div className="hero-actions">
            <a href="#analyzer" className="primary-link">
              Analyze a capture
            </a>
            <a href="#ir-builder" className="secondary-link">
              Build an IR file
            </a>
          </div>
        </div>
        <div className="hero-card">
          <span className="pulse" />
          <h2>Safety engine</h2>
          <p>Blocks car keys, access bypass, unknown security replay, and generic hack flows.</p>
          <p>Allows learning, labeling, documentation, GPIO safety notes, and safe IR tooling.</p>
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
              <div className="readout-card">
                <h3>{analysis.summary}</h3>
                <p>{analysis.plainEnglish}</p>
              </div>

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
              </div>

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
            </>
          ) : (
            <p>Paste a Flipper capture to see a safety readout.</p>
          )}
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
