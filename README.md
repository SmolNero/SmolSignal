# SmolSignal

SmolSignal is an AI signal copilot for Flipper Zero users. It turns Flipper capture files into plain-English explanations, classifies safety risk, can ask real local/cloud models for richer explanations, and generates only safe workflows such as consumer IR remote files.

## What It Does

- Reads common Flipper-style text captures: `.ir`, `.sub`, `.nfc`, `.rfid`, `.ibtn`, and `.txt`.
- Detects likely signal domain: infrared, Sub-GHz, NFC, RFID, iButton, GPIO, BLE, or unknown.
- Explains the capture in beginner-friendly language with a deterministic offline readout.
- Optionally asks real AI models through Ollama, GPT/OpenAI, DeepSeek, Qwen/DashScope, llama.cpp, vLLM, or any OpenAI-compatible endpoint.
- Fingerprints captures with a Shazam-style identity card, confidence score, signature, evidence, and warnings.
- Uses a local protocol/device category database to distinguish safe consumer IR, passive sensors, access credentials, vehicle/security signals, GPIO labs, and unknown RF.
- Provides passive sensor mode for safe RF documentation without replay/transmit steps.
- Adds local vector/RAG search over built-in safety and protocol notes.
- Supports photo context, Web Serial connection status, safe community profile matches, and exportable reports.
- Classifies the workflow as `safe`, `explain-only`, `blocked`, or `unknown`.
- Generates Flipper-compatible `.ir` files for safe consumer infrared remotes.
- Keeps the safety gate deterministic. The AI model is an explainer, not the permission system.

For risky captures, SmolSignal stays in explanation-only mode so the user can learn what category they are looking at without receiving misuse steps.

## Authorized Lab Mode

Authorized Lab Mode gives users more control for clearly owned, simulated, toy, or isolated lab work without removing SmolSignal's hard safety boundaries.

When enabled with meaningful scope notes, non-blocked caution/unknown captures can use richer workflows:

- Lab documentation.
- Exportable reports.
- Local RAG context.
- AI explanations.
- Passive sensor notes.
- Metadata, timing, and protocol-hint comparison.

Hard-blocked categories remain blocked even in lab mode:

- Car keys and vehicle systems.
- Access credentials and badges.
- Doors, gates, garages, alarms, and barriers.
- Bypass, cloning, unlock, replay, or unknown-security transmit workflows.

Example scope note:

```text
Owned toy transmitter connected to an isolated test receiver on my bench; no vehicles, credentials, gates, garages, alarms, or access systems.
```

The scope note is included in prompts and reports so the authorization context stays attached to the analysis.

## Quick Start

Requirements:

- Node.js 20 or newer.
- npm 10 or newer.

Install and run:

```bash
npm install
npm run dev
```

Open the local URL printed by Vite, usually:

```text
http://localhost:5173
```

Build for production:

```bash
npm run build
```

Preview the production build:

```bash
npm run preview
```

Run tests:

```bash
npm test
```

Run the optional local AI bridge:

```bash
npm run ai:bridge
```

## Using It With Flipper Files

1. Export or copy a Flipper text-format file such as `.ir`, `.sub`, `.nfc`, or `.rfid`.
2. Drag the file into SmolSignal or paste the text contents.
3. Describe your intent in the "What are you trying to do?" field.
4. Review the safety classification, plain-English summary, findings, and next steps.
5. Review the Shazam-style fingerprint, local RAG references, passive mode, and safe community matches.
6. Export a Markdown or JSON report if you want a durable lab note.
7. If it is a safe consumer IR workflow, use the IR Builder to create a `.ir` file.
8. Put the generated `.ir` file on your Flipper SD card under the infrared folder.

## Real Model Support

SmolSignal now has three AI modes.

| Mode | Best For | API Key Location |
| --- | --- | --- |
| `Ollama direct` | Local models such as Qwen, DeepSeek, Llama, Gemma | No API key |
| `OpenAI-compatible direct` | Local `llama.cpp`, vLLM, LM Studio, or trusted local endpoints | Browser field |
| `Local AI bridge` | GPT/OpenAI, DeepSeek, Qwen/DashScope, or custom cloud providers | Environment variable on your machine |

The deterministic safety gate runs before the model. The model receives a sanitized JSON summary, not raw replay-oriented payloads. Sensitive-looking fields such as keys, raw data, UIDs, commands, addresses, credentials, and secrets are redacted before prompting.

### Ollama Direct

Install Ollama and pull a model:

```bash
ollama pull qwen2.5:7b
ollama serve
```

Start SmolSignal:

```bash
npm run dev
```

In the app:

- Provider: `Ollama direct`
- Endpoint: `http://localhost:11434/api/chat`
- Model: `qwen2.5:7b`

If the browser blocks the local request, start Ollama with an allowed origin:

```bash
OLLAMA_ORIGINS=http://localhost:5173 ollama serve
```

### llama.cpp or vLLM Direct

Start a local OpenAI-compatible server:

```bash
llama-server -hf ggml-org/gemma-3-1b-it-GGUF --port 8080
```

In the app:

- Provider: `OpenAI-compatible direct`
- Endpoint: `http://localhost:8080/v1/chat/completions`
- Model: the model name your server expects
- API key: blank for most local servers

For vLLM, use:

```text
http://localhost:8000/v1/chat/completions
```

### GPT/OpenAI Through The Bridge

Use the bridge for cloud providers so keys are not typed into the browser:

```bash
export OPENAI_API_KEY="your_key_here"
npm run ai:bridge
```

In another terminal:

```bash
npm run dev
```

In the app:

- Provider: `Local AI bridge`
- Bridge upstream: `OpenAI / GPT`
- Endpoint: `http://localhost:8787/api/ai`
- Model: `gpt-4o-mini` or another chat model

### DeepSeek Through The Bridge

```bash
export DEEPSEEK_API_KEY="your_key_here"
npm run ai:bridge
```

In the app:

- Provider: `Local AI bridge`
- Bridge upstream: `DeepSeek`
- Model: `deepseek-chat`

### Qwen/DashScope Through The Bridge

```bash
export DASHSCOPE_API_KEY="your_key_here"
npm run ai:bridge
```

In the app:

- Provider: `Local AI bridge`
- Bridge upstream: `Qwen / DashScope`
- Model: a DashScope OpenAI-compatible model name available to your account

### Custom OpenAI-Compatible Bridge

```bash
export OPENAI_COMPATIBLE_ENDPOINT="https://your-provider.example/v1/chat/completions"
export OPENAI_COMPATIBLE_API_KEY="your_key_here"
npm run ai:bridge
```

In the app:

- Provider: `Local AI bridge`
- Bridge upstream: `Custom OpenAI-compatible`
- Model: the provider's chat model name

### Public Demo Warning

Do not put cloud API keys into a public GitHub Pages demo. Use local Ollama, a local OpenAI-compatible server, or the local AI bridge. If you host SmolSignal from a non-local origin and want it to call your local bridge, set `SMOLSIGNAL_ALLOWED_ORIGINS` before running the bridge:

```bash
SMOLSIGNAL_ALLOWED_ORIGINS=https://YOUR_USERNAME.github.io npm run ai:bridge
```

## Useful Signal Intelligence

### Signal-Aware Safety Gate

The safety gate now consumes signal features directly instead of relying only on text/protocol labels.

Each decision includes weighted evidence from:

- Domain: IR, Sub-GHz, NFC/RFID/iButton, GPIO, unknown.
- Frequency band: 315 MHz, 390 MHz, 433 MHz, 868 MHz, 915 MHz, or exact MHz when outside common bands.
- Protocol hints: safe consumer IR, sensor telemetry, rolling-code/security, credential/tag families.
- Shannon entropy: field text entropy, raw timing/value entropy, and hex-byte entropy.
- Timing shape: raw value count, min/max/average, standard deviation, unique ratio, and sign alternation ratio.
- User intent: clone, bypass, unlock, replay, transmit, badge, key fob, etc.
- Authorized Lab Mode scope.

Frequency alone never decides. It is weighted context. For example:

- `433 MHz + Oregon/weather terms` becomes passive sensor/caution.
- `433 MHz + unknown RAW` stays explain-only/passive.
- `315 MHz + KeeLoq + key-fob/replay intent` becomes blocked.
- `IR + NEC/Samsung/Sony` becomes allowed.

The UI shows a `Why this decision?` panel with safe/caution/blocked scores and every evidence item that contributed to the gate result.

### Capture Fingerprinting

Every analyzed capture gets a deterministic fingerprint:

- Likely category.
- Confidence score.
- Stable `smol-*` signature.
- Protocol/device evidence.
- Frequency band and modulation/preset summary.
- Raw pulse/value statistics when available.
- Shannon entropy metrics used by the safety gate.
- Safety warnings.

The fingerprint is intentionally conservative. A frequency band alone cannot classify a capture as safe or blocked; stronger protocol, text, and safety-gate evidence are required.

### Protocol/Device Category Database

SmolSignal includes a local protocol knowledge base for:

- Consumer IR remotes.
- Passive weather/sensor telemetry.
- TPMS-style passive sensors.
- Rolling-code/security remotes.
- Automotive/key-fob risk.
- Access-control credentials/tags.
- General NFC tags.
- GPIO/lab hardware.

This database powers the Shazam-style identity card and safe community library matching.

### Passive Sensor Mode

Sub-GHz sensor-like captures get a passive guide with:

- Observations to record.
- Safe documentation steps.
- Clear `never do` boundaries.
- No replay, no spoofing, no transmit workflow.

### Better IR Remote Generation

The IR Builder now supports:

- Parsed Flipper `.ir` button import from the current capture.
- Duplicate button-name validation.
- Safe starter profiles from the local community library.
- Markdown/JSON analysis reports that can include the AI explanation.

### Exportable Reports

Use the report buttons in the readout panel to export:

- Markdown lab notes.
- JSON analysis bundles.

Reports include the safety decision, fingerprint, evidence, passive guide, local RAG matches, safe community matches, photo metadata/notes, and optional AI explanation.

## Local UX

### Web Serial Flipper Connection

The Web Serial panel can request and open a USB serial connection in supported browsers.

Requirements:

- Chrome or Edge on desktop.
- A secure context such as `localhost` or HTTPS.
- Flipper connected over USB.

Current scope:

- Connection status.
- USB vendor/product info when available.
- Safe import/export workflow guidance.

Out of scope:

- Firmware updates.
- Replay/transmit automation.
- Credential operations.
- Bypass or cloning flows.

### Photo + Capture Analysis

Attach an image of the device or remote and add a short note such as `hotel AC unit`, `Samsung TV`, or `outdoor weather sensor`. SmolSignal uses image metadata and your notes to improve the fingerprint and AI explanation context.

The app does not send raw image bytes to AI providers. Only file name, dimensions, and your notes are included in the safe prompt context.

### Shazam For Signals

The identity card combines:

- Parsed Flipper metadata.
- Protocol database matches.
- Frequency and modulation features.
- Photo context.
- Local RAG snippets.
- Safety-gate output.

The result is a plain-English likely category with confidence and evidence.

### Local Vector Search/RAG

SmolSignal includes a small local knowledge base and a browser-side vector search. It retrieves relevant safety/protocol snippets and can pass those snippets into the AI explainer as safe context.

### Safe Community Profile Library

The community library is local and safety-filtered. It includes only:

- Consumer IR starter profiles.
- Passive sensor note templates.
- GPIO lab checklists.

It does not include vehicle, access, garage/gate, alarm, credential, or unknown-RF replay profiles.

## IR Builder

The IR Builder creates Flipper-compatible files like this:

```text
Filetype: IR signals file
Version: 1
#
name: Power
type: parsed
protocol: NEC
address: 00 FF 00 00
command: 12 ED 00 00
```

Supported safe IR protocol labels in this MVP:

- `NEC`
- `NECext`
- `Samsung32`
- `RC5`
- `RC6`
- `Sony`
- `SIRC`
- `Panasonic`
- `JVC`

## Project Structure

```text
src/App.tsx                    Main React UI
src/styles.css                 Responsive app styling
src/lib/flipperParser.ts       Flipper text parser
src/lib/safetyPolicy.ts        Safety classifier and explanations
src/lib/aiClient.ts            AI provider client, prompt builder, and redaction
src/lib/protocolDatabase.ts    Local protocol/device category database
src/lib/fingerprintEngine.ts   Signal fingerprinting and confidence scoring
src/lib/passiveSensor.ts       Passive sensor documentation mode
src/lib/localRag.ts            Local vector search/RAG over built-in docs
src/lib/communityLibrary.ts    Safe local profile/template library
src/lib/reportExporter.ts      Markdown and JSON report exporters
src/lib/irBuilder.ts           Safe .ir generator
src/lib/samples.ts             Built-in demo captures
server/ai-bridge.mjs           Optional local bridge for cloud providers
src/lib/*.test.ts              Unit tests
```

## GitHub Upload

This repo is ready to push as a normal static web app.

```bash
git init
git add .
git commit -m "Initial SmolSignal app"
git branch -M main
git remote add origin https://github.com/YOUR_USERNAME/SmolSignal.git
git push -u origin main
```

If this directory already has a git remote, inspect it first:

```bash
git remote -v
git status
```

## GitHub Pages Deploy Option

SmolSignal is a static Vite app, so it can be hosted on GitHub Pages, Netlify, Vercel, Cloudflare Pages, or any static host.

For GitHub Pages, set your repository Pages source to a built static deployment, or add a GitHub Actions workflow later that runs:

```bash
npm ci
npm run build
```

and publishes `dist/`.

## License

MIT. See `LICENSE`.
