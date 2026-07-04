# SmolSignal

SmolSignal is an offline-first, AI-style signal copilot for Flipper Zero users. It turns Flipper capture files into plain-English explanations, classifies safety risk, and generates only safe workflows such as consumer IR remote files.

This is not a bypass or cloning tool. The safety engine blocks car key cloning, access-control bypass, unknown security replay, and generic "hack this device" flows.

## What It Does

- Reads common Flipper-style text captures: `.ir`, `.sub`, `.nfc`, `.rfid`, `.ibtn`, and `.txt`.
- Detects likely signal domain: infrared, Sub-GHz, NFC, RFID, iButton, GPIO, BLE, or unknown.
- Explains the capture in beginner-friendly language.
- Classifies the workflow as `safe`, `explain-only`, `blocked`, or `unknown`.
- Generates Flipper-compatible `.ir` files for safe consumer infrared remotes.
- Runs locally in your browser with no paid API and no cloud dependency.

## Safety Boundaries

SmolSignal will not generate:

- Car key cloning or unlock flows.
- Access badge/card cloning.
- Bypass instructions for doors, gates, alarms, or vehicles.
- Replay/transmit workflows for unknown or security-like RF captures.
- Generic "hack this device" instructions.

For risky captures, SmolSignal stays in explanation-only mode so the user can learn what category they are looking at without receiving misuse steps.

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

## Using It With Flipper Files

1. Export or copy a Flipper text-format file such as `.ir`, `.sub`, `.nfc`, or `.rfid`.
2. Drag the file into SmolSignal or paste the text contents.
3. Describe your intent in the "What are you trying to do?" field.
4. Review the safety classification, plain-English summary, findings, and next steps.
5. If it is a safe consumer IR workflow, use the IR Builder to create a `.ir` file.
6. Put the generated `.ir` file on your Flipper SD card under the infrared folder.

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
src/lib/irBuilder.ts           Safe .ir generator
src/lib/samples.ts             Built-in demo captures
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

## Roadmap Ideas

- Optional local `llama.cpp`/Ollama explanation backend.
- More Flipper file formats and protocol hints.
- Community IR profile import/export.
- Safer GPIO wiring assistant.
- RF sensor labeling for weather and telemetry captures.
- Lab-only simulated protocol tutorials.

## License

MIT. See `LICENSE`.
