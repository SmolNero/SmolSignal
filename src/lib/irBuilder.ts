import type { IrBuildResult, IrButton } from "./types";

const SAFE_PROTOCOLS = ["NEC", "NECext", "Samsung32", "RC5", "RC6", "Sony", "SIRC", "Panasonic", "JVC"];

function sanitizeName(name: string, fallback: string) {
  const cleaned = name
    .trim()
    .replace(/[^a-zA-Z0-9 _-]/g, "")
    .replace(/\s+/g, "_")
    .slice(0, 48);
  return cleaned || fallback;
}

function normalizeHexBytes(value: string) {
  const cleaned = value.replace(/0x/gi, " ").replace(/[^a-fA-F0-9]/g, " ").trim();
  if (!cleaned) return "";

  const rawParts = cleaned.split(/\s+/).filter(Boolean);
  const parts = rawParts.length === 1 && rawParts[0].length > 2 ? rawParts[0].match(/.{1,2}/g) ?? [] : rawParts;

  if (!parts.length || parts.some((part) => part.length > 2 || !/^[a-fA-F0-9]+$/.test(part))) {
    return "";
  }

  return parts.map((part) => part.padStart(2, "0").toUpperCase()).join(" ");
}

function normalizeProtocol(protocol: string) {
  return SAFE_PROTOCOLS.find((candidate) => candidate.toLowerCase() === protocol.trim().toLowerCase()) ?? "";
}

function validateButton(button: IrButton, index: number) {
  const errors: string[] = [];
  const name = sanitizeName(button.name, `Button_${index + 1}`);
  const protocol = normalizeProtocol(button.protocol);
  const address = normalizeHexBytes(button.address);
  const command = normalizeHexBytes(button.command);

  if (!protocol) errors.push(`${name}: choose one of ${SAFE_PROTOCOLS.join(", ")}.`);
  if (!address) errors.push(`${name}: address must be hex bytes, for example 00 FF 00 00.`);
  if (!command) errors.push(`${name}: command must be hex bytes, for example 12 ED 00 00.`);

  return { errors, normalized: { name, protocol, address, command } };
}

export function buildIrFile(remoteName: string, buttons: IrButton[]): IrBuildResult {
  const cleanRemoteName = sanitizeName(remoteName, "SmolSignal_Remote");
  const normalizedButtons = buttons
    .map((button, index) => validateButton(button, index))
    .filter(({ normalized }) => normalized.name || normalized.protocol || normalized.address || normalized.command);

  const errors = normalizedButtons.flatMap(({ errors: itemErrors }) => itemErrors);

  if (!normalizedButtons.length) {
    errors.push("Add at least one IR button.");
  }

  if (errors.length) {
    return { ok: false, fileName: `${cleanRemoteName}.ir`, content: "", errors };
  }

  const body = normalizedButtons
    .map(({ normalized }) =>
      [
        "#",
        `name: ${normalized.name}`,
        "type: parsed",
        `protocol: ${normalized.protocol}`,
        `address: ${normalized.address}`,
        `command: ${normalized.command}`,
      ].join("\n"),
    )
    .join("\n");

  const content = [`Filetype: IR signals file`, `Version: 1`, body, ""].join("\n");

  return {
    ok: true,
    fileName: `${cleanRemoteName}.ir`,
    content,
    errors: [],
  };
}

export const safeIrProtocols = SAFE_PROTOCOLS;
