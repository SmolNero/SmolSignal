import type { SignalFingerprint } from "./fingerprintEngine";
import type { AnalysisResult, IrButton } from "./types";

export interface CommunityProfile {
  id: string;
  name: string;
  kind: "ir_profile" | "sensor_note" | "gpio_lab";
  safety: "safe" | "caution";
  description: string;
  tags: string[];
  buttons?: IrButton[];
  note?: string;
}

export interface CommunityMatch {
  profile: CommunityProfile;
  score: number;
  reason: string;
}

export const safeCommunityProfiles: CommunityProfile[] = [
  {
    id: "starter-nec-tv",
    name: "Starter NEC TV remote",
    kind: "ir_profile",
    safety: "safe",
    description: "A small consumer IR starter layout for NEC-like TV remotes. Commands are placeholders to replace with your own captured values.",
    tags: ["ir", "infrared", "nec", "tv", "power", "volume"],
    buttons: [
      { name: "Power", protocol: "NEC", address: "00 FF 00 00", command: "12 ED 00 00" },
      { name: "Volume_Up", protocol: "NEC", address: "00 FF 00 00", command: "18 E7 00 00" },
      { name: "Volume_Down", protocol: "NEC", address: "00 FF 00 00", command: "19 E6 00 00" },
      { name: "Mute", protocol: "NEC", address: "00 FF 00 00", command: "1A E5 00 00" },
    ],
  },
  {
    id: "starter-led-strip",
    name: "Starter LED strip remote",
    kind: "ir_profile",
    safety: "safe",
    description: "Safe consumer IR layout for documenting owned LED-strip remote captures.",
    tags: ["ir", "infrared", "led", "rgb", "strip", "nec"],
    buttons: [
      { name: "Power", protocol: "NEC", address: "00 FF 00 00", command: "45 BA 00 00" },
      { name: "Red", protocol: "NEC", address: "00 FF 00 00", command: "46 B9 00 00" },
      { name: "Green", protocol: "NEC", address: "00 FF 00 00", command: "47 B8 00 00" },
      { name: "Blue", protocol: "NEC", address: "00 FF 00 00", command: "44 BB 00 00" },
    ],
  },
  {
    id: "weather-sensor-note",
    name: "Weather sensor passive note",
    kind: "sensor_note",
    safety: "caution",
    description: "A safe note template for owned weather or telemetry sensor captures.",
    tags: ["subghz", "weather", "sensor", "433", "telemetry", "passive"],
    note: "Record frequency, approximate interval, location, device model, and protocol hint. Keep the workflow passive and do not replay frames.",
  },
  {
    id: "gpio-voltage-checklist",
    name: "GPIO voltage checklist",
    kind: "gpio_lab",
    safety: "safe",
    description: "Safe GPIO checklist for owned modules and sensors.",
    tags: ["gpio", "uart", "i2c", "spi", "voltage", "sensor"],
    note: "Verify voltage, ground, pin direction, and current limits before connecting Flipper GPIO to any module.",
  },
];

function tokenize(text: string) {
  return text.toLowerCase().split(/[^a-z0-9]+/).filter((token) => token.length >= 2);
}

export function findCommunityMatches(
  analysis: AnalysisResult,
  fingerprint: SignalFingerprint,
  userGoal = "",
): CommunityMatch[] {
  const query = tokenize(
    [
      userGoal,
      analysis.parsed.domain,
      fingerprint.category,
      fingerprint.label,
      fingerprint.features.protocols.join(" "),
      fingerprint.features.frequencyBand,
    ].join(" "),
  );

  return safeCommunityProfiles
    .map((profile) => {
      const haystack = tokenize(`${profile.name} ${profile.kind} ${profile.tags.join(" ")} ${profile.description}`);
      const hits = query.filter((token) => haystack.includes(token));
      const score = hits.length / Math.max(4, query.length);
      return {
        profile,
        score: Number(score.toFixed(3)),
        reason: hits.length ? `Matched ${Array.from(new Set(hits)).slice(0, 5).join(", ")}.` : "Low similarity.",
      };
    })
    .filter((match) => match.score > 0.04)
    .sort((a, b) => b.score - a.score)
    .slice(0, 4);
}

export function exportCommunityProfile(profile: CommunityProfile) {
  return JSON.stringify(
    {
      schema: "smolsignal.safe-profile.v1",
      exportedAt: new Date().toISOString(),
      profile,
      safetyNotice:
        "SmolSignal community profiles must not include car keys, access credentials, gates, garages, alarms, vehicle systems, or unknown RF replay data.",
    },
    null,
    2,
  );
}
