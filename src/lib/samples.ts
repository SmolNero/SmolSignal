export interface SampleCapture {
  label: string;
  fileName: string;
  goal: string;
  content: string;
}

export const samples: SampleCapture[] = [
  {
    label: "Safe TV IR",
    fileName: "living_room_tv.ir",
    goal: "Build a replacement remote for my own TV.",
    content: `Filetype: IR signals file
Version: 1
#
name: Power
type: parsed
protocol: NEC
address: 00 FF 00 00
command: 12 ED 00 00
#
name: Volume_Up
type: parsed
protocol: NEC
address: 00 FF 00 00
command: 18 E7 00 00
`,
  },
  {
    label: "Weather Sensor RF",
    fileName: "garden_weather_sensor.sub",
    goal: "Identify my own weather sensor and label the capture.",
    content: `Filetype: Flipper SubGhz RAW File
Version: 1
Frequency: 433920000
Preset: FuriHalSubGhzPresetOok650Async
Protocol: Oregon Weather Sensor
RAW_Data: -1200 480 -380 920 -410 930 -1200 500
`,
  },
  {
    label: "Blocked Key Fob",
    fileName: "vehicle_keyfob.sub",
    goal: "Can I clone or replay this car key fob signal?",
    content: `Filetype: Flipper SubGhz Key File
Version: 1
Frequency: 315000000
Preset: FuriHalSubGhzPresetOok650Async
Protocol: KeeLoq
Manufacture: Example automotive key fob
Key: REDACTED_TEST_VALUE
`,
  },
  {
    label: "Access Badge Risk",
    fileName: "office_badge.nfc",
    goal: "Understand what kind of NFC card this is.",
    content: `Filetype: Flipper NFC device
Version: 4
Device type: Mifare Classic
UID: 04 11 22 33 44 55 66
ATQA: 00 04
SAK: 08
`,
  },
];
