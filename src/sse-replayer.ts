export type SseEvent = { data: string; event?: string; id?: string };

export function parseSseBody(raw: string): SseEvent[] {
  const events: SseEvent[] = [];
  for (const block of raw.split(/\n\n+/)) {
    if (!block.trim()) continue;
    const ev: SseEvent = { data: "" };
    for (const line of block.split("\n")) {
      if (line.startsWith("data:")) ev.data += line.slice(5).trimStart() + "\n";
      else if (line.startsWith("event:")) ev.event = line.slice(6).trim();
      else if (line.startsWith("id:")) ev.id = line.slice(3).trim();
    }
    ev.data = ev.data.replace(/\n$/, "");
    events.push(ev);
  }
  return events;
}

export function serializeSseEvent(ev: SseEvent): string {
  const lines: string[] = [];
  if (ev.event) lines.push(`event: ${ev.event}`);
  if (ev.id) lines.push(`id: ${ev.id}`);
  for (const part of ev.data.split("\n")) lines.push(`data: ${part}`);
  return lines.join("\n") + "\n\n";
}

export function serializeSseStream(events: SseEvent[]): string {
  return events.map(serializeSseEvent).join("");
}

export async function replaySseChunks(events: SseEvent[], write: (chunk: string) => void): Promise<number> {
  const start = performance.now();
  for (const ev of events) write(serializeSseEvent(ev));
  return performance.now() - start;
}
