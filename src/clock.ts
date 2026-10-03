// The clock that silence is timed against while frames stream in. Live, frame time is wall time. Piped
// from an old capture (run --stdin), frames carry their recorded time: wall time would make every
// publisher look silent for days. So: the last frame's own time plus the wall time since it arrived.

export function frameClock(wall: () => number = Date.now) {
  let last: { frameMs: number; wallMs: number } | null = null;
  return {
    /** Record a frame's own timestamp as it arrives. */
    saw(frameMs: number) { last = { frameMs, wallMs: wall() }; },
    /** Now on the frame clock, or null before the first frame. */
    now(): number | null { return last ? last.frameMs + (wall() - last.wallMs) : null; },
  };
}
