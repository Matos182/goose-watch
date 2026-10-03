#!/usr/bin/env bun
// C29 negative controls for the hardening in src/rules.ts (C26-C28): each named mutant undoes one
// defence, and the test suite must fail for every one. mutate-rules.sh covers whole rules; this
// covers the guards inside them. The scratch copy holds every file git sees, and an unmutated copy
// must pass first. usage: bun scripts/mutate-hardening.ts
import { $ } from "bun";
import { cpSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const root = join(import.meta.dir, "..");
const src = readFileSync(join(root, "src/rules.ts"), "utf8");
const muts: [string, string, string][] = [
  ["RESTART_FRAMES 3→1", "const RESTART_FRAMES = 3;", "const RESTART_FRAMES = 1;"],
  ["RESTART_MIN_MS 10s→0", "const RESTART_MIN_MS = 10_000;", "const RESTART_MIN_MS = 0;"],
  ["future skew unchecked", " && age >= -FUTURE_SKEW_MS && age <= FRESH_MS;", " && age <= FRESH_MS;"],
  ["stale age unchecked", " && age >= -FUTURE_SKEW_MS && age <= FRESH_MS;", " && age >= -FUTURE_SKEW_MS;"],
  ["silence not required", "const restartEvidence = e.tMs - s.anchorSeen > tal && ", "const restartEvidence = "],
  ["anchor frame keeps restart eligibility", "      if (s.shadow) s.shadow.restartEvidence = false;\n", ""],
  ["anchor frame deletes the shadow", "      if (s.shadow) s.shadow.restartEvidence = false;", "      s.shadow = undefined;"],
  ["replayed copy proves liveness", "if (this.step(s, e, values) && advances) {", "if (this.step(s, e, values)) {"],
  ["rewinding shadow keeps evidence", "    if (e.stNum === sh.stNum && e.sqNum < sh.sqNum) sh.restartEvidence = false; // a sequence that rewinds is no reboot\n", ""],
  ["open map uncapped", "    for (const k of this.open.keys()) { if (this.open.size <= MAX_OPEN) break; this.open.delete(k); }\n", ""],
  ["overflow offender frozen", "      if (key === UNKNOWN_OVERFLOW_KEY) Object.assign(prev.detail, detail); // keep naming the latest offender\n", ""],
  ["empty gocbRef accepted", "  if (!e.gocbRef) bad.push(\"gocbRef\");\n", ""],
  ["absent publisher never reported", "      if (now - this.startMs <= wait) continue;", "      continue;"],
  ["absent publisher reported in the grace", "Math.max(known.timeAllowedToLive ?? ABSENT_DEFAULT_MS, START_GRACE_MS)", "known.timeAllowedToLive ?? ABSENT_DEFAULT_MS"],
  ["lower never replaces shadow", "if (!sh || e.stNum < sh.stNum) {", "if (!sh) {"],
  ["duplicates count", "const advances = e.stNum > sh.stNum || e.sqNum > sh.sqNum;", "const advances = true;"],
  ["TAL from frame history only", "return known.timeAllowedToLive ?? s.talSeen;", "return s.talSeen;"],
  ["TAL above baseline not alerted", " || e.timeAllowedToLive > (known.timeAllowedToLive ?? Infinity)", ""],
  ["regression folds across stNum", ", key, String(e.stNum));", ", key);"],
  ["no re-alert", " && e.tMs - prev.tMs < REALERT_MS", ""],
  ["unknown never evicted", "      if (!idle) return UNKNOWN_OVERFLOW_KEY;", "      return UNKNOWN_OVERFLOW_KEY;"],
  ["identity skipped on malformed", "      if (bad.length) this.raise(\"MALFORMED_PDU\", e, { fields: bad.join(\",\") }, alertKey);\n      if (overflow || bad.length) return;", "      if (overflow) return;"],
];

/** A scratch copy of every file git sees (tracked and untracked, not ignored), with rules.ts as given. */
async function scratch(rules: string): Promise<string> {
  const work = mkdtempSync(join(tmpdir(), "goose-mut-"));
  const files = (await $`git ls-files -co --exclude-standard`.cwd(root).text()).split("\n").filter(Boolean);
  for (const f of files) cpSync(join(root, f), join(work, f), { recursive: true });
  symlinkSync(join(root, "node_modules"), join(work, "node_modules"));
  writeFileSync(join(work, "src/rules.ts"), rules);
  return work;
}

// An unmutated copy must pass first: a suite that is red for another reason would make every mutant look killed.
const control = await scratch(src);
const ok = (await $`bun test`.cwd(control).quiet().nothrow()).exitCode === 0;
rmSync(control, { recursive: true, force: true });
if (!ok) { console.error("control: the unmutated copy fails, so no mutant result means anything"); process.exit(1); }
console.log("control: unmutated copy passes");

let survived = 0;
for (const [name, from, to] of muts) {
  if (!src.includes(from)) throw new Error(`mutant "${name}" no longer matches src/rules.ts: update this list`);
  const work = await scratch(src.replace(from, to));
  const r = await $`bun test`.cwd(work).quiet().nothrow();
  rmSync(work, { recursive: true, force: true });
  if (r.exitCode === 0) survived++;
  console.log(`${r.exitCode === 0 ? "SURVIVED" : "killed  "}  ${name}`);
}
console.log(`hardening controls: ${muts.length - survived}/${muts.length} killed`);
process.exit(survived ? 1 : 0);
