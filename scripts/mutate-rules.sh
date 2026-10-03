#!/usr/bin/env bash
# C5 negative controls: disable each rule in a scratch copy of the repository; its scenario test must fail.
# The scratch copy holds every file git sees, and an unmutated copy must pass first: a suite that is
# red for another reason would make every mutant look killed.
set -u
root=$(cd "$(dirname "$0")/.." && pwd)
classes="NEW_PUBLISHER CONFIG_CHANGE STNUM_REGRESSION STNUM_JUMP SQNUM_RESET DATA_WITHOUT_STNUM TTL_EXPIRY TEST_MODE SIM_BIT MALFORMED_PDU"
scratch() {
  local work; work=$(mktemp -d)
  (cd "$root" && git ls-files -co --exclude-standard -z | xargs -0 cp --parents -t "$work")
  ln -s "$root/node_modules" "$work/node_modules"
  echo "$work"
}
control=$(scratch)
if ! (cd "$control" && bun test >/dev/null 2>&1); then echo "control: the unmutated copy fails, so no mutant result means anything" >&2; rm -rf "$control"; exit 1; fi
rm -rf "$control"; echo "control: unmutated copy passes"
red=0; total=0
for c in $classes; do
  total=$((total+1))
  work=$(scratch)
  sed -i "s/this\.raise(\"$c\",/((..._: unknown[]) => {})(\"$c\",/" "$work/src/rules.ts"
  if grep -q "this.raise(\"$c\"" "$work/src/rules.ts"; then echo "$c: mutation not applied"; rm -rf "$work"; continue; fi
  if (cd "$work" && bun test >/dev/null 2>&1); then echo "$c: SURVIVED (tests still green)"; else echo "$c: killed"; red=$((red+1)); fi
  rm -rf "$work"
done
echo "negative controls: $red/$total killed"
[ "$red" -eq "$total" ]
