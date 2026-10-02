#!/usr/bin/env bash
# C5 negative controls: disable each rule in a scratch copy; its scenario test must fail.
set -u
root=$(cd "$(dirname "$0")/.." && pwd)
classes="NEW_PUBLISHER CONFIG_CHANGE STNUM_REGRESSION STNUM_JUMP SQNUM_RESET DATA_WITHOUT_STNUM TTL_EXPIRY TEST_MODE SIM_BIT"
red=0; total=0
for c in $classes; do
  total=$((total+1))
  work=$(mktemp -d); cp -r "$root/src" "$root/test" "$root/package.json" "$root/tsconfig.json" "$work/"
  sed -i "s/this\.raise(\"$c\",/((..._: unknown[]) => {})(\"$c\",/" "$work/src/rules.ts"
  if grep -q "this.raise(\"$c\"" "$work/src/rules.ts"; then echo "$c: mutation not applied"; continue; fi
  if (cd "$work" && bun test >/dev/null 2>&1); then echo "$c: SURVIVED (tests still green)"; else echo "$c: killed"; red=$((red+1)); fi
  rm -rf "$work"
done
echo "negative controls: $red/$total killed"
[ "$red" -eq "$total" ]
