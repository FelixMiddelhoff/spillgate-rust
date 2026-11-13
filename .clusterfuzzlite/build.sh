#!/bin/bash -eu
# Build every cargo-fuzz target of fuzz/Cargo.toml and copy it to $OUT.
# fuzz/Cargo.toml already enables the br and zstd features of the crate, so no flags are needed.
cd "$SRC/spillgate"

# Target names come from the [[bin]] tables, so a new target is picked up without editing this file.
targets=$(sed -n 's/^name = "\(.*\)"$/\1/p' fuzz/Cargo.toml | grep -vx 'spillgate-fuzz')
if [ -z "$targets" ]; then
  echo "no fuzz targets found in fuzz/Cargo.toml" >&2
  exit 1
fi

cargo fuzz build -O

out_dir=fuzz/target/x86_64-unknown-linux-gnu/release
for t in $targets; do
  cp "$out_dir/$t" "$OUT/$t"
done
