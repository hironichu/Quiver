#!/usr/bin/env sh
set -eu

# Collect generated DocC archives into Docs/docc
# Source: .build/plugins/Swift-DocC/outputs/*.doccarchive
# Dest:   Docs/docc/*.doccarchive

PROJECT_ROOT="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)"
SOURCE_DIR="$PROJECT_ROOT/.build/plugins/Swift-DocC/outputs"
DEST_DIR="$PROJECT_ROOT/Docs/docc"

echo "[docc] project root: $PROJECT_ROOT"
echo "[docc] source: $SOURCE_DIR"
echo "[docc] dest:   $DEST_DIR"

mkdir -p "$DEST_DIR"

if [ ! -d "$SOURCE_DIR" ]; then
  echo "[docc] source directory not found: $SOURCE_DIR"
  echo "[docc] generate docs first, e.g.:"
  echo "       swift package generate-documentation --target HTTP3"
  exit 1
fi

copied=0
# shellcheck disable=SC2039
for archive in "$SOURCE_DIR"/*.doccarchive; do
  if [ ! -e "$archive" ]; then
    break
  fi

  name="$(basename "$archive")"
  dest="$DEST_DIR/$name"

  rm -rf "$dest"
  cp -R "$archive" "$dest"
  copied=$((copied + 1))
  echo "[docc] copied: $name"
done

if [ "$copied" -eq 0 ]; then
  echo "[docc] no .doccarchive found in: $SOURCE_DIR"
  exit 2
fi

echo "[docc] done. copied $copied archive(s) to $DEST_DIR"