#!/bin/sh
set +e

FILTER="${2:-multipleBidiStreams}"
MAX_RUNS="${1:-30}"
n=0
failures=0

while [ "$n" -lt "$MAX_RUNS" ]; do
    n=$((n + 1))
    out=$(swift test --skip-build --filter "$FILTER" 2>&1)
    if echo "$out" | grep -q "DIAG"; then
        failures=$((failures + 1))
        echo "=== FAILURE on run $n ==="
        echo "$out" | grep -E "DIAG|readFromStream|finishedStreams|notifyStream"
        echo "=== END FAILURE ==="
    fi
done

echo ""
echo "Done: $failures failures out of $MAX_RUNS runs"