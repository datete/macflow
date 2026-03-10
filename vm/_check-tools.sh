#!/bin/bash
for c in curl tar zstd gzip sed awk python3 make gcc; do
    if command -v "$c" >/dev/null 2>&1; then
        echo "$c: OK"
    else
        echo "$c: MISSING"
    fi
done
# Check python3-pyelftools
python3 -c "import elftools" >/dev/null 2>&1 && echo "python3-pyelftools: OK" || echo "python3-pyelftools: MISSING"
# Check disk space
df -h /tmp 2>/dev/null | tail -1
