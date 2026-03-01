#!/usr/bin/env bash
for i in $(seq 1 10); do
    code=$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:8080/ 2>/dev/null)
    echo "attempt $i: http=$code"
    if [ "$code" = "200" ] || [ "$code" = "301" ] || [ "$code" = "302" ] || [ "$code" = "403" ]; then
        echo "iStoreOS web is UP"
        exit 0
    fi
    sleep 5
done
echo "timeout waiting for iStoreOS"
exit 1
