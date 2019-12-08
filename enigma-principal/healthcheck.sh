#!/bin/sh

OK=$(curl -s -o /dev/null -X POST \
     -d '{"jsonrpc": "2.0", "id": "1", "method": "getHealthCheck", "params": []}' \
     -H "Content-Type: application/json" http://localhost:3040 | jq -r '.result')

if [ "$OK" == "true" ]; then
   exit 0
else
   exit 1
fi