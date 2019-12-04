#!/bin/sh

OK=$(curl -s -o /dev/null -X POST \
     -d '{"jsonrpc": "2.0", "id": "1", "method": "getHealthCheck", "params": []}' \
     -H "Content-Type: application/json" -w '%{http_code}' http://localhost:3040)

if [ "$OK" == "200" ]; then
   exit 0
else
   echo $OK
   exit 1
fi