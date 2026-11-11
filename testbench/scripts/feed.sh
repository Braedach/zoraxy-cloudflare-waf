#!/bin/bash
# feed.sh <ip> [path]  -- append one synthetic scanner request to Zoraxy's log
L=/srv/zoraxy/log/zr_$(date +%Y)-$(date +%-m).log
printf '[%s] [router:host-http] [origin:bench.example.com] [client: %s] [useragent: bench-scanner] GET %s 404\n' "$(date '+%F %T.000000')" "$1" "${2:-/.env}" >> $L
