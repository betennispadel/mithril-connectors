#!/bin/sh
for v in WORKER_EGRESS_PROXY HTTP_PROXY HTTPS_PROXY ALL_PROXY http_proxy https_proxy all_proxy; do
  val=$(eval echo "\$$v" 2>/dev/null)
  [ -z "$val" ] || [ "$val" = "off" ] && continue
  fixed=$(echo "$val" | sed -E 's|(https?://)([^:/@]+)@|\1\2:\2@|')
  [ "$fixed" != "$val" ] && export $v="$fixed"
done
exec /usr/local/bin/connector "$@"
