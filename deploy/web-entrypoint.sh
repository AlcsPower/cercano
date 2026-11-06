#!/bin/sh
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Cercano Contributors
#
# Runs before nginx. Without mounted certificates nginx refuses to start, so
# generate a self-signed pair instead of leaving the console down.
set -e

CRT=/etc/nginx/certs/cercano.crt
KEY=/etc/nginx/certs/cercano.key

if [ ! -s "$CRT" ] || [ ! -s "$KEY" ]; then
    mkdir -p /etc/nginx/certs
    echo "cercano-web: no TLS certificates found; generating a self-signed pair" >&2
    openssl req -x509 -nodes -newkey rsa:2048 -days 365 \
        -subj "/CN=cercano.local" -keyout "$KEY" -out "$CRT" 2>/dev/null
fi
