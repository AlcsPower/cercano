#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Cercano Contributors
#
# Sincroniza los iconos e imagenes de marca desde branding/ hacia vendor/client/

set -euo pipefail
ROOT_DIR="$(git rev-parse --show-toplevel 2>/dev/null || pwd)"
cd "$ROOT_DIR"

if [[ -f "branding/png/cercano-icon.ico" ]]; then
  cp -f "branding/png/cercano-icon.ico" "vendor/client/res/icon.ico"
  cp -f "branding/png/cercano-icon.ico" "vendor/client/res/tray-icon.ico"
  cp -f "branding/png/cercano-icon.ico" "vendor/client/flutter/windows/runner/resources/app_icon.ico"
fi

if [[ -f "branding/png/cercano-icon-512.png" ]]; then
  cp -f "branding/png/cercano-icon-512.png" "vendor/client/res/icon.png"
fi

if [[ -f "branding/png/cercano-icon-32.png" ]]; then
  cp -f "branding/png/cercano-icon-32.png" "vendor/client/res/32x32.png"
fi

if [[ -f "branding/png/cercano-icon-64.png" ]]; then
  cp -f "branding/png/cercano-icon-64.png" "vendor/client/res/64x64.png"
fi

if [[ -f "branding/png/cercano-icon-128.png" ]]; then
  cp -f "branding/png/cercano-icon-128.png" "vendor/client/res/128x128.png"
fi

if [[ -f "branding/png/cercano-icon-256.png" ]]; then
  cp -f "branding/png/cercano-icon-256.png" "vendor/client/res/128x128@2x.png"
fi

echo "OK: Iconos de branding sincronizados en vendor/client/."
