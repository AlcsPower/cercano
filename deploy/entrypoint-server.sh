#!/usr/bin/env bash
# SPDX-License-Identifier: AGPL-3.0-only
# Copyright (C) 2026 Cercano Contributors
set -e

# Si el primer argumento es una opción o no se pasó comando, ejecutar hbbs por defecto
if [ "${1#-}" != "$1" ]; then
    set -- /opt/cercano/bin/hbbs "$@"
elif [ "$1" = "hbbs" ]; then
    shift
    set -- /opt/cercano/bin/hbbs "$@"
elif [ "$1" = "hbbr" ]; then
    shift
    set -- /opt/cercano/bin/hbbr "$@"
fi

exec "$@"
