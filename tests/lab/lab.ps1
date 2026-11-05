# Copyright (C) 2026 Cercano Contributors
# SPDX-License-Identifier: AGPL-3.0-only
<#
.SYNOPSIS
  Gestión del laboratorio de pruebas LAN de Cercano en Docker Desktop.
.EXAMPLE
  .\lab.ps1 up
  .\lab.ps1 status
  .\lab.ps1 smoke
  .\lab.ps1 netem latency 50
  .\lab.ps1 netem drop-udp
  .\lab.ps1 netem reset
  .\lab.ps1 down
#>

param(
    [Parameter(Position=0)]
    [ValidateSet("up", "down", "status", "logs", "smoke", "netem", "help")]
    [string]$Action = "help",

    [Parameter(Position=1)]
    [string]$Arg1,

    [Parameter(Position=2)]
    [string]$Arg2
)

$ErrorActionPreference = "Stop"
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ComposeFile = Join-Path $ScriptDir "docker-compose.yml"

function Show-Help {
    Write-Host "Uso: .\lab.ps1 <comando> [argumentos]" -ForegroundColor Cyan
    Write-Host "Comandos:"
    Write-Host "  up             Construye y levanta los servicios del laboratorio LAN"
    Write-Host "  down           Detiene y elimina contenedores y redes del laboratorio"
    Write-Host "  status         Muestra el estado de los contenedores"
    Write-Host "  logs [svc]     Muestra logs (ej: .\lab.ps1 logs cercano-api-stub)"
    Write-Host "  smoke          Ejecuta smoke test básico de conectividad"
    Write-Host "  netem latency <ms>   Agrega latencia artificial en client-linux-1"
    Write-Host "  netem drop-udp       Bloquea UDP directo para forzar relay hbbr"
    Write-Host "  netem reset          Limpia las reglas de red en los clientes"
}

switch ($Action) {
    "up" {
        Write-Host "==> Levantando laboratorio LAN en Docker Desktop..." -ForegroundColor Green
        docker compose -f $ComposeFile up -d --build
        Write-Host "==> Laboratorio activo." -ForegroundColor Green
        docker compose -f $ComposeFile ps
    }
    "down" {
        Write-Host "==> Deteniendo laboratorio LAN..." -ForegroundColor Yellow
        docker compose -f $ComposeFile down -v
        Write-Host "==> Laboratorio destruido." -ForegroundColor Yellow
    }
    "status" {
        docker compose -f $ComposeFile ps
    }
    "logs" {
        if ($Arg1) {
            docker compose -f $ComposeFile logs -f $Arg1
        } else {
            docker compose -f $ComposeFile logs --tail=50
        }
    }
    "smoke" {
        Write-Host "==> Verificando endpoint /healthz en API Stub (172.28.0.10 / localhost:21114)..." -ForegroundColor Cyan
        try {
            $resp = Invoke-RestMethod -Uri "http://localhost:21114/healthz" -Method Get -TimeoutSec 5
            Write-Host "API Stub OK: $($resp | ConvertTo-Json -Compress)" -ForegroundColor Green
        } catch {
            Write-Host "ERROR: No responde API Stub en localhost:21114" -ForegroundColor Red
            exit 1
        }

        Write-Host "==> Verificando conectividad LAN entre client-linux-1 y client-linux-2..." -ForegroundColor Cyan
        docker exec cercano-client-linux-1 ping -c 2 172.28.0.22 | Out-Null
        if ($LASTEXITCODE -eq 0) {
            Write-Host "Ping client-1 -> client-2: OK (172.28.0.22)" -ForegroundColor Green
        } else {
            Write-Host "Ping falló" -ForegroundColor Red
            exit 1
        }

        Write-Host "==> Verificando puertos del servidor desde client-linux-1..." -ForegroundColor Cyan
        docker exec cercano-client-linux-1 nc -z -v -w 2 172.28.0.11 21115
        Write-Host "==> Smoke test completado con éxito." -ForegroundColor Green
    }
    "netem" {
        switch ($Arg1) {
            "latency" {
                $ms = if ($Arg2) { $Arg2 } else { "100" }
                Write-Host "==> Aplicando latencia de ${ms}ms en client-linux-1..." -ForegroundColor Yellow
                docker exec --privileged cercano-client-linux-1 sh -c "tc qdisc del dev eth0 root 2>/dev/null || true; tc qdisc add dev eth0 root netem delay ${ms}ms"
                Write-Host "Latencia configurada: ${ms}ms." -ForegroundColor Green
            }
            "drop-udp" {
                Write-Host "==> Bloqueando tráfico UDP saliente directo hacia client-2 (forzar relay)..." -ForegroundColor Yellow
                docker exec --privileged cercano-client-linux-1 sh -c "iptables -F 2>/dev/null || true; iptables -A OUTPUT -p udp -d 172.28.0.22 -j DROP"
                Write-Host "Tráfico UDP directo bloqueado en client-1. Sesión obligada a relay." -ForegroundColor Green
            }
            "reset" {
                Write-Host "==> Limpiando reglas tc netem e iptables..." -ForegroundColor Cyan
                docker exec --privileged cercano-client-linux-1 sh -c "tc qdisc del dev eth0 root 2>/dev/null || true; iptables -F 2>/dev/null || true"
                Write-Host "Reglas de red restablecidas." -ForegroundColor Green
            }
            default {
                Write-Host "Subcomando netem no reconocido. Usa: latency <ms>, drop-udp, reset" -ForegroundColor Red
            }
        }
    }
    default {
        Show-Help
    }
}
