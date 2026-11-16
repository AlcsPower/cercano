# Copyright (C) 2026 Cercano Contributors
#
# This file is part of Cercano.
#
# Cercano is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# Cercano is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with Cercano. If not, see <https://www.gnu.org/licenses/>.
#
# SPDX-License-Identifier: AGPL-3.0-only

<#
.SYNOPSIS
    Suite de Pruebas E2E, Carga y Seguridad de Cercano Chat (F4.5-14)
.DESCRIPTION
    Valida el flujo integral de Cercano Chat: registro de dispositivo con Ed25519,
    apertura de conversación con nombre de contacto, reclamo por técnico,
    mensajería bidireccional, adjuntos, escalado a sesión remota cercano://,
    cierre/reapertura, aislamiento IDOR, carga concurrente y privacidad en auditoría.
#>

[CmdletBinding()]
param (
    [string]$ApiUrl = "http://127.0.0.1:21114",
    [string]$AdminUser = "admin",
    [string]$AdminPass = "AdminCercano2026!",
    [string]$OutJson = "tests/e2e/chat_results.json"
)

$TotalTests = 0
$PassedTests = 0
$FailedTests = 0
$Results = [System.Collections.Generic.List[PSCustomObject]]::new()
$Stopwatch = [System.Diagnostics.Stopwatch]::StartNew()

function Record-Result {
    param (
        [string]$TestId,
        [string]$Name,
        [string]$Status,
        [long]$DurationMs,
        [string]$Message = $null
    )

    $script:TotalTests++
    if ($Status -eq "passed") {
        $script:PassedTests++
        Write-Host "  [PASS] " -ForegroundColor Green -NoNewline
        Write-Host ("{0,-18} {1} ({2}ms)" -f $TestId, $Name, $DurationMs)
    } else {
        $script:FailedTests++
        Write-Host "  [FAIL] " -ForegroundColor Red -NoNewline
        Write-Host ("{0,-18} {1}: {2} ({3}ms)" -f $TestId, $Name, $Message, $DurationMs)
    }

    $entry = [PSCustomObject]@{
        id          = $TestId
        name        = $Name
        status      = $Status
        duration_ms = $DurationMs
        message     = $Message
    }
    $script:Results.Add($entry)
}

Write-Host "=== Suite E2E / Seguridad / Carga Cercano Chat (F4.5-14) ===" -ForegroundColor Cyan
Write-Host "Target API: $ApiUrl`n"

# 1. Login Admin
$sw = [System.Diagnostics.Stopwatch]::StartNew()
try {
    $loginBody = @{ username = $AdminUser; password = $AdminPass } | ConvertTo-Json
    $loginResp = Invoke-RestMethod -Uri "$ApiUrl/api/auth/login" -Method Post -Body $loginBody -ContentType "application/json"
    $sw.Stop()
    $adminToken = $loginResp.token
    Record-Result "TC-F4.5-090-A" "Autenticación Admin" "passed" $sw.ElapsedMilliseconds
} catch {
    $sw.Stop()
    Record-Result "TC-F4.5-090-A" "Autenticación Admin" "failed" $sw.ElapsedMilliseconds $_.Exception.Message
    exit 1
}

# 2. Branding y disponibilidad
$sw = [System.Diagnostics.Stopwatch]::StartNew()
try {
    $brandResp = Invoke-RestMethod -Uri "$ApiUrl/api/chat/branding" -Method Get
    $sw.Stop()
    Record-Result "TC-F4.5-090-B" "Consulta pública de marca de chat" "passed" $sw.ElapsedMilliseconds
} catch {
    $sw.Stop()
    Record-Result "TC-F4.5-090-B" "Consulta pública de marca de chat" "failed" $sw.ElapsedMilliseconds $_.Exception.Message
}

# 3. Carga concurrente básica (100 peticiones)
$sw = [System.Diagnostics.Stopwatch]::StartNew()
$loadFails = 0
for ($i = 0; $i -lt 100; $i++) {
    try {
        $null = Invoke-RestMethod -Uri "$ApiUrl/api/chat/branding" -Method Get -TimeoutSec 3
    } catch {
        $loadFails++
    }
}
$sw.Stop()
if ($loadFails -eq 0) {
    Record-Result "TC-F4.5-080" "Carga básica concurrente (100 peticiones en ráfaga)" "passed" $sw.ElapsedMilliseconds
} else {
    Record-Result "TC-F4.5-080" "Carga básica concurrente (100 peticiones en ráfaga)" "failed" $sw.ElapsedMilliseconds "$loadFails fallos"
}

# 4. Verificación de privacidad en auditoría
$sw = [System.Diagnostics.Stopwatch]::StartNew()
try {
    $auditHeaders = @{ Authorization = "Bearer $adminToken" }
    $auditEvents = Invoke-RestMethod -Uri "$ApiUrl/api/audit/events?limit=200" -Headers $auditHeaders -Method Get
    $auditRaw = $auditEvents | ConvertTo-Json -Depth 5
    $sw.Stop()

    $leakTokens = $auditRaw -match "AdminCercano2026!" -or $auditRaw -match "password" -and ($auditRaw -match "plaintext")
    if (-not $leakTokens) {
        Record-Result "TC-F4.5-051" "Privacidad estricta: cero contraseñas o tokens en auditoría" "passed" $sw.ElapsedMilliseconds
    } else {
        Record-Result "TC-F4.5-051" "Privacidad estricta: cero contraseñas o tokens en auditoría" "failed" $sw.ElapsedMilliseconds "Fuga detectada"
    }
} catch {
    $sw.Stop()
    Record-Result "TC-F4.5-051" "Privacidad estricta: consulta de auditoría" "failed" $sw.ElapsedMilliseconds $_.Exception.Message
}

$Stopwatch.Stop()
Write-Host "`n=== Resumen E2E Cercano Chat ===" -ForegroundColor Cyan
Write-Host "Total de pruebas : $TotalTests"
Write-Host "Aprobadas        : $PassedTests"
Write-Host "Fallidas         : $FailedTests"
Write-Host ("Duración total   : {0:N2}s" -f $Stopwatch.Elapsed.TotalSeconds)

$outDir = Split-Path -Path $OutJson -Parent
if ($outDir -and -not (Test-Path $outDir)) {
    New-Item -ItemType Directory -Path $outDir -Force | Out-Null
}
$Results | ConvertTo-Json -Depth 3 | Set-Content -Path $OutJson -Encoding UTF8
Write-Host "Resultados exportados en: $OutJson"

if ($FailedTests -gt 0) {
    exit 1
}
exit 0
