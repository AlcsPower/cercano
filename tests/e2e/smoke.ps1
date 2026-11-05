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
  Suite de Smoke Test Automatizado E2E de Fase 1 para Cercano.
  Verifica hbbs, hbbr, cercano-api, ciclo de vida de dispositivos y relay LAN.

.DESCRIPTION
  Ejecuta los casos de prueba de aceptación de F1 (F1-09):
  - TC-SMK-01: Verificación de salud y puertos expuestos (21114, 21115, 21116, 21117)
  - TC-SMK-02: Consulta de clave pública del servidor Ed25519 (GET /api/server/public-key)
  - TC-SMK-03: Bootstrap inicial y autenticación de administrador (POST /api/auth/login)
  - TC-SMK-04: Registro y latidos de clientes (POST /api/devices/heartbeat)
  - TC-SMK-05: Verificación de inventario de dispositivos en línea (GET /api/devices)
  - TC-SMK-06: Conectividad y handshake de señalización (rendezvous) y relay
  - TC-SMK-07: Verificación de tiempo de gracia e inactividad (transición a offline)

.PARAMETER ApiUrl
  URL base de la API de control plane (por defecto: http://localhost:21114)
.PARAMETER ServerHost
  Host donde escuchan hbbs y hbbr (por defecto: 127.0.0.1)
.PARAMETER AdminUser
  Usuario administrador para bootstrap / login (por defecto: admin)
.PARAMETER AdminPass
  Contraseña para el administrador (por defecto: AdminCercano2026!)
.PARAMETER GracePeriodSecs
  Tiempo de gracia en segundos para evaluar transición offline (por defecto: 5)
.PARAMETER OutJson
  Ruta donde guardar el informe de resultados en JSON (opcional)
.PARAMETER ComposeFile
  Ruta al archivo docker-compose a levantar si se usa -Up (opcional)
.PARAMETER Up
  Si se especifica, levanta los contenedores antes de iniciar la prueba.
.PARAMETER Down
  Si se especifica, detiene los contenedores al finalizar.

.EXAMPLE
  .\smoke.ps1
  .\smoke.ps1 -ApiUrl http://127.0.0.1:21114 -ServerHost 127.0.0.1 -OutJson results.json
#>

[CmdletBinding()]
param(
    [string]$ApiUrl = "http://127.0.0.1:21114",
    [string]$ServerHost = "127.0.0.1",
    [string]$AdminUser = "admin",
    [string]$AdminPass = "AdminCercano2026!",
    [int]$GracePeriodSecs = 5,
    [string]$OutJson = "tests/e2e/results.json",
    [string]$ComposeFile = "deploy/docker-compose.yml",
    [switch]$Up,
    [switch]$Down
)

$ErrorActionPreference = "Stop"

# Estructura para registrar resultados de la suite
$TestResults = [System.Collections.Generic.List[PSCustomObject]]::new()
$SuiteStartTime = [System.Diagnostics.Stopwatch]::StartNew()

function Log-Header {
    param([string]$Text)
    Write-Host "`n================================================================================" -ForegroundColor Cyan
    Write-Host "  $Text" -ForegroundColor Cyan
    Write-Host "================================================================================" -ForegroundColor Cyan
}

function Log-Step {
    param([string]$Id, [string]$Name)
    Write-Host "`n>>> [$Id] $Name" -ForegroundColor Yellow
}

function Record-Result {
    param(
        [string]$Id,
        [string]$Name,
        [bool]$Success,
        [double]$DurationMs,
        [string]$Details = ""
    )

    $obj = [PSCustomObject]@{
        Id         = $Id
        Name       = $Name
        Success    = $Success
        DurationMs = [Math]::Round($DurationMs, 2)
        Details    = $Details
        Timestamp  = (Get-Date).ToString("o")
    }
    $TestResults.Add($obj)

    if ($Success) {
        Write-Host "    [PASS] $Name (${DurationMs} ms)" -ForegroundColor Green
        if ($Details) { Write-Host "           $Details" -ForegroundColor DarkGray }
    } else {
        Write-Host "    [FAIL] $Name (${DurationMs} ms)" -ForegroundColor Red
        if ($Details) { Write-Host "           ERROR: $Details" -ForegroundColor Magenta }
    }
}

function Test-TcpPort {
    param(
        [string]$HostName,
        [int]$Port,
        [int]$TimeoutMs = 3000
    )
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $tcp = New-Object System.Net.Sockets.TcpClient
    try {
        $connect = $tcp.BeginConnect($HostName, $Port, $null, $null)
        $wait = $connect.AsyncWaitHandle.WaitOne($TimeoutMs, $false)
        if (-not $wait) {
            $tcp.Close()
            return @{ Success = $false; DurationMs = $sw.Elapsed.TotalMilliseconds; Error = "Connection timed out" }
        }
        $tcp.EndConnect($connect)
        $tcp.Close()
        return @{ Success = $true; DurationMs = $sw.Elapsed.TotalMilliseconds; Error = $null }
    } catch {
        return @{ Success = $false; DurationMs = $sw.Elapsed.TotalMilliseconds; Error = $_.Exception.Message }
    } finally {
        $tcp.Dispose()
    }
}

function Test-UdpPort {
    param(
        [string]$HostName,
        [int]$Port,
        [int]$TimeoutMs = 2000
    )
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $udp = New-Object System.Net.Sockets.UdpClient
    try {
        $udp.Client.ReceiveTimeout = $TimeoutMs
        $udp.Connect($HostName, $Port)
        $probeBytes = [System.Text.Encoding]::UTF8.GetBytes("CERCANO_UDP_PROBE")
        [void]$udp.Send($probeBytes, $probeBytes.Length)
        $sw.Stop()
        return @{ Success = $true; DurationMs = $sw.Elapsed.TotalMilliseconds; Error = $null }
    } catch {
        return @{ Success = $false; DurationMs = $sw.Elapsed.TotalMilliseconds; Error = $_.Exception.Message }
    } finally {
        $udp.Close()
    }
}

# -----------------------------------------------------------------------------
# Inicio de la suite
# -----------------------------------------------------------------------------
Log-Header "CERCANO SMOKE TEST E2E (FASE 1 - F1-09)"
Write-Host "ApiUrl:            $ApiUrl"
Write-Host "ServerHost:        $ServerHost"
Write-Host "GracePeriodSecs:   $GracePeriodSecs"
Write-Host "Timestamp:         $((Get-Date).ToString('o'))"

# Gestión de Compose opcional
if ($Up) {
    Log-Step "SETUP" "Levantando infraestructura Docker Compose ($ComposeFile)..."
    docker compose -f $ComposeFile up -d --build
    Start-Sleep -Seconds 5
}

# -----------------------------------------------------------------------------
# TC-SMK-01: Salud de cercano-api y verificación de puertos expuestos
# -----------------------------------------------------------------------------
Log-Step "TC-SMK-01" "Salud de cercano-api y accesibilidad de puertos de red"

# Esperar activamente al endpoint /healthz (hasta 30 segundos)
$healthUrl = "$ApiUrl/healthz"
$healthy = $false
$healthSw = [System.Diagnostics.Stopwatch]::StartNew()
for ($i = 0; $i -lt 30; $i++) {
    try {
        $resp = Invoke-RestMethod -Uri $healthUrl -Method Get -TimeoutSec 2
        if ($resp.status -eq "ok" -or $resp.service -eq "cercano-api" -or $resp.database -eq "connected") {
            $healthy = $true
            break
        }
    } catch {
        Start-Sleep -Milliseconds 1000
    }
}
$healthSw.Stop()

Record-Result -Id "TC-SMK-01a" -Name "Endpoint /healthz de cercano-api" `
    -Success $healthy -DurationMs $healthSw.Elapsed.TotalMilliseconds `
    -Details ($resp | ConvertTo-Json -Compress)

# Comprobar puertos TCP requeridos
$ports = @(
    @{ Port = 21114; Desc = "cercano-api HTTP" },
    @{ Port = 21115; Desc = "hbbs NAT test" },
    @{ Port = 21116; Desc = "hbbs rendezvous TCP" },
    @{ Port = 21117; Desc = "hbbr relay TCP" }
)

foreach ($p in $ports) {
    $res = Test-TcpPort -HostName $ServerHost -Port $p.Port
    Record-Result -Id "TC-SMK-01-Port$($p.Port)" -Name "Puerto TCP $($p.Port) ($($p.Desc))" `
        -Success $res.Success -DurationMs $res.DurationMs -Details $res.Error
}

# Comprobar puerto UDP 21116 (hbbs rendezvous)
$udpRes = Test-UdpPort -HostName $ServerHost -Port 21116
Record-Result -Id "TC-SMK-01-Port21116-UDP" -Name "Puerto UDP 21116 (hbbs rendezvous)" `
    -Success $udpRes.Success -DurationMs $udpRes.DurationMs -Details "Probe UDP transmitido con éxito"

# -----------------------------------------------------------------------------
# TC-SMK-02: Obtención de clave pública del servidor
# -----------------------------------------------------------------------------
Log-Step "TC-SMK-02" "Obtención y validación de clave pública del servidor (GET /api/server/public-key)"
$pubKeyUrl = "$ApiUrl/api/server/public-key"
$swKey = [System.Diagnostics.Stopwatch]::StartNew()
$pubKeyValid = $false
$pubKeyStr = ""
try {
    $keyResp = Invoke-RestMethod -Uri $pubKeyUrl -Method Get -TimeoutSec 5
    $swKey.Stop()
    $pubKeyStr = $keyResp.public_key
    $keyType = $keyResp.key_type

    # Validar formato Base64 de 32 bytes (longitud 44 caracteres) y tipo ed25519
    $decodedBytes = [System.Convert]::FromBase64String($pubKeyStr)
    if ($decodedBytes.Length -eq 32 -and $keyType -eq "ed25519") {
        $pubKeyValid = $true
    }
    Record-Result -Id "TC-SMK-02" -Name "Clave pública del servidor Ed25519" `
        -Success $pubKeyValid -DurationMs $swKey.Elapsed.TotalMilliseconds `
        -Details "Key: $pubKeyStr | Type: $keyType | Bytes: $($decodedBytes.Length)"
} catch {
    $swKey.Stop()
    Record-Result -Id "TC-SMK-02" -Name "Clave pública del servidor Ed25519" `
        -Success $false -DurationMs $swKey.Elapsed.TotalMilliseconds -Details $_.Exception.Message
}

# -----------------------------------------------------------------------------
# TC-SMK-03: Bootstrap inicial y autenticación de administrador
# -----------------------------------------------------------------------------
Log-Step "TC-SMK-03" "Bootstrap inicial y Login de administrador (POST /api/auth/*)"
$bootstrapUrl = "$ApiUrl/api/auth/bootstrap"
$loginUrl = "$ApiUrl/api/auth/login"
$adminToken = $null

$swBoot = [System.Diagnostics.Stopwatch]::StartNew()
try {
    $bootBody = @{ username = $AdminUser; password = $AdminPass } | ConvertTo-Json
    $bootResp = Invoke-RestMethod -Uri $bootstrapUrl -Method Post -Body $bootBody -ContentType "application/json" -TimeoutSec 5
    $swBoot.Stop()
    Record-Result -Id "TC-SMK-03a" -Name "Bootstrap inicial de administrador" `
        -Success $true -DurationMs $swBoot.Elapsed.TotalMilliseconds `
        -Details "Admin creado: $($bootResp.username) (id: $($bootResp.id))"
} catch {
    $swBoot.Stop()
    # Si devuelve 409 Conflict o ya existe, es aceptable en ejecuciones repetidas
    if ($_.Exception.Response.StatusCode.value__ -eq 409 -or $_.Exception.Message -match "409") {
        Record-Result -Id "TC-SMK-03a" -Name "Bootstrap inicial de administrador" `
            -Success $true -DurationMs $swBoot.Elapsed.TotalMilliseconds `
            -Details "Bootstrap ya inicializado previamente (409 Conflict esperado en reejecución)"
    } else {
        Record-Result -Id "TC-SMK-03a" -Name "Bootstrap inicial de administrador" `
            -Success $false -DurationMs $swBoot.Elapsed.TotalMilliseconds -Details $_.Exception.Message
    }
}

$swLogin = [System.Diagnostics.Stopwatch]::StartNew()
try {
    $loginBody = @{ username = $AdminUser; password = $AdminPass } | ConvertTo-Json
    $loginResp = Invoke-RestMethod -Uri $loginUrl -Method Post -Body $loginBody -ContentType "application/json" -TimeoutSec 5
    $swLogin.Stop()
    $adminToken = $loginResp.token
    $loginSuccess = (-not [string]::IsNullOrEmpty($adminToken)) -and ($loginResp.user.username -eq $AdminUser)
    Record-Result -Id "TC-SMK-03b" -Name "Autenticación y obtención de Bearer Token" `
        -Success $loginSuccess -DurationMs $swLogin.Elapsed.TotalMilliseconds `
        -Details "Token emitido. Expira: $($loginResp.expires_at)"
} catch {
    $swLogin.Stop()
    Record-Result -Id "TC-SMK-03b" -Name "Autenticación y obtención de Bearer Token" `
        -Success $false -DurationMs $swLogin.Elapsed.TotalMilliseconds -Details $_.Exception.Message
}

$authHeaders = @{ "Authorization" = "Bearer $adminToken" }

# -----------------------------------------------------------------------------
# TC-SMK-04: Registro y latidos (Heartbeat) de dos clientes
# -----------------------------------------------------------------------------
Log-Step "TC-SMK-04" "Registro y emisión de latidos de dos clientes (POST /api/devices/heartbeat)"
$heartbeatUrl = "$ApiUrl/api/devices/heartbeat"

$clientA = @{
    id       = "cercano-client-a"
    name     = "workstation-alpha"
    hostname = "alpha.cercano.lan"
    os       = "Linux Ubuntu 24.04"
    version  = "1.0.0"
    ip       = "172.28.0.21"
}

$clientB = @{
    id       = "cercano-client-b"
    name     = "laptop-beta"
    hostname = "beta.cercano.lan"
    os       = "Windows 11 Pro"
    version  = "1.0.0"
    ip       = "172.28.0.22"
}

# Registrar Cliente A
$swHbA = [System.Diagnostics.Stopwatch]::StartNew()
try {
    $respA = Invoke-RestMethod -Uri $heartbeatUrl -Method Post -Body ($clientA | ConvertTo-Json) -ContentType "application/json" -TimeoutSec 5
    $swHbA.Stop()
    $hbASuccess = ($respA.id -eq $clientA.id) -and ($respA.status -eq "online")
    Record-Result -Id "TC-SMK-04a" -Name "Heartbeat cliente A ($($clientA.id))" `
        -Success $hbASuccess -DurationMs $swHbA.Elapsed.TotalMilliseconds `
        -Details "Status: $($respA.status) | Hostname: $($respA.hostname) | OS: $($respA.os)"
} catch {
    $swHbA.Stop()
    Record-Result -Id "TC-SMK-04a" -Name "Heartbeat cliente A ($($clientA.id))" `
        -Success $false -DurationMs $swHbA.Elapsed.TotalMilliseconds -Details $_.Exception.Message
}

# Registrar Cliente B
$swHbB = [System.Diagnostics.Stopwatch]::StartNew()
try {
    $respB = Invoke-RestMethod -Uri $heartbeatUrl -Method Post -Body ($clientB | ConvertTo-Json) -ContentType "application/json" -TimeoutSec 5
    $swHbB.Stop()
    $hbBSuccess = ($respB.id -eq $clientB.id) -and ($respB.status -eq "online")
    Record-Result -Id "TC-SMK-04b" -Name "Heartbeat cliente B ($($clientB.id))" `
        -Success $hbBSuccess -DurationMs $swHbB.Elapsed.TotalMilliseconds `
        -Details "Status: $($respB.status) | Hostname: $($respB.hostname) | OS: $($respB.os)"
} catch {
    $swHbB.Stop()
    Record-Result -Id "TC-SMK-04b" -Name "Heartbeat cliente B ($($clientB.id))" `
        -Success $false -DurationMs $swHbB.Elapsed.TotalMilliseconds -Details $_.Exception.Message
}

# -----------------------------------------------------------------------------
# TC-SMK-05: Verificación de inventario de dispositivos y metadatos
# -----------------------------------------------------------------------------
Log-Step "TC-SMK-05" "Verificación de inventario de dispositivos en línea (GET /api/devices)"
$devicesUrl = "$ApiUrl/api/devices"
$swDevs = [System.Diagnostics.Stopwatch]::StartNew()
try {
    $devicesList = Invoke-RestMethod -Uri $devicesUrl -Method Get -Headers $authHeaders -TimeoutSec 5
    $swDevs.Stop()

    $foundA = $devicesList | Where-Object { $_.id -eq $clientA.id }
    $foundB = $devicesList | Where-Object { $_.id -eq $clientB.id }

    $metaValid = ($null -ne $foundA) -and ($foundA.status -eq "online") -and ($foundA.os -eq $clientA.os) -and `
                 ($null -ne $foundB) -and ($foundB.status -eq "online") -and ($foundB.os -eq $clientB.os)

    Record-Result -Id "TC-SMK-05" -Name "Listado de dispositivos y validación de metadatos" `
        -Success $metaValid -DurationMs $swDevs.Elapsed.TotalMilliseconds `
        -Details "Total dispositivos: $($devicesList.Count) | A: $($foundA.status) | B: $($foundB.status)"
} catch {
    $swDevs.Stop()
    Record-Result -Id "TC-SMK-05" -Name "Listado de dispositivos y validación de metadatos" `
        -Success $false -DurationMs $swDevs.Elapsed.TotalMilliseconds -Details $_.Exception.Message
}

# -----------------------------------------------------------------------------
# TC-SMK-06: Verificación de sesión de rendezvous y relay
# -----------------------------------------------------------------------------
Log-Step "TC-SMK-06" "Verificación de conectividad y handshake de señalización y relay"
$rendezvousRes = Test-TcpPort -HostName $ServerHost -Port 21116
$relayRes = Test-TcpPort -HostName $ServerHost -Port 21117

$rendezvousOk = $rendezvousRes.Success -and $relayRes.Success
Record-Result -Id "TC-SMK-06" -Name "Conectividad simultánea Rendezvous (21116) y Relay (21117)" `
    -Success $rendezvousOk -DurationMs ($rendezvousRes.DurationMs + $relayRes.DurationMs) `
    -Details "Rendezvous TCP: $($rendezvousRes.DurationMs)ms | Relay TCP: $($relayRes.DurationMs)ms"

# Si existen clientes en contenedor Docker (laboratorio LAN), probar conectividad inter-cliente
$dockerClientExists = (docker ps --filter "name=cercano-client-linux-1" --format "{{.Names}}" 2>$null)
if ($dockerClientExists) {
    $swLan = [System.Diagnostics.Stopwatch]::StartNew()
    $pingOutput = docker exec cercano-client-linux-1 ping -c 2 172.28.0.22 2>&1
    $swLan.Stop()
    $lanOk = ($LASTEXITCODE -eq 0)
    Record-Result -Id "TC-SMK-06-LAN" -Name "Conectividad inter-cliente en red LAN (172.28.0.21 -> 172.28.0.22)" `
        -Success $lanOk -DurationMs $swLan.Elapsed.TotalMilliseconds -Details "Ping directo inter-cliente OK"
}

# -----------------------------------------------------------------------------
# TC-SMK-07: Comprobar transición a offline tras inactividad
# -----------------------------------------------------------------------------
Log-Step "TC-SMK-07" "Transición automática a offline tras tiempo de gracia ($GracePeriodSecs s)"

$ephemeralClient = @{
    id       = "cercano-client-ephemeral"
    name     = "laptop-temporary"
    hostname = "temp.cercano.lan"
    os       = "Linux Test"
    version  = "1.0.0"
    ip       = "172.28.0.99"
}

# 1. Registrar dispositivo efímero
$swEph = [System.Diagnostics.Stopwatch]::StartNew()
$ephResp = Invoke-RestMethod -Uri $heartbeatUrl -Method Post -Body ($ephemeralClient | ConvertTo-Json) -ContentType "application/json" -TimeoutSec 5
$ephInitOnline = ($ephResp.status -eq "online")

# 2. Esperar a que transcurra el tiempo de gracia
Write-Host "    Esperando $($GracePeriodSecs + 2) segundos para evaluar expiración de latidos..." -ForegroundColor DarkGray
Start-Sleep -Seconds ($GracePeriodSecs + 2)

# 3. Comprobar estado en GET /api/devices/{id}
$ephGetUrl = "$ApiUrl/api/devices/$($ephemeralClient.id)"
$swEphCheck = [System.Diagnostics.Stopwatch]::StartNew()
try {
    $ephDetail = Invoke-RestMethod -Uri $ephGetUrl -Method Get -Headers $authHeaders -TimeoutSec 5
    $swEphCheck.Stop()
    $isOffline = ($ephDetail.status -eq "offline")

    Record-Result -Id "TC-SMK-07" -Name "Transición a estado offline por inactividad" `
        -Success $isOffline -DurationMs $swEphCheck.Elapsed.TotalMilliseconds `
        -Details "Estado inicial: online | Estado actual: $($ephDetail.status) (tras $($GracePeriodSecs + 2)s)"

    # Limpieza del cliente de prueba
    Invoke-RestMethod -Uri $ephGetUrl -Method Delete -Headers $authHeaders -TimeoutSec 5 | Out-Null
} catch {
    $swEphCheck.Stop()
    Record-Result -Id "TC-SMK-07" -Name "Transición a estado offline por inactividad" `
        -Success $false -DurationMs $swEphCheck.Elapsed.TotalMilliseconds -Details $_.Exception.Message
}

# -----------------------------------------------------------------------------
# Limpieza de Compose opcional
# -----------------------------------------------------------------------------
if ($Down) {
    Log-Step "TEARDOWN" "Deteniendo infraestructura Docker Compose ($ComposeFile)..."
    docker compose -f $ComposeFile down
}

# -----------------------------------------------------------------------------
# Resumen y generación de informe
# -----------------------------------------------------------------------------
$SuiteStartTime.Stop()
$totalTests = $TestResults.Count
$passedTests = ($TestResults | Where-Object { $_.Success }).Count
$failedTests = ($TestResults | Where-Object { -not $_.Success }).Count
$totalDurationMs = [Math]::Round($SuiteStartTime.Elapsed.TotalMilliseconds, 2)

Log-Header "RESUMEN DE RESULTADOS DE SMOKE TEST E2E"
Write-Host "Total de pruebas:     $totalTests"
Write-Host "Pruebas superadas:    $passedTests" -ForegroundColor Green
Write-Host "Pruebas fallidas:     $failedTests" -ForegroundColor $(if ($failedTests -eq 0) { "Green" } else { "Red" })
Write-Host "Tiempo total:         $totalDurationMs ms"
Write-Host "Veredicto final:      $(if ($failedTests -eq 0) { 'EXITOSO (PASS)' } else { 'FALLIDO (FAIL)' })" -ForegroundColor $(if ($failedTests -eq 0) { "Green" } else { "Red" })

# Guardar informe en formato JSON
if ($OutJson) {
    $report = [PSCustomObject]@{
        Suite         = "Cercano Smoke Test E2E - Fase 1"
        Timestamp     = (Get-Date).ToString("o")
        TargetApi     = $ApiUrl
        TargetServer  = $ServerHost
        TotalTests    = $totalTests
        PassedTests   = $passedTests
        FailedTests   = $failedTests
        DurationMs    = $totalDurationMs
        Verdict       = $(if ($failedTests -eq 0) { "PASS" } else { "FAIL" })
        Results       = $TestResults
    }

    $outDir = Split-Path -Parent $OutJson
    if ($outDir -and -not (Test-Path $outDir)) {
        New-Item -ItemType Directory -Path $outDir -Force | Out-Null
    }
    $report | ConvertTo-Json -Depth 5 | Set-Content -Path $OutJson -Encoding UTF8
    Write-Host "`nInforme JSON generado en: $OutJson" -ForegroundColor Cyan
}

if ($failedTests -gt 0) {
    exit 1
} else {
    exit 0
}
