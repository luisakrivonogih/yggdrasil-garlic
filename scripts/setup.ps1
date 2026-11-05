# Сборка и установка Yggdrasil + Garlic для Windows (запускать из PowerShell).
#
#   powershell -ExecutionPolicy Bypass -File scripts\setup.ps1 build
#   powershell -ExecutionPolicy Bypass -File scripts\setup.ps1 install     (от администратора)
#   powershell -ExecutionPolicy Bypass -File scripts\setup.ps1 uninstall   (от администратора)
#
# Параметры: -Peers "tls://host:port,tls://host2:port"  -SiteAddr "127.0.0.1:8080"
#            -Trusted "<ключ узла relay>,..."  -Mode client|relay
param(
  [ValidateSet('build','install','uninstall')][string]$Command = 'build',
  [string]$Peers = '',
  [string]$SiteAddr = '',
  [string]$Trusted = '',
  [ValidateSet('','client','relay')][string]$Mode = '',
  [string]$InstallDir = "$env:ProgramFiles\Yggdrasil"
)
$ErrorActionPreference = 'Stop'
Set-Location (Split-Path $PSScriptRoot -Parent)
$Root = (Get-Location).Path
$ConfPath = "$env:ProgramData\Yggdrasil\yggdrasil.conf"

function Build {
  if ((Test-Path .git) -and (Get-Command git -ErrorAction SilentlyContinue)) {
    Write-Host '==> git pull --ff-only'
    git pull --ff-only
    if ($LASTEXITCODE -ne 0) { Write-Host 'не удалось обновить, собираю текущую версию' }
  }
  if (-not (Get-Command go -ErrorAction SilentlyContinue)) { throw 'Не найден Go (нужен >= 1.26): https://go.dev/dl/' }
  New-Item -ItemType Directory -Force bin | Out-Null
  $pkg = 'github.com/yggdrasil-network/yggdrasil-go/src/version'
  $ld = "-s -w -X $pkg.buildName=yggdrasil -X $pkg.buildVersion=dev"
  foreach ($c in 'yggdrasil','yggdrasilctl') {
    Write-Host "==> build $c"
    go build -trimpath -ldflags="$ld" -o "bin\$c.exe" ".\cmd\$c"
    if ($LASTEXITCODE -ne 0) { throw "сборка $c не удалась" }
  }
  Write-Host "Готово: $Root\bin\yggdrasil.exe, yggdrasilctl.exe"
}

function Configure {
  New-Item -ItemType Directory -Force (Split-Path $ConfPath) | Out-Null
  if (-not (Test-Path $ConfPath)) {
    Write-Host "==> создаю $ConfPath"
    & "$InstallDir\yggdrasil.exe" -genconf | Out-File -Encoding ascii $ConfPath
  } else { Write-Host "==> $ConfPath уже есть, ключи не трогаю" }
  Copy-Item $ConfPath "$ConfPath.bak" -Force
  $t = (& "$InstallDir\yggdrasil.exe" -useconffile $ConfPath -normaliseconf) -join "`n"
  $t = [regex]::Replace($t, '(?ms)(^\s*Garlic:\s*\{.*?^\s*Enabled:) false', '$1 true')
  if ($Peers) {
    $list = ($Peers -split ',' | ForEach-Object { '"' + $_.Trim() + '"' }) -join ' '
    $t = [regex]::Replace($t, '(?m)^(\s*)Peers: \[\]', "`$1Peers: [ $list ]")
  }
  if ($Mode) {
    $t = [regex]::Replace($t, '(?m)^(\s*)Mode: .*$', "`$1Mode: $Mode")
  }
  if ($Trusted) {
    $keys = $Trusted -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -match '^[0-9a-fA-F]{64}$' }
    if (-not $keys) { throw 'Trusted: нужны 64-символьные hex-ключи узлов (Public key из getSelf)' }
    $list = ($keys | ForEach-Object { '"' + $_ + '"' }) -join ' '
    $t = [regex]::Replace($t, '(?m)^(\s*)TrustedPeers: \[.*$', "`$1TrustedPeers: [ $list ]")
  }
  if ($SiteAddr) {
    $t = [regex]::Replace($t, '(?m)^(\s*)Services: \[\]', "`$1Services: [ { ServiceID: `"`", LocalAddr: `"$SiteAddr`" } ]")
  }
  $tmp = "$ConfPath.tmp"
  Set-Content -Encoding ascii $tmp $t
  & "$InstallDir\yggdrasil.exe" -useconffile $tmp -normaliseconf | Out-Null
  if ($LASTEXITCODE -ne 0) { Remove-Item $tmp; throw "Новый конфиг не прошёл проверку, оставляю прежний $ConfPath" }
  Move-Item $tmp $ConfPath -Force
}

function Install {
  if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole('Administrator')) {
    throw 'Нужен запуск от администратора'
  }
  Build
  New-Item -ItemType Directory -Force $InstallDir | Out-Null
  Copy-Item bin\*.exe $InstallDir -Force
  Configure
  # Windows-сервис через sc.exe; драйвер wintun.dll нужен рядом с yggdrasil.exe
  # (скачай с https://www.wintun.net и положи в $InstallDir, если ещё нет).
  sc.exe stop Yggdrasil 2>$null | Out-Null
  sc.exe delete Yggdrasil 2>$null | Out-Null
  sc.exe create Yggdrasil binPath= "`"$InstallDir\yggdrasil.exe`" -useconffile `"$ConfPath`"" start= auto | Out-Null
  sc.exe start Yggdrasil | Out-Null
  Write-Host "Установлено. Проверка: & '$InstallDir\yggdrasilctl.exe' getGarlicDomain"
  Write-Host "Если сервис не стартует — нет wintun.dll, или запусти вручную в консоли для просмотра логов."
  Write-Host "Браузерный прокси Garlic: http://127.0.0.1:4444 (PAC: http://127.0.0.1:4444/proxy.pac)"
}

function Uninstall {
  sc.exe stop Yggdrasil 2>$null | Out-Null
  sc.exe delete Yggdrasil 2>$null | Out-Null
  Remove-Item "$InstallDir\yggdrasil.exe","$InstallDir\yggdrasilctl.exe" -ErrorAction SilentlyContinue
  Write-Host "Удалено. Конфиг $ConfPath сохранён (там ключи)."
}

switch ($Command) { 'build' { Build } 'install' { Install } 'uninstall' { Uninstall } }
