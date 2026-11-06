# Сборка и установка Yggdrasil + Garlic для Windows (запускать из PowerShell).
#
#   powershell -ExecutionPolicy Bypass -File scripts\setup.ps1 build
#   powershell -ExecutionPolicy Bypass -File scripts\setup.ps1 install     (от администратора)
#   powershell -ExecutionPolicy Bypass -File scripts\setup.ps1 uninstall   (от администратора)
#
# Параметры: -Peers "tls://host:port,tls://host2:port"  -SiteAddr "127.0.0.1:8080"
#            -Trusted "<ключ узла relay>,..."  -Mode client|relay  -ReplaceLists
# -Peers и -Trusted дополняют списки в конфиге (с -ReplaceLists заменяют их).
# Переустановка не сбрасывает ключи и пиры; пиры, добавленные через
# yggdrasilctl addPeer / addGarlicPeer, демон сам сохраняет в конфиг.
param(
  [ValidateSet('build','install','uninstall')][string]$Command = 'build',
  [string]$Peers = '',
  [string]$SiteAddr = '',
  [string]$Trusted = '',
  [ValidateSet('','client','relay')][string]$Mode = '',
  [switch]$ReplaceLists,
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

# Merge-List: старый список + новые элементы через запятую, без повторов.
function Merge-List($old, [string]$add, [switch]$Lower) {
  $out = New-Object System.Collections.Generic.List[string]
  foreach ($x in @($old) + @($add -split ',')) {
    if ($null -eq $x) { continue }
    $v = "$x".Trim()
    if ($Lower) { $v = $v.ToLower() }
    if ($v -and -not $out.Contains($v)) { $out.Add($v) }
  }
  return ,$out.ToArray()
}

# Configure правит конфиг через его JSON-представление: Peers и TrustedPeers
# дополняются (с -ReplaceLists заменяются), ключи и остальное не трогаются.
function Configure {
  $ygg = "$InstallDir\yggdrasil.exe"
  New-Item -ItemType Directory -Force (Split-Path $ConfPath) | Out-Null
  if (-not (Test-Path $ConfPath) -or (Get-Item $ConfPath).Length -eq 0) {
    Write-Host "==> создаю $ConfPath"
    & $ygg -genconf | Out-File -Encoding ascii $ConfPath
  } else { Write-Host "==> $ConfPath уже есть, ключи и пиры сохраняю" }
  Copy-Item $ConfPath "$ConfPath.bak" -Force
  $json = (& $ygg -useconffile $ConfPath -normaliseconf -json) -join "`n"
  if ($LASTEXITCODE -ne 0 -or -not $json) { throw "Текущий конфиг $ConfPath не читается, оставляю как есть" }
  $c = $json | ConvertFrom-Json
  $c.Garlic.Enabled = $true
  if ($Mode) { $c.Garlic.Mode = $Mode }
  if ($Peers) {
    foreach ($p in $Peers -split ',') {
      if ($p.Trim() -notmatch '^(tcp|tls|quic|ws|wss|socks|sockstls|unix)://[][A-Za-z0-9.:%_-]+:[0-9]{1,5}([/?][ -~]*)?$') {
        throw "Неверный адрес пира: $p (пример: tls://1.2.3.4:443)"
      }
    }
    $old = if ($ReplaceLists) { @() } else { $c.Peers }
    $c.Peers = Merge-List $old $Peers
  }
  if ($Trusted) {
    $keys = $Trusted -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ -match '^[0-9a-fA-F]{64}$' }
    if (-not $keys) { throw 'Trusted: нужны 64-символьные hex-ключи узлов (Public key из getSelf)' }
    $old = if ($ReplaceLists) { @() } else { @($c.Garlic.TrustedPeers | ForEach-Object { "$_".ToLower() }) }
    $c.Garlic.TrustedPeers = Merge-List $old ($keys -join ',') -Lower
  }
  $services = @($c.Garlic.Services | Where-Object { $null -ne $_ })
  if ($SiteAddr -and $services.Count -eq 0) {
    $c.Garlic.Services = @([pscustomobject]@{ ServiceID = ''; LocalAddr = $SiteAddr })
  }
  $tmpJson = "$ConfPath.tmp.json"
  $c | ConvertTo-Json -Depth 20 | Set-Content -Encoding ascii $tmpJson
  $out = (& $ygg -useconffile $tmpJson -normaliseconf) -join "`n"
  $ok = ($LASTEXITCODE -eq 0) -and $out
  Remove-Item $tmpJson
  if (-not $ok) { throw "Новый конфиг не прошёл проверку, оставляю прежний $ConfPath" }
  Set-Content -Encoding ascii "$ConfPath.tmp" $out
  Move-Item "$ConfPath.tmp" $ConfPath -Force
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
