#!/bin/sh
# Сборка и установка Yggdrasil + Garlic для macOS и Linux.
#
#   sh scripts/setup.sh build            собрать в ./bin
#   sh scripts/setup.sh install          собрать, установить, создать конфиг, запустить сервис (нужен sudo)
#   sh scripts/setup.sh uninstall        остановить сервис и удалить бинарники (конфиг остаётся)
#
# Переменные окружения:
#   PEERS="tls://host:port,tls://host2:port"   публичные пиры для обычной сети Yggdrasil
#   SITE_ADDR=127.0.0.1:8080                   опубликовать локальный HTTP-сервер как .yggg сайт
#   PREFIX=/usr/local                          куда ставить бинарники
set -e

cd "$(dirname "$0")/.."
ROOT=$(pwd)
CMD=${1:-build}
PREFIX=${PREFIX:-/usr/local}
CONF=${CONF:-/etc/yggdrasil.conf}
OS=$(uname -s)

need_go() {
  command -v go >/dev/null 2>&1 || { echo "Не найден Go (нужен >= 1.26): https://go.dev/dl/" >&2; exit 1; }
}

build() {
  need_go
  PKGSRC=github.com/yggdrasil-network/yggdrasil-go/src/version
  NAME=$(sh contrib/semver/name.sh 2>/dev/null || echo yggdrasil)
  VER=$(sh contrib/semver/version.sh --bare 2>/dev/null || echo dev)
  LDFLAGS="-s -w -X $PKGSRC.buildName=$NAME -X $PKGSRC.buildVersion=$VER"
  mkdir -p bin
  for c in yggdrasil yggdrasilctl; do
    echo "==> build $c"
    go build -trimpath -ldflags="$LDFLAGS" -o "bin/$c" "./cmd/$c"
  done
  echo "Готово: $ROOT/bin/yggdrasil, $ROOT/bin/yggdrasilctl"
}

# Правит конфиг: включает Garlic, при необходимости пиры и сайт.
configure() {
  if [ ! -f "$CONF" ]; then
    echo "==> создаю $CONF"
    "$ROOT/bin/yggdrasil" -genconf > "$CONF"
    chmod 600 "$CONF"
  else
    echo "==> $CONF уже есть, ключи не трогаю"
  fi
  # Простые правки через sed работают, т.к. -genconf выдаёт по одному ключу на строку.
  SED_I="sed -i"; [ "$OS" = Darwin ] && SED_I="sed -i ''"
  eval "$SED_I -E '/^  Garlic:/,/^  }/ s/^(    Enabled:) false/\\1 true/' \"$CONF\""
  if [ -n "$PEERS" ]; then
    LIST=$(echo "$PEERS" | tr ',' '\n' | sed 's/^ *//;s/ *$//;s/.*/    "&"/' | tr '\n' ' ')
    eval "$SED_I -E 's|^  Peers: \\[\\]|  Peers: [ $LIST ]|' \"$CONF\""
  fi
  if [ -n "$SITE_ADDR" ]; then
    eval "$SED_I -E 's|^    Services: \\[\\]|    Services: [ { ServiceID: \"\", LocalAddr: \"$SITE_ADDR\" } ]|' \"$CONF\""
  fi
  if ! "$ROOT/bin/yggdrasil" -useconffile "$CONF" -normaliseconf 2>/dev/null | sed -n '/^  Garlic:/,/^  }/p' | grep -q '^    Enabled: true'; then
    echo "ВНИМАНИЕ: не удалось автоматически включить Garlic — поставь Garlic.Enabled: true в $CONF вручную." >&2
  fi
}

install_all() {
  [ "$(id -u)" = 0 ] || { echo "Запусти с sudo: sudo -E sh scripts/setup.sh install" >&2; exit 1; }
  # go при sudo может быть не в PATH
  [ -x bin/yggdrasil ] || build
  install -d "$PREFIX/bin"
  install -m 755 bin/yggdrasil bin/yggdrasilctl "$PREFIX/bin/"
  configure
  case "$OS" in
    Darwin)
      sed "s|/usr/local/bin/yggdrasil -useconffile /etc/yggdrasil.conf|$PREFIX/bin/yggdrasil -useconffile $CONF|" \
        contrib/macos/yggdrasil.plist > /Library/LaunchDaemons/yggdrasil.plist
      launchctl unload /Library/LaunchDaemons/yggdrasil.plist 2>/dev/null || true
      launchctl load -w /Library/LaunchDaemons/yggdrasil.plist
      ;;
    Linux)
      id yggdrasil >/dev/null 2>&1 || groupadd -r yggdrasil 2>/dev/null || true
      sed "s|/usr/bin/yggdrasil|$PREFIX/bin/yggdrasil|" contrib/systemd/yggdrasil.service > /etc/systemd/system/yggdrasil.service
      systemctl daemon-reload
      systemctl enable --now yggdrasil
      ;;
    *) echo "ОС $OS не поддерживается этим скриптом" >&2; exit 1 ;;
  esac
  echo
  echo "Установлено. Проверка:"
  echo "  yggdrasilctl getSelf"
  echo "  yggdrasilctl getGarlicDomain"
  echo "Браузерный прокси Garlic: http://127.0.0.1:4444 (PAC: http://127.0.0.1:4444/proxy.pac)"
}

uninstall_all() {
  [ "$(id -u)" = 0 ] || { echo "Запусти с sudo" >&2; exit 1; }
  case "$OS" in
    Darwin) launchctl unload /Library/LaunchDaemons/yggdrasil.plist 2>/dev/null || true; rm -f /Library/LaunchDaemons/yggdrasil.plist ;;
    Linux) systemctl disable --now yggdrasil 2>/dev/null || true; rm -f /etc/systemd/system/yggdrasil.service; systemctl daemon-reload ;;
  esac
  rm -f "$PREFIX/bin/yggdrasil" "$PREFIX/bin/yggdrasilctl"
  echo "Удалено. Конфиг $CONF сохранён (там ключи)."
}

case "$CMD" in
  build) build ;;
  install) install_all ;;
  uninstall) uninstall_all ;;
  *) echo "Использование: $0 {build|install|uninstall}" >&2; exit 1 ;;
esac
