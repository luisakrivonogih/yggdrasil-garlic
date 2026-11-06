#!/bin/sh
# Сборка и установка Yggdrasil + Garlic для macOS и Linux.
#
#   sh scripts/setup.sh build            собрать в ./bin
# (из git-клона скрипт сам делает git pull --ff-only; NO_UPDATE=1 отключает)
#   sh scripts/setup.sh install          собрать, установить, создать конфиг, запустить сервис (нужен sudo)
#   sh scripts/setup.sh uninstall        остановить сервис и удалить бинарники (конфиг остаётся)
#
# Переменные окружения:
#   PEERS="tls://host:port,tls://host2:port"   пиры обычной сети Yggdrasil (добавляются к списку в конфиге)
#   SITE_ADDR=127.0.0.1:8080                   опубликовать локальный HTTP-сервер как .yggg сайт
#   TRUSTED="<ключ узла>,<ключ узла>"          доверенные Garlic-relay (Public key из getSelf), первый хоп;
#                                              добавляются к Garlic.TrustedPeers
#   REPLACE_LISTS=1                            PEERS и TRUSTED заменяют списки, а не дополняют их
#
# Переустановка ничего не сбрасывает: ключи, пиры и режим остаются. Пиры,
# добавленные через yggdrasilctl addPeer / addGarlicPeer, демон сам сохраняет в конфиг.
#   MODE=client|relay                          client (по умолчанию, скрытый) или relay (публичный, для серверов)
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

# Подтягивает свежий код, если запущено из git-клона и он отстаёт от origin.
update_source() {
  [ "${NO_UPDATE:-0}" = 1 ] && return 0
  [ -d .git ] || return 0
  command -v git >/dev/null 2>&1 || return 0
  # от sudo git ругается на владельца каталога
  # под sudo обновляем от имени владельца, чтобы не оставить в .git файлы root
  if [ "$(id -u)" = 0 ] && [ -n "$SUDO_USER" ]; then GIT="sudo -u $SUDO_USER git"; else GIT="git"; fi
  BR=$($GIT rev-parse --abbrev-ref HEAD 2>/dev/null) || return 0
  $GIT fetch -q origin "$BR" 2>/dev/null || { echo "==> не удалось связаться с origin, собираю локальную версию"; return 0; }
  if [ "$($GIT rev-parse HEAD)" = "$($GIT rev-parse FETCH_HEAD)" ]; then
    echo "==> код актуален ($($GIT rev-parse --short HEAD))"
  elif $GIT merge-base --is-ancestor HEAD FETCH_HEAD; then
    echo "==> обновляю $BR: $($GIT rev-parse --short HEAD) -> $($GIT rev-parse --short FETCH_HEAD)"
    $GIT merge -q --ff-only FETCH_HEAD || echo "==> не удалось обновить (локальные изменения?), собираю как есть"
  else
    echo "==> локальная ветка опережает или разошлась с origin, не трогаю"
  fi
}

build() {
  need_go
  update_source
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

# set_list FILE "  Key:" 'ITEMS' - заменяет массив целиком (и однострочный
# "Key: []", и многострочный, как его пишет -normaliseconf).
set_list() {
  awk -v key="$2" -v val="$3" '
    BEGIN { match(key, /^ */); close_line = substr(key, 1, RLENGTH) "]" }
    skip { if ($0 == close_line) skip = 0; next }
    index($0, key " [") == 1 { print key " [ " val "]"; if ($0 !~ /\]$/) skip = 1; next }
    { print }' "$1" > "$1.new" && mv "$1.new" "$1"
}

# json_list KEY - элементы массива KEY из текущего конфига, по одному в строке
# (Peers или TrustedPeers; ищется по JSON-выводу -normaliseconf).
json_list() {
  "$YGG" -useconffile "$CONF" -normaliseconf -json | awk -v key="$1" '
    $0 ~ "^ *\"" key "\": \\[\\]" { exit }
    $0 ~ "^ *\"" key "\": \\[" { on = 1; next }
    on && /^ *\]/ { exit }
    on { gsub(/^ *"|",? *$/, ""); print }'
}

# merge_quoted "OLD" "NEW" - объединяет два списка (по строке на элемент) без
# повторов и с сохранением порядка, в виде "a" "b" для set_list.
merge_quoted() {
  printf '%s\n%s\n' "$1" "$2" | awk 'NF && !seen[$0]++ { printf "\"%s\" ", $0 }'
}

# Правит конфиг: включает Garlic, режим, доверенные пиры, обычные пиры и сайт.
# Старый конфиг сначала нормализуется (переходит на новые поля), а итог
# проверяется до перезапуска - при ошибке возвращается резервная копия.
configure() {
  YGG="$ROOT/bin/yggdrasil"
  if [ ! -f "$CONF" ]; then
    echo "==> создаю $CONF"
    "$YGG" -genconf > "$CONF"
    chmod 600 "$CONF"
  else
    echo "==> $CONF уже есть, ключи сохраняю"
  fi
  cp "$CONF" "$CONF.bak"
  TMP="$CONF.tmp"
  "$YGG" -useconffile "$CONF" -normaliseconf > "$TMP" || { echo "Текущий конфиг не читается, оставляю как есть" >&2; rm -f "$TMP"; return 1; }
  SED_I="sed -i"; [ "$OS" = Darwin ] && SED_I="sed -i ''"
  eval "$SED_I -E '/^  Garlic:/,/^  }/ s/^(    Enabled:) false/\\1 true/' \"$TMP\""
  if [ -n "$MODE" ]; then
    case "$MODE" in client|relay) ;; *) echo "MODE должен быть client или relay" >&2; rm -f "$TMP"; return 1 ;; esac
    eval "$SED_I -E 's/^    Mode: .*/    Mode: $MODE/' \"$TMP\""
  fi
  if [ -n "$TRUSTED" ]; then
    NEW=$(echo "$TRUSTED" | tr ',' '\n' | sed 's/^ *//;s/ *$//' | grep -E '^[0-9a-fA-F]{64}$' | tr 'A-F' 'a-f')
    [ -n "$NEW" ] || { echo "TRUSTED: нужны 64-символьные hex-ключи узлов (Public key из getSelf)" >&2; rm -f "$TMP"; return 1; }
    OLD=""; [ "${REPLACE_LISTS:-0}" = 1 ] || OLD=$(json_list TrustedPeers | tr 'A-F' 'a-f')
    set_list "$TMP" "    TrustedPeers:" "$(merge_quoted "$OLD" "$NEW")"
  fi
  if [ -n "$PEERS" ]; then
    # -normaliseconf не проверяет адреса пиров, а неверный адрес роняет демон
    # при старте - проверяем формат сами.
    for p in $(echo "$PEERS" | tr ',' ' '); do
      if ! printf '%s' "$p" | LC_ALL=C grep -Eq '^(tcp|tls|quic|ws|wss|socks|sockstls|unix)://[][A-Za-z0-9.:%_-]+:[0-9]{1,5}([/?][ -~]*)?$'; then
        echo "Неверный адрес пира: $p (пример: tls://1.2.3.4:443)" >&2
        rm -f "$TMP"
        return 1
      fi
    done
    NEW=$(echo "$PEERS" | tr ',' '\n' | sed 's/^ *//;s/ *$//')
    OLD=""; [ "${REPLACE_LISTS:-0}" = 1 ] || OLD=$(json_list Peers)
    set_list "$TMP" "  Peers:" "$(merge_quoted "$OLD" "$NEW")"
  fi
  if [ -n "$SITE_ADDR" ]; then
    eval "$SED_I -E 's|^    Services: \\[\\]|    Services: [ { ServiceID: \"\", LocalAddr: \"$SITE_ADDR\" } ]|' \"$TMP\""
  fi
  if ! "$YGG" -useconffile "$TMP" -normaliseconf > /dev/null 2>&1; then
    echo "Новый конфиг не прошёл проверку (неверный адрес пира?) - оставляю прежний $CONF" >&2
    "$YGG" -useconffile "$TMP" -normaliseconf 2>&1 | tail -3 >&2
    rm -f "$TMP"
    return 1
  fi
  mv "$TMP" "$CONF"
  chmod 600 "$CONF"
  if ! "$YGG" -useconffile "$CONF" -normaliseconf -json | tr -d ' \n' | grep -q '"TrustedPeers":\["'; then
    echo "ВНИМАНИЕ: Garlic.TrustedPeers пуст - цепочки строиться не будут. Добавьте: TRUSTED=<ключ узла relay> или yggdrasilctl addGarlicPeer key=..." >&2
  fi
}

install_all() {
  [ "$(id -u)" = 0 ] || { echo "Запусти с sudo: sudo -E sh scripts/setup.sh install" >&2; exit 1; }
  # go при sudo может быть не в PATH
  build
  install -d "$PREFIX/bin"
  install -m 755 bin/yggdrasil bin/yggdrasilctl "$PREFIX/bin/"
  configure || exit 1
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
