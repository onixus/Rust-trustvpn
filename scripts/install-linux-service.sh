#!/bin/sh
set -eu
if [ "$(id -u)" != 0 ]; then echo 'Run as root: install-linux-service.sh DESKTOP_UID SERVICE_BINARY' >&2; exit 1; fi
if [ "$#" != 2 ]; then echo 'Usage: install-linux-service.sh DESKTOP_UID SERVICE_BINARY' >&2; exit 1; fi
case "$1" in ''|*[!0-9]*|0) echo 'Choose a non-root desktop UID' >&2; exit 1;; esac
test -x /usr/sbin/ip || { echo 'Install iproute2 first' >&2; exit 1; }
test -c /dev/net/tun || { echo '/dev/net/tun is required' >&2; exit 1; }
command -v systemctl >/dev/null
script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
assert_idle() {
    for state in /run/rtrust/full.json /run/rtrust/lease.json /var/lib/rtrust/always-on.rtrust; do
        if [ -e "$state" ] || [ -L "$state" ]; then
            echo 'Disable always-on, disconnect and recover VPN before installing the service.' >&2
            return 1
        fi
    done
}
assert_idle
# Only one desktop UID per machine is supported in this preview.
if systemctl list-units --state=active --no-legend 'rtrust-service@*.service' | awk 'NF {print $1}' | while read -r unit; do
    [ "$unit" = "rtrust-service@$1.service" ] || exit 1
done; then :; else echo 'A different desktop UID already has an active service' >&2; exit 1; fi
install -d -m 0755 /usr/libexec/rtrust
staged=$(mktemp /usr/libexec/rtrust/.rtrust-service.XXXXXX)
trap 'rm -f "$staged"' EXIT HUP INT TERM
install -m 0755 "$2" "$staged"
unit_file="$script_dir/../deploy/rtrust-service@.service"
if [ -f "$script_dir/rtrust-service@.service" ]; then unit_file="$script_dir/rtrust-service@.service"; fi
boot_unit="$script_dir/../deploy/rtrust-boot-guard@.service"
if [ -f "$script_dir/rtrust-boot-guard@.service" ]; then boot_unit="$script_dir/rtrust-boot-guard@.service"; fi
test -r "$unit_file" && test -r "$boot_unit"
# Stop the old executable before replacing it. A connection can race the first
# check; the stopped service can no longer accept IPC, so check its journal again.
if systemctl cat "rtrust-service@$1.service" >/dev/null 2>&1; then
    systemctl stop "rtrust-service@$1.service"
    if ! assert_idle; then
        systemctl start "rtrust-service@$1.service"
        exit 1
    fi
fi
mv -f "$staged" /usr/libexec/rtrust/rtrust-service
install -D -m 0644 "$unit_file" /etc/systemd/system/rtrust-service@.service
install -D -m 0644 "$boot_unit" /etc/systemd/system/rtrust-boot-guard@.service
# Both supported network managers must wait for a successful early guard.
# With no opt-in policy the guard is a no-op and does not require nftables.
for manager in NetworkManager systemd-networkd; do
    install -d -m 0755 "/etc/systemd/system/$manager.service.d"
    printf '[Unit]\nRequires=rtrust-boot-guard@%s.service\nAfter=rtrust-boot-guard@%s.service\n' "$1" "$1" > "/etc/systemd/system/$manager.service.d/rtrust-boot-guard.conf"
done
systemctl daemon-reload
systemctl enable "rtrust-service@$1.service"
systemctl restart "rtrust-service@$1.service"
systemctl is-active --quiet "rtrust-service@$1.service"
echo 'Service installed. Choose selected networks or whole-computer mode in the desktop application.'
if [ ! -x /usr/sbin/nft ] || [ ! -x /usr/bin/resolvectl ]; then
    echo 'Whole-computer mode additionally requires nftables and active systemd-resolved.'
fi
