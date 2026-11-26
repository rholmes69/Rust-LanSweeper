# RustSweeper Linux inventory collector. POSIX sh; works with bash, dash and busybox.
# Runs as the SSH user (no sudo). Prints "@@section" markers followed by raw command output.
LC_ALL=C; export LC_ALL
sec() { printf '@@%s\n' "$1"; }
sec hostname; hostname 2>/dev/null || cat /etc/hostname 2>/dev/null
sec os; cat /etc/os-release 2>/dev/null
sec kernel; uname -r; uname -m
sec uptime; cut -d' ' -f1 /proc/uptime 2>/dev/null
sec now; date +%s
sec cpu; grep -m1 -E '^(model name|Model|Hardware)' /proc/cpuinfo 2>/dev/null | cut -d: -f2-; nproc 2>/dev/null || grep -c '^processor' /proc/cpuinfo
sec cores; grep -E '^cpu cores' /proc/cpuinfo 2>/dev/null | head -n1 | cut -d: -f2
sec mem; grep '^MemTotal' /proc/meminfo 2>/dev/null
sec dmi
for f in sys_vendor product_name product_serial bios_version bios_date; do
  printf '%s=' "$f"; cat "/sys/class/dmi/id/$f" 2>/dev/null || echo
done
sec df; df -P -k 2>/dev/null
sec addr; ip -o -4 addr show 2>/dev/null
sec link; ip -o link show 2>/dev/null
sec who; who 2>/dev/null
sec reboot; if [ -f /var/run/reboot-required ]; then echo yes; else echo no; fi
sec pkgs
if command -v dpkg-query >/dev/null 2>&1; then
  dpkg-query -W -f='${db:Status-Abbrev}\t${Package}\t${Version}\t${Architecture}\n' 2>/dev/null | grep '^ii' | cut -f2-
elif command -v rpm >/dev/null 2>&1; then
  rpm -qa --qf '%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\n' 2>/dev/null
elif command -v apk >/dev/null 2>&1; then
  apk info -v 2>/dev/null
fi
sec units; systemctl list-units --type=service --all --no-legend --plain --no-pager 2>/dev/null
sec unitfiles; systemctl list-unit-files --type=service --no-legend --no-pager 2>/dev/null
sec end
