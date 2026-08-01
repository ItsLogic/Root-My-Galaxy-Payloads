#!/system/bin/sh
#
# disable_updates.sh — stop Samsung FOTA / software-update on the Tri Fold
# so the kernel (and CVE-2026-43499) never gets patched.
#
# Run as root through the su client (helper):
#   $HELPER /system/bin/sh /data/local/tmp/disable_updates.sh
# or from a root shell:  sh /data/local/tmp/disable_updates.sh
#
# What persists across reboots (covers the unrooted window):
#   - `pm disable-user` writes /data/system/users/0/package-restrictions.xml;
#     disabled packages stay disabled with NO root needed afterwards.
#   - `settings put` writes the settings DB (also persistent).
#
# What does NOT persist (iptables is flushed on reboot): the FOTA endpoint
# REJECT rules. Re-run this script after every reboot once you have root
# (or have the app execute it right after each successful root).

log() { echo "[disable-updates] $*"; }

# 1) Samsung update packages — disable for user 0 (persistent).
PKGS="
com.wssyncmldm
com.sec.android.soagent
com.sec.android.systemupdate
com.samsung.sdm
com.samsung.sdm.sts
"

if [ "$1" = "--check" ]; then
  log "current state:"
  for p in $PKGS; do
    state=$(pm list packages -d 2>/dev/null | sed 's/^package://' | grep -x "$p")
    if [ -n "$state" ]; then
      log "  $p: DISABLED"
    else
      log "  $p: enabled"
    fi
  done
  exit 0
fi

for p in $PKGS; do
  if pm path "$p" >/dev/null 2>&1; then
    pm disable-user --user 0 "$p" 2>&1 | sed 's/^/[pm] /'
  fi
done

# 1b) discovery fallback: catch any other update-ish package on this build
pm list packages 2>/dev/null | sed 's/^package://' |
  grep -iE 'wssync|soagent|systemupdate|fota|samsung\.sdm' |
  while read -r p; do
    case " $PKGS " in *" $p "*) ;; *)
      pm disable-user --user 0 "$p" 2>&1 | sed 's/^/[pm-extra] /' ;;
    esac
  done

# 2) Update settings (persistent; harmless if a key does not exist).
settings put global software_update_auto_download 0 2>/dev/null
settings put secure software_update_auto_download 0 2>/dev/null
settings put system auto_download 0 2>/dev/null
settings put system auto_update 0 2>/dev/null

# 3) Block Samsung FOTA endpoints for this session (kernel/iptables).
#    HTTPS SNI is plaintext in the TLS ClientHello, so the string match
#    catches the connections even though the hostnames resolve to CDN IPs.
iptables -N FOTA_BLOCK 2>/dev/null
iptables -F FOTA_BLOCK
for host in \
  fota-cloud-dn.samsungmobile.com \
  fota-ss.samsungmobile.com \
  dm-fota.samsungmobile.com \
  fota.samsungmobile.com; do
  iptables -A FOTA_BLOCK -m string --string "$host" --algo bm -j REJECT
done
iptables -I OUTPUT -j FOTA_BLOCK

log "done."
log "  - FOTA packages disabled (survives reboot; nothing to do while unrooted)"
log "  - update settings off"
log "  - FOTA endpoints blocked for this boot only"
log "  - re-run after each reboot once rooted: sh $0"
