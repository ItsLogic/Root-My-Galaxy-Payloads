#!/system/bin/sh
#
# disable_updates.sh — stop Samsung FOTA / software-update on the Tri Fold
# so the kernel (and CVE-2026-43499) never gets patched.
#
# CONFIRMED ON F968NKSS6BZG3 (One UI 8.0, Android 16), 2026-07-31:
#   com.wssyncmldm                 FotaAgent 4.5.18   (downloader/installer)
#   com.sec.android.soagent        SOAgent77 7.7.01   (update agent)
#   com.samsung.android.app.updatecenter  3.9.06      (Update Center UI)
#   /system/bin/update_engine                  (native installer; cannot
#                                                pm-disable; stop per boot)
#   com.sec.android.systemupdate / com.samsung.sdm / .sts are NOT present
#   on this build (One UI 6-era names; kept below, skipped when absent).
#
# Run as root through the su client (helper):
#   $HELPER /system/bin/sh /data/local/tmp/disable_updates.sh
# or from a root shell:  sh /data/local/tmp/disable_updates.sh
#
# What persists across reboots (covers the unrooted window):
#   - `pm disable-user` writes /data/system/users/0/package-restrictions.xml;
#     disabled packages stay disabled with NO root needed afterwards.
#   - `stop update_engine` and iptables rules last until the next reboot;
#     re-apply them each root session (or have the app do it after rooting).
#
# The auto-download toggle is NOT in Settings.* on this build (keys are
# null); it lives in FotaAgent's private prefs — moot once the agent is
# disabled. The settings puts below are harmless no-ops kept for older
# One UI builds.

log() { echo "[disable-updates] $*"; }

# 1) Samsung update packages — disable for user 0 (persistent).
PKGS="
com.wssyncmldm
com.sec.android.soagent
com.samsung.android.app.updatecenter
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

# 3) Native OTA installer — cannot pm-disable (it is a native daemon).
#    `stop` halts it until the next reboot; re-run after each reboot.
stop update_engine 2>/dev/null && log "update_engine stopped (until reboot)"

# 4) Block Samsung FOTA endpoints for this session (kernel/iptables).
#    HTTPS SNI is plaintext in the TLS ClientHello, so the string match
#    catches the connections even though the hostnames resolve to CDN IPs.
#    NOTE: the classic fota-*.samsungmobile.com domains no longer resolve
#    on One UI 8 builds — keep them as legacy net, then harvest the real
#    endpoints from FotaAgent's private data (root) and add them below.
iptables -N FOTA_BLOCK 2>/dev/null
iptables -F FOTA_BLOCK
for host in \
  fota-cloud-dn.samsungmobile.com \
  fota-ss.samsungmobile.com \
  dm-fota.samsungmobile.com \
  fota.samsungmobile.com; do
  iptables -A FOTA_BLOCK -m string --string "$host" --algo bm -j REJECT
done

# 4b) Harvest any server URLs stored by the FOTA agent and block their hosts.
for url in $(grep -rhoE 'https?://[A-Za-z0-9.-]+' \
    /data/user_de/0/com.wssyncmldm/ 2>/dev/null | sort -u); do
  host=$(echo "$url" | sed 's|https\?://||; s|/.*||')
  case "$host" in
    *.samsungmobile.com|*.samsungcloud.com)
      iptables -A FOTA_BLOCK -m string --string "$host" --algo bm -j REJECT
      log "FOTA endpoint from agent config: $host";;
  esac
done
iptables -I OUTPUT -j FOTA_BLOCK

log "done."
log "  - FOTA packages disabled (survives reboot; nothing to do while unrooted)"
log "  - update settings off"
log "  - FOTA endpoints blocked for this boot only"
log "  - re-run after each reboot once rooted: sh $0"
