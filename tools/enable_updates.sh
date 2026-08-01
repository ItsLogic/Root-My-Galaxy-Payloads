#!/system/bin/sh
#
# enable_updates.sh — undo disable_updates.sh when you actually want an OTA.
# Run as root through the su client:
#   $HELPER /system/bin/sh /data/local/tmp/enable_updates.sh

log() { echo "[enable-updates] $*"; }

PKGS="
com.wssyncmldm
com.sec.android.soagent
com.sec.android.systemupdate
com.samsung.sdm
com.samsung.sdm.sts
"

for p in $PKGS; do
  if pm path "$p" >/dev/null 2>&1; then
    pm enable "$p" 2>&1 | sed 's/^/[pm] /'
  fi
done

iptables -D OUTPUT -j FOTA_BLOCK 2>/dev/null
start update_engine 2>/dev/null
iptables -F FOTA_BLOCK 2>/dev/null
iptables -X FOTA_BLOCK 2>/dev/null

settings put global software_update_auto_download 1 2>/dev/null

log "done. Update packages re-enabled; FOTA rules removed."
log "Manual check: Settings > Software update."
