# Disabling automatic updates (Samsung Tri Fold / q7mq) — findings

Status: **method + scripts built; NOT yet applied on-device** — verified
read-only over ADB (2026-07-31), no disabler changes made. Apply with
`disable_updates.sh` when ready and verify with `--check`.

## Why

An OTA replaces the kernel → CVE-2026-43499 gets patched → the root
exploit stops working. The phone must never auto-update, including in the
short window after a reboot before the exploit has been re-run.

## The core insight: pm-disable survives reboots without root

`pm disable-user --user 0 <pkg>` writes the disabled state to
`/data/system/users/0/package-restrictions.xml` — a `/data` file that
persists across reboots and needs **no root to stay in effect**. So the
entire "unrooted window after reboot" problem is solved by disabling the
update packages ONCE while rooted: after any reboot the FOTA clients are
dead before the exploit even runs. There is no window to defend.

What persists across reboots:

| Mechanism | Persistent? |
|---|---|
| `pm disable-user` (package restrictions in /data) | Yes |
| `settings put …` (settings DB in /data) | Yes |
| `stop update_engine` (native service) | Until next reboot |
| iptables REJECT rules | **No** (flushed at boot; re-apply each root session) |

## Confirmed update surface on F968NKSS6BZG3 (One UI 8.0, Android 16)

Verified over ADB, 2026-07-31 (read-only):

| Component | Package / path | Version | Role |
|---|---|---|---|
| FotaAgent | `com.wssyncmldm` | 4.5.18 | downloader/installer — **the one to kill** |
| SOAgent | `com.sec.android.soagent` | 7.7.01 | update agent |
| Update Center | `com.samsung.android.app.updatecenter` | 3.9.06 | update UI/notifications |
| update_engine | `/system/bin/update_engine` (native, runs as root) | — | AOSP seamless installer; **cannot pm-disable**; `stop update_engine` per boot |

NOT present on this build (One UI 6-era names — kept in the script, skipped
when absent): `com.sec.android.systemupdate`, `com.samsung.sdm`,
`com.samsung.sdm.sts`.

NOT update-related (leave alone): `com.ims.dm` (OpenImsDm — carrier IMS),
`com.samsung.android.mdm` (MDMApp — enterprise), Knox cloudmdm,
`com.google.android.configupdater` (Google config/Mainline).

## FOTA endpoints — the classic list is stale

As of this check, **none of the classic domains resolve** (workstation and
device DNS): `fota-cloud-dn.samsungmobile.com`, `fota-ss…`, `dm-fota…`,
`fota.samsungmobile.com`, `ota.samsungmobile.com`, `swupdate.samsungmobile.com`
→ all NXDOMAIN. One UI 8-era builds moved endpoints. The script keeps the
old names as a legacy net and additionally **harvests the real server URLs
from FotaAgent's private data** (`/data/user_de/0/com.wssyncmldm/`) at root
time, adding SNI string-match rules for any `*.samsungmobile.com` /
`*.samsungcloud.com` host found there.

SNI technique: `iptables -A FOTA_BLOCK -m string --string "$host" --algo bm
-j REJECT` — the TLS ClientHello SNI is plaintext, so this catches HTTPS
connections regardless of CDN IP churn. Rules live in a dedicated
`FOTA_BLOCK` chain inserted into `OUTPUT`; they die on reboot (Layer 1
makes that harmless).

## Settings keys — absent on this build

`software_update_auto_download`, `auto_download`, `auto_update` are all
**null** in global/system/secure. The real auto-download toggle lives in
FotaAgent's private prefs (root-only path) — moot once the agent is
disabled. The script's `settings put` lines are harmless no-ops kept for
older One UI builds.

## Files

- `tools/disable_updates.sh` — disable + check mode
  (`--check` prints each package's state)
- `tools/enable_updates.sh` — re-enable, remove iptables rules,
  `start update_engine`
- Committed on `q7mq-support`, POSIX sh, `sh -n` clean.

## Usage

```sh
HELPER=/data/app/~~TYe0tvIgaok-*/dev.busung.s25uroot-*/lib/arm64/libcve43499root.so
adb push tools/disable_updates.sh /data/local/tmp/

# as root, via the su client:
adb shell "$HELPER /system/bin/sh /data/local/tmp/disable_updates.sh"
adb shell "$HELPER /system/bin/sh /data/local/tmp/disable_updates.sh --check"

# when an OTA is actually wanted:
adb shell "$HELPER /system/bin/sh /data/local/tmp/enable_updates.sh"
```

## Caveats

- Only a *successful* system update or a factory reset can undo
  `pm disable-user` — neither can happen while the clients are disabled.
- The manual Settings → Software update button fails quietly.
- Google Play system updates (Mainline APEX) do not touch the Samsung
  kernel; irrelevant to the exploit.
- `stop update_engine` + iptables rules need re-application after each
  reboot once rooted; the natural automation hook is the app running
  `disable_updates.sh` through the daemon right after each successful root.

## Pixel 7 follow-up (TODO when the Pixel is connected)

Same goal, different stack — the update chain on Pixel is not Samsung FOTA:

- Pixel OTA is driven by **GMS** (`com.google.android.gms`,
  SystemUpdateService) + the native **`update_engine`** daemon + seamless
  A/B installs at reboot. There is no `com.wssyncmldm` equivalent; disabling
  GMS wholesale breaks too much.
- To research on-device:
  1. Enumerate update-related components
     (`dumpsys package com.google.android.gms | grep -i update`,
     `pm list packages | grep -iE 'update|ota|gms'`, `getprop | grep -i ota`).
  2. Decide the disable surface: GMS SystemUpdate components
     (`pm disable-user` on GMS *components* or `cmd jobscheduler`-level
     suppression) vs blocking `update_engine` (native — cannot pm-disable;
     candidates: `stop update_engine` at root time, or iptables REJECT on
     the OTA endpoints — `update.googleapis.com` / `dl.google.com` paths —
     while rooted).
  3. Re-check the reboot window: Pixel auto-installs *staged* updates at
     reboot; killing the download path (GMS) is the persistent layer, same
     principle as the Samsung fix.
- Kernel side: Pixel kernel comes from the same OTA, so the exploit is
  equally exposed — the persistent disable is the priority.
