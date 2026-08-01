# Disabling automatic updates (Samsung Tri Fold / q7mq) — findings

Status: **method + scripts built; NOT yet applied on-device** (phone was
disconnected when this was written). Verify with `--check` on first run.

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
| iptables REJECT rules | **No** (flushed at boot; re-apply each root session) |

## Samsung FOTA chain (One UI, Android 16 / F968NKSS6BZG3)

| Package | Role |
|---|---|
| `com.wssyncmldm` | FOTA / DM client — downloads and applies updates |
| `com.sec.android.soagent` | software update agent |
| `com.sec.android.systemupdate` | update installer |
| `com.samsung.sdm` | Samsung Device Management — FOTA orchestration (One UI 6+) |
| `com.samsung.sdm.sts` | service tag system (sdm companion) |

Plus a discovery fallback in the script: grep `pm list packages` for
`wssync|soagent|systemupdate|fota|samsung\.sdm` and disable anything else
that matches.

## FOTA endpoints (blocked with iptables while rooted)

```
fota-cloud-dn.samsungmobile.com
fota-ss.samsungmobile.com
dm-fota.samsungmobile.com
fota.samsungmobile.com
```

Blocked via **SNI string match** — `iptables -A FOTA_BLOCK -m string
--string "$host" --algo bm -j REJECT` — because the TLS ClientHello SNI is
plaintext, this catches HTTPS connections even when the hostnames resolve
to CDN IPs. Rules live in a dedicated `FOTA_BLOCK` chain inserted into
`OUTPUT`. They die on reboot; Layer 1 (pm-disable) makes that harmless.

## Settings flipped (persistent)

```
settings put global  software_update_auto_download 0
settings put secure  software_update_auto_download 0
settings put system  auto_download 0
settings put system  auto_update 0
```
(Keys that don't exist on a build are silently ignored.)

## Files

- `tools/disable_updates.sh` — disable + check mode
  (`--check` prints each package's state)
- `tools/enable_updates.sh` — re-enable + remove iptables rules
- Both committed on `q7mq-support` (`d023c62`), POSIX sh, `sh -n` clean.

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
- iptables rules need re-application after each reboot once rooted; the
  natural automation hook is the app running `disable_updates.sh` through
  the daemon right after each successful root.

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
