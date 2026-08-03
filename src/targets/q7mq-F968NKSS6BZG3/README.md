# q7mq-F968NKSS6BZG3 — Galaxy Z Tri Fold (SM-F968N)

Snapdragon 8 Elite (SM8750-for-Galaxy), Korean (KOO). This is a sibling build
of the Galaxy S25 Ultra `pa3q` profiles: the device ships the **same
`android15-6.6` GKI kernel** (`6.6.98-android15-8-pd6ff1cd`), so every named
symbol and every BTF struct layout is identical to `pa3q-S938NKSUACZF1`. Only
one rodata-derived offset differs (below); the rest of `target.h` is the
verified `pa3q` value set.

## Firmware identity

```text
model:          SM-F968N
region:         KOO
AP/PDA:         F968NKSS6BZG3
CSC:            F968NOKR6BZG3
CP:             F968NKSS6BZG1
four-part:      F968NKSS6BZG3/F968NOKR6BZG3/F968NKSS6BZG1/F968NKSS6BZG3
display build:  BP4A.251205.006.F968NKSS6BZG3
fingerprint:    samsung/q7mqksx/q7mq:16/BP4A.251205.006/F968NKSS6BZG3_OKR6BZG3:user/release-keys
kernel release: 6.6.98-android15-8-pd6ff1cd-abogkiF968NKSS6BZG3-4k
kernel /proc/version:
  Linux version 6.6.98-android15-8-pd6ff1cd-abogkiF968NKSS6BZG3-4k
  (kleaf@build-host) (Android (11368308, +pgo, +bolt, +lto, +mlgo, based on r510928)
  clang version 18.0.0 (477610d4d0d988e69dbc3fae4fe86bff3f07f2b5), LLD 18.0.0)
  #1 SMP PREEMPT Thu Jul  2 00:47:40 UTC 2026
```

## Provenance

```text
firmware zip:      SM-F968N_2_20260702194730_o101gz8vv3_fac.zip (17029533328 bytes)
boot.img size:     101122048
boot.img SHA-256:  EB39653B4A64993AA02C4B289322AA2DC2E214609407AE3C4BC8C4CC42377402
kernel size:       38849024 (0x250ca00)
kernel SHA-256:    0031FD61B7DE362042C88E3CD2FB7641F19B32400F83D75D4AB1811DB1084C72
ARM64 Image:       text_offset=0x0  image_size=0x27b0000  flags=0xa
recovered ELF base:0xffffffc080000000  (== KIMAGE_TEXT_BASE)
sched_blocked_reason trace event id: 109  (live read; == slide.c default)
```

Boot image header is v4, page-aligned at 4096; `kernel_size` at header offset
`0x08`, kernel payload at `0x1000`.

## Offsets

All named-symbol offsets and all BTF struct layouts match `pa3q` exactly (each
was re-derived from this kernel's `vmlinux.elf` / raw BTF, not copied):

- ashmem ioctl/mmap/open/release/show_fdinfo, `ashmem_misc`+0x10, `ashmem_fops`,
  `anon_pipe_buf_ops`, `configfs_*`, `copy_splice_read`, `noop_llseek`,
  `init_task`, `root_task_group`, `selinux_state.enforcing`, `kmalloc_caches`,
  `system_unbound_wq`, `call_usermodehelper_exec_work`, `nfulnl_logger`,
  `sysctl_bootid`, `random_table` boot-id data pointer — all identical to `pa3q`.
- `SLIDE_TRACEFS_WORKER_CALLER_OFF = 0x000d97ec` (the insn after the
  `bl schedule` in `worker_thread`).
- `P0_KERNEL_PHYS_LOAD = 0xa8000000` — same SM8750-for-Galaxy boot chain as
  `pa3q`. Qualcomm ABL (`abl.elf`, no `sboot.bin`); load address is an
  XBL/ABL PCD constant shared across the SM8750 family.

**One value differs from `pa3q`** because this is a separate rebuild
(Thu Jul 2 vs Mon Jun 1) and rodata placement shifted:

| macro | pa3q | q7mq | source |
| --- | --- | --- | --- |
| `SLIDE_NFULNL_LOGGER_NAME_OFF` | `0x0175e2a1` | **`0x0175e299`** | first qword of `nfulnl_logger` (0x02302278) dereferenced; points to `"nfnetlink_log"` |

The `p0_fingerprint.h` table was regenerated from this raw kernel (slide-0
word-0 = `0x147a5019fa405a4d`, vs pa3q `0xf9400108c89ffd00`), so it is
build-specific and must not be reused across profiles.

## KernelSU

Reuses `kernelsu/ksud-s25u-kdp` (`android15-6.6`, 6854464 bytes) — identical
to the `pa3q` profiles. As of the ReSukiSU swap, this is a **ReSukiSU**
(SukiSU-Ultra fork) late-load binary embedding the ReSukiSU module with the
ported Samsung KDP/RKP/DEFEX adaptations (see
`kernelsu/README.md`); the on-device path `/data/local/tmp/ksud-s25u-kdp` and
the `late-load --kmi android15-6.6 --package-name <manager>` invocation used
by `su_daemon.c` are unchanged. Any KernelSU-compatible manager
(`com.resukisu.resukisu`, `me.weishu.kernelsu`, …) can connect.

## Build

```sh
make TARGET=q7mq-F968NKSS6BZG3 ANDROID_NDK_HOME=/path/to/android-ndk release
```

Release payload is exactly `104128` bytes, staged at
`artifacts/q7mq-F968NKSS6BZG3/cve-2026-43499-app.so`.

Hardware execution remains the separate validation step; this profile has not
yet been executed on an `SM-F968N` device.
