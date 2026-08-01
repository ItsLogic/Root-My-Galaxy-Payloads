# Pixel 7 (panther) from-scratch exploit — research & design

Goal: a CVE-2026-43499 payload written from scratch for the Pixel 7
(BP3A.250905.014, GKI 6.1.134), architecturally different from the
Galaxy payload.

## 1. CVE-2026-43499 (GhostLock) — what the bug is

- Reported by **Nebula Security** (found via their VEGA tool), fixed in
  mainline commit `3bfdc63936dd`, Linux 7.1. Introduced in 2011
  (2.6.39); depends only on `CONFIG_FUTEX_PI`.
- AlmaLinux writeup (2026-07-09): use-after-free in
  `kernel/locking/rtmutex.c` `remove_waiter()` on the futex PI path.
  `remove_waiter()` assumes the waiter belongs to `current`; on the
  `FUTEX_CMP_REQUEUE_PI` deadlock rollback (`-EDEADLK`) it unwinds on
  behalf of a *different* sleeping thread and clears `pi_blocked_on` on
  the wrong task → dangling pointer into freed kernel stack memory.
- Upstream fix: "rtmutex: Use waiter::task instead of current in
  remove_waiter()".
- Trigger: 3 futexes + coordinated threads → priority-inversion deadlock
  (FUTEX_WAIT_REQUEUE_PI + FUTEX_CMP_REQUEUE_PI + FUTEX_LOCK_PI) →
  -EDEADLK rollback → stale `pi_blocked_on` → the kernel later
  `remove_waiter(lock, waiter)` with a reclaimed/forged waiter.
- Public sources: AlmaLinux blog (patch advisory), NVD,
  NebuSec/CyberMeowfia (PoC + exploit source), ThreatPost/SecurityWeek
  writeups, Project Zero "Defeating KASLR by Doing Nothing at All"
  (2025-11, Pixel linear-map analysis).

### Confirmed on the shipped panther kernel (6.1.134)

`remove_waiter` (0xffffffc00900553c):
```asm
mrs x20, SP_EL0          ; x20 = current (the REQUEUER)
str xzr, [x20, #0x950]   ; current->pi_blocked_on = NULL  ← THE BUG
```
`pi_blocked_on` @ task_struct+0x950 (BTF-verified). The bug pattern is
identical to the q7mq 6.6 kernel.

## 2. The constrained write (the primitive)

The forged waiter is an `rt_mutex_waiter` (6.1 LEGACY layout, 88 bytes,
BTF-verified): tree_entry @0x00, pi_tree_entry @0x18, task @0x30, lock
@0x38, wake_state @0x40, prio @0x44, deadline @0x48, ww_ctx @0x50.

The rb_erase on the forged node performs:
```
PRIMARY:   *(root->rb_node) = rb_right          (corrupts a chosen slot)
SECONDARY: *(rb_right) = __rb_parent_color      → *(TARGET) = VALUE
```
with the node fields `{__rb_parent_color = VALUE, rb_right = 0,
rb_left = TARGET}` (left-child case). VALUE and TARGET are both
attacker-controlled → **one 8-byte write to an arbitrary kernel address
per trigger**.

## 3. The static linear map — no KASLR needed for writes

Project Zero (2025-11): on Pixel, the kernel is decompressed at a STATIC
phys every boot (image base 0x80000000, _stext 0x80010000). With
VA_BITS=39, PAGE_OFFSET=0xffffff8000000000, PHYS_OFFSET=0x80000000:

```
phys_to_virt(x) = ((x - 0x80000000) | 0xffffff8000000000)
alias(image_offset O) = 0xffffff8000000000 + O     (static, RW for .data)
```

So the write TARGET never needs the KASLR slide. Verified in the
shipped kernel: `memstart_addr`/zone layout (RAM [0x80000000,
0x280000000), 8GB).

## 4. What is broken on this device (the galaxy port's blocker)

### 4a. boot_id pointer leak — dead
`/proc/sys/kernel/random/boot_id` = a random UUID on GKI
(observed `0afed118-...`), not a Samsung-style kernel pointer.

### 4b. kernelsnitch mm_struct leak — dead AND dangerous
The futex-hash timing channel works (piled-bucket walks measured at
~5750 CNTVCT ticks vs ~11 baseline), the userside jhash2/key/seed were
verified byte-identical against the shipped kernel (futex_hash disasm:
jhash2(key,4,offset-seed) & (futex_hashsize-1), futex_key layout via
BTF, hashsize 2048), yet the mm-correlation NEVER matches any candidate
(max score 3/8 across all tag models 0x00-0x0f / 0xf0-0xff / canonical,
window up to 256GB). The shared-futex probe independently confirmed the
userside hash disagrees with the kernel's real buckets for every i_seq
(0..5M) and hashsize (256..65536). Root cause of the disagreement is
NOT yet identified — a genuine discrepancy between the userside hash and
this kernel's futex_hash remains unexplained.
The 2048-thread pile additionally **kernel-panicked the device**
(bootreason=kernel_panic; log ends mid-bruteforce). The kernelsnitch
path is unusable here.

### 4c. Consequences for the ported payload
Every galaxy-route stage needs the mm/slab leak: pipe_buffer arrays
(pipe physrw), the fake-waiter/fake-task/fake-lock page (slide bank),
the oracle. With 4b dead, the ported payload cannot progress past
stage 1 on this device.

## 5. From-scratch design (different from the galaxy payload)

Chain (no kernelsnitch, no pipes, no fops overwrite, no configfs, no
kCFI trampoline, no UMH):

```
[trigger]  futex PI deadlock → -EDEADLK rollback → forged waiter
[write]    one 8-byte write: *(TARGET) = VALUE, TARGET = static linear
           alias of any kernel .data address (no slide needed)
[repeat]   supervisor forks fresh processes, one trigger each
[root]     writes to static-alias targets:
           1. selinux_state.enforcing → 0      (alias 0xffffff80022293d0)
           2. modprobe_path → /data/local/tmp/x (alias +0x...)
           then trigger modprobe → root script → chmod 4755 helper
```

Differentiators vs the galaxy payload:
- no ashmem/fops/configfs/kCFI stage (the galaxy overwrites
  ashmem_misc.fops and trampolines through configfs with kCFI-valid
  slid text pointers)
- no KernelSnitch mm-slab leak, no pipe_buffer forging, no pipe physrw
- root via static-alias data writes + modprobe (after SELinux
  permissive), not UMH workqueue injection
- no boot_id/nfulnl leak, no fingerprint oracle

### Open problem: fake-object placement (the blocker)

The trigger needs the forged `rt_mutex_waiter` + a fake task/lock at
kernel addresses the fd-set words can reference. The galaxy route put
them in a sprayed sk_buff page whose address came from the mm leak.
Candidate solutions to research/implement:

1. **pselect kernel fd-set copy as the forged waiter**: the pselect
   fd_set words (the waiter's field values) are copied into a kmalloc
   buffer by core_sys_select; the waiter node address is unknown but the
   erase only follows the node FIELDS (parent/target). The fake
   task/lock pointers are the remaining unknown addresses.
2. **PR_SET_MM_MAP placement** (original PoC): requires
   CAP_SYS_RESOURCE — blocked on Android app context.
3. **Kernel-stack reclaim**: the freed rt_waiter stack slot reclaimed by
   a sibling thread's stack frames (natural reclaim); needs the stack
   address for the task/lock pointers.
4. **Revisit the futex_hash discrepancy** (4b): if the mm-correlation
   is repaired (or replaced by an oracle that does not need the hash,
   e.g. a timing-only bucket membership check per candidate is too
   slow), the whole galaxy placement machinery becomes usable again.
   The shared-futex probe is a clean, isolated reproducer for this.

## 6. Kernel-specific constants (shipped image, all verified)

```
KIMAGE_TEXT_BASE       0xffffffc008000000     _text (unslid)
PAGE_OFFSET            0xffffff8000000000     VA_BITS=39
PHYS_OFFSET            0x80000000
image phys base        0x80000000             static (no phys KASLR)
VMEMMAP_START          0xfffffffe00000000
selinux_state          +0x22293d0 (enforcing @ +0, bool)
modprobe_path          +0x?? (to be located via kallsyms)
rt_mutex_waiter        88 B LEGACY (pi_tree@0x18, task@0x30, lock@0x38,
                       wake_state@0x40, prio@0x44, deadline@0x48,
                       ww_ctx@0x50)
task_struct            pi_lock@0x924 pi_waiters@0x938 pi_top_task@0x948
                       pi_blocked_on@0x950
kCFI                   hashes at fn-4 (ashmem_open 0x8f07ca55,
                       configfs 0xc6175f03) — irrelevant to this design
KASAN_HW_TAGS          tags = 0xF0|tag in the top byte
                       (mte_get_ptr_tag: "format of KASAN tags is 0xF<x>")
```

## 7. Repo artifacts

- `src/targets/panther-BP3A.250905.014/` — target header (offsets,
  MTE flags), fingerprint table (unused by the new design), README
- `src/kernelsnitch/` — debugging changes (tag model, instrumentation,
  score matching) — the restored original semantics is the current
  state; further kernelsnitch work is on hold pending the hash question
- `docs/DISABLING-UPDATES.md` — unrelated device-ops doc

## 8. Status

Research complete. Design complete (architecture above) except the
fake-object placement, which is the single blocker. On-device evidence:
trigger/timing primitives verified working; the mm leak path panics and
is abandoned.
