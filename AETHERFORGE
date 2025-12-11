#!/usr/bin/env bash
# === Aetherforge Ω — NetReaper Fusion (Master Full Featured, Simplified) ===

set -euo pipefail

BASE="$HOME/.aetherforge"
REAPER_DIR="$BASE/reaper-blade"
REAPER_REPO="https://github.com/runran223-cmd/AetherForge.git"
REAPER_FUSION="$BASE/reaper_fusion.py"
AF_BIN="$HOME/bin/af"
LOG="$BASE/reaper_install.log"
LOG_SIZE=5242880

echo "== Aetherforge Ω—Master Installer =="

# 1. Requirements
for dep in python3 git; do
    command -v $dep >/dev/null 2>&1 || { echo "Please install $dep before running this."; exit 1; }
done
python3 -c "import requests" 2>/dev/null || pip3 install --user requests

mkdir -p "$BASE" "$REAPER_DIR" "$(dirname $AF_BIN)"
chmod 700 "$BASE" "$REAPER_DIR"

# 2. Clone/Update NetReaper repo (AetherForge)
if [ ! -d "$REAPER_DIR/.git" ]; then
    git clone "$REAPER_REPO" "$REAPER_DIR"
else
    git -C "$REAPER_DIR" pull --ff-only
fi

# 3. Anti-tamper Baseline
[ ! -f "$BASE/.baseline.sha256" ] && \
    { find "$BASE" -type f ! -name "*.log*" | sort | xargs sha256sum | sha256sum > "$BASE/.baseline.sha256"; }

tamper_check() {
    baseline="$BASE/.baseline.sha256"
    now_hash=$(find "$BASE" -type f ! -name "*.log*" | sort | xargs sha256sum | sha256sum)
    diff <(echo "$now_hash") "$baseline" >/dev/null || \
        { echo "[!] WARN: Possible code tampering detected at $(date)!" | tee -a "$LOG"; }
}

# 4. Fusion Program
cat > "$REAPER_FUSION" <<'EOF'
#!/usr/bin/env python3
import os, sys, subprocess, time, json, getpass, platform, hashlib
from datetime import datetime

BASE = os.path.expanduser("~/.aetherforge")
REAPER = f"{BASE}/reaper-blade"
LOG = f"{BASE}/reaper.log"
MAXLOG = 5242880
HOST_ID = hashlib.sha256((platform.node()+getpass.getuser()).encode()).hexdigest()[:16]

def rotate_log():
    if os.path.exists(LOG) and os.path.getsize(LOG) > MAXLOG:
        os.rename(LOG, LOG+".old")
        open(LOG, "w").close()

def log(msg):
    with open(LOG, "a") as f: f.write(f"[{datetime.now().strftime('%H:%M:%S')}] {msg}\n")
    print(msg)

def tamper_check():
    baseline = os.path.join(BASE, ".baseline.sha256")
    now_hash = subprocess.check_output(
        f"find '{BASE}' -type f ! -name '*.log*' | sort | xargs sha256sum | sha256sum", shell=True, text=True)
    with open(baseline) as f:
        if now_hash.strip() != f.read().strip():
            log("[!] TAMPER DETECTED [!]")
            print("Tamper detected: Do not trust this install.")

def run_reaper(tool, target=None, advanced=False):
    tools_def = ['recon','wireless','osint']
    tools_adv = tools_def + ['exploit','credentials','stress','maintenance']
    if (tool not in tools_adv) or (not advanced and tool not in tools_def):
        log("Tool not permitted.")
        print("Tool not allowed in this mode.")
        return
    cmd = [f"{REAPER}/netreaper.sh", tool]
    if target: cmd.append(target)
    log(f"Running: {' '.join(cmd)}")
    try:
        output = subprocess.run(cmd, capture_output=True, text=True, timeout=400)
        print((output.stdout or "")[:2000])
        log(f"{tool} RC={output.returncode}")
        if output.returncode != 0: print(output.stderr)
    except Exception as e:
        log(f"ERROR {tool}: {e}"); print("Run error:",e)

def fingerprint():
    info = {
        "host":HOST_ID,
        "hostname":platform.node(),
        "user":getpass.getuser(),
        "os":platform.platform(),
        "python":platform.python_version()
    }
    print(json.dumps(info, indent=2))

def menu(advanced=True):
    rotate_log()
    tamper_check()
    while True:
        print("\n=== AETHERFORGE Ω | NetReaper ===")
        print("1) Autonomous Scan   4) Single Tool (adv)")
        print("2) Defense Only      5) Host Fingerprint")
        print("3) View Logs         6) Maintenance")
        print("0) Exit")
        choice = input("Choice: ").strip()
        if choice=="1":
            t = input("Target (default: scanme.nmap.org): ") or "scanme.nmap.org"
            for tool in ["recon","wireless","osint","exploit","credentials","stress"]: run_reaper(tool, t, True)
        elif choice=="2":
            t = input("Target (default: scanme.nmap.org): ") or "scanme.nmap.org"
            for tool in ["recon","wireless","osint"]: run_reaper(tool, t, False)
        elif choice=="3":
            with open(LOG) as f: print(''.join(f.readlines()[-40:]))
        elif choice=="4":
            tool = input("Tool: [recon/wireless/osint/exploit/credentials/stress/maintenance]: ").strip()
            target = input("Target: (blank for N/A): ").strip() or None
            run_reaper(tool, target, True)
        elif choice=="5":
            fingerprint()
        elif choice=="6":
            run_reaper("maintenance", advanced=True)
        else:
            print("Bye."); break

if __name__ == "__main__":
    menu()
EOF

chmod 700 "$REAPER_FUSION"

# 5. Add/Update Command Alias
touch "$AF_BIN"
chmod 700 "$AF_BIN"
grep -q 'reaper)' "$AF_BIN" || echo '  reaper) python3 ~/.aetherforge/reaper_fusion.py ;;' >> "$AF_BIN"

echo -e "\n[✓] Install complete! Run 'af reaper' for the menu."
