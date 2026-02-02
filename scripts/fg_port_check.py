import socket
import sys
import subprocess
import shutil

host = sys.argv[1]
port = int(sys.argv[2])

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.settimeout(0.25)
try:
    rc = s.connect_ex((host, port))
finally:
    s.close()

if rc != 0:
    print(f"✅ Port free: {host}:{port}")
    raise SystemExit(0)

print(f"❌ Refusing to start: {host}:{port} already has a listener")

if shutil.which("lsof"):
    try:
        out = subprocess.check_output(
            ["lsof", "-nP", f"-iTCP:{port}", "-sTCP:LISTEN"],
            stderr=subprocess.DEVNULL,
            text=True,
        ).strip()
        if out:
            print("\n--- lsof output ---")
            print(out)
    except Exception:
        pass

raise SystemExit(1)
