#!/usr/bin/env bash
# =============================================
# start_demos.sh
# Start local demo servers for OWASP automation
# - flask_login_otp.py  -> port 5001
# - flask_cookie_demo.py -> port 5002
# Logs are written to logs/<name>.log
# =============================================

set -euo pipefail

ROOT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT_DIR"

# ensure venv is available and activate
if [ -f venv/bin/activate ]; then
  source venv/bin/activate
else
  echo "⚠️  No venv found at $ROOT_DIR/venv. Please create and install requirements first."
fi

mkdir -p logs

# start login+OTP demo (port 5001)
if pgrep -f "flask_login_otp.py" >/dev/null 2>&1; then
  echo "flask_login_otp.py already running"
else
  nohup python3 src/flask_login_otp.py > logs/flask_login_otp.log 2>&1 &
  echo "Started flask_login_otp.py (logs/flask_login_otp.log)"
fi

# start cookie demo (port 5002)
if pgrep -f "flask_cookie_demo.py" >/dev/null 2>&1; then
  echo "flask_cookie_demo.py already running"
else
  nohup python3 src/flask_cookie_demo.py > logs/flask_cookie_demo.log 2>&1 &
  echo "Started flask_cookie_demo.py (logs/flask_cookie_demo.log)"
fi

echo ""
echo "Use 'ps aux | grep python' or 'pgrep -af flask' to inspect processes."
echo "To stop: use 'pkill -f flask_login_otp.py' and 'pkill -f flask_cookie_demo.py' or kill the PIDs."
