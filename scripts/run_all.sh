#!/usr/bin/env bash
# =====================================================================
# File: run_all.sh
# Author: Security Automation Team
#
# Purpose:
#   Runs ALL OWASP checks defined in config/checks.yml sequentially.
#   It calls scripts/run_check.sh for each test automatically.
#
# Behavior:
#   1. Reads the YAML config file (config/checks.yml)
#   2. Iterates through each defined check
#   3. Calls ./scripts/run_check.sh <check_name>
#   4. Collects JSON reports in reports/raw/
#   5. Generates an HTML dashboard summary
#
# Usage:
#   ./scripts/run_all.sh
#
# Works on:
#   ✅ macOS (zsh)
#   ✅ Linux (bash)
# =====================================================================

set -euo pipefail

CONFIG_FILE="config/checks.yml"

echo "==========================================="
echo "🚀 Starting OWASP Automation Suite"
echo "==========================================="

# ---------------------------------------------------------------------
# 1️⃣ Validate configuration file
# ---------------------------------------------------------------------
if [ ! -f "$CONFIG_FILE" ]; then
  echo "❌ Configuration file not found: $CONFIG_FILE"
  exit 1
fi

# ---------------------------------------------------------------------
# 2️⃣ Detect available YAML parser
# ---------------------------------------------------------------------
# We use yq if available, otherwise Python fallback
if command -v yq >/dev/null 2>&1; then
  CHECK_NAMES=($(yq -r '.[].name' "$CONFIG_FILE"))
else
  echo "⚠️  yq not found — using Python YAML parser fallback."
  CHECK_NAMES=($(python3 - <<PY
import yaml
cfg = "$CONFIG_FILE"
with open(cfg) as f:
    data = yaml.safe_load(f)
for item in data:
    print(item.get("name"))
PY
))
fi

# ---------------------------------------------------------------------
# 3️⃣ Run each check sequentially
# ---------------------------------------------------------------------
for CHECK in "${CHECK_NAMES[@]}"; do
  echo
  echo "➡️  Running check: $CHECK"
  echo "-------------------------------------------"
  ./scripts/run_check.sh "$CHECK" || {
    echo "⚠️  Skipping to next check (error in $CHECK)"
  }
  echo "-------------------------------------------"
done

# ---------------------------------------------------------------------
# 4️⃣ Generate consolidated HTML report
# ---------------------------------------------------------------------
echo
echo "🧩 Generating consolidated HTML report..."
python3 src/generate_html_report.py || {
  echo "⚠️  Failed to generate HTML report. Check Python logs."
}

echo
echo "✅ All checks completed!"
echo "📊 HTML dashboard: reports/aggregated/owasp_report.html"
echo "==========================================="
