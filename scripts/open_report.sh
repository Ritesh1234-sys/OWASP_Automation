#!/bin/bash
# ===========================================
# open_report.sh
# -------------------------------------------
# Safely open the latest OWASP HTML report.
# Works in macOS, Linux, and VSCode terminals.
# ===========================================

REPORT_PATH="reports/aggregated/owasp_report.html"

if [ ! -f "$REPORT_PATH" ]; then
  echo "❌ No report found at $REPORT_PATH"
  echo "💡 Tip: Run './scripts/run_all.sh' first to generate it."
  exit 1
fi

echo "✅ Opening OWASP Automation Dashboard..."
if [[ "$OSTYPE" == "darwin"* ]]; then
  open "$REPORT_PATH"
elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
  xdg-open "$REPORT_PATH" >/dev/null 2>&1 &
else
  echo "⚠️ Unsupported OS — please open manually: $REPORT_PATH"
fi
