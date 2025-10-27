#!/usr/bin/env bash
# =====================================================================
# File: run_check.sh
# Author: Security Automation Team
#
# Purpose:
#   Runs ONE specific OWASP automation check defined in config/checks.yml.
#
#   It:
#     - Reads config/checks.yml
#     - Finds the entry with name == <check_name>
#     - Extracts the Python module path, output path, and argument list
#     - Runs: python3 <module> <args...>
#     - Confirms that a report file was generated
#
# Usage:
#   ./scripts/run_check.sh <check_name>
# Example:
#   ./scripts/run_check.sh password_validation_check
#
# Works on:
#   ✅ macOS (zsh)
#   ✅ Linux (bash)
# =====================================================================

# ---------------------------------------------------------------------
# 1. Shell configuration
# ---------------------------------------------------------------------
# "set -euo pipefail" means:
#   -e : exit immediately if a command fails
#   -u : treat undefined variables as errors
#   -o pipefail : if any command in a pipeline fails, the whole pipeline fails
set -euo pipefail

# ---------------------------------------------------------------------
# 2. Input validation
# ---------------------------------------------------------------------
# Expecting a single argument — the check name (as defined in checks.yml)
if [ $# -lt 1 ]; then
  echo "Usage: $0 <check_name>"
  exit 2
fi

CHECK_NAME="$1"
CONFIG_FILE="config/checks.yml"

# Make sure the YAML config file exists
if [ ! -f "$CONFIG_FILE" ]; then
  echo "❌ Missing configuration file: $CONFIG_FILE"
  exit 3
fi

# ---------------------------------------------------------------------
# 3. Helper function: Extract a key (module/output/args) from YAML
# ---------------------------------------------------------------------
# This uses `yq` if available (fast, ideal),
# otherwise falls back to a small inline Python YAML parser (portable).
get_config_value() {
  local key="$1"
  if command -v yq >/dev/null 2>&1; then
    # yq available: use it directly
    if [ "$key" = "args" ]; then
      # Extract arguments array as JSON (default empty list)
      yq -r ".[] | select(.name==\"${CHECK_NAME}\") | .args // []" "$CONFIG_FILE" || echo "[]"
    else
      # Extract single value (module/output)
      yq -r ".[] | select(.name==\"${CHECK_NAME}\") | .${key} // \"\"" "$CONFIG_FILE" || echo ""
    fi
  else
    # Python fallback if yq not installed
    python3 - <<PY
import yaml, json
cfg = "$CONFIG_FILE"
name = "$CHECK_NAME"
with open(cfg) as f:
    data = yaml.safe_load(f)
for entry in data:
    if entry.get("name")==name:
        if "$key"=="args":
            print(json.dumps(entry.get("args", [])))
        else:
            print(entry.get("$key",""))
        break
PY
  fi
}

# ---------------------------------------------------------------------
# 4. Extract configuration values for this check
# ---------------------------------------------------------------------
MODULE=$(get_config_value module)   # e.g. src/password_validation_check.py
OUTPUT=$(get_config_value output)   # e.g. reports/raw/password_validation_report.json
ARGS_JSON=$(get_config_value args)  # e.g. ["--target","https://example.com"]

# ---------------------------------------------------------------------
# 5. Validate that the module was found
# ---------------------------------------------------------------------
if [ -z "$MODULE" ] || [ "$MODULE" = "null" ]; then
  echo "❌ Unknown or missing module for check: $CHECK_NAME"
  exit 4
fi

# ---------------------------------------------------------------------
# 6. Convert JSON args (["--target","url"]) into a Bash array
# ---------------------------------------------------------------------
# We use Python to read the JSON array safely (portable between macOS/Linux)
ARGS_ARRAY=()
if [ -n "$ARGS_JSON" ] && [ "$ARGS_JSON" != "[]" ]; then
  while IFS= read -r arg; do
    ARGS_ARRAY+=("$arg")
  done < <(python3 - <<PY
import json
for x in json.loads('''$ARGS_JSON'''):
    print(x)
PY
)
fi

# ---------------------------------------------------------------------
# 7. Display check summary before running
# ---------------------------------------------------------------------
echo "📘 Running check: $CHECK_NAME"
echo " - Module : $MODULE"
echo " - Output : $OUTPUT"
if [ ${#ARGS_ARRAY[@]} -gt 0 ]; then
  echo " - Args   : ${ARGS_ARRAY[*]}"
else
  echo " - Args   : (none)"
fi
echo "---------------------------------------------"

# ---------------------------------------------------------------------
# 8. Ensure the target Python module exists
# ---------------------------------------------------------------------
if [ ! -f "$MODULE" ]; then
  echo "❌ Module file not found: $MODULE"
  exit 5
fi

# ---------------------------------------------------------------------
# 9. Execute the module with its arguments
# ---------------------------------------------------------------------
#   e.g. python3 src/password_validation_check.py --target https://example.com
set +e  # temporarily disable "exit on error" to catch Python exit code
python3 "$MODULE" "${ARGS_ARRAY[@]}"
RC=$?
set -e  # re-enable strict mode

# ---------------------------------------------------------------------
# 10. Handle success or failure
# ---------------------------------------------------------------------
if [ $RC -ne 0 ]; then
  echo "❌ Check failed: $CHECK_NAME (exit code $RC)"
  exit $RC
fi

# ---------------------------------------------------------------------
# 11. Confirm output file exists (if one was defined)
# ---------------------------------------------------------------------
if [ -n "$OUTPUT" ] && [ -f "$OUTPUT" ]; then
  echo "✅ $CHECK_NAME finished successfully. Report saved: $OUTPUT"
else
  echo "⚠️  $CHECK_NAME completed but no report file found."
fi

echo "---------------------------------------------"
exit 0
