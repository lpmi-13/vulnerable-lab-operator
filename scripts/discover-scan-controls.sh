#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_DIR="$(dirname "$SCRIPT_DIR")/scan-output"
RESULTS_FILE="$OUTPUT_DIR/discovery-results.txt"

mkdir -p "$OUTPUT_DIR"

# Associative arrays for tracking results
# SCRIPT_CONTROLS stores entries as newline-delimited "C-XXXX|Control Name|count" lines
# (space-delimited caused parsing bugs when control names contain spaces)
declare -A SCRIPT_CONTROLS   # script -> newline-delimited "CID|Name|count" entries
declare -A SCRIPT_STATUS     # script -> OK|DUPLICATE|MULTI|NO_TRIGGER|HIGH_COUNT
declare -A CONTROL_FIRST_SEEN # control_id -> first script that triggered it

echo "=== KUBESCAPE CONTROL DISCOVERY ===" | tee "$RESULTS_FILE"
echo "Started: $(date)" | tee -a "$RESULTS_FILE"
echo "" | tee -a "$RESULTS_FILE"

# Collect all k*-sub*.sh scripts, sorted
SCRIPTS=()
while IFS= read -r -d '' f; do
  SCRIPTS+=("$(basename "$f")")
done < <(find "$SCRIPT_DIR" -maxdepth 1 -name 'k*-sub*.sh' -print0 | sort -z)

echo "Found ${#SCRIPTS[@]} sub-issue scripts: ${SCRIPTS[*]}" | tee -a "$RESULTS_FILE"
echo "" | tee -a "$RESULTS_FILE"

for SCRIPT_NAME in "${SCRIPTS[@]}"; do
  SCRIPT_PATH="$SCRIPT_DIR/$SCRIPT_NAME"
  SCAN_OUTPUT_FILE="$OUTPUT_DIR/${SCRIPT_NAME%.sh}-scan.txt"

  echo "--- Processing $SCRIPT_NAME ---" | tee -a "$RESULTS_FILE"

  # Full cluster reset: delete VulnerableLab and all RBAC resources created by K03
  # (K03 Role/RoleBinding/ClusterRoleBinding resources persist after VulnerableLab deletion
  # since they are not part of the baseline stack cleaned up by the controller)
  echo "  Resetting cluster state..." | tee -a "$RESULTS_FILE"
  kubectl delete vulnerablelab test-lab --ignore-not-found --wait=true 2>&1 | tee -a "$RESULTS_FILE" || true
  kubectl delete role,rolebinding -n test-lab \
    -l rbac.k8s.lab/managed-by=vulnerable-lab \
    --ignore-not-found 2>&1 | tee -a "$RESULTS_FILE" || true
  kubectl delete clusterrole,clusterrolebinding \
    -l rbac.k8s.lab/managed-by=vulnerable-lab \
    --ignore-not-found 2>&1 | tee -a "$RESULTS_FILE" || true
  sleep 5

  # Run the sub-issue script
  echo "  Running $SCRIPT_NAME..." | tee -a "$RESULTS_FILE"
  if ! bash "$SCRIPT_PATH" 2>&1 | tee -a "$RESULTS_FILE"; then
    echo "  ERROR: $SCRIPT_NAME failed to apply" | tee -a "$RESULTS_FILE"
    SCRIPT_CONTROLS["$SCRIPT_NAME"]=""
    SCRIPT_STATUS["$SCRIPT_NAME"]="ERROR"
    continue
  fi

  # Wait for all deployments to be ready
  echo "  Waiting for deployments to be ready..." | tee -a "$RESULTS_FILE"
  if ! kubectl wait deployment --all -n test-lab --for=condition=Available --timeout=120s 2>&1 | tee -a "$RESULTS_FILE"; then
    echo "  WARNING: Not all deployments became available in time" | tee -a "$RESULTS_FILE"
  fi

  # Let API cache settle
  sleep 5

  # Run kubescape scan
  echo "  Running kubescape scan..." | tee -a "$RESULTS_FILE"
  kubescape scan --include-namespaces test-lab 2>&1 | tee "$SCAN_OUTPUT_FILE" | tee -a "$RESULTS_FILE"

  # Parse controls from kubescape output.
  # Store entries newline-delimited to avoid splitting on spaces within control names.
  CONTROLS_FOUND=""
  while IFS= read -r line; do
    CONTROL_ID=$(echo "$line" | grep -oP 'C-[0-9]+' | head -1)
    COUNT=$(echo "$line" | awk -F'│' '{gsub(/ /,"",$3); print $3}' | tr -d ' ')
    CONTROL_NAME=$(echo "$line" | awk -F'│' '{print $2}' | sed 's/^ *//;s/ *$//')

    if [[ -n "$CONTROL_ID" && -n "$COUNT" && "$COUNT" =~ ^[0-9]+$ && "$COUNT" -gt 0 ]]; then
      CONTROLS_FOUND="${CONTROLS_FOUND}${CONTROLS_FOUND:+$'\n'}${CONTROL_ID}|${CONTROL_NAME}|${COUNT}"
    fi
  done < <(grep -E '│.*│.*[1-9][0-9]*.*│.*C-[0-9]+' "$SCAN_OUTPUT_FILE" || true)

  SCRIPT_CONTROLS["$SCRIPT_NAME"]="$CONTROLS_FOUND"
  echo "" | tee -a "$RESULTS_FILE"
done

echo "" | tee -a "$RESULTS_FILE"
echo "=== DISCOVERY RESULTS ===" | tee -a "$RESULTS_FILE"
echo "" | tee -a "$RESULTS_FILE"

# Determine statuses and first-seen controls
for SCRIPT_NAME in "${SCRIPTS[@]}"; do
  CONTROLS="${SCRIPT_CONTROLS[$SCRIPT_NAME]:-}"

  if [[ "${SCRIPT_STATUS[$SCRIPT_NAME]:-}" == "ERROR" ]]; then
    continue
  fi

  # Count distinct controls (entries are newline-delimited)
  CONTROL_COUNT=0
  if [[ -n "$CONTROLS" ]]; then
    while IFS= read -r entry; do
      [[ -z "$entry" ]] && continue
      CONTROL_COUNT=$((CONTROL_COUNT + 1))
    done <<< "$CONTROLS"
  fi

  # Determine status
  if [[ $CONTROL_COUNT -eq 0 ]]; then
    SCRIPT_STATUS["$SCRIPT_NAME"]="NO_TRIGGER"
  elif [[ $CONTROL_COUNT -gt 1 ]]; then
    SCRIPT_STATUS["$SCRIPT_NAME"]="MULTI"
  else
    # Single control - check count and duplication
    entry=$(head -1 <<< "$CONTROLS")
    IFS='|' read -r CID CNAME CCOUNT <<< "$entry"
    if [[ "$CCOUNT" -gt 1 ]]; then
      SCRIPT_STATUS["$SCRIPT_NAME"]="HIGH_COUNT"
    elif [[ -n "${CONTROL_FIRST_SEEN[$CID]:-}" ]]; then
      SCRIPT_STATUS["$SCRIPT_NAME"]="DUPLICATE"
    else
      SCRIPT_STATUS["$SCRIPT_NAME"]="OK"
      CONTROL_FIRST_SEEN["$CID"]="$SCRIPT_NAME"
    fi
  fi
done

# Print results per script
for SCRIPT_NAME in "${SCRIPTS[@]}"; do
  echo "$SCRIPT_NAME:" | tee -a "$RESULTS_FILE"
  CONTROLS="${SCRIPT_CONTROLS[$SCRIPT_NAME]:-}"
  STATUS="${SCRIPT_STATUS[$SCRIPT_NAME]:-UNKNOWN}"

  if [[ -z "$CONTROLS" ]]; then
    echo "  (none)" | tee -a "$RESULTS_FILE"
  else
    while IFS= read -r entry; do
      [[ -z "$entry" ]] && continue
      IFS='|' read -r CID CNAME CCOUNT <<< "$entry"
      echo "  $CID $CNAME: $CCOUNT" | tee -a "$RESULTS_FILE"
    done <<< "$CONTROLS"
  fi

  # Build status message
  case "$STATUS" in
    OK)
      echo "  STATUS: OK (1 control, count=1)" | tee -a "$RESULTS_FILE"
      ;;
    DUPLICATE)
      entry=$(head -1 <<< "$CONTROLS")
      IFS='|' read -r CID _ _ <<< "$entry"
      FIRST="${CONTROL_FIRST_SEEN[$CID]:-unknown}"
      echo "  STATUS: DUPLICATE (same control as $FIRST)" | tee -a "$RESULTS_FILE"
      ;;
    MULTI)
      echo "  STATUS: MULTI (triggers multiple controls)" | tee -a "$RESULTS_FILE"
      ;;
    NO_TRIGGER)
      echo "  STATUS: NO_TRIGGER (no controls detected)" | tee -a "$RESULTS_FILE"
      ;;
    HIGH_COUNT)
      echo "  STATUS: HIGH_COUNT (count > 1)" | tee -a "$RESULTS_FILE"
      ;;
    ERROR)
      echo "  STATUS: ERROR (script failed)" | tee -a "$RESULTS_FILE"
      ;;
    *)
      echo "  STATUS: UNKNOWN" | tee -a "$RESULTS_FILE"
      ;;
  esac
  echo "" | tee -a "$RESULTS_FILE"
done

echo "=== SUMMARY ===" | tee -a "$RESULTS_FILE"
echo "" | tee -a "$RESULTS_FILE"

for STATUS_TYPE in OK DUPLICATE MULTI NO_TRIGGER HIGH_COUNT ERROR; do
  MATCHING=()
  for SCRIPT_NAME in "${SCRIPTS[@]}"; do
    if [[ "${SCRIPT_STATUS[$SCRIPT_NAME]:-}" == "$STATUS_TYPE" ]]; then
      MATCHING+=("${SCRIPT_NAME%.sh}")
    fi
  done

  if [[ ${#MATCHING[@]} -gt 0 ]]; then
    case "$STATUS_TYPE" in
      OK)         LABEL="OK (1 control, count=1)" ;;
      DUPLICATE)  LABEL="DUPLICATE (same control as another OK script)" ;;
      MULTI)      LABEL="MULTI (triggers multiple controls)" ;;
      NO_TRIGGER) LABEL="NO_TRIGGER (no controls detected)" ;;
      HIGH_COUNT) LABEL="HIGH_COUNT (count > 1)" ;;
      ERROR)      LABEL="ERROR (script execution failed)" ;;
    esac
    echo "$LABEL: $(IFS=', '; echo "${MATCHING[*]}")" | tee -a "$RESULTS_FILE"
  fi
done

echo "" | tee -a "$RESULTS_FILE"
echo "Full results saved to: $RESULTS_FILE" | tee -a "$RESULTS_FILE"
echo "Individual scan outputs in: $OUTPUT_DIR/" | tee -a "$RESULTS_FILE"
echo "Completed: $(date)" | tee -a "$RESULTS_FILE"
