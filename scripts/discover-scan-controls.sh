#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUTPUT_DIR="$(dirname "$SCRIPT_DIR")/scan-output"
RESULTS_FILE="$OUTPUT_DIR/discovery-results.txt"

mkdir -p "$OUTPUT_DIR"

# Associative arrays for tracking results
# SCRIPT_CONTROLS stores entries as newline-delimited "C-XXXX|Control Name|count" lines
# (space-delimited caused parsing bugs when control names contain spaces)
declare -A SCRIPT_CONTROLS    # script -> newline-delimited "CID|Name|count" entries
declare -A SCRIPT_STATUS      # script -> PASS|FAIL
declare -A SCRIPT_FAIL_REASON # script -> human-readable failure reason
declare -A CONTROL_FIRST_SEEN # control_id -> first script that triggered it

# Expected control per script — the 1:1 kubescape control mapping goal
declare -A EXPECTED_CONTROL
EXPECTED_CONTROL["k01-sub0.sh"]="C-0057"  # Privileged container
EXPECTED_CONTROL["k01-sub1.sh"]="C-0013"  # Non-root containers (RunAsNonRoot)
EXPECTED_CONTROL["k01-sub2.sh"]="C-0038"  # Host PID / IPC privileges
EXPECTED_CONTROL["k01-sub3.sh"]="C-0041"  # HostNetwork access
EXPECTED_CONTROL["k01-sub4.sh"]="C-0048"  # HostPath mount
EXPECTED_CONTROL["k03-sub0.sh"]="C-0015"  # List Kubernetes secrets
EXPECTED_CONTROL["k03-sub1.sh"]="C-0188"  # Create pods
EXPECTED_CONTROL["k03-sub2.sh"]="C-0007"  # Delete Kubernetes resources
EXPECTED_CONTROL["k03-sub3.sh"]="C-0063"  # Portforwarding privileges
EXPECTED_CONTROL["k03-sub4.sh"]="C-0002"  # Exec into container
EXPECTED_CONTROL["k07-sub0.sh"]="C-0260"  # Missing network policy
EXPECTED_CONTROL["k08-sub0.sh"]="C-0012"  # Applications credentials in configuration files

echo "=== KUBESCAPE CONTROL DISCOVERY ===" | tee "$RESULTS_FILE"
echo "Started: $(date)" | tee -a "$RESULTS_FILE"
echo "Objective: each script triggers exactly 1 unique kubescape control with count=1" | tee -a "$RESULTS_FILE"
echo "" | tee -a "$RESULTS_FILE"

# Collect all k*-sub*.sh scripts, sorted
SCRIPTS=()
while IFS= read -r -d '' f; do
  SCRIPTS+=("$(basename "$f")")
done < <(find "$SCRIPT_DIR" -maxdepth 1 -name 'k*-sub*.sh' -print0 | sort -z)

echo "Found ${#SCRIPTS[@]} sub-issue scripts: ${SCRIPTS[*]}" | tee -a "$RESULTS_FILE"

# Validate that we have all expected scripts and no unexpected ones
EXPECTED_SCRIPTS=("${!EXPECTED_CONTROL[@]}")
IFS=$'\n' EXPECTED_SCRIPTS_SORTED=($(sort <<< "${EXPECTED_SCRIPTS[*]}")); unset IFS
echo "Expected ${#EXPECTED_CONTROL[@]} scripts based on target mapping" | tee -a "$RESULTS_FILE"

for EXPECTED in "${EXPECTED_SCRIPTS_SORTED[@]}"; do
  if [[ ! -f "$SCRIPT_DIR/$EXPECTED" ]]; then
    echo "  WARNING: Expected script $EXPECTED not found" | tee -a "$RESULTS_FILE"
  fi
done
for SCRIPT_NAME in "${SCRIPTS[@]}"; do
  if [[ -z "${EXPECTED_CONTROL[$SCRIPT_NAME]:-}" ]]; then
    echo "  WARNING: Script $SCRIPT_NAME has no expected control mapping" | tee -a "$RESULTS_FILE"
  fi
done
echo "" | tee -a "$RESULTS_FILE"

for SCRIPT_NAME in "${SCRIPTS[@]}"; do
  SCRIPT_PATH="$SCRIPT_DIR/$SCRIPT_NAME"
  SCAN_OUTPUT_FILE="$OUTPUT_DIR/${SCRIPT_NAME%.sh}-scan.txt"
  EXPECTED="${EXPECTED_CONTROL[$SCRIPT_NAME]:-UNKNOWN}"

  echo "--- Processing $SCRIPT_NAME (expected: $EXPECTED) ---" | tee -a "$RESULTS_FILE"

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
    SCRIPT_STATUS["$SCRIPT_NAME"]="FAIL"
    SCRIPT_FAIL_REASON["$SCRIPT_NAME"]="script execution failed"
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
echo "=== PER-SCRIPT RESULTS ===" | tee -a "$RESULTS_FILE"
echo "" | tee -a "$RESULTS_FILE"

# Determine pass/fail for each script
for SCRIPT_NAME in "${SCRIPTS[@]}"; do
  CONTROLS="${SCRIPT_CONTROLS[$SCRIPT_NAME]:-}"
  EXPECTED="${EXPECTED_CONTROL[$SCRIPT_NAME]:-UNKNOWN}"

  # Skip scripts that already have a status set (e.g. ERROR during execution)
  if [[ -n "${SCRIPT_STATUS[$SCRIPT_NAME]:-}" ]]; then
    continue
  fi

  # Count distinct controls
  CONTROL_COUNT=0
  if [[ -n "$CONTROLS" ]]; then
    while IFS= read -r entry; do
      [[ -z "$entry" ]] && continue
      CONTROL_COUNT=$((CONTROL_COUNT + 1))
    done <<< "$CONTROLS"
  fi

  if [[ $CONTROL_COUNT -eq 0 ]]; then
    SCRIPT_STATUS["$SCRIPT_NAME"]="FAIL"
    SCRIPT_FAIL_REASON["$SCRIPT_NAME"]="NO_TRIGGER: no controls detected"
  elif [[ $CONTROL_COUNT -gt 1 ]]; then
    SCRIPT_STATUS["$SCRIPT_NAME"]="FAIL"
    CONTROLS_LIST=""
    while IFS= read -r entry; do
      [[ -z "$entry" ]] && continue
      IFS='|' read -r CID _ _ <<< "$entry"
      CONTROLS_LIST="${CONTROLS_LIST:+$CONTROLS_LIST, }$CID"
    done <<< "$CONTROLS"
    SCRIPT_FAIL_REASON["$SCRIPT_NAME"]="MULTI: triggers $CONTROL_COUNT controls ($CONTROLS_LIST)"
  else
    # Exactly one control — validate it
    entry=$(head -1 <<< "$CONTROLS")
    IFS='|' read -r ACTUAL_CID _ ACTUAL_COUNT <<< "$entry"

    if [[ "$ACTUAL_CID" != "$EXPECTED" ]]; then
      SCRIPT_STATUS["$SCRIPT_NAME"]="FAIL"
      SCRIPT_FAIL_REASON["$SCRIPT_NAME"]="WRONG_CONTROL: got $ACTUAL_CID, expected $EXPECTED"
    elif [[ "$ACTUAL_COUNT" -gt 1 ]]; then
      SCRIPT_STATUS["$SCRIPT_NAME"]="FAIL"
      SCRIPT_FAIL_REASON["$SCRIPT_NAME"]="HIGH_COUNT: $ACTUAL_CID triggered with count=$ACTUAL_COUNT (expected 1)"
    elif [[ -n "${CONTROL_FIRST_SEEN[$ACTUAL_CID]:-}" ]]; then
      SCRIPT_STATUS["$SCRIPT_NAME"]="FAIL"
      FIRST="${CONTROL_FIRST_SEEN[$ACTUAL_CID]}"
      SCRIPT_FAIL_REASON["$SCRIPT_NAME"]="DUPLICATE: $ACTUAL_CID already triggered by $FIRST"
    else
      SCRIPT_STATUS["$SCRIPT_NAME"]="PASS"
      CONTROL_FIRST_SEEN["$ACTUAL_CID"]="$SCRIPT_NAME"
    fi
  fi
done

# Print per-script results
for SCRIPT_NAME in "${SCRIPTS[@]}"; do
  CONTROLS="${SCRIPT_CONTROLS[$SCRIPT_NAME]:-}"
  STATUS="${SCRIPT_STATUS[$SCRIPT_NAME]:-FAIL}"
  EXPECTED="${EXPECTED_CONTROL[$SCRIPT_NAME]:-UNKNOWN}"

  printf "%-20s  expected=%-7s  " "$SCRIPT_NAME" "$EXPECTED" | tee -a "$RESULTS_FILE"

  if [[ -z "$CONTROLS" ]]; then
    printf "actual=(none)\n" | tee -a "$RESULTS_FILE"
  else
    ACTUAL_LIST=""
    while IFS= read -r entry; do
      [[ -z "$entry" ]] && continue
      IFS='|' read -r CID _ COUNT <<< "$entry"
      ACTUAL_LIST="${ACTUAL_LIST:+$ACTUAL_LIST, }${CID}(${COUNT})"
    done <<< "$CONTROLS"
    printf "actual=%-20s  " "$ACTUAL_LIST" | tee -a "$RESULTS_FILE"
  fi

  if [[ "$STATUS" == "PASS" ]]; then
    printf "PASS\n" | tee -a "$RESULTS_FILE"
  else
    REASON="${SCRIPT_FAIL_REASON[$SCRIPT_NAME]:-unknown}"
    printf "FAIL  [%s]\n" "$REASON" | tee -a "$RESULTS_FILE"
  fi
done

echo "" | tee -a "$RESULTS_FILE"
echo "=== SUMMARY ===" | tee -a "$RESULTS_FILE"
echo "" | tee -a "$RESULTS_FILE"

PASS_COUNT=0
FAIL_COUNT=0
FAIL_SCRIPTS=()

for SCRIPT_NAME in "${SCRIPTS[@]}"; do
  STATUS="${SCRIPT_STATUS[$SCRIPT_NAME]:-FAIL}"
  if [[ "$STATUS" == "PASS" ]]; then
    PASS_COUNT=$((PASS_COUNT + 1))
  else
    FAIL_COUNT=$((FAIL_COUNT + 1))
    FAIL_SCRIPTS+=("${SCRIPT_NAME%.sh}")
  fi
done

TOTAL="${#SCRIPTS[@]}"
echo "Results: $PASS_COUNT/$TOTAL scripts PASS" | tee -a "$RESULTS_FILE"

if [[ $FAIL_COUNT -gt 0 ]]; then
  echo "Failed:  $(IFS=', '; echo "${FAIL_SCRIPTS[*]}")" | tee -a "$RESULTS_FILE"
fi

echo "" | tee -a "$RESULTS_FILE"

if [[ $FAIL_COUNT -eq 0 && $TOTAL -eq ${#EXPECTED_CONTROL[@]} ]]; then
  echo "OBJECTIVE MET: all $TOTAL scripts trigger exactly 1 unique kubescape control with count=1" | tee -a "$RESULTS_FILE"
  OBJECTIVE_MET=0
else
  echo "OBJECTIVE NOT MET: $FAIL_COUNT/$TOTAL scripts failed" | tee -a "$RESULTS_FILE"
  OBJECTIVE_MET=1
fi

echo "" | tee -a "$RESULTS_FILE"
echo "Full results saved to: $RESULTS_FILE" | tee -a "$RESULTS_FILE"
echo "Individual scan outputs in: $OUTPUT_DIR/" | tee -a "$RESULTS_FILE"
echo "Completed: $(date)" | tee -a "$RESULTS_FILE"

exit $OBJECTIVE_MET
