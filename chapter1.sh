#!/bin/bash

# audit sum
total_audits=0
passed_audits=0
failed_audits=0
failed_scored=0
failed_not_scored=0
failed_scored_ids=""
failed_not_scored_ids=""

all_checked_chapters="" #to check for missing chapters, ensuring its all there

# Header output function
print_header() {
    audit_id="$1"
    audit_title="$2"
    scoring="$3"

    echo "-------------------------------------------------------------"
    echo -e "Audit ID: $audit_id"
    echo "Title   : $audit_title"
    echo "SCORING : $scoring"
    echo ""
    echo "Audit Check: $4"
    echo ""
}

# Generic result printer
print_result() {
    local result=$1
    local reason=$2
    if [[ "$result" == "PASS" ]]; then
        echo -e "Result : PASS"
    else
        echo -e "Result : FAIL"
    fi
    echo "Reason : $reason"
    echo ""

    track_result "$audit_id" "$scoring" "$result"
}

# Track summary
track_result() {
    local audit_id="$1"
    local scoring="$2"
    local result="$3"

    total_audits=$((total_audits + 1))
    all_checked_chapters+="$audit_id\n"

    if [[ "$result" == "PASS" ]]; then
        passed_audits=$((passed_audits + 1))
    else
        failed_audits=$((failed_audits + 1))
        if [[ "$scoring" == "Scored" ]]; then
            failed_scored=$((failed_scored + 1))
            failed_scored_ids+=" - $audit_id\n"
        else
            failed_not_scored=$((failed_not_scored + 1))
            failed_not_scored_ids+=" - $audit_id\n"
        fi
    fi
}

echo "Chapter 1 Audit: Patching and Software Updates"

# 1.1 - Install Updates, Patches and Additional Security Software
check_1_1() {
    print_header "1.1" "Install Updates, Patches and Additional Security Software" "Not Scored" \
        "Check if the package database is updated and if unattended-upgrades or similar is installed."

    local update_stamp="/var/lib/apt/periodic/update-success-stamp"
    local seven_days=$((7 * 24 * 60 * 60))
    local current_time=$(date +%s)

    if [[ ! -f "$update_stamp" ]]; then
        print_result "FAIL" "System has no record of 'apt-get update' being run."
        return
    fi

    local last_update
    last_update=$(stat -c %Y "$update_stamp" 2>/dev/null)
    local time_diff=$((current_time - last_update))

    local unattended_installed
    unattended_installed=$(dpkg -l | grep unattended-upgrades)

    if [[ "$time_diff" -gt "$seven_days" ]]; then
        print_result "FAIL" "'apt-get update' has not been run in the last 7 days."
    elif [[ -z "$unattended_installed" ]]; then
        print_result "FAIL" "unattended-upgrades package is not installed."
    else
        print_result "PASS" "Package database was updated recently and unattended-upgrades is installed."
    fi
}

# Call the audit
check_1_1

# Final Summary
echo -e "========================================"
echo "              Audit Summary             "
echo "========================================"
echo "Total Audits           : $total_audits"
echo "Passed Audits          : $passed_audits"
echo "Failed Audits          : $failed_audits"
echo "  - Scored             : $failed_scored"
echo "  - Not Scored         : $failed_not_scored"
echo ""

if [[ -n "$failed_scored_ids" ]]; then
    echo -e "Failed Scored Audit IDs:"
    echo -e "$failed_scored_ids"
fi

if [[ -n "$failed_not_scored_ids" ]]; then
    echo -e "Failed Not Scored Audit IDs:"
    echo -e "$failed_not_scored_ids"
fi

echo "========================================"
