#!/bin/bash

# Audit summary counters
total_audits=0
passed_audits=0
failed_audits=0
failed_scored=0
failed_not_scored=0
failed_scored_ids=""
failed_not_scored_ids=""
all_checked_chapters=""

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

# Result printer
print_result() {
    local result=$1
    local reason=$2
    if [[ "$result" == "PASS" ]]; then
        echo -e "Result : PASS"
    else
        echo -e "Result : FAIL$"
    fi
    echo "Reason : $reason"
    echo ""
    track_result "$audit_id" "$scoring" "$result"
}

# Summary tracker
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

echo "Chapter 11 Audit: Warning Banners"

# === 11.1 Set Warning Banner for Standard Login Services ===
check_11_1() {
    print_header "11.1" "Set Warning Banner for Standard Login Services" "Scored" \
        "Ensure /etc/motd, /etc/issue, /etc/issue.net have proper banner"

    expected_banner="Authorized uses only. All activity may be monitored and reported."
    files=("/etc/motd" "/etc/issue" "/etc/issue.net")
    for file in "${files[@]}"; do
        if [ -f "$file" ]; then
            if ! grep -q "$expected_banner" "$file"; then
                print_result "FAIL" "Banner not found or incorrect in $file"
                return
            fi
        else
            print_result "FAIL" "$file does not exist"
            return
        fi
    done

    print_result "PASS" "Banner correctly configured in all standard login files"
}

# === 11.2 Remove OS Information from Login Warning Banners ===
check_11_2() {
    print_header "11.2" "Remove OS Information from Login Warning Banners" "Scored" \
        "Ensure /etc/issue and /etc/issue.net do not contain OS info"

    for file in "/etc/issue" "/etc/issue.net"; do
        if [ -f "$file" ]; then
            if grep -E "(\\v|\\r|\\m|\\s)" "$file" > /dev/null; then
                print_result "FAIL" "OS info variable found in $file"
                return
            fi
        fi
    done

    print_result "PASS" "No OS information variables present in login banner files"
}

# === 11.3 Set Graphical Warning Banner ===
check_11_3() {
    print_header "11.3" "Set Graphical Warning Banner" "Not Scored" \
        "Check if graphical login banner is set in /etc/gdm/Init/Default or similar"

    expected_banner="Authorized uses only. All activity may be monitored and reported."
    banner_file="/etc/gdm/Init/Default"
    if [ -f "$banner_file" ]; then
        if grep -q "$expected_banner" "$banner_file"; then
            print_result "PASS" "Graphical warning banner is set in $banner_file"
        else
            print_result "FAIL" "Graphical warning banner not correctly set in $banner_file"
        fi
    else
        print_result "FAIL" "$banner_file not found (GDM may not be installed)"
    fi
}

# Run all Chapter 11 checks
check_11_1
check_11_2
check_11_3

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
