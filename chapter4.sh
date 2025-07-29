#!/bin/bash


# Audit summary
total_audits=0
passed_audits=0
failed_audits=0
failed_scored=0
failed_not_scored=0
failed_scored_ids=""
failed_not_scored_ids=""
all_checked_chapters=""

# Header output
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

# Track audit results
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

echo "Chapter 4 Audit: Additional Process Hardening"

# 4.1 Restrict Core Dumps
check_4_1() {
    print_header "4.1" "Restrict Core Dumps" "Scored" \
        "Check /etc/security/limits.conf for '* hard core 0', sysctl fs.suid_dumpable is 0, and apport & whoopsie are disabled"

    if grep -q "^* hard core 0" /etc/security/limits.conf &&
       [[ $(sysctl -n fs.suid_dumpable) -eq 0 ]] &&
       ! initctl show-config apport 2>&1 | grep -q "start on runlevel \[2345\]" &&
       ! initctl show-config whoopsie 2>&1 | grep -q "start on runlevel \[2345\]" ; then
        print_result "PASS" "Core dumps are restricted and apport/whoopsie services are disabled."
    else
        print_result "FAIL" "Core dumps are not restricted or apport/whoopsie services are enabled."
    fi
}

# 4.2 Enable XD/NX Support
check_4_2() {
    print_header "4.2" "Enable XD/NX Support on 32-bit x86 Systems" "Not Scored" \
        "Check dmesg output for 'NX (Execute Disable) protection: active'"

    if dmesg | grep -q "NX (Execute Disable) protection: active"; then
        print_result "PASS" "NX/XD protection is active."
    else
        print_result "FAIL" "NX/XD protection is not active."
    fi
}

# 4.3 Enable ASLR
check_4_3() {
    print_header "4.3" "Enable Randomized Virtual Memory Region Placement" "Scored" \
        "Check if kernel.randomize_va_space sysctl value is 2"

    if [[ $(sysctl -n kernel.randomize_va_space) -eq 2 ]]; then
        print_result "PASS" "ASLR is enabled with kernel.randomize_va_space set to 2."
    else
        print_result "FAIL" "ASLR is not properly enabled."
    fi
}

# 4.4 Disable Prelink
check_4_4() {
    print_header "4.4" "Disable Prelink" "Scored" \
        "Ensure prelink package is not installed"

    if ! dpkg -s prelink &>/dev/null; then
        print_result "PASS" "Prelink package is not installed."
    else
        print_result "FAIL" "Prelink package is installed."
    fi
}

# 4.5 Activate AppArmor
check_4_5() {
    print_header "4.5" "Activate AppArmor" "Scored" \
        "Check that apparmor is loaded, profiles enforced, and no unconfined or complain mode processes"

    if apparmor_status | grep -q "apparmor module is loaded" &&
       apparmor_status | grep -q "profiles are loaded" &&
       ! apparmor_status | grep -q "profiles are in complain mode" &&
       ! apparmor_status | grep -q "processes are unconfined"; then
        print_result "PASS" "AppArmor is active, with all profiles in enforce mode and no unconfined processes."
    else
        print_result "FAIL" "AppArmor is not active, or has complain/unconfined processes."
    fi
}

# Run all checks
check_4_1
check_4_2
check_4_3
check_4_4
check_4_5

# Summary
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
    echo ""
fi

if [[ -n "$failed_not_scored_ids" ]]; then
    echo -e "Failed Not Scored Audit IDs:"
    echo -e "$failed_not_scored_ids"
    echo ""
fi

echo "========================================"
