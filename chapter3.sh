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
    echo -e "Audit ID: $audit_id "
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
        echo -e "Result : FAIL"
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

echo "Chapter 3 Audit: Secure Boot Settings"

# === 3.1 Set User/Group Owner on bootloader config ===
check_3_1() {
    print_header "3.1" "Set User/Group Owner on bootloader config" "Scored" \
        "Check ownership of /boot/grub/grub.cfg or /boot/grub/menu.lst"

    GRUB_FILE="/boot/grub/grub.cfg"
    [ -f "$GRUB_FILE" ] || GRUB_FILE="/boot/grub/menu.lst"

    if [ -f "$GRUB_FILE" ]; then
        owner=$(stat -c "%U:%G" "$GRUB_FILE")
        if [ "$owner" = "root:root" ]; then
            print_result "PASS" "$GRUB_FILE is owned by root:root"
        else
            print_result "FAIL" "$GRUB_FILE is owned by $owner instead of root:root"
        fi
    else
        print_result "FAIL" "GRUB config file not found"
    fi
}

# === 3.2 Set Permissions on bootloader config ===
check_3_2() {
    print_header "3.2" "Set Permissions on bootloader config" "Scored" \
        "Ensure /boot/grub/grub.cfg or /boot/grub/menu.lst has permissions 600"

    GRUB_FILE="/boot/grub/grub.cfg"
    [ -f "$GRUB_FILE" ] || GRUB_FILE="/boot/grub/menu.lst"

    if [ -f "$GRUB_FILE" ]; then
        perms=$(stat -c "%a" "$GRUB_FILE")
        if [ "$perms" -eq 600 ]; then
            print_result "PASS" "$GRUB_FILE has correct permissions (600)"
        else
            print_result "FAIL" "$GRUB_FILE has incorrect permissions ($perms), expected 600"
        fi
    else
        print_result "FAIL" "GRUB config file not found"
    fi
}

# === 3.3 Set Boot Loader Password ===
check_3_3() {
    print_header "3.3" "Set Boot Loader Password" "Scored" \
        "Verify password line exists in /boot/grub/grub.cfg or /boot/grub/menu.lst"

    GRUB_FILE="/boot/grub/grub.cfg"
    [ -f "$GRUB_FILE" ] || GRUB_FILE="/boot/grub/menu.lst"

    if [ -f "$GRUB_FILE" ]; then
        if grep -q "^password" "$GRUB_FILE"; then
            print_result "PASS" "Password is set in GRUB config"
        else
            print_result "FAIL" "No password line found in $GRUB_FILE"
        fi
    else
        print_result "FAIL" "GRUB config file not found"
    fi
}

# === 3.4 Require Authentication for Single-User Mode ===
check_3_4() {
    print_header "3.4" "Require Authentication for Single-User Mode" "Scored" \
        "Verify /sbin/sulogin is required for single-user mode"

    INIT_FILE="/etc/init/rc-sysinit.conf"
    ALT_FILE="/etc/inittab"

    if [ -f "$INIT_FILE" ]; then
        if grep -q "/sbin/sulogin" "$INIT_FILE"; then
            print_result "PASS" "sulogin is configured in $INIT_FILE"
        else
            print_result "FAIL" "sulogin not found in $INIT_FILE"
        fi
    elif [ -f "$ALT_FILE" ]; then
        if grep -q "single.*sulogin" "$ALT_FILE"; then
            print_result "PASS" "sulogin is configured in $ALT_FILE"
        else
            print_result "FAIL" "sulogin not found in $ALT_FILE"
        fi
    else
        print_result "FAIL" "No init file found for single-user mode configuration"
    fi
}

# Run all Chapter 3 checks
check_3_1
check_3_2
check_3_3
check_3_4

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
