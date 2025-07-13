#!/bin/bash

# Summary counters
total_audits=0
passed_audits=0
failed_audits=0
failed_scored=0
failed_not_scored=0
failed_scored_ids=""
failed_not_scored_ids=""

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

print_result() {
    local result=$1
    local reason=$2
    local audit_id=$3
    local scoring=$4
    if [[ "$result" == "PASS" ]]; then
        echo -e "Result : PASS"
    else
        echo -e "Result : FAIL"
    fi
    echo "Reason : $reason"
    echo ""

    # Track summary
    total_audits=$((total_audits + 1))
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

# === Helper function to check systemd service status for multiple services ===
check_services_disabled() {
    local services=("$@")
    for svc in "${services[@]}"; do
        if systemctl is-enabled "$svc" &>/dev/null; then
            return 1
        fi
    done
    return 0
}

echo "Chapter 5 Audit: OS Services"

# === 5.1.1 Ensure NIS is not installed ===
check_5_1_1() {
    print_header "5.1.1" "Ensure NIS is not installed" "Scored" "Check if 'nis' package is not installed"
    if dpkg -s nis &>/dev/null; then
        print_result "FAIL" "NIS package is installed" "5.1.1" "Scored"
    else
        print_result "PASS" "NIS package is not installed" "5.1.1" "Scored"
    fi
}

# === 5.1.2 Ensure rsh server is not enabled ===
check_5_1_2() {
    print_header "5.1.2" "Ensure rsh server is not enabled" "Scored" "Ensure rsh server service is not active"
    # Check rsh-related sockets: rsh.socket, rlogin.socket, rexec.socket
    if check_services_disabled rsh.socket rlogin.socket rexec.socket; then
        print_result "PASS" "rsh-related services are not enabled" "5.1.2" "Scored"
    else
        print_result "FAIL" "rsh-related services are enabled" "5.1.2" "Scored"
    fi
}

# === 5.1.3 Ensure rsh client is not installed ===
check_5_1_3() {
    print_header "5.1.3" "Ensure rsh client is not installed" "Scored" "Check if 'rsh-client' package is not installed"
    if dpkg -s rsh-client &>/dev/null; then
        print_result "FAIL" "rsh-client package is installed" "5.1.3" "Scored"
    else
        print_result "PASS" "rsh-client package is not installed" "5.1.3" "Scored"
    fi
}

# === 5.1.4 Ensure talk server is not enabled ===
check_5_1_4() {
    print_header "5.1.4" "Ensure talk server is not enabled" "Scored" "Ensure talk server is not enabled"
    if systemctl is-enabled ntalk &>/dev/null; then
        print_result "FAIL" "ntalk service is enabled" "5.1.4" "Scored"
    else
        print_result "PASS" "ntalk service is not enabled" "5.1.4" "Scored"
    fi
}

# === 5.1.5 Ensure talk client is not installed ===
check_5_1_5() {
    print_header "5.1.5" "Ensure talk client is not installed" "Scored" "Check if 'talk' package is not installed"
    if dpkg -s talk &>/dev/null; then
        print_result "FAIL" "talk package is installed" "5.1.5" "Scored"
    else
        print_result "PASS" "talk package is not installed" "5.1.5" "Scored"
    fi
}

# === 5.1.6 Ensure telnet server is not enabled ===
check_5_1_6() {
    print_header "5.1.6" "Ensure telnet server is not enabled" "Scored" "Ensure telnet server is not enabled"
    if systemctl is-enabled telnet.socket &>/dev/null; then
        print_result "FAIL" "telnet server is enabled" "5.1.6" "Scored"
    else
        print_result "PASS" "telnet server is not enabled" "5.1.6" "Scored"
    fi
}

# === 5.1.7 Ensure tftp-server is not enabled ===
check_5_1_7() {
    print_header "5.1.7" "Ensure tftp-server is not enabled" "Scored" "Ensure tftp service is not enabled"
    if systemctl is-enabled tftp.socket &>/dev/null; then
        print_result "FAIL" "tftp server is enabled" "5.1.7" "Scored"
    else
        print_result "PASS" "tftp server is not enabled" "5.1.7" "Scored"
    fi
}

# === 5.1.8 Ensure xinetd is not enabled ===
check_5_1_8() {
    print_header "5.1.8" "Ensure xinetd is not enabled" "Scored" "Ensure xinetd service is not enabled"
    if systemctl is-enabled xinetd &>/dev/null; then
        print_result "FAIL" "xinetd service is enabled" "5.1.8" "Scored"
    else
        print_result "PASS" "xinetd service is not enabled" "5.1.8" "Scored"
    fi
}

# === 5.2 Ensure chargen is not enabled ===
check_5_2() {
    print_header "5.2" "Ensure chargen is not enabled" "Scored" \
        "Check if chargen is disabled in /etc/xinetd.d/chargen or systemd"
    if [ -f /etc/xinetd.d/chargen ]; then
        if grep -q "disable.*no" /etc/xinetd.d/chargen; then
            print_result "FAIL" "chargen is enabled in xinetd" "5.2" "Scored"
        else
            print_result "PASS" "chargen is disabled in xinetd" "5.2" "Scored"
        fi
    elif systemctl is-enabled chargen.socket &>/dev/null; then
        print_result "FAIL" "chargen.socket is enabled" "5.2" "Scored"
    else
        print_result "PASS" "chargen service is not enabled" "5.2" "Scored"
    fi
}

# === 5.3 Ensure daytime is not enabled ===
check_5_3() {
    print_header "5.3" "Ensure daytime is not enabled" "Scored" \
        "Check if daytime is disabled in /etc/xinetd.d/daytime or systemd"
    if [ -f /etc/xinetd.d/daytime ]; then
        if grep -q "disable.*no" /etc/xinetd.d/daytime; then
            print_result "FAIL" "daytime is enabled in xinetd" "5.3" "Scored"
        else
            print_result "PASS" "daytime is disabled in xinetd" "5.3" "Scored"
        fi
    elif systemctl is-enabled daytime.socket &>/dev/null; then
        print_result "FAIL" "daytime.socket is enabled" "5.3" "Scored"
    else
        print_result "PASS" "daytime service is not enabled" "5.3" "Scored"
    fi
}

# === 5.4 Ensure echo is not enabled ===
check_5_4() {
    print_header "5.4" "Ensure echo is not enabled" "Scored" \
        "Check if echo is disabled in /etc/xinetd.d/echo or systemd"
    if [ -f /etc/xinetd.d/echo ]; then
        if grep -q "disable.*no" /etc/xinetd.d/echo; then
            print_result "FAIL" "echo is enabled in xinetd" "5.4" "Scored"
        else
            print_result "PASS" "echo is disabled in xinetd" "5.4" "Scored"
        fi
    elif systemctl is-enabled echo.socket &>/dev/null; then
        print_result "FAIL" "echo.socket is enabled" "5.4" "Scored"
    else
        print_result "PASS" "echo service is not enabled" "5.4" "Scored"
    fi
}

# === 5.5 Ensure discard is not enabled ===
check_5_5() {
    print_header "5.5" "Ensure discard is not enabled" "Scored" \
        "Check if discard is disabled in /etc/xinetd.d/discard or systemd"
    if [ -f /etc/xinetd.d/discard ]; then
        if grep -q "disable.*no" /etc/xinetd.d/discard; then
            print_result "FAIL" "discard is enabled in xinetd" "5.5" "Scored"
        else
            print_result "PASS" "discard is disabled in xinetd" "5.5" "Scored"
        fi
    elif systemctl is-enabled discard.socket &>/dev/null; then
        print_result "FAIL" "discard.socket is enabled" "5.5" "Scored"
    else
        print_result "PASS" "discard service is not enabled" "5.5" "Scored"
    fi
}

# === 5.6 Ensure time is not enabled ===
check_5_6() {
    print_header "5.6" "Ensure time is not enabled" "Scored" \
        "Check if time is disabled in /etc/xinetd.d/time or systemd"
    if [ -f /etc/xinetd.d/time ]; then
        if grep -q "disable.*no" /etc/xinetd.d/time; then
            print_result "FAIL" "time is enabled in xinetd" "5.6" "Scored"
        else
            print_result "PASS" "time is disabled in xinetd" "5.6" "Scored"
        fi
    elif systemctl is-enabled time.socket &>/dev/null; then
        print_result "FAIL" "time.socket is enabled" "5.6" "Scored"
    else
        print_result "PASS" "time service is not enabled" "5.6" "Scored"
    fi
}

# Run all audits
check_5_1_1
check_5_1_2
check_5_1_3
check_5_1_4
check_5_1_5
check_5_1_6
check_5_1_7
check_5_1_8
check_5_2
check_5_3
check_5_4
check_5_5
check_5_6

# Final summary
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
