#!/bin/bash

# audit summary counters
total_audits=0
passed_audits=0
failed_audits=0
failed_scored=0
failed_not_scored=0
failed_scored_ids=""
failed_not_scored_ids=""
all_checked_chapters="" # to check for missing chapters

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

echo "Chapter 7 Audit: Network Configuration and Firewall"

# === Section 7 Audit Checks ===

check_7_1_1() {
    print_header "7.1.1" "Disable IP Forwarding" "Scored" \
        "Checking if net.ipv4.ip_forward is set to 0"
    if [[ $(/sbin/sysctl -n net.ipv4.ip_forward) -eq 0 ]]; then
        print_result "PASS" "net.ipv4.ip_forward is correctly set to 0."
    else
        print_result "FAIL" "net.ipv4.ip_forward is not set to 0."
    fi
}

check_7_1_2() {
    print_header "7.1.2" "Disable Send Packet Redirects" "Scored" \
        "Checking if send_redirects are set to 0"
    if [[ $(/sbin/sysctl -n net.ipv4.conf.all.send_redirects) -eq 0 && $(/sbin/sysctl -n net.ipv4.conf.default.send_redirects) -eq 0 ]]; then
        print_result "PASS" "Both send_redirects are correctly set to 0."
    else
        print_result "FAIL" "One or both send_redirects are not set to 0."
    fi
}

check_7_2_1() {
    print_header "7.2.1" "Disable Source Routed Packet Acceptance" "Scored" \
        "Checking if accept_source_route is set to 0"
    if [[ $(/sbin/sysctl -n net.ipv4.conf.all.accept_source_route) -eq 0 && $(/sbin/sysctl -n net.ipv4.conf.default.accept_source_route) -eq 0 ]]; then
        print_result "PASS" "Source routed packet acceptance is disabled."
    else
        print_result "FAIL" "Source routed packet acceptance is not properly disabled."
    fi
}

check_7_2_2() {
    print_header "7.2.2" "Disable ICMP Redirect Acceptance" "Scored" \
        "Checking if ICMP redirect acceptance is disabled"
    if [[ $(/sbin/sysctl -n net.ipv4.conf.all.accept_redirects) -eq 0 && $(/sbin/sysctl -n net.ipv4.conf.default.accept_redirects) -eq 0 ]]; then
        print_result "PASS" "ICMP redirect acceptance is disabled."
    else
        print_result "FAIL" "ICMP redirect acceptance is not properly disabled."
    fi
}

check_7_2_3() {
    print_header "7.2.3" "Disable Secure ICMP Redirect Acceptance" "Scored" \
        "Checking if secure ICMP redirect acceptance is disabled"
    if [[ $(/sbin/sysctl -n net.ipv4.conf.all.secure_redirects) -eq 0 && $(/sbin/sysctl -n net.ipv4.conf.default.secure_redirects) -eq 0 ]]; then
        print_result "PASS" "Secure ICMP redirect acceptance is disabled."
    else
        print_result "FAIL" "Secure ICMP redirect acceptance is not properly disabled."
    fi
}

check_7_2_4() {
    print_header "7.2.4" "Log Suspicious Packets" "Scored" \
        "Checking if martian packet logging is enabled"
    if [[ $(/sbin/sysctl -n net.ipv4.conf.all.log_martians) -eq 1 && $(/sbin/sysctl -n net.ipv4.conf.default.log_martians) -eq 1 ]]; then
        print_result "PASS" "Suspicious packet logging is enabled."
    else
        print_result "FAIL" "Suspicious packet logging is not enabled."
    fi
}

check_7_2_5() {
    print_header "7.2.5" "Enable Ignore Broadcast Requests" "Scored" \
        "Checking if net.ipv4.icmp_echo_ignore_broadcasts is set to 1"
    if [[ $(/sbin/sysctl -n net.ipv4.icmp_echo_ignore_broadcasts) -eq 1 ]]; then
        print_result "PASS" "Broadcast requests are ignored."
    else
        print_result "FAIL" "Broadcast requests are not ignored."
    fi
}

check_7_2_6() {
    print_header "7.2.6" "Enable Bad Error Message Protection" "Scored" \
        "Checking if bad error message protection is enabled"
    if [[ $(/sbin/sysctl -n net.ipv4.icmp_ignore_bogus_error_responses) -eq 1 ]]; then
        print_result "PASS" "Bad error message protection is enabled."
    else
        print_result "FAIL" "Bad error message protection is not enabled."
    fi
}

check_7_2_7() {
    print_header "7.2.7" "Enable RFC-recommended Source Route Validation" "Scored" \
        "Checking if rp_filter is set to 1"
    if [[ $(/sbin/sysctl -n net.ipv4.conf.all.rp_filter) -eq 1 && $(/sbin/sysctl -n net.ipv4.conf.default.rp_filter) -eq 1 ]]; then
        print_result "PASS" "Source route validation is enabled."
    else
        print_result "FAIL" "Source route validation is not enabled."
    fi
}

check_7_2_8() {
    print_header "7.2.8" "Enable TCP SYN Cookies" "Scored" \
        "Checking if TCP SYN Cookies are enabled"
    if [[ $(/sbin/sysctl -n net.ipv4.tcp_syncookies) -eq 1 ]]; then
        print_result "PASS" "TCP SYN Cookies are enabled."
    else
        print_result "FAIL" "TCP SYN Cookies are not enabled."
    fi
}

# 7.3.1 - Disable IPv6 Router Advertisements
check_7_3_1() {
    print_header "7.3.1" "Disable IPv6 Router Advertisements" "Not Scored" \
        "Checking if net.ipv6.conf.all.accept_ra and net.ipv6.conf.default.accept_ra are set to 0"

    if [[ $(/sbin/sysctl -n net.ipv6.conf.all.accept_ra) -eq 0 && $(/sbin/sysctl -n net.ipv6.conf.default.accept_ra) -eq 0 ]]; then
        print_result "PASS" "Both net.ipv6.conf.all.accept_ra and net.ipv6.conf.default.accept_ra are correctly set to 0."
    else
        print_result "FAIL" "One or both of net.ipv6.conf.all.accept_ra or net.ipv6.conf.default.accept_ra are not set to 0."
    fi
}

# 7.3.2 - Disable IPv6 Redirect Acceptance
check_7_3_2() {
    print_header "7.3.2" "Disable IPv6 Redirect Acceptance" "Not Scored" \
        "Checking if net.ipv6.conf.all.accept_redirects and net.ipv6.conf.default.accept_redirects are set to 0"

    if [[ $(/sbin/sysctl -n net.ipv6.conf.all.accept_redirects) -eq 0 && $(/sbin/sysctl -n net.ipv6.conf.default.accept_redirects) -eq 0 ]]; then
        print_result "PASS" "Both net.ipv6.conf.all.accept_redirects and net.ipv6.conf.default.accept_redirects are correctly set to 0."
    else
        print_result "FAIL" "One or both of net.ipv6.conf.all.accept_redirects or net.ipv6.conf.default.accept_redirects are not set to 0."
    fi
}

# 7.3.3 - Disable IPv6
check_7_3_3() {
    print_header "7.3.3" "Disable IPv6" "Not Scored" \
        "Checking if IPv6 is disabled by verifying the absence of inet6 addresses"

    if ! ip addr | grep -q inet6; then
        print_result "PASS" "IPv6 is disabled. No inet6 addresses found."
    else
        print_result "FAIL" "IPv6 appears to be enabled. inet6 addresses were found."
    fi
}

# 7.4.1 - Install TCP Wrappers
check_7_4_1() {
    print_header "7.4.1" "Install TCP Wrappers" "Scored" \
        "Checking if the tcpd package is installed"

    if dpkg -s tcpd 2>/dev/null | grep -q 'Status: install ok installed'; then
        print_result "PASS" "tcpd package is installed."
    else
        print_result "FAIL" "tcpd package is not installed."
    fi
}

# 7.4.2 - Create /etc/hosts.allow
check_7_4_2() {
    print_header "7.4.2" "Create /etc/hosts.allow" "Not Scored" \
        "Checking if /etc/hosts.allow exists and is not empty"

    if [[ -s /etc/hosts.allow ]]; then
        print_result "PASS" "/etc/hosts.allow exists and contains configuration."
    else
        print_result "FAIL" "/etc/hosts.allow is missing or empty."
    fi
}

# 7.4.3 - Verify Permissions on /etc/hosts.allow
check_7_4_3() {
    print_header "7.4.3" "Verify Permissions on /etc/hosts.allow" "Scored" \
        "Checking if /etc/hosts.allow has permissions set to 644"

    if [[ $(stat -c %a /etc/hosts.allow 2>/dev/null) -eq 644 ]]; then
        print_result "PASS" "/etc/hosts.allow has correct permissions of 644."
    else
        print_result "FAIL" "/etc/hosts.allow does not have permissions set to 644."
    fi
}

# 7.4.4 - Create /etc/hosts.deny
check_7_4_4() {
    print_header "7.4.4" "Create /etc/hosts.deny" "Not Scored" \
        "Checking if /etc/hosts.deny exists and contains 'ALL: ALL'"

    if grep -q '^ALL:\s*ALL' /etc/hosts.deny 2>/dev/null; then
        print_result "PASS" "/etc/hosts.deny exists and is configured to deny all hosts not listed in /etc/hosts.allow."
    else
        print_result "FAIL" "/etc/hosts.deny is missing or not properly configured to deny all hosts."
    fi
}

# 7.4.5 - Verify Permissions on /etc/hosts.deny
check_7_4_5() {
    print_header "7.4.5" "Verify Permissions on /etc/hosts.deny" "Scored" \
        "Checking if /etc/hosts.deny has permissions set to 644"

    if [[ $(stat -c %a /etc/hosts.deny 2>/dev/null) -eq 644 ]]; then
        print_result "PASS" "/etc/hosts.deny has correct permissions of 644."
    else
        print_result "FAIL" "/etc/hosts.deny does not have permissions set to 644."
    fi
}

# 7.5.1 - Disable DCCP
check_7_5_1() {
    print_header "7.5.1" "Disable DCCP" "Not Scored" \
        "Checking if DCCP is disabled in /etc/modprobe.d/CIS.conf"

    if grep -q '^install dccp /bin/true' /etc/modprobe.d/CIS.conf 2>/dev/null; then
        print_result "PASS" "DCCP is disabled by redirecting its install to /bin/true."
    else
        print_result "FAIL" "DCCP is not disabled. Missing 'install dccp /bin/true' in /etc/modprobe.d/CIS.conf."
    fi
}

# 7.5.2 - Disable SCTP
check_7_5_2() {
    print_header "7.5.2" "Disable SCTP" "Not Scored" \
        "Checking if SCTP is disabled in /etc/modprobe.d/CIS.conf"

    if grep -q '^install sctp /bin/true' /etc/modprobe.d/CIS.conf 2>/dev/null; then
        print_result "PASS" "SCTP is disabled by redirecting its install to /bin/true."
    else
        print_result "FAIL" "SCTP is not disabled. Missing 'install sctp /bin/true' in /etc/modprobe.d/CIS.conf."
    fi
}

# 7.5.3 - Disable RDS
check_7_5_3() {
    print_header "7.5.3" "Disable RDS" "Not Scored" \
        "Checking if RDS is disabled in /etc/modprobe.d/CIS.conf"

    if grep -q '^install rds /bin/true' /etc/modprobe.d/CIS.conf 2>/dev/null; then
        print_result "PASS" "RDS is disabled by redirecting its install to /bin/true."
    else
        print_result "FAIL" "RDS is not disabled. Missing 'install rds /bin/true' in /etc/modprobe.d/CIS.conf."
    fi
}

# 7.5.4 - Disable TIPC
check_7_5_4() {
    print_header "7.5.4" "Disable TIPC" "Not Scored" \
        "Checking if TIPC is disabled in /etc/modprobe.d/CIS.conf"

    if grep -q '^install tipc /bin/true' /etc/modprobe.d/CIS.conf 2>/dev/null; then
        print_result "PASS" "TIPC is disabled by redirecting its install to /bin/true."
    else
        print_result "FAIL" "TIPC is not disabled. Missing 'install tipc /bin/true' in /etc/modprobe.d/CIS.conf."
    fi
}

# 7.6 - Deactivate Wireless Interfaces
check_7_6() {
    print_header "7.6" "Deactivate Wireless Interfaces" "Not Scored" \
        "Checking if wireless interfaces are active using ifconfig"

    if ! ifconfig -a | grep -qiE 'wl|wlan'; then
        print_result "PASS" "All wireless interfaces appear to be deactivated or not present."
    else
        print_result "FAIL" "Wireless interfaces are active. Consider disabling them using: nmcli radio wifi off"
    fi
}

# 7.7 - Ensure Firewall is active
check_7_7() {
    print_header "7.7" "Ensure Firewall is active" "Scored" \
        "Checking if UFW firewall is enabled"

    if ufw status | grep -q 'Status: active'; then
        print_result "PASS" "UFW is active and providing firewall protection."
    else
        print_result "FAIL" "UFW is not active. Run 'ufw enable' after configuring required firewall rules."
    fi
}


# === Run Selected Checks ===
check_7_1_1
check_7_1_2
check_7_2_1
check_7_2_2
check_7_2_3
check_7_2_4
check_7_2_5
check_7_2_6
check_7_2_7
check_7_2_8
check_7_3_1
check_7_3_2
check_7_3_3
check_7_4_1
check_7_4_2
check_7_4_3
check_7_4_4
check_7_4_5
check_7_5_1
check_7_5_2
check_7_5_3
check_7_5_4
check_7_6
check_7_7


# === Summary ===
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
