#!/bin/bash

# Summary variables
total_audits=0
passed_audits=0
failed_audits=0
failed_scored=0
failed_not_scored=0
failed_scored_ids=""
failed_not_scored_ids=""
all_checked_chapters=""

# Output header
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

# Output result
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

echo "Chapter 6 Audit: Special Purpose Services"

# ==============================
# Section 6.1: Sample Audit
# ==============================

check_6_1() {
    print_header "6.1" "Ensure the X Window system is not installed" "Scored" \
        "Check that xserver-xorg-core package is not installed."

    if ! dpkg -l "xserver-xorg-core*" 2>/dev/null | grep -E "^ii" >/dev/null; then
        print_result "PASS" "X Window system is not installed."
    else
        print_result "FAIL" "X Window system is installed."
    fi
}

check_6_2() {
    print_header "6.2" "Ensure Avahi Server is not enabled" "Scored" \
        "Check if avahi-daemon has no start conditions configured in init system."

    if ! initctl show-config avahi-daemon 2>/dev/null | grep -q 'start on'; then
        print_result "PASS" "avahi-daemon has no start conditions and is not enabled."
    else
        print_result "FAIL" "avahi-daemon has start conditions set and may be enabled."
    fi
}

check_6_3() {
    print_header "6.3" "Ensure print server is not enabled" "Not Scored" \
        "Check if cups has no start conditions configured in init system."

    if ! initctl show-config cups 2>/dev/null | grep -q 'start on'; then
        print_result "PASS" "cups has no start conditions and is not enabled."
    else
        print_result "FAIL" "cups has start conditions set and may be enabled."
    fi
}

check_6_4() {
    print_header "6.4" "Ensure DHCP Server is not enabled" "Scored" \
        "Check if isc-dhcp-server and isc-dhcp-server6 have no start conditions configured in init system."

    if ! initctl show-config isc-dhcp-server 2>/dev/null | grep -q 'start on' && \
       ! initctl show-config isc-dhcp-server6 2>/dev/null | grep -q 'start on'; then
        print_result "PASS" "DHCP server is not enabled."
    else
        print_result "FAIL" "DHCP server (isc-dhcp-server or isc-dhcp-server6) has start conditions and may be enabled."
    fi
}

check_6_5() {
    print_header "6.5" "Configure Network Time Protocol (NTP)" "Scored" \
        "Check if ntp is installed, properly configured, and running as unprivileged user."

    if dpkg -s ntp 2>/dev/null | grep -q "Status: install ok installed" && \
       grep -Eq "^restrict -4 default kod nomodify notrap nopeer noquery" /etc/ntp.conf && \
       grep -Eq "^restrict -6 default kod nomodify notrap nopeer noquery" /etc/ntp.conf && \
       grep -Eq "^server\s+\S+" /etc/ntp.conf && \
       grep -q "RUNASUSER=ntp" /etc/init.d/ntp; then
        print_result "PASS" "NTP is installed, properly configured with secure restrictions, and running as unprivileged user."
    else
        print_result "FAIL" "NTP is not properly installed or configured."
    fi
}


check_6_6() {
    print_header "6.6" "Ensure LDAP is not enabled" "Not Scored" \
        "Check if slapd (LDAP) package is not installed."

    if ! dpkg -s slapd 2>/dev/null | grep -q 'Status: install ok installed'; then
        print_result "PASS" "LDAP (slapd) package is not installed."
    else
        print_result "FAIL" "LDAP (slapd) package is installed."
    fi
}

check_6_7() {
    print_header "6.7" "Ensure NFS and RPC are not enabled" "Not Scored" \
        "Check if rpcbind-boot has no start conditions and nfs-kernel-server has no start links."

    if ! initctl show-config rpcbind-boot 2>/dev/null | grep -q 'start on' && \
       [ -z "$(ls /etc/rc*.d/S*nfs-kernel-server 2>/dev/null)" ]; then
        print_result "PASS" "NFS and RPC services are not enabled."
    else
        print_result "FAIL" "NFS and/or RPC services are enabled."
    fi
}

check_6_8() {
    print_header "6.8" "Ensure DNS Server is not enabled" "Not Scored" \
        "Check if bind9 has no start links in /etc/rc*.d"

    if [ -z "$(ls /etc/rc*.d/S*bind9 2>/dev/null)" ]; then
        print_result "PASS" "DNS server (bind9) is not enabled."
    else
        print_result "FAIL" "DNS server (bind9) has startup links and may be enabled."
    fi
}

check_6_9() {
    print_header "6.9" "Ensure FTP Server is not enabled" "Not Scored" \
        "Check if vsftpd has no start conditions configured in init system"

    if ! initctl show-config vsftpd 2>/dev/null | grep -q 'start on'; then
        print_result "PASS" "FTP server (vsftpd) is not enabled."
    else
        print_result "FAIL" "FTP server (vsftpd) has start conditions and may be enabled."
    fi
}

check_6_10() {
    print_header "6.10" "Ensure HTTP Server is not enabled" "Not Scored" \
        "Check if apache2 has no start links in /etc/rc*.d"

    if [ -z "$(ls /etc/rc*.d/S*apache2 2>/dev/null)" ]; then
        print_result "PASS" "HTTP server (apache2) is not enabled."
    else
        print_result "FAIL" "HTTP server (apache2) has startup links and may be enabled."
    fi
}

check_6_11() {
    print_header "6.11" "Ensure IMAP and POP server is not enabled" "Not Scored" \
        "Check if dovecot service has no start conditions"

    if ! initctl show-config dovecot 2>/dev/null | grep -q 'start on'; then
        print_result "PASS" "IMAP/POP server (dovecot) is not enabled."
    else
        print_result "FAIL" "IMAP/POP server (dovecot) has start conditions and may be enabled."
    fi
}

check_6_12() {
    print_header "6.12" "Ensure Samba is not enabled" "Not Scored" \
        "Check if smbd service has no start conditions"

    if ! initctl show-config smbd 2>/dev/null | grep -q 'start on'; then
        print_result "PASS" "Samba server (smbd) is not enabled."
    else
        print_result "FAIL" "Samba server (smbd) has start conditions and may be enabled."
    fi
}

check_6_13() {
    print_header "6.13" "Ensure HTTP Proxy Server is not enabled" "Not Scored" \
        "Check if squid3 service has no start conditions"

    if ! initctl show-config squid3 2>/dev/null | grep -q 'start on'; then
        print_result "PASS" "HTTP proxy server (squid3) is not enabled."
    else
        print_result "FAIL" "HTTP proxy server (squid3) has start conditions and may be enabled."
    fi
}

check_6_14() {
    print_header "6.14" "Ensure SNMP Server is not enabled" "Not Scored" \
        "Check if SNMP server (snmpd) has no start links"

    if [ -z "$(ls /etc/rc*.d/S*snmpd 2>/dev/null)" ]; then
        print_result "PASS" "SNMP server (snmpd) is not enabled."
    else
        print_result "FAIL" "SNMP server (snmpd) has startup links and may be enabled."
    fi
}

check_6_15() {
    print_header "6.15" "Configure Mail Transfer Agent for Local-Only Mode" "Scored" \
        "Ensure the mail transfer agent is listening only on localhost (127.0.0.1)"

    if netstat -an | grep LISTEN | grep -qE '127.0.0.1:25[[:space:]]'; then
        print_result "PASS" "MTA is correctly configured to listen only on localhost."
    else
        print_result "FAIL" "MTA is listening on a non-localhost address."
    fi
}

check_6_16() {
    print_header "6.16" "Ensure rsync service is not enabled" "Scored" \
        "Verifying RSYNC_ENABLE is set to 'false' in /etc/default/rsync"

    if grep -q '^RSYNC_ENABLE=false' /etc/default/rsync 2>/dev/null; then
        print_result "PASS" "RSYNC_ENABLE is correctly set to false."
    else
        print_result "FAIL" "RSYNC_ENABLE is not set to false or not found."
    fi
}

check_6_17() {
    print_header "6.17" "Ensure biosdevname is not enabled" "Scored" \
        "Checking if biosdevname package is not installed"

    if ! dpkg -s biosdevname 2>/dev/null | grep -q 'Status: install ok installed'; then
        print_result "PASS" "biosdevname package is not installed."
    else
        print_result "FAIL" "biosdevname package is installed."
    fi
}



     check_6_1
     check_6_2
     check_6_3
     check_6_4
     check_6_5
     check_6_6
     check_6_7
     check_6_8
     check_6_9
     check_6_10
     check_6_11
     check_6_12
     check_6_13
     check_6_14
     check_6_15
     check_6_16
     check_6_17



# ===================
# Summary
# ===================
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
