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

print_header() {
    audit_id="$1"
    audit_title="$2"
    scoring="$3"
    echo "-------------------------------------------------------------"
    echo "Audit ID: $audit_id"
    echo "Title   : $audit_title"
    echo "SCORING : $scoring"
    echo ""
    echo "Audit Check: $4"
    echo ""
}

print_result() {
    local result=$1
    local reason=$2
    if [[ "$result" == "PASS" ]]; then
        echo "Result : PASS"
    else
        echo "Result : FAIL"
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

echo "Chapter 9 Audit: System Access, Authentication and Authorization"


check_9_1_1() {
    print_header "9.1.1" "Enable cron Daemon" "Scored" "Ensure proper start conditions for cron"
    local output=$(/sbin/initctl show-config cron 2>/dev/null)
    if [ -z "$output" ]; then
        print_result "FAIL" "No configuration found."
    else
        print_result "PASS" "Proper start conditions for cron have been set."
    fi
}

check_9_1_2() {
    print_header "9.1.2" "Set Owner/Permissions on /etc/crontab" "Scored" "Verify /etc/crontab has correct permissions"
    local output=$(stat -c "%a %u %g" /etc/crontab | egrep ".00 0 0")
    if [ -n "$output" ]; then
        print_result "PASS" "Permissions on /etc/crontab are correctly set."
    else
        print_result "FAIL" "Incorrect permissions on /etc/crontab."
    fi
}

check_9_1_3() {
    print_header "9.1.3" "Set User/Group Owner and Permission on /etc/cron.hourly" "Scored" \
        "Verifying that /etc/cron.hourly has the correct permissions"

    local output
    output=$(stat -c "%a %u %g" /etc/cron.hourly 2>/dev/null | egrep ".00 0 0")

    if [ -z "$output" ]; then
        print_result "FAIL" "No configuration found on /etc/cron.hourly."
    else
        print_result "PASS" "User/Group Owner and Permission is correctly set on /etc/cron.hourly: $output"
    fi
}

check_9_1_4() {
    print_header "9.1.4" "Set User/Group Owner and Permission on /etc/cron.daily" "Scored" \
        "Verifying that /etc/cron.daily has the correct permissions"

    local output
    output=$(stat -c "%a %u %g" /etc/cron.daily 2>/dev/null | egrep ".00 0 0")

    if [ -z "$output" ]; then
        print_result "FAIL" "No configuration found on /etc/cron.daily."
    else
        print_result "PASS" "User/Group Owner and Permission is correctly set on /etc/cron.daily: $output"
    fi
}

check_9_1_5() {
    print_header "9.1.5" "Set User/Group Owner and Permission on /etc/cron.weekly" "Scored" \
        "Verifying that /etc/cron.weekly has the correct permissions"

    local output
    output=$(stat -c "%a %u %g" /etc/cron.weekly 2>/dev/null | egrep ".00 0 0")

    if [ -z "$output" ]; then
        print_result "FAIL" "No configuration found on /etc/cron.weekly."
    else
        print_result "PASS" "User/Group Owner and Permissions are correctly set on /etc/cron.weekly: $output"
    fi
}

check_9_1_6() {
    print_header "9.1.6" "Set User/Group Owner and Permission on /etc/cron.monthly" "Scored" \
        "Verifying that /etc/cron.monthly has the correct permissions"

    local output
    output=$(stat -c "%a %u %g" /etc/cron.monthly 2>/dev/null | egrep ".00 0 0")

    if [ -z "$output" ]; then
        print_result "FAIL" "No configuration found on /etc/cron.monthly."
    else
        print_result "PASS" "User/Group Owner and Permission are correctly set on /etc/cron.monthly: $output"
    fi
}

check_9_1_7() {
    print_header "9.1.7" "Set User/Group Owner and Permission on /etc/cron.d" "Scored" \
        "Verifying that /etc/cron.d has the correct permissions"

    local output
    output=$(stat -c "%a %u %g" /etc/cron.d 2>/dev/null | egrep ".00 0 0")

    if [ -z "$output" ]; then
        print_result "FAIL" "No configuration found on /etc/cron.d."
    else
        print_result "PASS" "User/Group Owner and Permissions are correctly set on /etc/cron.d: $output"
    fi
}

check_9_1_8() {
    print_header "9.1.8" "Restrict at/cron to Authorized Users" "Scored" \
        "Ensuring only specific users can access at/cron services"

    local fail=0

    local output_1=$(ls -l /etc/cron.deny 2>/dev/null)
    local output_2=$(ls -l /etc/at.deny 2>/dev/null)
    local output_3=$(ls -l /etc/cron.allow 2>/dev/null)
    local output_4=$(ls -l /etc/at.allow 2>/dev/null)

    [[ -n "$output_1" ]] && fail=$((fail+1))
    [[ -n "$output_2" ]] && fail=$((fail+1))
    [[ -z "$output_3" ]] && fail=$((fail+1))
    [[ -z "$output_4" ]] && fail=$((fail+1))

    if [[ "$fail" -eq 4 ]]; then
        print_result "FAIL" "All four expected conditions failed — system is not compliant."
    else
        print_result "PASS" "Sufficient at/cron restrictions are configured."
    fi
}

check_9_2_1() {
    print_header "9.2.1" "Set Password Creation Requirement Parameters Using pam_cracklib" "Scored" \
        "Determine the current settings in the /etc/pam.d/common-password file"

    local output
    output=$(grep pam_cracklib.so /etc/pam.d/common-password 2>/dev/null)

    if [ -z "$output" ]; then
        print_result "FAIL" "No pam_cracklib.so configuration found."
    else
        if echo "$output" | grep -q "retry=3" && \
           echo "$output" | grep -q "minlen=14" && \
           echo "$output" | grep -q "dcredit=-1" && \
           echo "$output" | grep -q "ucredit=-1" && \
           echo "$output" | grep -q "ocredit=-1" && \
           echo "$output" | grep -q "lcredit=-1"; then
            print_result "PASS" "Password complexity requirements are properly configured."
        else
            print_result "FAIL" "Password complexity settings are incomplete or misconfigured: $output"
        fi
    fi
}

check_9_2_2() {
    print_header "9.2.2" "Set Lockout for Failed Password Attempts" "Not Scored" \
        "Determine the current settings for user lockout in /etc/pam.d/login"

    local output
    output=$(grep "pam_tally2" /etc/pam.d/login 2>/dev/null)

    if [ -z "$output" ]; then
        print_result "FAIL" "pam_tally2 configuration not found — lockout settings not applied."
    else
        if echo "$output" | grep -q "onerr=fail" && \
           echo "$output" | grep -q "audit" && \
           echo "$output" | grep -q "silent" && \
           echo "$output" | grep -q "deny=5" && \
           echo "$output" | grep -q "unlock_time=900"; then
            print_result "PASS" "Lockout is properly set for failed password attempts."
        else
            print_result "FAIL" "Incomplete lockout configuration for failed attempts: $output"
        fi
    fi
}

check_9_2_3() {
    print_header "9.2.3" "Limit Password Reuse" "Scored" \
        "Determine the current settings for reuse of older passwords in /etc/pam.d/common-password"

    local output
    output=$(grep "remember" /etc/pam.d/common-password 2>/dev/null)

    if [ -z "$output" ]; then
        print_result "FAIL" "No configuration found — password reuse limitation is not applied."
    else
        if echo "$output" | grep -q "remember=5"; then
            print_result "PASS" "Password reuse is limited as required (remember=5)."
        else
            print_result "FAIL" "Password reuse is not limited properly. Found: $output"
        fi
    fi
}

check_9_3_1() {
    print_header "9.3.1" "Set SSH Protocol to 2" "Scored" \
        "To verify the correct SSH Protocol setting in /etc/ssh/sshd_config"

    local output
    output=$(grep "^Protocol" /etc/ssh/sshd_config 2>/dev/null)

    if [ -z "$output" ]; then
        print_result "FAIL" "No 'Protocol' line found in /etc/ssh/sshd_config."
    elif echo "$output" | grep -q "^Protocol[[:space:]]*2$"; then
        print_result "PASS" "SSH Protocol is correctly set to 2: $output"
    else
        print_result "FAIL" "SSH Protocol is not set to 2. Current value: $output"
    fi
}

check_9_3_2() {
    print_header "9.3.2" "Set LogLevel to INFO" "Scored" \
        "Verify the correct SSH LogLevel setting in /etc/ssh/sshd_config"

    local output
    output=$(grep "^LogLevel" /etc/ssh/sshd_config 2>/dev/null)

    if [ -z "$output" ]; then
        print_result "FAIL" "No LogLevel setting found in /etc/ssh/sshd_config."
    elif echo "$output" | grep -q "^LogLevel[[:space:]]*INFO$"; then
        print_result "PASS" "SSH LogLevel is correctly set to INFO: $output"
    else
        print_result "FAIL" "SSH LogLevel is not set to INFO. Current value: $output"
    fi
}

check_9_3_3() {
    print_header "9.3.3" "Set Permissions on /etc/ssh/sshd_config" "Scored" \
        "Ensure nonprivileged users cannot make unauthorized changes"

    local output
    output=$(ls -l /etc/ssh/sshd_config 2>/dev/null)

    if [ -z "$output" ]; then
        print_result "FAIL" "No permissions found for /etc/ssh/sshd_config."
    elif echo "$output" | grep -qE "^-..[r-]-[r-]--"; then
        print_result "PASS" "Correct permissions set on /etc/ssh/sshd_config: $output"
    else
        print_result "FAIL" "Permissions are not properly set on /etc/ssh/sshd_config: $output"
    fi
}

check_9_3_4() {
    print_header "9.3.4" "Disable SSH X11 Forwarding" "Scored" \
        "Verify that SSH X11 Forwarding is disabled in /etc/ssh/sshd_config"

    local output
    output=$(grep "^X11Forwarding" /etc/ssh/sshd_config 2>/dev/null)

    if [ -z "$output" ]; then
        print_result "FAIL" "X11Forwarding directive not found in sshd_config."
    elif echo "$output" | grep -q "^X11Forwarding[[:space:]]*no$"; then
        print_result "PASS" "SSH X11 Forwarding is correctly disabled: $output"
    else
        print_result "FAIL" "X11Forwarding is not disabled. Current setting: $output"
    fi
}

check_9_3_5() {
    print_header "9.3.5" "Set SSH MaxAuthTries to 4 or Less" "Scored" \
        "Verify that MaxAuthTries is configured to 4 or less in /etc/ssh/sshd_config"

    local output
    output=$(grep "^MaxAuthTries" /etc/ssh/sshd_config 2>/dev/null)

    if [ -z "$output" ]; then
        print_result "FAIL" "MaxAuthTries directive not found."
    else
        local value
        value=$(echo "$output" | awk '{print $2}')
        if [[ "$value" =~ ^[0-9]+$ && "$value" -le 4 ]]; then
            print_result "PASS" "MaxAuthTries is correctly set to $value."
        else
            print_result "FAIL" "MaxAuthTries is set to $value (should be 4 or less)."
        fi
    fi
}

check_9_3_6() {
    print_header "9.3.6" "Set SSH IgnoreRhosts to Yes" "Scored" \
        "Verify that IgnoreRhosts is set to 'yes' in /etc/ssh/sshd_config"

    local output
    output=$(grep "^IgnoreRhosts" /etc/ssh/sshd_config 2>/dev/null)

    if [ -z "$output" ]; then
        print_result "FAIL" "IgnoreRhosts directive not found in sshd_config."
    elif echo "$output" | grep -q "^IgnoreRhosts[[:space:]]*yes$"; then
        print_result "PASS" "IgnoreRhosts is correctly set to 'yes': $output"
    else
        print_result "FAIL" "IgnoreRhosts is not set to 'yes'. Current setting: $output"
    fi
}

check_9_3_7() {
    print_header "9.3.7" "Set SSH HostbasedAuthentication to No" "Scored" \
        "Verify that HostbasedAuthentication is set to 'no' in /etc/ssh/sshd_config"

    local output
    output=$(grep "^HostbasedAuthentication" /etc/ssh/sshd_config 2>/dev/null)

    if [ -z "$output" ]; then
        print_result "FAIL" "HostbasedAuthentication directive not found in sshd_config."
    elif echo "$output" | grep -q "^HostbasedAuthentication[[:space:]]*no$"; then
        print_result "PASS" "HostbasedAuthentication is correctly set to 'no': $output"
    else
        print_result "FAIL" "HostbasedAuthentication is not set to 'no'. Current setting: $output"
    fi
}

check_9_3_8() {
    print_header "9.3.8" "Disable SSH Root Login" "Scored" \
        "Verify that PermitRootLogin is set to 'no' in /etc/ssh/sshd_config"

    local output
    output=$(grep "^PermitRootLogin" /etc/ssh/sshd_config 2>/dev/null)

    if [ -z "$output" ]; then
        print_result "FAIL" "PermitRootLogin directive not found in sshd_config."
    elif echo "$output" | grep -q "^PermitRootLogin[[:space:]]*no$"; then
        print_result "PASS" "PermitRootLogin is correctly set to 'no': $output"
    else
        print_result "FAIL" "PermitRootLogin is not set to 'no'. Current setting: $output"
    fi
}

check_9_3_9() {
    print_header "9.3.9" "Set SSH PermitEmptyPasswords to No" "Scored" \
        "Verify that PermitEmptyPasswords is set to 'no' in /etc/ssh/sshd_config"

    local output
    output=$(grep "^PermitEmptyPasswords" /etc/ssh/sshd_config 2>/dev/null)

    if [ -z "$output" ]; then
        print_result "FAIL" "PermitEmptyPasswords directive not found in sshd_config."
    elif echo "$output" | grep -q "^PermitEmptyPasswords[[:space:]]*no$"; then
        print_result "PASS" "PermitEmptyPasswords is correctly set to 'no': $output"
    else
        print_result "FAIL" "PermitEmptyPasswords is not set to 'no'. Current setting: $output"
    fi
}

check_9_3_10() {
    print_header "9.3.10" "Do Not Allow Users to Set Environment Options" "Scored" \
        "Verify that PermitUserEnvironment is set to 'no' in /etc/ssh/sshd_config"

    local output
    output=$(grep "^PermitUserEnvironment" /etc/ssh/sshd_config 2>/dev/null)

    if [ -z "$output" ]; then
        print_result "FAIL" "PermitUserEnvironment directive not found in sshd_config."
    elif echo "$output" | grep -q "^PermitUserEnvironment[[:space:]]*no$"; then
        print_result "PASS" "PermitUserEnvironment is correctly set to 'no': $output"
    else
        print_result "FAIL" "PermitUserEnvironment is not set to 'no'. Current setting: $output"
    fi
}

check_9_3_11() {
    print_header "9.3.11" "Use Only Approved Cipher in Counter Mode" "Scored" \
        "Verify that only approved counter-mode ciphers are used in /etc/ssh/sshd_config"

    local output
    output=$(grep "^Ciphers" /etc/ssh/sshd_config 2>/dev/null)

    if [ -z "$output" ]; then
        print_result "FAIL" "Ciphers directive not found in sshd_config."
    elif echo "$output" | grep -Eq 'aes128-ctr|aes192-ctr|aes256-ctr'; then
        print_result "PASS" "Only approved counter mode ciphers are used: $output"
    else
        print_result "FAIL" "Unapproved or missing counter mode ciphers: $output"
    fi
}

check_9_3_12() {
    print_header "9.3.12" "Set Idle Timeout Interval for User Login" "Scored" \
        "Verify that ClientAliveInterval and ClientAliveCountMax are configured in /etc/ssh/sshd_config"

    local interval count output_1 output_2
    output_1=$(grep "^ClientAliveInterval" /etc/ssh/sshd_config 2>/dev/null)
    output_2=$(grep "^ClientAliveCountMax" /etc/ssh/sshd_config 2>/dev/null)

    if [ -z "$output_1" ] || [ -z "$output_2" ]; then
        print_result "FAIL" "ClientAliveInterval or ClientAliveCountMax not set."
    else
        print_result "PASS" "Idle timeout interval settings found: $output_1 | $output_2"
    fi
}

check_9_3_13() {
    print_header "9.3.13" "Limit Access via SSH" "Scored" \
        "Verify that at least one of the following SSH restrictions is configured: AllowUsers, AllowGroups, DenyUsers, DenyGroups"

    local output_1 output_2 output_3 output_4
    output_1=$(grep "^AllowUsers" /etc/ssh/sshd_config 2>/dev/null)
    output_2=$(grep "^AllowGroups" /etc/ssh/sshd_config 2>/dev/null)
    output_3=$(grep "^DenyUsers" /etc/ssh/sshd_config 2>/dev/null)
    output_4=$(grep "^DenyGroups" /etc/ssh/sshd_config 2>/dev/null)

    if [ -z "$output_1" ] && [ -z "$output_2" ] && [ -z "$output_3" ] && [ -z "$output_4" ]; then
        print_result "FAIL" "None of the SSH access restriction options (AllowUsers, AllowGroups, DenyUsers, DenyGroups) are configured."
    else
        print_result "PASS" "At least one SSH access restriction is configured. Found settings:
$output_1
$output_2
$output_3
$output_4"
    fi
}

check_9_3_14() {
    print_header "9.3.14" "Set SSH Banner" "Scored" \
        "Verify that the SSH banner is set to /etc/issue or /etc/issue.net in /etc/ssh/sshd_config"

    local output
    output=$(grep "^Banner" /etc/ssh/sshd_config 2>/dev/null)

    if [ -z "$output" ]; then
        print_result "FAIL" "No Banner configuration found in /etc/ssh/sshd_config."
    elif echo "$output" | grep -Eq "^Banner[[:space:]]+/etc/issue(\.net)?"; then
        print_result "PASS" "SSH banner is set correctly to: $output"
    else
        print_result "FAIL" "SSH banner is set incorrectly. Current setting: $output"
    fi
}

check_9_4() {
    print_header "9.4" "Restrict root login to System console" "Scored" \
        "Ensure root login is only allowed from a secure console via /etc/securetty"

    local output
    output=$(cat /etc/securetty 2>/dev/null)

    if [ -z "$output" ]; then
        print_result "FAIL" "No entries found in /etc/securetty. Root login is not properly restricted."
    else
        print_result "PASS" "Root login is restricted to terminals listed in /etc/securetty."
    fi
}

check_9_5() {
    print_header "9.5" "Restrict Access to the su Command" "Scored" \
        "Ensure the use of su is restricted using pam_wheel and the wheel group"

    local output_1 output_2
    output_1=$(grep "pam_wheel.so" /etc/pam.d/su 2>/dev/null)
    output_2=$(grep "^wheel:" /etc/group 2>/dev/null)

    if echo "$output_1" | grep -q "use_uid" && [ -n "$output_2" ]; then
        print_result "PASS" "Access to 'su' command is restricted via pam_wheel and the wheel group exists."
    else
        local reason=""
        if ! echo "$output_1" | grep -q "use_uid"; then
            reason+="pam_wheel.so with use_uid not found. "
        fi
        if [ -z "$output_2" ]; then
            reason+="wheel group not found or has no members."
        fi
        print_result "FAIL" "$reason"
    fi
}

# === Run all Chapter 9 Checks ===
check_9_1_1
check_9_1_2
check_9_1_3
check_9_1_4
check_9_1_5
check_9_1_6
check_9_1_7
check_9_1_8
check_9_2_1
check_9_2_2
check_9_2_3
check_9_3_1
check_9_3_2
check_9_3_3
check_9_3_4
check_9_3_5
check_9_3_6
check_9_3_7
check_9_3_8
check_9_3_9
check_9_3_10
check_9_3_11
check_9_3_12
check_9_3_13
check_9_3_14
check_9_4
check_9_5

# === Summary Output ===
echo "========================================"
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
