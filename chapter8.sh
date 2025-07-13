#!/bin/bash

# aduit sum
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
    audit_id="$1"         # Store globally
    audit_title="$2"
    scoring="$3"          # Store globally

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

#finale table
track_result "$audit_id" "$scoring" "$result"
}

#2
#3 -------------------------------------------------------------[Call summury]

track_result() {
    local audit_id="$1"
    local scoring="$2"
    local result="$3"

    total_audits=$((total_audits + 1))
    all_checked_chapters+="$audit_id\n" # remove this later

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

echo "Chapter 8 Audit: Logging and Auditing"


# 8.1.1.1 - Configure Audit Log Storage Size
check_8_1_1_1() {
    print_header "8.1.1.1" "Configure Audit Log Storage Size" "NOT Scored" \
        "Verifying 'max_log_file' is set in /etc/audit/auditd.conf."

    local audit_conf="/etc/audit/auditd.conf"
    local param="max_log_file"

    if [[ ! -f "$audit_conf" ]]; then
        print_result "FAIL" "$audit_conf not found. Cannot verify '$param' setting."
        return
    fi

    local value
    value=$(grep -E "^$param\s*=" "$audit_conf" | awk -F '=' '{print $2}' | xargs)

    if [[ -n "$value" ]]; then
        print_result "PASS" "'$param' is set to $value MB in $audit_conf"
    else
        print_result "FAIL" "'$param' is not set in $audit_conf"
    fi
}


# 8.1.1.2 - Disable System on Audit Log Full
check_8_1_1_2() {
    print_header "8.1.1.2" "Disable System on Audit Log Full" "NOT Scored" \
        "Verifying auditd is configured to email admin and halt system when audit logs are full."

    local audit_conf="/etc/audit/auditd.conf"
    local fail_msgs=()

    if [[ ! -f "$audit_conf" ]]; then
        print_result "FAIL" "$audit_conf not found. Cannot verify audit log full behavior."
        return
    fi

    local space_left_action=$(grep -E "^space_left_action\s*=" "$audit_conf" | awk -F= '{print $2}' | xargs)
    local action_mail_acct=$(grep -E "^action_mail_acct\s*=" "$audit_conf" | awk -F= '{print $2}' | xargs)
    local admin_space_left_action=$(grep -E "^admin_space_left_action\s*=" "$audit_conf" | awk -F= '{print $2}' | xargs)

    [[ "$space_left_action" != "email" ]] && fail_msgs+=("space_left_action is '$space_left_action' (expected: email)")
    [[ "$action_mail_acct" != "root" ]] && fail_msgs+=("action_mail_acct is '$action_mail_acct' (expected: root)")
    [[ "$admin_space_left_action" != "halt" ]] && fail_msgs+=("admin_space_left_action is '$admin_space_left_action' (expected: halt)")

    if [[ ${#fail_msgs[@]} -eq 0 ]]; then
        print_result "PASS" "Auditd is configured to email root and halt system when logs are full."
    else
        print_result "FAIL" "${fail_msgs[*]}"
    fi
}



# 8.1.1.3 - Keep All Auditing Information
check_8_1_1_3() {
    print_header "8.1.1.3" "Keep All Auditing Information" "Scored" \
        "Verifying 'max_log_file_action' is set to 'keep_logs' in /etc/audit/auditd.conf."

    local audit_conf="/etc/audit/auditd.conf"

    if [[ ! -f "$audit_conf" ]]; then
        print_result "FAIL" "$audit_conf not found. Cannot verify audit log retention setting."
        return
    fi

    local value
    value=$(grep -E "^max_log_file_action\s*=" "$audit_conf" | awk -F= '{print $2}' | xargs)

    if [[ "$value" == "keep_logs" ]]; then
        print_result "PASS" "'max_log_file_action' is set to 'keep_logs' in $audit_conf"
    else
        print_result "FAIL" "'max_log_file_action' is set to '$value' (expected: keep_logs)"
    fi
}

# 8.1.2 - Install and Enable auditd Service
check_8_1_2() {
    print_header "8.1.2" "Install and Enable auditd Service" "Scored" \
        "Verifying 'auditd' is installed and enabled for runlevels 2, 3, 4, and 5."

    local auditd_status=""
    local required_levels=(2 3 4 5)
    local missing_levels=()
    local found_levels=()

    # Check if auditd is installed
    if command -v dpkg >/dev/null 2>&1; then
        auditd_status=$(dpkg -s auditd 2>/dev/null | grep -i "Status" || true)
        if ! echo "$auditd_status" | grep -q "Status: install ok installed"; then
            print_result "FAIL" "'auditd' package is not properly installed (status: $auditd_status)"
            return
        fi
    else
        if ! rpm -q audit >/dev/null 2>&1 && ! rpm -q auditd >/dev/null 2>&1; then
            print_result "FAIL" "'auditd' package is not installed (rpm check)"
            return
        fi
    fi

    # Try systemd first
    if command -v systemctl >/dev/null 2>&1; then
        if systemctl is-enabled auditd >/dev/null 2>&1 && systemctl is-active auditd >/dev/null 2>&1; then
            print_result "PASS" "'auditd' is installed, enabled, and running (systemd) for runlevels 2, 3, 4, and 5."
            return
        fi
        # silently continue to SysV fallback if systemd check fails
    fi

    # Fallback to SysV init check
    for level in "${required_levels[@]}"; do
        if ls /etc/rc${level}.d/S*auditd >/dev/null 2>&1; then
            found_levels+=("$level")
        else
            missing_levels+=("$level")
        fi
    done

    if [[ ${#missing_levels[@]} -eq 0 ]]; then
        print_result "PASS" "'auditd' is installed, enabled, and running (SysV) for runlevels 2, 3, 4, and 5."
    else
        print_result "FAIL" "'auditd' missing startup links in runlevels: ${missing_levels[*]}"
    fi
}


# 8.1.3 - Enable Auditing for Processes That Start Prior to auditd
check_8_1_3() {
    print_header "8.1.3" "Enable Auditing for Processes That Start Prior to auditd" "Scored" \
        "Verifying all 'linux' lines in /boot/grub/grub.cfg include 'audit=1'."

    local grub_file="/boot/grub/grub.cfg"

    if [[ ! -f "$grub_file" ]]; then
        print_result "FAIL" "$grub_file not found. Cannot verify kernel boot parameters."
        return
    fi

    # Grab all lines starting with 'linux' and ignore memtest or non-kernel entries
    local linux_lines
    linux_lines=$(grep -E "^\s*linux" "$grub_file" | grep -v "memtest" 2>/dev/null)

    if [[ -z "$linux_lines" ]]; then
        print_result "FAIL" "No valid 'linux' boot entries found in $grub_file to validate 'audit=1'."
        return
    fi

    local fail_count=0

    while IFS= read -r line; do
        if ! echo "$line" | grep -qw "audit=1"; then
            fail_count=$((fail_count + 1))
        fi
    done <<< "$linux_lines"

    if [[ $fail_count -eq 0 ]]; then
        print_result "PASS" "All 'linux' boot entries in $grub_file contain 'audit=1'"
    else
        print_result "FAIL" "$fail_count 'linux' entries in $grub_file are missing 'audit=1'"
    fi
}


# 8.1.4 - Record Events That Modify Date and Time Information
check_8_1_4() {
    print_header "8.1.4" "Record Events That Modify Date and Time Information" "Scored" \
        "Verifying auditd is configured to record time change events in /etc/audit/audit.rules."

    local audit_rules_file="/etc/audit/audit.rules"
    local fail_rules=()

    if [[ ! -f "$audit_rules_file" ]]; then
        print_result "FAIL" "$audit_rules_file not found. Cannot verify time-change audit rules."
        return
    fi

    # Required rules
    local required_rules=(
        "-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change"
        "-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change"
        "-a always,exit -F arch=b64 -S clock_settime -k time-change"
        "-a always,exit -F arch=b32 -S clock_settime -k time-change"
        "-w /etc/localtime -p wa -k time-change"
    )

    for rule in "${required_rules[@]}"; do
        if ! grep -F -- "$rule" "$audit_rules_file" > /dev/null 2>&1; then
            fail_rules+=("$rule")
        fi
    done

    if [[ ${#fail_rules[@]} -eq 0 ]]; then
        print_result "PASS" "All required time-change audit rules are present in $audit_rules_file"
    else
        print_result "FAIL" "Missing rules in $audit_rules_file: ${fail_rules[*]}"
    fi
}


# 8.1.5 - Record Events That Modify User/Group Information
check_8_1_5() {
    print_header "8.1.5" "Record Events That Modify User/Group Information" "Scored" \
        "Verifying auditd is configured to monitor user/group account files."

    local audit_rules_file="/etc/audit/audit.rules"
    local required_files=(
        "/etc/group"
        "/etc/passwd"
        "/etc/gshadow"
        "/etc/shadow"
        "/etc/security/opasswd"
    )
    local missing_rules=()

    if [[ ! -f "$audit_rules_file" ]]; then
        print_result "FAIL" "$audit_rules_file not found. Cannot verify identity audit rules."
        return
    fi

    for file in "${required_files[@]}"; do
        if ! grep -Eq -- "-w\s+$file\s+-p\s+wa\s+-k\s+identity" "$audit_rules_file"; then
            missing_rules+=("$file")
        fi
    done

    if [[ ${#missing_rules[@]} -eq 0 ]]; then
        print_result "PASS" "All required identity audit rules are present in $audit_rules_file"
    else
        print_result "FAIL" "Missing rules for: ${missing_rules[*]} in $audit_rules_file"
    fi
}

# 8.1.6 - Record Events That Modify the System's Network Environment
check_8_1_6() {
    print_header "8.1.6" "Record Events That Modify the System's Network Environment" "Scored" \
        "Verifying auditd is configured to record network environment changes in /etc/audit/audit.rules."

    local audit_rules_file="/etc/audit/audit.rules"
    local fail_rules=()

    if [[ ! -f "$audit_rules_file" ]]; then
        print_result "FAIL" "$audit_rules_file not found. Cannot verify system-locale audit rules."
        return
    fi

    local required_rules=(
        "-a exit,always -F arch=b64 -S sethostname -S setdomainname -k system-locale"
        "-a exit,always -F arch=b32 -S sethostname -S setdomainname -k system-locale"
        "-w /etc/issue -p wa -k system-locale"
        "-w /etc/issue.net -p wa -k system-locale"
        "-w /etc/hosts -p wa -k system-locale"
        "-w /etc/network -p wa -k system-locale"
    )

    for rule in "${required_rules[@]}"; do
        if ! grep -F -- "$rule" "$audit_rules_file" > /dev/null 2>&1; then
            fail_rules+=("$rule")
        fi
    done

    if [[ ${#fail_rules[@]} -eq 0 ]]; then
        print_result "PASS" "All required system-locale audit rules are present in $audit_rules_file"
    else
        print_result "FAIL" "Missing rules in $audit_rules_file: ${fail_rules[*]}"
    fi
}

# 8.1.7 - Record Events That Modify the System's Mandatory Access Controls
check_8_1_7() {
    print_header "8.1.7" "Record Events That Modify the System's Mandatory Access Controls" "Scored" \
        "Verifying auditd is configured to monitor changes to /etc/selinux directory."

    local audit_rules_file="/etc/audit/audit.rules"
    local required_rule="-w /etc/selinux/ -p wa -k MAC-policy"

    if [[ ! -f "$audit_rules_file" ]]; then
        print_result "FAIL" "$audit_rules_file not found. Cannot verify MAC-policy audit rule."
        return
    fi

    if grep -Fqs -- "$required_rule" "$audit_rules_file"; then
        print_result "PASS" "$audit_rules_file includes rule to monitor /etc/selinux"
    else
        print_result "FAIL" "Missing rule for /etc/selinux in $audit_rules_file"
    fi
}

# 8.1.8 - Collect Login and Logout Events
check_8_1_8() {
    print_header "8.1.8" "Collect Login and Logout Events" "Scored" \
        "Verifying auditd is configured to monitor login/logout related log files."

    local audit_rules_file="/etc/audit/audit.rules"
    local required_files=(
        "/var/log/faillog"
        "/var/log/lastlog"
        "/var/log/tallylog"
    )
    local missing_rules=()

    if [[ ! -f "$audit_rules_file" ]]; then
        print_result "FAIL" "$audit_rules_file not found. Cannot verify login/logout audit rules."
        return
    fi

    for file in "${required_files[@]}"; do
        if ! grep -Eq -- "-w\s+$file\s+-p\s+wa\s+-k\s+logins" "$audit_rules_file"; then
            missing_rules+=("$file")
        fi
    done

    if [[ ${#missing_rules[@]} -eq 0 ]]; then
        print_result "PASS" "All required login/logout audit rules are present in $audit_rules_file"
    else
        print_result "FAIL" "Missing rules for: ${missing_rules[*]} in $audit_rules_file"
    fi
}

# 8.1.9 - Collect Session Initiation Information
check_8_1_9() {
    print_header "8.1.9" "Collect Session Initiation Information" "Scored" \
        "Verifying auditd is configured to monitor session initiation related files."

    local audit_rules_file="/etc/audit/audit.rules"
    local required_files=(
        "/var/run/utmp"
        "/var/log/wtmp"
        "/var/log/btmp"
    )
    local missing_rules=()

    if [[ ! -f "$audit_rules_file" ]]; then
        print_result "FAIL" "$audit_rules_file not found. Cannot verify session audit rules."
        return
    fi

    for file in "${required_files[@]}"; do
        if ! grep -Eq -- "-w\s+$file\s+-p\s+wa\s+-k\s+session" "$audit_rules_file"; then
            missing_rules+=("$file")
        fi
    done

    if [[ ${#missing_rules[@]} -eq 0 ]]; then
        print_result "PASS" "All required session audit rules are present in $audit_rules_file"
    else
        print_result "FAIL" "Missing rules for: ${missing_rules[*]} in $audit_rules_file"
    fi
}


# 8.1.10 - Collect Discretionary Access Control Permission Modification Events
check_8_1_10() {
    print_header "8.1.10" "Collect Discretionary Access Control Permission Modification Events" "Scored" \
        "Verifying auditd is configured to monitor permission modification syscalls."

    local audit_rules_file="/etc/audit/audit.rules"
    local missing=()

    if [[ ! -f "$audit_rules_file" ]]; then
        print_result "FAIL" "$audit_rules_file not found. Cannot verify perm_mod audit rules."
        return
    fi

    local patterns=(
        "arch=b64.*chmod.*fchmod.*fchmodat.*auid>=500.*auid!=4294967295.*perm_mod"
        "arch=b32.*chmod.*fchmod.*fchmodat.*auid>=500.*auid!=4294967295.*perm_mod"
        "arch=b64.*chown.*fchown.*fchownat.*lchown.*auid>=500.*auid!=4294967295.*perm_mod"
        "arch=b32.*chown.*fchown.*fchownat.*lchown.*auid>=500.*auid!=4294967295.*perm_mod"
        "arch=b64.*setxattr.*lsetxattr.*fsetxattr.*removexattr.*lremovexattr.*fremovexattr.*auid>=500.*auid!=4294967295.*perm_mod"
        "arch=b32.*setxattr.*lsetxattr.*fsetxattr.*removexattr.*lremovexattr.*fremovexattr.*auid>=500.*auid!=4294967295.*perm_mod"
    )

    for pattern in "${patterns[@]}"; do
        if ! grep -Pq "$pattern" "$audit_rules_file"; then
            missing+=("$pattern")
        fi
    done

    if [[ ${#missing[@]} -eq 0 ]]; then
        print_result "PASS" "All required perm_mod audit rules are present in $audit_rules_file"
    else
        print_result "FAIL" "Missing one or more required audit rules for perm_mod in $audit_rules_file"
    fi
}

# 8.1.11 - Collect Unsuccessful Unauthorized Access Attempts to Files
check_8_1_11() {
    print_header "8.1.11" "Collect Unsuccessful Unauthorized Access Attempts to Files" "Scored" \
        "Verifying auditd is configured to capture failed open/create/truncate attempts (EACCES/EPERM) by non-system users."

    local audit_rules_file="/etc/audit/audit.rules"
    local missing=()

    if [[ ! -f "$audit_rules_file" ]]; then
        print_result "FAIL" "$audit_rules_file not found. Cannot verify access failure audit rules."
        return
    fi

    local content
    content=$(tr '\n' ' ' < "$audit_rules_file" | tr -s '[:space:]')

    check_combined_rule() {
        local arch=$1
        local exitcode=$2

        local found=1

        # Must contain all required keywords
        for syscall in creat open openat truncate ftruncate; do
            if ! echo "$content" | grep -qE "arch=${arch}.*${syscall}.*exit=${exitcode}.*auid>=500.*auid!=4294967295.*-k.*access"; then
                found=0
                break
            fi
        done

        if [[ "$found" -eq 0 ]]; then
            missing+=("${arch} ${exitcode}")
        fi
    }

    check_combined_rule b64 -EACCES
    check_combined_rule b64 -EPERM
    check_combined_rule b32 -EACCES
    check_combined_rule b32 -EPERM

    if [[ ${#missing[@]} -eq 0 ]]; then
        print_result "PASS" "All required access failure audit rules are present in $audit_rules_file"
    else
        print_result "FAIL" "Missing syscall audit coverage for: ${missing[*]}"
    fi
}

# 8.1.12 - Collect Use of Privileged Commands
check_8_1_12() {
    print_header "8.1.12" "Collect Use of Privileged Commands" "Scored" \
        "Verifying auditd is configured to monitor all privileged (setuid/setgid) commands."

    local audit_file="/etc/audit/audit.rules"
    local missing=()
    local temp_file
    temp_file=$(mktemp)

    if [[ ! -f "$audit_file" ]]; then
        print_result "FAIL" "$audit_file not found. Cannot verify privileged command audit rules."
        return
    fi

    # Get all privileged binaries (setuid/setgid)
    find / -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null | sort -u > "$temp_file"

    while IFS= read -r file; do
        # Escape slashes for grep
        escaped_file=$(printf '%s\n' "$file" | sed 's:/:\\/:g')

        # Match either auid!=4294967295 or auid!=-1
        if ! grep -Eq -- "-a\s+always,exit\s+-F\s+path=$escaped_file\s+-F\s+perm=x\s+-F\s+auid>=500\s+(-F\s+auid!=4294967295|-F\s+auid!=-1)\s+-k\s+privileged" "$audit_file"; then
            missing+=("$file")
        fi
    done < "$temp_file"

    rm -f "$temp_file"

    if [[ "${#missing[@]}" -eq 0 ]]; then
        print_result "PASS" "All privileged commands are audited in $audit_file"
    else
        local list=$(printf " - %s\n" "${missing[@]}" | pr -T -w 100 -4)
        print_result "FAIL" "Missing audit rules in $audit_file for:\n$list"
    fi
}

# 8.1.13 - Collect Successful File System Mounts
check_8_1_13() {
    print_header "8.1.13" "Collect Successful File System Mounts" "Scored" \
        "Verifying auditd is configured to record use of the mount syscall by unprivileged users."

    local audit_rules_file="/etc/audit/audit.rules"
    local missing_rules=()

    if [[ ! -f "$audit_rules_file" ]]; then
        print_result "FAIL" "$audit_rules_file not found. Cannot verify mount audit rules."
        return
    fi

    local required_rules=(
        "-a always,exit -F arch=b64 -S mount -F auid>=500 -F auid!=4294967295 -k mounts"
        "-a always,exit -F arch=b32 -S mount -F auid>=500 -F auid!=4294967295 -k mounts"
    )

    for rule in "${required_rules[@]}"; do
        if ! grep -F -- "$rule" "$audit_rules_file" > /dev/null 2>&1; then
            missing_rules+=("$rule")
        fi
    done

    if [[ ${#missing_rules[@]} -eq 0 ]]; then
        print_result "PASS" "All required mount syscall audit rules are present in $audit_rules_file"
    else
        print_result "FAIL" "Missing rules in $audit_rules_file: ${missing_rules[*]}"
    fi
}


# 8.1.14 - Collect File Deletion Events by User
check_8_1_14() {
    print_header "8.1.14" "Collect File Deletion Events by User" "Scored" \
        "Verifying auditd is configured to monitor deletion and rename syscalls."

    local audit_rules_file="/etc/audit/audit.rules"
    local missing_rules=()

    if [[ ! -f "$audit_rules_file" ]]; then
        print_result "FAIL" "$audit_rules_file not found. Cannot verify delete syscall audit rules."
        return
    fi

    local required_rules=(
        "-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=500 -F auid!=4294967295 -k delete"
        "-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=500 -F auid!=4294967295 -k delete"
    )

    for rule in "${required_rules[@]}"; do
        if ! grep -F -- "$rule" "$audit_rules_file" > /dev/null 2>&1; then
            missing_rules+=("$rule")
        fi
    done

    if [[ ${#missing_rules[@]} -eq 0 ]]; then
        print_result "PASS" "All required delete syscall audit rules are present in $audit_rules_file"
    else
        print_result "FAIL" "Missing rules in $audit_rules_file: ${missing_rules[*]}"
    fi
}

# 8.1.15 - Collect Changes to System Administration Scope (sudoers)
check_8_1_15() {
    print_header "8.1.15" "Collect Changes to System Administration Scope (sudoers)" "Scored" \
        "Verifying auditd is configured to monitor changes to /etc/sudoers."

    local audit_rules_file="/etc/audit/audit.rules"
    local missing_rules=()

    if [[ ! -f "$audit_rules_file" ]]; then
        print_result "FAIL" "$audit_rules_file not found. Cannot verify sudoers audit rule."
        return
    fi

    local required_rule="-w /etc/sudoers -p wa -k scope"

    if ! grep -F -- "$required_rule" "$audit_rules_file" > /dev/null 2>&1; then
        missing_rules+=("$required_rule")
    fi

    if [[ ${#missing_rules[@]} -eq 0 ]]; then
        print_result "PASS" "Audit rule for monitoring /etc/sudoers is present in $audit_rules_file"
    else
        print_result "FAIL" "Missing rules in $audit_rules_file: ${missing_rules[*]}"
    fi
}

# 8.1.16 - Collect System Administrator Actions (sudo log)
check_8_1_16() {
    print_header "8.1.16" "Collect System Administrator Actions (sudolog)" "Scored" \
        "Verifying auditd is configured to monitor changes to /var/log/sudo.log."

    local audit_rules_file="/etc/audit/audit.rules"
    local missing_rules=()

    if [[ ! -f "$audit_rules_file" ]]; then
        print_result "FAIL" "$audit_rules_file not found. Cannot verify sudolog audit rule."
        return
    fi

    local required_rule='-w /var/log/sudo.log -p wa -k actions'

    if ! grep -F -- "$required_rule" "$audit_rules_file" > /dev/null 2>&1; then
        missing_rules+=("$required_rule")
    fi

    if [[ ${#missing_rules[@]} -eq 0 ]]; then
        print_result "PASS" "Audit rule for monitoring /var/log/sudo.log is present in $audit_rules_file"
    else
        print_result "FAIL" "Missing rules in $audit_rules_file: ${missing_rules[*]}"
    fi
}

# 8.1.17 - Collect Kernel Module Loading and Unloading
check_8_1_17() {
    print_header "8.1.17" "Collect Kernel Module Loading and Unloading" "Scored" \
        "Verifying auditd is configured to monitor use of kernel module load/unload programs and syscalls."

    local audit_rules_file="/etc/audit/audit.rules"
    local missing_rules=()

    if [[ ! -f "$audit_rules_file" ]]; then
        print_result "FAIL" "$audit_rules_file not found. Cannot verify kernel module audit rules."
        return
    fi

    local required_rules=(
        "-w /sbin/insmod -p x -k modules"
        "-w /sbin/rmmod -p x -k modules"
        "-w /sbin/modprobe -p x -k modules"
        "-a always,exit -F arch=b64 -S init_module -S delete_module -k modules"
        "-a always,exit -F arch=b32 -S init_module -S delete_module -k modules"
    )

    for rule in "${required_rules[@]}"; do
        if ! grep -F -- "$rule" "$audit_rules_file" > /dev/null 2>&1; then
            missing_rules+=("$rule")
        fi
    done

    if [[ ${#missing_rules[@]} -eq 0 ]]; then
        print_result "PASS" "All required kernel module audit rules are present in $audit_rules_file"
    else
	result="FAIL"
    	print_result "$result" "Missing rules in $audit_rules_file:"
        printf '%s\n' "${missing_rules[@]}" | pr -T -w 120 -3
        echo "-------------------------------------------------------------"
        echo ""
    fi
}


# 8.1.18 - Make the Audit Configuration Immutable
check_8_1_18() {
    print_header "8.1.18" "Make the Audit Configuration Immutable" "Scored" \
        "Verifying that audit configuration is set to immutable mode (-e 2)."

    local audit_rules_file="/etc/audit/audit.rules"

    if [[ ! -f "$audit_rules_file" ]]; then
        print_result "FAIL" "$audit_rules_file not found. Cannot verify immutable audit setting."
        return
    fi

    if tail -n 1 "$audit_rules_file" | grep -q -- "-e 2"; then
        print_result "PASS" "Audit configuration is set to immutable mode in $audit_rules_file"
    else
        print_result "FAIL" "Immutable setting (-e 2) not found as last line in $audit_rules_file"
    fi
}


# 8.2.1 - Install the rsyslog package
check_8_2_1() {
    print_header "8.2.1" "Install the rsyslog package" "Scored" \
        "Verifying that the rsyslog package is installed to enhance syslog capabilities with TCP, filtering, and encryption."

    local rsyslog_installed=""

    if command -v dpkg >/dev/null 2>&1; then
        # Debian/Ubuntu
        if dpkg -s rsyslog 2>/dev/null | grep -q "Status: install ok installed"; then
            rsyslog_installed="yes"
        fi
    elif command -v rpm >/dev/null 2>&1; then
        # RHEL/CentOS/SUSE/Amazon Linux
        if rpm -q rsyslog >/dev/null 2>&1; then
            rsyslog_installed="yes"
        fi
    else
        print_result "FAIL" "Unsupported package manager. Cannot determine rsyslog installation status."
        return
    fi

    if [[ "$rsyslog_installed" == "yes" ]]; then
        print_result "PASS" "rsyslog package is installed"
    else
        print_result "FAIL" "rsyslog package is NOT installed"
    fi
}


# 8.2.2 - Ensure the rsyslog Service is activated
check_8_2_2() {
    print_header "8.2.2" "Ensure the rsyslog Service is activated" "Scored" \
        "Verifying that the rsyslog service is actively running on the system."

    local rsyslog_active=""
    local service_tool=""

    if command -v systemctl >/dev/null 2>&1; then
        service_tool="systemctl"
        if systemctl is-active rsyslog 2>/dev/null | grep -q "^active$"; then
            rsyslog_active="yes"
        fi
    elif command -v service >/dev/null 2>&1; then
        service_tool="service"
        if service rsyslog status 2>/dev/null | grep -Eiq "running"; then
            rsyslog_active="yes"
        fi
    elif command -v initctl >/dev/null 2>&1; then
        service_tool="initctl"
        if initctl status rsyslog 2>/dev/null | grep -q "start/"; then
            rsyslog_active="yes"
        fi
    else
        print_result "FAIL" "Unsupported init system. Cannot verify rsyslog service status."
        return
    fi

    if [[ "$rsyslog_active" == "yes" ]]; then
        print_result "PASS" "rsyslog service is active (${service_tool})"
    else
        print_result "FAIL" "rsyslog service is NOT active (${service_tool})"
    fi
}

# 8.2.3 - Configure /etc/rsyslog.conf
check_8_2_3() {
    print_header "8.2.3" "Configure /etc/rsyslog.conf" "Not Scored" \
        "Reviewing rsyslog configuration files and verifying log files are present in /var/log/ as per CIS benchmark audit guidance."

    local config_main="/etc/rsyslog.conf"
    local config_dir="/etc/rsyslog.d"
    local config_files=()
    local missing=()

    # Check for required files and directories
    if [[ -f "$config_main" ]]; then
        config_files+=("$config_main")
    else
        missing+=("$config_main")
    fi

    if [[ -d "$config_dir" ]]; then
        local dir_files
        dir_files=$(find "$config_dir" -type f 2>/dev/null)
        if [[ -n "$dir_files" ]]; then
            config_files+=($dir_files)
        else
            missing+=("$config_dir (no config files)")
        fi
    else
        missing+=("$config_dir")
    fi

    if [[ ${#missing[@]} -gt 0 ]]; then
	result="FAIL"
    	print_result "$result" "Missing rsyslog configuration file(s):"
        printf '%s\n' "${missing[@]}" | pr -T -w 120 -3
        echo "-------------------------------------------------------------"
        echo ""
        return
    fi

    # Look for active (non-commented) logging rules like "*.info", "auth.*", etc.
    local has_rules="no"
    for file in "${config_files[@]}"; do
        if grep -E '^[^#]*[[:alnum:]]+\.[[:alnum:]]+' "$file" >/dev/null 2>&1; then
            has_rules="yes"
            break
        fi
    done

    if [[ "$has_rules" != "yes" ]]; then
        print_result "FAIL" "rsyslog configuration exists but no active logging rules found"
        return
    fi

    # Check if /var/log contains any log files
    local log_count
    log_count=$(find /var/log -type f 2>/dev/null | wc -l)

    if [[ "$log_count" -eq 0 ]]; then
        print_result "FAIL" "/var/log contains no log files. Logging may not be working"
        return
    fi

    print_result "PASS" "rsyslog is configured with active rules and logs are being generated in /var/log/"
}


# 8.2.4 - Create and Set Permissions on rsyslog Log Files
check_8_2_4() {
    print_header "8.2.4" "Create and Set Permissions on rsyslog Log Files" "Scored" \
        "Checking ownership and permissions of rsyslog log files defined in /etc/rsyslog.conf"

    local config_file="/etc/rsyslog.conf"
    local log_files
    local insecure_files=()
    local missing_files=()

    if [[ ! -f "$config_file" ]]; then
        print_result "FAIL" "$config_file not found. Cannot audit log file permissions."
        return
    fi

    # Extract log file paths from rsyslog.conf (format: *.info /var/log/messages)
    log_files=$(grep -E '^[^#].*[[:space:]]+/var/log/' "$config_file" | awk '{print $NF}' | sort -u)

    if [[ -z "$log_files" ]]; then
        print_result "FAIL" "No log files found in $config_file. Cannot verify permissions."
        return
    fi

    for file in $log_files; do
        if [[ -e "$file" ]]; then
            local perms owner group mode
            perms=$(stat -c "%a" "$file")
            owner=$(stat -c "%U" "$file")
            group=$(stat -c "%G" "$file")

            if [[ "$owner" != "root" ]]; then
                insecure_files+=("$file (owner: $owner)")
                continue
            fi

            if [[ "$group" == "root" && "$perms" != "600" ]]; then
                insecure_files+=("$file (perm: $perms group: root)")
            elif [[ "$group" != "root" && "$perms" != "640" ]]; then
                insecure_files+=("$file (perm: $perms group: $group)")
            fi
        else
            missing_files+=("$file")
        fi
    done

    if [[ ${#missing_files[@]} -eq 0 && ${#insecure_files[@]} -eq 0 ]]; then
        print_result "PASS" "All rsyslog log files exist and have correct ownership and permissions"
    else
	result="FAIL"
	print_result "$result" "Issues found with rsyslog log files:"
        if [[ ${#missing_files[@]} -gt 0 ]]; then
            echo "Missing log files:"
            printf '%s\n' "${missing_files[@]}" | pr -T -w 120 -3
        fi
        if [[ ${#insecure_files[@]} -gt 0 ]]; then
            echo "Incorrect permissions or ownership:"
            printf '%s\n' "${insecure_files[@]}" | pr -T -w 120 -3
        fi
        echo "-------------------------------------------------------------"
        echo ""
    fi
}

# 8.2.5 - Configure rsyslog to Send Logs to a Remote Log Host
check_8_2_5() {
    print_header "8.2.5" "Configure rsyslog to Send Logs to a Remote Log Host" "Scored" \
        "Verifying that /etc/rsyslog.conf is configured to send logs to a remote host."

    local config_file="/etc/rsyslog.conf"

    if [[ ! -f "$config_file" ]]; then
        print_result "FAIL" "$config_file not found. Cannot verify remote logging configuration."
        return
    fi

    # Match lines like *.* @host or *.* @@host, excluding commented lines
    local matches
    matches=$(grep -E '^\s*\*\.\*[^I]*@' "$config_file" | grep -v '^\s*#')

    if [[ -n "$matches" ]]; then
    	result="PASS"
    	print_result "$result" "$config_file contains remote log host configuration:"
        echo "$matches"
        echo "-------------------------------------------------------------"
        echo ""
    else
        print_result "FAIL" "$config_file does not contain remote log host configuration"
    fi
}

# 8.2.6 - Accept Remote rsyslog Messages Only on Designated Log Hosts
check_8_2_6() {
    print_header "8.2.6" "Accept Remote rsyslog Messages Only on Designated Log Hosts" "Not Scored" \
        "Verifying that only designated log hosts accept remote rsyslog messages via TCP."

    local config_file="/etc/rsyslog.conf"

    if [[ ! -f "$config_file" ]]; then
        print_result "FAIL" "$config_file not found. Cannot verify remote rsyslog receive settings."
        return
    fi

    local modload_line input_line
    modload_line=$(grep '^\$ModLoad imtcp.so' "$config_file" 2>/dev/null | grep -v '^\s*#')
    input_line=$(grep '^\$InputTCPServerRun' "$config_file" 2>/dev/null | grep -v '^\s*#')

    if [[ -n "$modload_line" && -n "$input_line" ]]; then
    	result="PASS"
    	print_result "$result" "rsyslog is configured to receive remote messages:"
        echo "$modload_line"
        echo "$input_line"
        echo "-------------------------------------------------------------"
        echo ""
    elif [[ -n "$modload_line" || -n "$input_line" ]]; then
	result="FAIL"
    	print_result "$result" "Incomplete remote logging configuration in $config_file:"
        [[ -z "$modload_line" ]] && echo "Missing: \$ModLoad imtcp.so"
        [[ -z "$input_line" ]] && echo "Missing: \$InputTCPServerRun 514"
        [[ -n "$modload_line" ]] && echo "Found:   $modload_line"
        [[ -n "$input_line" ]] && echo "Found:   $input_line"
        echo "-------------------------------------------------------------"
        echo ""
    else
        print_result "PASS" "rsyslog is not configured to receive remote messages — appropriate for non-log hosts"
    fi
}

# 8.3.1 - Install AIDE
check_8_3_1() {
    print_header "8.3.1" "Install AIDE" "Scored" \
        "Verifying that the AIDE package is installed for file integrity monitoring."

    local pkg_ok="no"

    if command -v dpkg >/dev/null 2>&1; then
        if dpkg -s aide 2>/dev/null | grep -q "Status: install ok installed"; then
            pkg_ok="yes"
        fi
    elif command -v rpm >/dev/null 2>&1; then
        if rpm -q aide >/dev/null 2>&1; then
            pkg_ok="yes"
        fi
    else
        print_result "FAIL" "Unsupported package manager. Cannot verify AIDE installation."
        return
    fi

    if [[ "$pkg_ok" == "yes" ]]; then
        print_result "PASS" "AIDE package is installed"
    else
        print_result "FAIL" "AIDE package is NOT installed"
    fi
}


# 8.3.2 - Implement Periodic Execution of File Integrity
check_8_3_2() {
    print_header "8.3.2" "Implement Periodic Execution of File Integrity" "Scored" \
        "Checking if AIDE file integrity check is scheduled via cron."

    local found_entry=""
    local aide_command="/usr/sbin/aide --check"

    # Check root's crontab
    if crontab -u root -l 2>/dev/null | grep -q "$aide_command"; then
        found_entry=$(crontab -u root -l | grep "$aide_command")
    fi

    # Check /etc/crontab if not found in root's crontab
    if [[ -z "$found_entry" ]] && grep -q "$aide_command" /etc/crontab 2>/dev/null; then
        found_entry=$(grep "$aide_command" /etc/crontab)
    fi

    if [[ -n "$found_entry" ]]; then
	result="PASS"
    	print_result "$result" "AIDE periodic check is scheduled via cron:"
        echo "$found_entry"
        echo "-------------------------------------------------------------"
        echo ""
    else
        print_result "FAIL" "No scheduled cron job found to run '$aide_command'"
    fi
}

# 8.4 - Configure logrotate
check_8_4() {
    print_header "8.4" "Configure logrotate" "Not Scored" \
        "Verifying that /etc/logrotate.d/rsyslog exists and includes log rotation directives."

    local config_file="/etc/logrotate.d/rsyslog"

    if [[ ! -f "$config_file" ]]; then
        print_result "FAIL" "$config_file not found. Cannot verify log rotation settings for rsyslog."
        return
    fi

    local rotated_logs
    rotated_logs=$(grep -E '^\s*/var/log/' "$config_file" | grep -v '^\s*#')

    if [[ -n "$rotated_logs" ]]; then
        result="PASS"
        print_result "$result" "$config_file includes log rotation directives: $(echo "$rotated_logs" | tr '\n' ' ')"
    else
        result="FAIL"
        print_result "$result" "$config_file exists but contains no active log rotation rules"
    fi
}

#call final function:
check_8_1_1_1
check_8_1_1_2
check_8_1_1_3
check_8_1_2
check_8_1_3
check_8_1_4
check_8_1_5
check_8_1_6
check_8_1_7
check_8_1_8
check_8_1_9
check_8_1_10
check_8_1_11
check_8_1_12
check_8_1_13
check_8_1_14
check_8_1_15
check_8_1_16
check_8_1_17
check_8_1_18
check_8_2_1
check_8_2_2
check_8_2_3
check_8_2_4
check_8_2_5
check_8_2_6
check_8_3_1
check_8_3_2
check_8_4


#sum table for finale  lookers
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
