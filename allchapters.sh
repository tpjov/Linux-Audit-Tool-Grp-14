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

echo "Chapter 2 Audit: Filesystem Configuration"

check_2_1() {
    print_header "2.1" "Create Separate Partition for /tmp" "Scored" \
        "Check if /tmp is listed as a separate mount in /etc/fstab or /proc/mounts"
    if mount | grep -q "on /tmp "; then
        print_result "PASS" "/tmp is mounted as a separate partition"
    else
        print_result "FAIL" "/tmp is not mounted as a separate partition"
    fi
}

check_2_2() {
    print_header "2.2" "Set nodev option for /tmp Partition" "Scored" \
        "Verify /tmp has nodev option in mount settings"
    if mount | grep "/tmp" | grep -q "nodev"; then
        print_result "PASS" "nodev option is set on /tmp"
    else
        print_result "FAIL" "nodev option is not set on /tmp"
    fi
}

check_2_3() {
    print_header "2.3" "Set nosuid option for /tmp Partition" "Scored" \
        "Verify /tmp has nosuid option in mount settings"
    if mount | grep "/tmp" | grep -q "nosuid"; then
        print_result "PASS" "nosuid option is set on /tmp"
    else
        print_result "FAIL" "nosuid option is not set on /tmp"
    fi
}

check_2_4() {
    print_header "2.4" "Set noexec option for /tmp Partition" "Scored" \
        "Verify /tmp has noexec option in mount settings"
    if mount | grep "/tmp" | grep -q "noexec"; then
        print_result "PASS" "noexec option is set on /tmp"
    else
        print_result "FAIL" "noexec option is not set on /tmp"
    fi
}
check_2_5() {
    print_header "2.5" "Create Separate Partition for /var" "Scored" \
        "Check if /var is listed as a separate mount in /etc/fstab or /proc/mounts"
    if mount | grep -q "on /var "; then
        print_result "PASS" "/var is mounted as a separate partition"
    else
        print_result "FAIL" "/var is not mounted as a separate partition"
    fi
}

check_2_6() {
    print_header "2.6" "Bind Mount the /var/tmp directory to /tmp" "Scored" \
        "Verify if /var/tmp is bind-mounted to /tmp"
    if mount | grep -q "/var/tmp.*bind"; then
        print_result "PASS" "/var/tmp is bind mounted to /tmp"
    else
        print_result "FAIL" "/var/tmp is not bind mounted to /tmp"
    fi
}

check_2_7() {
    print_header "2.7" "Create Separate Partition for /var/log" "Scored" \
        "Check if /var/log is listed as a separate mount"
    if mount | grep -q "on /var/log "; then
        print_result "PASS" "/var/log is mounted as a separate partition"
    else
        print_result "FAIL" "/var/log is not mounted as a separate partition"
    fi
}

check_2_8() {
    print_header "2.8" "Create Separate Partition for /var/log/audit" "Scored" \
        "Check if /var/log/audit is listed as a separate mount"
    if mount | grep -q "on /var/log/audit "; then
        print_result "PASS" "/var/log/audit is mounted as a separate partition"
    else
        print_result "FAIL" "/var/log/audit is not mounted as a separate partition"
    fi
}

check_2_9() {
    print_header "2.9" "Create Separate Partition for /home" "Scored" \
        "Check if /home is listed as a separate mount"
    if mount | grep -q "on /home "; then
        print_result "PASS" "/home is mounted as a separate partition"
    else
        print_result "FAIL" "/home is not mounted as a separate partition"
    fi
}

check_2_10() {
    print_header "2.10" "Add nodev Option to /home" "Scored" \
        "Verify /home has nodev option in mount settings"
    if mount | grep "/home" | grep -q "nodev"; then
        print_result "PASS" "nodev option is set on /home"
    else
        print_result "FAIL" "nodev option is not set on /home"
    fi
}
check_2_11() {
    print_header "2.11" "Add nodev Option to Removable Media Partitions" "Not Scored" \
        "Verify nodev option is set on removable media partitions"
    if mount | grep "/media" | grep -q "nodev"; then
        print_result "PASS" "nodev option is set on removable media partitions"
    else
        print_result "FAIL" "nodev option is not set on removable media partitions"
    fi
}

check_2_12() {
    print_header "2.12" "Add noexec Option to Removable Media Partitions" "Not Scored" \
        "Verify noexec option is set on removable media partitions"
    if mount | grep "/media" | grep -q "noexec"; then
        print_result "PASS" "noexec option is set on removable media partitions"
    else
        print_result "FAIL" "noexec option is not set on removable media partitions"
    fi
}

check_2_13() {
    print_header "2.13" "Add nosuid Option to Removable Media Partitions" "Not Scored" \
        "Verify nosuid option is set on removable media partitions"
    if mount | grep "/media" | grep -q "nosuid"; then
        print_result "PASS" "nosuid option is set on removable media partitions"
    else
        print_result "FAIL" "nosuid option is not set on removable media partitions"
    fi
}

check_2_14() {
    print_header "2.14" "Add nodev Option to /run/shm Partition" "Scored" \
        "Verify /run/shm has nodev option in mount settings"
    if mount | grep "/run/shm" | grep -q "nodev"; then
        print_result "PASS" "nodev option is set on /run/shm"
    else
        print_result "FAIL" "nodev option is not set on /run/shm"
    fi
}

check_2_15() {
    print_header "2.15" "Add nosuid Option to /run/shm Partition" "Scored" \
        "Verify /run/shm has nosuid option in mount settings"
    if mount | grep "/run/shm" | grep -q "nosuid"; then
        print_result "PASS" "nosuid option is set on /run/shm"
    else
        print_result "FAIL" "nosuid option is not set on /run/shm"
    fi
}

check_2_16() {
    print_header "2.16" "Add noexec Option to /run/shm Partition" "Scored" \
        "Verify /run/shm has noexec option in mount settings"
    if mount | grep "/run/shm" | grep -q "noexec"; then
        print_result "PASS" "noexec option is set on /run/shm"
    else
        print_result "FAIL" "noexec option is not set on /run/shm"
    fi
}

check_2_17() {
    print_header "2.17" "Set Sticky Bit on All World-Writable Directories" "Scored" \
        "Verify all world-writable directories have the sticky bit set"
    if find / \( -path /proc -o -path /sys -o -path /run -o -path /snap -o -path /dev \) -prune -o -type d -perm -0002 2>/dev/null | while read dir; do
        ls -ld "$dir" | grep -q "t" || echo "Missing sticky bit: $dir"
    done | grep -q "Missing sticky bit"; then
        print_result "FAIL" "Some world-writable directories are missing the sticky bit"
    else
        print_result "PASS" "All world-writable directories have the sticky bit"
    fi
}
check_2_18() {
    print_header "2.18" "Disable Mounting of cramfs Filesystems" "Not Scored" \
        "Verify cramfs filesystem is disabled in /etc/fstab"
    if grep -q " cramfs " /etc/fstab; then
        print_result "FAIL" "cramfs filesystem is enabled"
    else
        print_result "PASS" "cramfs filesystem is disabled"
    fi
}

check_2_19() {
    print_header "2.19" "Disable Mounting of freevxfs Filesystems" "Not Scored" \
        "Verify freevxfs filesystem is disabled in /etc/fstab"
    if grep -q " freevxfs " /etc/fstab; then
        print_result "FAIL" "freevxfs filesystem is enabled"
    else
        print_result "PASS" "freevxfs filesystem is disabled"
    fi
}

check_2_20() {
    print_header "2.20" "Disable Mounting of jffs2 Filesystems" "Not Scored" \
        "Verify jffs2 filesystem is disabled in /etc/fstab"
    if grep -q " jffs2 " /etc/fstab; then
        print_result "FAIL" "jffs2 filesystem is enabled"
    else
        print_result "PASS" "jffs2 filesystem is disabled"
    fi
}

check_2_21() {
    print_header "2.21" "Disable Mounting of hfs Filesystems" "Not Scored" \
        "Verify hfs filesystem is disabled in /etc/fstab"
    if grep -q " hfs " /etc/fstab; then
        print_result "FAIL" "hfs filesystem is enabled"
    else
        print_result "PASS" "hfs filesystem is disabled"
    fi
}

check_2_22() {
    print_header "2.22" "Disable Mounting of hfsplus Filesystems" "Not Scored" \
        "Verify hfsplus filesystem is disabled in /etc/fstab"
    if grep -q " hfsplus " /etc/fstab; then
        print_result "FAIL" "hfsplus filesystem is enabled"
    else
        print_result "PASS" "hfsplus filesystem is disabled"
    fi
}

check_2_23() {
    print_header "2.23" "Disable Mounting of squashfs Filesystems" "Not Scored" \
        "Verify squashfs filesystem is disabled in /etc/fstab"
    if grep -q " squashfs " /etc/fstab; then
        print_result "FAIL" "squashfs filesystem is enabled"
    else
        print_result "PASS" "squashfs filesystem is disabled"
    fi
}

check_2_24() {
    print_header "2.24" "Disable Mounting of udf Filesystems" "Not Scored" \
        "Verify udf filesystem is disabled in /etc/fstab"
    if grep -q " udf " /etc/fstab; then
        print_result "FAIL" "udf filesystem is enabled"
    else
        print_result "PASS" "udf filesystem is disabled"
    fi
}

check_2_25() {
    print_header "2.25" "Disable Automounting" "Scored" \
        "Verify automounting is disabled in /etc/fstab"
    if grep -q "autofs" /etc/fstab; then
        print_result "FAIL" "Automounting is enabled"
    else
        print_result "PASS" "Automounting is disabled"
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

echo "Chapter 10 Audit: User Accounts and Environment"

# 10.1.1 - Set Password Expiration Days
check_10_1_1() {
    print_header "10.1.1" "Set Password Expiration Days" "Scored" \
        "Ensuring PASS_MAX_DAYS in /etc/login.defs and user account settings are set to 90 or fewer days."

    local login_defs="/etc/login.defs"
    local max_days_def
    local fail_flag=0
    local user_fail_list=()

    # --- Check login.defs value ---
    if [[ ! -f "$login_defs" ]]; then
        print_result "FAIL" "$login_defs not found. Cannot verify PASS_MAX_DAYS."
        return
    fi

    max_days_def=$(grep -E '^PASS_MAX_DAYS' "$login_defs" | awk '{print $2}')
    if [[ -z "$max_days_def" || "$max_days_def" -gt 90 ]]; then
        result="FAIL"
        print_result "$result" "PASS_MAX_DAYS in $login_defs is not set to 90 or fewer. Current: ${max_days_def:-unset}, Expected: ≤ 90"
        return
    fi

    # --- Check user-specific password max age ---
    for user in $(awk -F: '($3 >= 1000 && $1 != "nobody") { print $1 }' /etc/passwd); do
        max_days_user=$(chage --list "$user" 2>/dev/null | grep "Maximum number of days" | awk -F: '{print $2}' | tr -d ' ')
        if [[ "$max_days_user" =~ ^[0-9]+$ && "$max_days_user" -gt 90 ]]; then
            user_fail_list+=("$user ($max_days_user days)")
            fail_flag=1
        fi
    done

    if [[ "$fail_flag" -eq 1 ]]; then
	 result="FAIL"
	 print_result "$result" "The following users exceed PASS_MAX_DAYS > 90:"
    	 printf '%s\n' "${user_fail_list[@]}" | pr -T -w 120 -3
    	 echo "-------------------------------------------------------------"
    	 echo ""
     else
    	 result="PASS"
    	 print_result "$result" "PASS_MAX_DAYS in $login_defs is set to $max_days_def and all users have max days ≤ 90"
    fi

}


# 10.1.2 - Set Password Change Minimum Number of Days
check_10_1_2() {
    print_header "10.1.2" "Set Password Change Minimum Number of Days" "Scored" \
        "Ensuring PASS_MIN_DAYS in /etc/login.defs and user account settings are set to 7 or more days."

    local login_defs="/etc/login.defs"
    local min_days_def
    local fail_flag=0
    local user_fail_list=()

    # --- Check login.defs value ---
    if [[ ! -f "$login_defs" ]]; then
        print_result "FAIL" "$login_defs not found. Cannot verify the PASS_MIN_DAYS."
        return
    fi

    min_days_def=$(grep -E '^PASS_MIN_DAYS' "$login_defs" | awk '{print $2}')
    if [[ -z "$min_days_def" || "$min_days_def" -lt 7 ]]; then
	result="FAIL"
	print_result "$result" "PASS_MIN_DAYS in $login_defs is not set to 7 or more. Current: ${min_days_def:-unset}, Expected: ≥ 7"
	return
    fi

    # --- Check user-specific password min age ---
    for user in $(awk -F: '($3 >= 1000 && $1 != "nobody") { print $1 }' /etc/passwd); do
        min_days_user=$(chage --list "$user" 2>/dev/null | grep "Minimum number of days" | awk -F: '{print $2}' | tr -d ' ')
        if [[ "$min_days_user" =~ ^[0-9]+$ && "$min_days_user" -lt 7 ]]; then
            user_fail_list+=("$user ($min_days_user days)")
            fail_flag=1
        fi
    done

    if [[ "$fail_flag" -eq 1 ]]; then
	result="FAIL"
	print_result "$result" "The following users have PASS_MIN_DAYS set below 7:"
	printf '%s\n' "${user_fail_list[@]}" | pr -T -w 120 -3
	echo "-------------------------------------------------------------"
	echo ""
    else
        print_result "PASS" "PASS_MIN_DAYS in $login_defs is set to $min_days_def and all users have min days ≥ 7"
    fi
}


# 10.1.3 - Set Password Expiring Warning Days
check_10_1_3() {
    print_header "10.1.3" "Set Password Expiring Warning Days" "Scored" \
        "Ensuring PASS_WARN_AGE in /etc/login.defs and user account settings are set to 7 or more days."

    local login_defs="/etc/login.defs"
    local warn_days_def
    local fail_flag=0
    local user_fail_list=()

    # --- Check login.defs value ---
    if [[ ! -f "$login_defs" ]]; then
        print_result "FAIL" "$login_defs not found. Cannot verify PASS_WARN_AGE."
        return
    fi

    warn_days_def=$(grep -E '^PASS_WARN_AGE' "$login_defs" | awk '{print $2}')
    if [[ -z "$warn_days_def" || "$warn_days_def" -lt 7 ]]; then
	result="FAIL"
	print_result "$result" "PASS_WARN_AGE in $login_defs is not set to 7 or more (Current: ${warn_days_def:-unset}, Expected: ≥ 7)"
        echo "-------------------------------------------------------------"
        echo ""
        return
    fi

    # --- Check user-specific warning age ---
    for user in $(awk -F: '($3 >= 1000 && $1 != "nobody") { print $1 }' /etc/passwd); do
        warn_user=$(chage --list "$user" 2>/dev/null | grep "Number of days of warning" | awk -F: '{print $2}' | tr -d ' ')
        if [[ "$warn_user" =~ ^[0-9]+$ && "$warn_user" -lt 7 ]]; then
            user_fail_list+=("$user ($warn_user days)")
            fail_flag=1
        fi
    done

    if [[ "$fail_flag" -eq 1 ]]; then
    	result="FAIL"
    	print_result "$result" "The following users have PASS_WARN_AGE set below 7:"
        printf '%s\n' "${user_fail_list[@]}" | pr -T -w 120 -3
        echo "-------------------------------------------------------------"
        echo ""
    else
        print_result "PASS" "PASS_WARN_AGE in $login_defs is set to $warn_days_def and all users have warning days ≥ 7"
    fi
}


# 10.2 - Disable System Accounts
check_10_2() {
    print_header "10.2" "Disable System Accounts" "Scored" \
        "Checking that all system accounts (UID < 500) use /usr/sbin/nologin or /bin/false to prevent interactive shell access."

    local bad_accounts
    bad_accounts=$(egrep -v "^\+" /etc/passwd | awk -F: \
        '($1!="root" && $1!="sync" && $1!="shutdown" && $1!="halt" && $3<500 && $7!="/usr/sbin/nologin" && $7!="/bin/false") {print $1 " (UID="$3", shell=" $7 ")"}')

    if [[ -n "$bad_accounts" ]]; then
	result="FAIL"
	print_result "$result" "The following system accounts have interactive shells:"
        echo "$bad_accounts" | pr -T -w 120 -3
        echo "-------------------------------------------------------------"
        echo ""
    else
        print_result "PASS" "All system accounts have non-interactive shells set (/usr/sbin/nologin or /bin/false)"
    fi
}

# 10.3 - Set Default Group for root Account
check_10_3() {
    print_header "10.3" "Set Default Group for root Account" "Scored" \
        "Verifying that the root account's default group ID (GID) is set to 0 (root group)."

    local gid
    gid=$(grep "^root:" /etc/passwd | cut -d: -f4)

    if [[ "$gid" == "0" ]]; then
        print_result "PASS" "The root account's default group ID is correctly set to 0"
    else
	result="FAIL"
	print_result "$result" "The root account's default group ID is not set to 0 (Current: GID=$gid, Expected: GID=0)"
        echo "-------------------------------------------------------------"
        echo ""
    fi
}

# 10.4 - Set Default umask for Users
check_10_4() {
    print_header "10.4" "Set Default umask for Users" "Scored" \
        "Verifying that the default UMASK in /etc/login.defs is set to 077 for secure file creation."

    local login_defs="/etc/login.defs"
    local umask_value

    if [[ ! -f "$login_defs" ]]; then
	result="FAIL"
        print_result "$result" "$login_defs not found. Cannot verify default umask."
        return
    fi

    umask_value=$(grep -E '^UMASK' "$login_defs" | awk '{print $2}' | head -n 1)

    if [[ "$umask_value" == "077" ]]; then
    	result="PASS"
    	print_result "$result" "UMASK in $login_defs is correctly set to 077"
    else
    	result="FAIL"
    	print_result "$result" "UMASK in $login_defs is not set to 077. Current: UMASK=${umask_value:-unset}, Expected: UMASK=077"
    fi
}


# 10.5 - Lock Inactive User Accounts
check_10_5() {
    print_header "10.5" "Lock Inactive User Accounts" "Scored" \
        "Verifying that inactive accounts are disabled after 35 days for both new and existing users."

    local default_inactive
    local user_fail_list=()
    local fail_flag=0

    # Check default inactivity setting
    default_inactive=$(useradd -D | grep '^INACTIVE' | cut -d= -f2)

    if [[ "$default_inactive" != "35" ]]; then
    	result="FAIL"
	print_result "$result" "INACTIVE default is not set to 35 in useradd settings (Current: INACTIVE=${default_inactive:-unset}, Expected: INACTIVE=35)"
        echo "-------------------------------------------------------------"
        echo ""
        return
    fi

    # Check existing user inactivity settings
    for user in $(awk -F: '($3 >= 1000 && $1 != "nobody") { print $1 }' /etc/passwd); do
        inactive_days=$(chage --list "$user" 2>/dev/null | grep "Account expires after inactive" | awk -F: '{print $2}' | tr -d ' ')
        if [[ "$inactive_days" != "35" ]]; then
            user_fail_list+=("$user ($inactive_days days)")
            fail_flag=1
        fi
    done

    if [[ "$fail_flag" -eq 1 ]]; then
	result="FAIL"
    	print_result "$result" "The following users have incorrect inactivity lock settings (not 35 days):"
        printf '%s\n' "${user_fail_list[@]}" | pr -T -w 120 -3
        echo "-------------------------------------------------------------"
        echo ""
    else
        print_result "PASS" "Default INACTIVE is 35 and all existing users are configured with 35-day inactivity lock"
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

echo "Chapter 12 Audit: Verify System File Permissions"


#3-------------------------------------------------------------------------------------------------------------------------



# 12.1 - Verify Permissions on /etc/passwd
check_12_1() {
    print_header "12.1" "Verify Permissions on /etc/passwd" "Scored" \
        "Checking ownership and permissions of /etc/passwd to prevent unauthorized modifications."

    local target="/etc/passwd"

    if [[ ! -e "$target" ]]; then
        print_result "FAIL" "$target not found. Cannot verify permissions."
        return
    fi

    local perms owner group
    perms=$(stat -c "%a" "$target")
    owner=$(stat -c "%U" "$target")
    group=$(stat -c "%G" "$target")

    if [[ "$owner" == "root" && "$group" == "root" && "$perms" == "644" ]]; then
        print_result "PASS" "$target is owned by root:root with correct permissions (644)"
    else
	result="FAIL"
	print_result "$result" "$target permissions or ownership are incorrect (Current: owner=$owner group=$group perms=$perms, Expected: owner=root group=root perms=644)"
        echo "-------------------------------------------------------------"
        echo ""
    fi
}

# 12.2 - Verify Permissions on /etc/shadow
check_12_2() {
    print_header "12.2" "Verify Permissions on /etc/shadow" "Scored" \
        "Checking ownership and permissions of /etc/shadow to prevent unauthorized access to password hashes."

    local target="/etc/shadow"

    if [[ ! -e "$target" ]]; then
        print_result "FAIL" "$target not found. Cannot verify permissions."
        return
    fi

    local perms owner group
    perms=$(stat -c "%a" "$target")
    owner=$(stat -c "%U" "$target")
    group=$(stat -c "%G" "$target")

    if [[ "$owner" == "root" && "$group" == "shadow" && "$perms" == "640" ]]; then
        print_result "PASS" "$target is owned by root:shadow with correct permissions (640)"
    else
	result="FAIL"
	print_result "$result" "$target permissions or ownership are incorrect (Current: owner=$owner group=$group perms=$perms, Expected: owner=root group=shadow perms=640)"
        echo "-------------------------------------------------------------"
        echo ""
    fi
}


# 12.3 - Verify Permissions on /etc/group
check_12_3() {
    print_header "12.3" "Verify Permissions on /etc/group" "Scored" \
        "Checking ownership and permissions of /etc/group to prevent unauthorized modifications."

    local target="/etc/group"

    if [[ ! -e "$target" ]]; then
        print_result "FAIL" "$target not found. Cannot verify permissions."
        return
    fi

    local perms owner group
    perms=$(stat -c "%a" "$target")
    owner=$(stat -c "%U" "$target")
    group=$(stat -c "%G" "$target")

    if [[ "$owner" == "root" && "$group" == "root" && "$perms" == "644" ]]; then
        print_result "PASS" "$target is owned by root:root with correct permissions (644)"
    else
	result="FAIL"
	print_result "$result" "$target permissions or ownership are incorrect (Current: owner=$owner group=$group perms=$perms, Expected: owner=root group=root perms=644)"
        echo "-------------------------------------------------------------"
        echo ""
    fi
}

# 12.4 - Verify User/Group Ownership on /etc/passwd
check_12_4() {
    print_header "12.4" "Verify User/Group Ownership on /etc/passwd" "Scored" \
        "Ensuring /etc/passwd is owned by root:root to prevent unauthorized modifications."

    local target="/etc/passwd"

    if [[ ! -e "$target" ]]; then
        print_result "FAIL" "$target not found. Cannot verify ownership."
        return
    fi

    local owner group
    owner=$(stat -c "%U" "$target")
    group=$(stat -c "%G" "$target")

    if [[ "$owner" == "root" && "$group" == "root" ]]; then
        print_result "PASS" "$target is owned by root:root"
    else
        result="FAIL"
	print_result "$result" "$target ownership is incorrect (Current: owner=$owner group=$group, Expected: owner=root group=root)"
        echo "-------------------------------------------------------------"
        echo ""
    fi
}


# 12.5 - Verify User/Group Ownership on /etc/shadow
check_12_5() {
    print_header "12.5" "Verify User/Group Ownership on /etc/shadow" "Scored" \
        "Checking that /etc/shadow is owned by root and grouped under root or shadow."

    local target="/etc/shadow"

    if [[ ! -e "$target" ]]; then
        print_result "FAIL" "$target not found. Cannot verify ownership."
        return
    fi

    local owner group
    owner=$(stat -c "%U" "$target")
    group=$(stat -c "%G" "$target")

    if [[ "$owner" == "root" && ( "$group" == "shadow" || "$group" == "root" ) ]]; then
        print_result "PASS" "$target is owned by root with group set to root or shadow"
    else
	result="FAIL"
	print_result "$result" "$target ownership is incorrect (Current: owner=$owner group=$group, Expected: owner=root group=root or shadow)"
        echo "-------------------------------------------------------------"
        echo ""

    fi
}


# 12.6 - Verify User/Group Ownership on /etc/group
check_12_6() {
    print_header "12.6" "Verify User/Group Ownership on /etc/group" "Scored" \
        "Ensuring /etc/group is owned by root:root to protect group definitions from unauthorized modifications."

    local target="/etc/group"

    if [[ ! -e "$target" ]]; then
        print_result "FAIL" "$target not found. Cannot verify ownership."
        return
    fi

    local owner group
    owner=$(stat -c "%U" "$target")
    group=$(stat -c "%G" "$target")

    if [[ "$owner" == "root" && "$group" == "root" ]]; then
        print_result "PASS" "$target is owned by root:root"
    else
	result="FAIL"
	print_result "$result" "$target ownership is incorrect (Current: owner=$owner group=$group, Expected: owner=root group=root)"
        echo "-------------------------------------------------------------"
        echo ""
    fi
}


# 12.7 - Find World Writable Files
check_12_7() {
    print_header "12.7" "Find World Writable Files" "Not Scored" \
        "Searching all local file systems for world-writable files that could be a security risk."

    local world_writable
    world_writable=$(df --local -P | awk 'NR!=1 {print $6}' | xargs -I '{}' find '{}' -xdev -type f -perm -0002 2>/dev/null)

    if [[ -n "$world_writable" ]]; then
	result="FAIL"
	print_result "$result" "The following world-writable files were found:"
        echo "$world_writable" | pr -T -w 120 -3
        echo "-------------------------------------------------------------"
        echo ""
    else
        print_result "PASS" "No world-writable files found on local file systems"
    fi
}

# 12.8 - Find Un-owned Files and Directories
check_12_8() {
    print_header "12.8" "Find Un-owned Files and Directories" "Scored" \
        "Searching local file systems for files and directories not owned by any user (orphaned UID)."

    local unowned
    unowned=$(df --local -P | awk 'NR!=1 {print $6}' | xargs -I '{}' find '{}' -xdev -nouser 2>/dev/null)

    if [[ -n "$unowned" ]]; then
        result="FAIL"
        print_result "$result" "The following un-owned files or directories were found:" 
        echo "$unowned" | pr -T -w 120 -3
        echo "-------------------------------------------------------------"
        echo ""
    else
        print_result "PASS" "No un-owned files or directories found on local file systems"
    fi
}


# 12.9 - Find Un-grouped Files and Directories
check_12_9() {
    print_header "12.9" "Find Un-grouped Files and Directories" "Scored" \
        "Searching local file systems for files and directories not owned by any group (orphaned GID)."

    local ungrouped
    ungrouped=$(df --local -P | awk 'NR!=1 {print $6}' | xargs -I '{}' find '{}' -xdev -nogroup 2>/dev/null)

    if [[ -n "$ungrouped" ]]; then
	result="FAIL"
        print_result "$result" "The following un-grouped files or directories were found:" 
        echo "$ungrouped" | pr -T -w 120 -3
        echo "-------------------------------------------------------------"
        echo ""
    else
        print_result "PASS" "No un-grouped files or directories found on local file systems"
    fi
}


# 12.10 - Find SUID System Executables
check_12_10() {
    print_header "12.10" "Find SUID System Executables" "Not Scored" \
        "Identifying all files on local file systems with the SUID permission bit set."

    local baseline="/var/lib/cis-audit/suid-approved.txt"
    local current="/var/lib/cis-audit/suid-current.txt"

    # Try to create required directory (ignore error silently)
    mkdir -p /var/lib/cis-audit 2>/dev/null

    # Check if either file is missing
    if [[ ! -f "$baseline" || ! -f "$current" ]]; then
        print_result "FAIL" "Missing one or more required files: $baseline or $current"
        echo "The approved file lists known-safe SUID binaries and must be created manually (DIY)."
        echo "ensure the exact file name and path is the exact same and create/run in root. "
        echo ""
        echo "To create baseline for each files: (Follow exactly)"
        echo "  cp $current $baseline"
        echo "  sort -u $baseline -o $baseline"
        echo "-------------------------------------------------------------"
        echo ""
        return
    fi

    # Generate current snapshot
    df --local -P | awk 'NR!=1 {print $6}' | xargs -I '{}' find '{}' -xdev -type f -perm -4000 2>/dev/null | sort -u > "$current"

    # Compare current list to baseline
    if diff -q "$baseline" "$current" >/dev/null; then
        print_result "PASS" "All current SUID binaries match the approved baseline."
        echo "Approved list: $baseline"
    else
        print_result "FAIL" "New or unexpected SUID binaries found."
        comm -13 "$baseline" "$current" | pr -T -w 120 -3
        echo ""
        echo "Review each new file. If safe, add to $baseline:"
        echo "  echo \"/path/to/binary\" | tee -a $baseline > /dev/null"
        echo "  sort -u $baseline -o $baseline"
    fi

    echo "-------------------------------------------------------------"
    echo ""
}


check_12_11() {
    print_header "12.11" "Find SGID System Executables" "Not Scored" \
        "Identifying all files on local file systems with the SGID permission bit set."

    local baseline="/var/lib/cis-audit/sgid-approved.txt"
    local current="/var/lib/cis-audit/sgid-current.txt"

    # Ensure target directory exists (ignore permission error)
    mkdir -p /var/lib/cis-audit 2>/dev/null

    # Check if either required file is missing
    if [[ ! -f "$baseline" || ! -f "$current" ]]; then
	result="FAIL"
   	print_result "$result" "Missing required file(s): $baseline or $current"
        echo "The approved file lists known-safe SGID binaries and must be created manually (DIY)."
        echo "Ensure the exact file name and path is the same, and create/run this as root."
        echo ""
        echo "To create baseline this files:"
        echo "  cp $current $baseline"
        echo "  sort -u $baseline -o $baseline"
        echo "-------------------------------------------------------------"
        echo ""
        return
    fi

    # Get current list of SGID executables
    df --local -P | awk 'NR!=1 {print $6}' | xargs -I '{}' find '{}' -xdev -type f -perm -2000 2>/dev/null | sort > "$current"

    # Compare current list with baseline
    if diff -q "$baseline" "$current" >/dev/null; then
        result="PASS"
        print_result "$result" "No unauthorized SGID files detected. All files match approved baseline (self-check/update)."
        echo "To view the approved list, see: $baseline"
    else
	result="FAIL"
	print_result "$result" "New/Unexpected SGID files detected:"
        comm -13 "$baseline" "$current" | pr -T -w 120 -3
        echo ""
        echo "To resolve this finding:"
        echo "1. Manually review the new SGID files listed above."
        echo "   Use commands like:"
        echo "     file /path/to/binary"
        echo "     stat /path/to/binary"
        echo "     dpkg -S /path/to/binary   #If using apt"
        echo ""
        echo "2. If a file is safe and expected, you can add it to the approved baseline:"
        echo "     echo \"/path/to/binary\" | sudo tee -a $baseline > /dev/null"
        echo "     sort -u $baseline -o $baseline"
        echo ""
        echo "3. Re-run the CIS 12.11 check to verify the update."
    fi

    echo "-------------------------------------------------------------"
    echo ""
}

echo "Chapter 13 Audit: Review User and Group Settings"

# Chapter 13.1 - Ensure Password Fields are Not Empty
check_13_1() {
    print_header "13.1" "Ensure Password Fields are Not Empty" "Scored" \
        "Ensure no accounts have empty password fields in /etc/shadow"

    local output
    output=$(/bin/cat /etc/shadow | /usr/bin/awk -F: '($2 == "") { print $1 " does not have a password "}' 2>/dev/null)

    if [ -z "$output" ]; then
        print_result "PASS" "All accounts have passwords set."
    else
        print_result "FAIL" "The following accounts have empty password fields: $output"
    fi
}

check_13_2() {
    print_header "13.2" "Verify No Legacy '+' Entries Exist in /etc/passwd File" "Scored" \
        "Ensure there are no legacy '+' entries in /etc/passwd"

    local output
    output=$(grep '^+:' /etc/passwd 2>/dev/null)

    if [ -z "$output" ]; then
        print_result "PASS" "No legacy '+' entries found in /etc/passwd."
    else
        print_result "FAIL" "Legacy '+' entries exist in /etc/passwd: $output"
    fi
}

check_13_3() {
    print_header "13.3" "Verify No Legacy '+' Entries Exist in /etc/shadow File" "Scored" \
        "Ensure there are no legacy '+' entries in /etc/shadow"

    local output
    output=$(grep '^+:' /etc/shadow 2>/dev/null)

    if [ -z "$output" ]; then
        print_result "PASS" "No legacy '+' entries found in /etc/shadow."
    else
        print_result "FAIL" "Legacy '+' entries exist in /etc/shadow: $output"
    fi
}

check_13_4() {
    print_header "13.4" "Verify No Legacy '+' Entries Exist in /etc/group File" "Scored" \
        "Ensure that no legacy '+' entries exist in /etc/group"

    local output
    output=$(grep '^+:' /etc/group 2>/dev/null)

    if [ -z "$output" ]; then
        print_result "PASS" "No legacy '+' entries found in /etc/group."
    else
        print_result "FAIL" "Legacy '+' entries found in /etc/group: $output"
    fi
}

check_13_5() {
    print_header "13.5" "Verify No UID 0 Accounts Exist Other Than root" "Scored" \
        "Ensure that only the user 'root' has UID 0 in /etc/passwd"

    local output
    output=$(awk -F: '($3 == 0 && $1 != "root") { print $1 }' /etc/passwd 2>/dev/null)

    if [ -z "$output" ]; then
        print_result "PASS" "Only 'root' has UID 0."
    else
        print_result "FAIL" "Other UID 0 accounts found: $output"
    fi
}

check_13_6() {
    print_header "13.6" "Ensure root PATH Integrity" "Scored" \
        "Check that the PATH variable for root is secure (no ::, no trailing :, no . in path, all dirs owned by root, not writable by group/others)"

    local fail=0
    local path_dirs
    path_dirs=$(echo "$PATH" | sed -e 's/::/:/' -e 's/:/ /g')

    if echo "$PATH" | grep -q "::"; then
        echo "Issue: PATH contains empty directory (::)"
        fail=1
    fi

    if echo "$PATH" | grep -q ":$"; then
        echo "Issue: PATH ends with ':'"
        fail=1
    fi

    for dir in $path_dirs; do
        if [ "$dir" = "." ]; then
            echo "Issue: PATH contains current directory (.)"
            fail=1
            continue
        fi

        if [ -d "$dir" ]; then
            local perms owner
            perms=$(ls -ldH "$dir" | cut -f1 -d" ")
            owner=$(ls -ldH "$dir" | awk '{print $3}')

            if [ "$(echo "$perms" | cut -c6)" != "-" ]; then
                echo "Issue: Directory $dir is group writable"
                fail=1
            fi
            if [ "$(echo "$perms" | cut -c9)" != "-" ]; then
                echo "Issue: Directory $dir is world writable"
                fail=1
            fi
            if [ "$owner" != "root" ]; then
                echo "Issue: Directory $dir is not owned by root"
                fail=1
            fi
        else
            echo "Issue: $dir in PATH does not exist"
            fail=1
        fi
    done

    if [ "$fail" -eq 0 ]; then
        print_result "PASS" "ROOT PATH integrity is secure."
    else
        print_result "FAIL" "One or more issues were found in the ROOT PATH."
    fi
}

check_13_7() {
    print_header "13.7" "Check Permissions on User Home Directories" "Scored" \
        "Ensure user home directories are not group-writable or world-readable/writable/executable"

    local fail=0
    local dirperm

    for dir in $(awk -F: '!/root|halt|sync|shutdown/ && $7 !~ /(false|nologin)/ {print $6}' /etc/passwd); do
        if [ -d "$dir" ]; then
            dirperm=$(ls -ld "$dir" | awk '{print $1}')

            if [ "$(echo "$dirperm" | cut -c6)" = "w" ]; then
                echo "Issue: Group write permission set on $dir"
                fail=1
            fi
            if [ "$(echo "$dirperm" | cut -c8)" = "r" ]; then
                echo "Issue: Other read permission set on $dir"
                fail=1
            fi
            if [ "$(echo "$dirperm" | cut -c9)" = "w" ]; then
                echo "Issue: Other write permission set on $dir"
                fail=1
            fi
            if [ "$(echo "$dirperm" | cut -c10)" = "x" ]; then
                echo "Issue: Other execute permission set on $dir"
                fail=1
            fi
        fi
    done

    if [ "$fail" -eq 0 ]; then
        print_result "PASS" "All user home directories have secure permissions."
    else
        print_result "FAIL" "One or more user home directories have insecure permissions."
    fi
}

check_13_8() {
    print_header "13.8" "Check User Dot File Permissions" "Scored" \
        "Ensure user dot files are not group- or world-writable"

    local fail=0
    local perm

    for dir in $(awk -F: '($3 >= 1000 && $7 !~ /nologin|false/ && $1 !~ /^(root|sync|halt|shutdown)$/) { print $6 }' /etc/passwd); do
        for file in "$dir"/.[A-Za-z0-9]*; do
            if [ -f "$file" ] && [ ! -h "$file" ]; then
                perm=$(ls -ld "$file" | cut -c6,9)

                if [ "$(echo "$perm" | cut -c1)" = "w" ]; then
                    echo "Issue: Group write permission set on file $file"
                    fail=1
                fi
                if [ "$(echo "$perm" | cut -c2)" = "w" ]; then
                    echo "Issue: Other write permission set on file $file"
                    fail=1
                fi
            fi
        done
    done

    if [ "$fail" -eq 0 ]; then
        print_result "PASS" "All user dot files have secure permissions."
    else
        print_result "FAIL" "One or more dot files have insecure permissions."
    fi
}

check_13_9() {
    print_header "13.9" "Check Permissions on User .netrc Files" "Scored" \
        "Ensure user .netrc files are not group- or world-accessible"

    local fail=0
    local file perm

    for dir in $(awk -F: '($3 >= 1000 && $7 !~ /nologin|false/ && $1 !~ /^(root|sync|halt|shutdown)$/) { print $6 }' /etc/passwd); do
        file="$dir/.netrc"

        if [ -f "$file" ] && [ ! -h "$file" ]; then
            perm=$(ls -ld "$file" | cut -c5-10)

            if [ "$(echo "$perm" | cut -c1)" != "-" ]; then
                echo "Issue: Group read permission set on $file"
                fail=1
            fi
            if [ "$(echo "$perm" | cut -c2)" != "-" ]; then
                echo "Issue: Group write permission set on $file"
                fail=1
            fi
            if [ "$(echo "$perm" | cut -c3)" != "-" ]; then
                echo "Issue: Group execute permission set on $file"
                fail=1
            fi
            if [ "$(echo "$perm" | cut -c4)" != "-" ]; then
                echo "Issue: Other read permission set on $file"
                fail=1
            fi
            if [ "$(echo "$perm" | cut -c5)" != "-" ]; then
                echo "Issue: Other write permission set on $file"
                fail=1
            fi
            if [ "$(echo "$perm" | cut -c6)" != "-" ]; then
                echo "Issue: Other execute permission set on $file"
                fail=1
            fi
        fi
    done

    if [ "$fail" -eq 0 ]; then
        print_result "PASS" "All .netrc files have secure permissions."
    else
        print_result "FAIL" "One or more .netrc files have insecure permissions."
    fi
}

check_13_10() {
    print_header "13.10" "Check for Presence of User .rhosts Files" "Scored" \
        "Ensure no user .rhosts files are present"

    local fail=0
    local file

    for dir in $(awk -F: '($3 >= 1000 && $1 !~ /^(root|halt|sync|shutdown)$/ && $7 !~ /nologin|false/) { print $6 }' /etc/passwd); do
        file="$dir/.rhosts"

        if [ -f "$file" ] && [ ! -h "$file" ]; then
            echo "Issue: .rhosts file found in $file"
            fail=1
        fi
    done

    if [ "$fail" -eq 0 ]; then
        print_result "PASS" "No .rhosts files found."
    else
        print_result "FAIL" "One or more .rhosts files found on the system."
    fi
}

check_13_11() {
    print_header "13.11" "Check Groups in /etc/passwd" "Scored" \
        "Ensure all group IDs referenced in /etc/passwd exist in /etc/group"

    local fail=0

    for gid in $(cut -s -d: -f4 /etc/passwd | sort -u); do
        if ! grep -q "^[^:]*:[^:]*:$gid:" /etc/group; then
            echo "Issue: Group ID $gid is referenced in /etc/passwd but not defined in /etc/group"
            fail=1
        fi
    done

    if [ "$fail" -eq 0 ]; then
        print_result "PASS" "All group IDs in /etc/passwd exist in /etc/group."
    else
        print_result "FAIL" "One or more group IDs in /etc/passwd are not present in /etc/group."
    fi
}

check_13_12() {
    print_header "13.12" "Check That Users Are Assigned Valid Home Directories" "Scored" \
        "Ensure each user with UID >= 500 has a valid home directory"

    local fail=0

    while IFS=: read -r user _ uid _ _ homedir _; do
        if [ "$uid" -ge 500 ] && [ "$user" != "nfsnobody" ] && [ "$user" != "nobody" ]; then
            if [ ! -d "$homedir" ]; then
                echo "Issue: $user does not have a valid home directory ($homedir)"
                fail=1
            fi
        fi
    done < /etc/passwd

    if [ "$fail" -eq 0 ]; then
        print_result "PASS" "All users are assigned valid home directories."
    else
        print_result "FAIL" "One or more users do not have valid home directories."
    fi
}

check_13_13() {
    print_header "13.13" "Check User Home Directory Ownership" "Scored" \
        "Ensure users own the home directories they are assigned to"

    local fail=0

    awk -F: '($3 >= 1000 && $7 ~ /bash|sh/ && $1 !~ /^(nobody|systemd|dnsmasq|fwupd|polkitd)$/)' /etc/passwd | \
    while read -r user _ uid gid desc homedir shell; do
        if [ -d "$homedir" ]; then
            owner=$(stat -L -c "%U" "$homedir")
            if [ "$owner" != "$user" ]; then
                echo "Issue: Home directory $homedir of user '$user' is owned by '$owner'"
                fail=1
            fi
        fi
    done

    if [ "$fail" -eq 0 ]; then
        print_result "PASS" "All user home directories are correctly owned by their respective users."
    else
        print_result "FAIL" "One or more user home directories are not owned by the correct user."
    fi
}

check_13_14() {
    print_header "13.14" "Check for Duplicate UIDs" "Scored" \
        "Ensure all UIDs in the /etc/passwd file are unique"

    local fail=0
    local output=""

    while read -r count uid; do
        if [ "$count" -gt 1 ]; then
            users=$(awk -F: -v id="$uid" '($3 == id) { print $1 }' /etc/passwd | xargs)
            output+="Duplicate UID ($uid): $users"$'\n'
            fail=1
        fi
    done < <(cut -d: -f3 /etc/passwd | sort -n | uniq -c)

    if [ "$fail" -eq 0 ]; then
        print_result "PASS" "All UIDs are unique in /etc/passwd."
    else
        print_result "FAIL" "There are duplicate UIDs in /etc/passwd:\n$output"
    fi
}

check_13_15() {
    print_header "13.15" "Check for Duplicate GIDs" "Scored" \
        "Ensure all GIDs in the /etc/group file are unique"

    local fail=0
    local output=""

    while read -r count gid; do
        if [ "$count" -gt 1 ]; then
            groups=$(awk -F: -v id="$gid" '($3 == id) { print $1 }' /etc/group | xargs)
            output+="Duplicate GID ($gid): $groups"$'\n'
            fail=1
        fi
    done < <(cut -d: -f3 /etc/group | sort -n | uniq -c)

    if [ "$fail" -eq 0 ]; then
        print_result "PASS" "All GIDs are unique in /etc/group."
    else
        print_result "FAIL" "There are duplicate GIDs in /etc/group:\n$output"
    fi
}

check_13_16() {
    print_header "13.16" "Check for User Names" "Scored" \
        "Ensure all user names in the /etc/passwd file are unique"

    local fail=0
    local output=""

    while read -r count username; do
        if [ "$count" -gt 1 ]; then
            uids=$(awk -F: -v name="$username" '($1 == name) { print $3 }' /etc/passwd | xargs)
            output+="Duplicate Username ($username): UIDs = $uids"$'\n'
            fail=1
        fi
    done < <(cut -d: -f1 /etc/passwd | sort | uniq -c)

    if [ "$fail" -eq 0 ]; then
        print_result "PASS" "All user names are unique in /etc/passwd."
    else
        print_result "FAIL" "There are duplicate user names in /etc/passwd:\n$output"
    fi
}

check_13_17() {
    print_header "13.17" "Check for Duplicate Group Names" "Scored" \
        "Ensure all group names in the /etc/group file are unique"

    local fail=0
    local output=""

    while read -r count groupname; do
        if [ "$count" -gt 1 ]; then
            gids=$(awk -F: -v name="$groupname" '($1 == name) { print $3 }' /etc/group | xargs)
            output+="Duplicate group name ($groupname) with GIDs: $gids"$'\n'
            fail=1
        fi
    done < <(cut -d: -f1 /etc/group | sort | uniq -c)

    if [ "$fail" -eq 0 ]; then
        print_result "PASS" "All group names are unique in /etc/group."
    else
        print_result "FAIL" "There are duplicate group names in /etc/group:\n$output"
    fi
}

check_13_18() {
    print_header "13.18" "Check for Presence of User .netrc Files" "Scored" \
        "Ensure that no .netrc files exist in user home directories"

    local fail=0
    local output=""

    while read -r dir; do
        if [ -f "$dir/.netrc" ] && [ ! -h "$dir/.netrc" ]; then
            output+=".netrc file found: $dir/.netrc"$'\n'
            fail=1
        fi
    done < <(awk -F: '($3 >= 1000 && $7 !~ /nologin|false/) { print $6 }' /etc/passwd)

    if [ "$fail" -eq 0 ]; then
        print_result "PASS" "No user .netrc files found."
    else
        print_result "FAIL" "One or more .netrc files found:\n$output"
    fi
}

check_13_19() {
    print_header "13.19" "Check for Presence of User .forward Files" "Scored" \
        "Ensure that no .forward files exist in user home directories"

    local fail=0
    local output=""

    while read -r dir; do
        if [ -f "$dir/.forward" ] && [ ! -h "$dir/.forward" ]; then
            output+=".forward file found: $dir/.forward"$'\n'
            fail=1
        fi
    done < <(awk -F: '($3 >= 1000 && $7 !~ /nologin|false/) { print $6 }' /etc/passwd)

    if [ "$fail" -eq 0 ]; then
        print_result "PASS" "No user .forward files found."
    else
        print_result "FAIL" "One or more .forward files found:\n$output"
    fi
}

check_13_20() {
    print_header "13.20" "Ensure shadow group is empty" "Scored" \
        "Ensure there are no users in the shadow group and no users have shadow as their primary group."

    local fail=0
    local output=""
    
    local shadow_group_entry
    shadow_group_entry=$(grep '^shadow:' /etc/group)
    local shadow_gid
    shadow_gid=$(echo "$shadow_group_entry" | cut -d: -f3)
    local shadow_members
    shadow_members=$(echo "$shadow_group_entry" | cut -d: -f4)

    if [ -n "$shadow_members" ]; then
        output+="Members of 'shadow' group: $shadow_members"$'\n'
        fail=1
    fi

    local shadow_primary_users
    shadow_primary_users=$(awk -F: -v gid="$shadow_gid" '($4 == gid) { print $1 }' /etc/passwd)

    if [ -n "$shadow_primary_users" ]; then
        output+="Users with 'shadow' as primary group: $shadow_primary_users"$'\n'
        fail=1
    fi

    if [ "$fail" -eq 0 ]; then
        print_result "PASS" "No users belong to the 'shadow' group or have it as their primary group."
    else
        print_result "FAIL" "One or more users belong to the 'shadow' group:\n$output"
    fi
}

# Call the audit
check_1_1
check_2_1
check_2_2
check_2_3
check_2_4
check_2_5
check_2_6
check_2_7
check_2_8
check_2_9
check_2_10
check_2_11
check_2_12
check_2_13
check_2_14
check_2_15
check_2_16
check_2_17
check_2_18
check_2_19
check_2_20
check_2_21
check_2_22
check_2_23
check_2_24
check_2_25
check_3_1
check_3_2
check_3_3
check_3_4
check_4_1
check_4_2
check_4_3
check_4_4
check_4_5
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
check_10_1_1
check_10_1_2
check_10_1_3
check_10_2
check_10_3
check_10_4
check_10_5
check_11_1
check_11_2
check_11_3
check_12_1
check_12_2
check_12_3
check_12_4
check_12_5
check_12_6
check_12_7
check_12_8
check_12_9
check_12_10
check_12_11
check_13_1
check_13_2
check_13_3
check_13_4
check_13_5
check_13_6
check_13_7
check_13_8
check_13_9
check_13_10
check_13_11
check_13_12
check_13_13
check_13_14
check_13_15
check_13_16
check_13_17
check_13_18
check_13_19
check_13_20


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
