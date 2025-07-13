#!/bin/bash

# Initialize counters
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
# Call the audit
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
