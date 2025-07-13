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

#2--------------------------------------------------------------[Best prataice]


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


