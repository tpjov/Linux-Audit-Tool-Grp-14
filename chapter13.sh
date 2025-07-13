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

# Run Chapter 13 audit functions
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
