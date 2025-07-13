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


#4--------------------------------------------------------------------------[Chapt 8]


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






#-----

check_10_1_1
check_10_1_2
check_10_1_3
check_10_2
check_10_3
check_10_4
check_10_5




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





