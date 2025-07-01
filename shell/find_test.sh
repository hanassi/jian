#!/bin/sh

#######################
# 호환성 체크
#######################

# bash나 ksh가 있으면 전환
if command -v bash >/dev/null 2>&1 && [ -z "$SHELL_SWITCHED" ]; then
    export SHELL_SWITCHED=1
    exec bash "$0" "$@"
elif command -v ksh >/dev/null 2>&1 && [ -z "$SHELL_SWITCHED" ]; then
    export SHELL_SWITCHED=1
    exec ksh "$0" "$@"
fi

#######################
# 로케일 설정 함수
#######################
set_locale() {
    if locale -a | grep -iq '^ko_KR\.utf8$'; then
        LANG=ko_KR.utf8
    elif locale -a | grep -iq '^ko_KR\.UTF-8$'; then
        LANG=ko_KR.UTF-8
    elif locale -a | grep -iq '^ko_KR\.euckr$'; then
        LANG=ko_KR.euckr
    elif locale -a | grep -iq '^ko_KR$' && ! locale -a | grep -iq 'euckr\|utf8'; then
        LANG=ko_KR
    else
        LANG=C
    fi
    export LANG
}

#######################
# 파일 존재여부 체크 함수
#######################
file_check() {
    [ -e "$1" ]
    return $?
}

#######################
# 텍스트 출력 관련 함수
#######################
WIDTH=75
PRINT_WIDTH=70
LINE=$(printf '%*s' "$WIDTH" '' | tr ' ' '#')
LINE1=$(printf '%*s' "$PRINT_WIDTH" '' | tr ' ' '=')
LINE2=$(printf '%*s' "$PRINT_WIDTH" '' | tr ' ' '-')
LINE3=$(printf '%*s' "$PRINT_WIDTH" '' | tr ' ' '*')

center() {
    text="$1"
    text_length=${#text}
    padding_left=$(( (WIDTH - text_length) / 2 ))
    padding_right=$(( WIDTH - text_length - padding_left ))
    printf "#%*s%s%*s#\n" "$padding_left" "" "$text" "$padding_right" ""
}

center_line() {
    local text="$1"
    local len=${#text}
    local pad=$(( (PRINT_WIDTH - len - 2) / 2 ))
    printf "%s\n" "$LINE2"
    printf "%*s[%s]%*s\n" "$pad" "" "$text" "$pad" ""
    printf "%s\n" "$LINE2"
}

print_title() {
    echo "$LINE1" >> $CREATE_FILE
    printf "%*s\n" $(( (PRINT_WIDTH + ${#1}) / 2 )) "$1" >> $CREATE_FILE
    echo "$LINE1" >> $CREATE_FILE
    echo "" >> $CREATE_FILE
}

#######################
# 초기 전역 변수 설정
#######################
set_locale

OS=`uname -s`
if [ "$OS" = Linux ]; then
    IP=`hostname -I | sed 's/ //g'`
elif [ "$OS" = SunOS ]; then
    IP=`ifconfig -a | grep broadcast | cut -f 2 -d ' '`
elif [ "$OS" = AIX ]; then
    IP=`ifconfig en0 | grep 'inet' | awk '{print $2}'`
elif [ "$OS" = HP-UX ]; then
    IP=`ifconfig lan0 | grep 'inet' | awk '{print $2}'`
fi

HOMEDIRS=`awk -F":" 'length($6) > 0 {print $6}' /etc/passwd | grep -wv "/" | sort -u`
USERLIST=`egrep -vi "nologin|false|shutdown|halt|sync" /etc/passwd`
CREATE_FILE="[Lyn_secure]`hostname`_${OS}_${IP}_`date +%m%d`.txt"
CHECK_FILE=`[ -f $CREATE_FILE ] && echo 1 || echo 0`

#######################
# (화면출력) 헤더
#######################
echo "$LINE"
center ""
center "Security Inspection of Server (Unix ver.)"
center "Version : 1.6"
center "Copyright 2025, Lyn Secure. All Rights Reserved."
center "ALL RIGHTS RESERVED."
center ""
echo "$LINE"

#######################
# (화면출력) 진단 전 안내 
#######################
center_line "진단 전 주의사항"
echo "※ 반드시 Super 유저 권한에서 진단을 시작해야 합니다!"
echo "$LINE2"

#######################
# 시스템 정보
#######################
print_title "UNIX/Linux Security Check"
print_title "INFO_CHK START"
echo "[Start Time]" >> $CREATE_FILE
date >> $CREATE_FILE
print_title "INFO_CHK END"
echo "" >> $CREATE_FILE

print_title "System Information Query Start"
echo "[Kernel Information]" >> $CREATE_FILE
uname -a >> $CREATE_FILE
echo "" >> $CREATE_FILE
echo "[IP Information]" >> $CREATE_FILE
ifconfig -a >> $CREATE_FILE
echo "" >> $CREATE_FILE
echo "[Network Status]" >> $CREATE_FILE
netstat -an | egrep -i "LISTEN|ESTABLISHED" >> $CREATE_FILE
echo "" >> $CREATE_FILE
echo "[Routing Information]" >> $CREATE_FILE
netstat -rn >> $CREATE_FILE
echo "" >> $CREATE_FILE
echo "[Process Status]" >> $CREATE_FILE
ps -ef >> $CREATE_FILE
echo "" >> $CREATE_FILE
echo "[User Environment]" >> $CREATE_FILE
env >> $CREATE_FILE
echo "" >> $CREATE_FILE

print_title "System Information Query End"
print_title "Security Check START"