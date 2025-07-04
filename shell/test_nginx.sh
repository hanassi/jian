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
CREATE_FILE="[Lyn_secure]Nginx_`hostname`_${OS}_${IP}_`date +%m%d`.txt"
WEB_NAME="Nginx"



#######################
# (화면출력) 헤더
#######################
echo "$LINE"
center ""
center "Security Inspection of Web Server (Unix ver.)"
center "Version : 2.1"
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




#================================================================================
# Nginx 스크립트 시작
#================================================================================




#================================================================================
# Nginx 변수 설정
#================================================================================

# nginx 경로 정보 추출
nginx_info=$(nginx -V 2>&1)

# prefix, conf-path, access log 추출
prefix=$(echo "$nginx_info" | grep -oP -- '--prefix=\K\S+')
NGINX_CONF=$(echo "$nginx_info" | grep -oP -- '--conf-path=\K\S+')
NGINX_LOG=$(echo "$nginx_info" | grep -oP -- '--http-log-path=\K\S+')
NGINX_D_CONF=""

# include 구문 전체 추출 (세미콜론 제외)
INCLUDE_LINES=$(grep -Po 'include\s+\K[^;]*\.conf[^;]*' "$NGINX_CONF")

if [ -z "$INCLUDE_LINES" ]; then
    echo "[-] nginx.conf에 Default 파일에 대한 include 구문이 없습니다."
fi

FOUND=0

while read -r LINE; do
	NGINX_CONF_DIR=$(dirname "$NGINX_CONF")
    DIR=$(dirname "$LINE")
    FILE=$(basename "$LINE")
	
    # 상대경로인 경우 nginx.conf 기준으로 해석
    if [[ "$DIR" = /* ]]; then
        DIR_ABS="$DIR"
    else
        DIR_ABS="$NGINX_CONF_DIR/$DIR"
    fi

    TARGET_PATH="$DIR_ABS/$FILE"

    echo "[+] 경로: $TARGET_PATH"

    # 와일드카드가 포함된 경우 (예: *.conf)
    if [[ "$FILE" == *"*"* ]]; then
        if compgen -G "$TARGET_PATH" > /dev/null; then
            for f in $TARGET_PATH; do
                echo "Default 파일이 존재합니다. $f"
				NGINX_D_CONF="$NGINX_D_CONF $f"
				FOUND=1
            done
        fi
    else
        # 단일 파일 검사
        if [ -f "$TARGET_PATH" ]; then
            echo "$TARGET_PATH"
			NGINX_D_CONF="$NGINX_D_CONF $f"
			FOUND=1
        fi
    fi
done <<< "$INCLUDE_LINES"

if [ $FOUND -eq 0 ]; then
    echo "[-] Default 파일이 존재하지 않습니다."
fi

echo "nginx.conf 경로:        $NGINX_CONF"
echo "default.conf 경로:      $NGINX_D_CONF"
echo "access log 경로:        $NGINX_LOG"
echo "$LINE2"
