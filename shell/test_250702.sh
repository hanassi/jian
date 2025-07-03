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

RESULT_XML="result.xml"
RESULT_TXT="result.txt"


############################
# 파일 생성 XML 함수
############################

# XML 시작
START_ITEM(){
	cat <<EOF >> $RESULT_XML
<?xml version="1.0" encoding="UTF-8" ?>
<lynsecure>
EOF
}

# XML 끝
END_ITEM(){
	cat <<EOF >> $RESULT_XML
</lynsecure>
EOF

}

# 화면 및 파일 출력
write_contents() {
	local num="$1"
	local title="$2"
	local result="$3"
	local contents="$4"
	local ref="$5"

	cat <<EOF >> $RESULT_XML
  <item>
	<item_num>${num}</item_num>
	<item_title>${title}</item_title>
	<item_result>${result}</item_result>
	<contents><![CDATA[${contents}]]></contents>
	<ref><![CDATA[${ref}]]></ref>
  </item>
EOF

	cat <<EOF >> $RESULT_TXT
=============================================
[${num}] ${title}
=============================================
결과 : ${result}
---------------------------------------------
현황
${contents}

---------------------------------------------
참고
${ref}

EOF

	echo " [+] [$num] $title		Done"
}

# 결과 누적
# contents=""
append_to_contents() {
	contents+=$'\n'"$1"$'\n'
}

# 파일 생성 TXT
echo_info(){
	local name=$1
	local command=$2
	local result=$3

	cat <<EOF >> $RESULT_TXT
=============================================
[*] ${name}
=============================================
${command}

${result}

EOF

}


############################
# 양호 취약 판단 함수
############################

owner_YN(){
	local current="$1"
	local allowed="$2"
	
	current=$(perm_check $current | awk '{print $2}')
	
	if [ "$current" = "$allowed" ]; then
		echo "Y"
	else
		echo "N"
	fi
}

perm_YN() {
	local current_file="$1"
	local allowed="$2"

	# 실제 퍼미션 숫자 추출
	local current
	current=$(perm_check "$current_file" | awk '{print $1}')

	# 잘못된 값이면 바로 N
	if ! [[ "$current" =~ ^[0-7]{3,4}$ && "$allowed" =~ ^[0-7]{3,4}$ ]]; then
		echo "N"
		return
	fi

	# 자리수 맞추기
	while [ "${#current}" -lt 4 ]; do current="0$current"; done
	while [ "${#allowed}" -lt 4 ]; do allowed="0$allowed"; done

	# Special bit + u/g/o 권한 분리
	local c_s=$((10#${current:0:1}))
	local c_u=$((10#${current:1:1}))
	local c_g=$((10#${current:2:1}))
	local c_o=$((10#${current:3:1}))

	local a_s=$((10#${allowed:0:1}))
	local a_u=$((10#${allowed:1:1}))
	local a_g=$((10#${allowed:2:1}))
	local a_o=$((10#${allowed:3:1}))

	# 비교 - 현재 권한이 허용 권한보다 크면 취약 (즉, 수치가 낮아야 안전)
	if [ "$c_s" -le "$a_s" ] && [ "$c_u" -le "$a_u" ] && [ "$c_g" -le "$a_g" ] && [ "$c_o" -le "$a_o" ]; then
		echo "Y"
	else
		echo "N"
	fi
}

multi_YN() {
	for result in "$@"; do
		if [ "$result" = "N" ]; then
			result="취약"
			return
		fi
	done
	result="양호"
}

# 문자 퍼미션 --> 숫자 변환
permstr_to_num() {
	local permstr="$1"
	local perms="${permstr:1:9}"
	local special=0
	local out=""

	# Special bits
	[[ "${permstr:3:1}" == "s" || "${permstr:3:1}" == "S" ]] && ((special+=4))  # SUID
	[[ "${permstr:6:1}" == "s" || "${permstr:6:1}" == "S" ]] && ((special+=2))  # SGID
	[[ "${permstr:9:1}" == "t" || "${permstr:9:1}" == "T" ]] && ((special+=1))  # Sticky

	for ((i=0; i<9; i+=3)); do
		local num=0
		[[ "${perms:$i:1}" == "r" ]] && ((num+=4))
		[[ "${perms:$i+1:1}" == "w" ]] && ((num+=2))
		[[ "${perms:$i+2:1}" =~ [xst] ]] && ((num+=1))
		out+="$num"
	done

	echo "${special}${out}"
}

# 퍼미션 및 소유자 정보 반환
perm_check() {
	local file="$1"

	if [ -e "$file" ]; then
		local info perms_str perms_num owner

		info=$(ls -l "$file" 2>/dev/null)
		perms_str=$(echo "$info" | awk '{print $1}')
		owner=$(echo "$info" | awk '{print $3}')
		perms_num=$(permstr_to_num "$perms_str")

		echo "$perms_num $owner"
	else
		echo "파일이 존재하지 않습니다."
	fi
}


############################
# 안전 함수
############################
# cat 안전 함수
cat() {
	local args=()
	local files=()

	# 인자를 분리: 옵션은 args, 파일은 files
	for arg in "$@"; do
		if [[ "$arg" == -* ]]; then
			args+=("$arg")
		else
			files+=("$arg")
		fi
	done

	for file in "${files[@]}"; do
		if [ -e "$file" ]; then
			command cat "${args[@]}" "$file"
		else
			echo "[-] 파일이 존재하지 않습니다: $file"
		fi
	done
}

# ls 안전 함수
ls() {
	local args=()
	local targets=()

	for arg in "$@"; do
		if [[ "$arg" == -* ]]; then
			args+=("$arg")
		else
			targets+=("$arg")
		fi
	done

	# 인자로 경로가 없을 경우 현재 디렉터리(.)를 대상으로 설정
	if [ ${#targets[@]} -eq 0 ]; then
		targets=(".")
	fi

	for target in "${targets[@]}"; do
		if [ -e "$target" ]; then
			command ls "${args[@]}" "$target"
		else
			echo "[-] 경로가 존재하지 않습니다: $target"
		fi
	done
}


# grep 안전 함수
grep() {
	local pattern
	local args=()
	local files=()
	local pattern_set=false

	for arg in "$@"; do
		if [[ "$arg" == -* ]]; then
			args+=("$arg")
		elif [ "$pattern_set" = false ]; then
			pattern="$arg"
			pattern_set=true
		else
			files+=("$arg")
		fi
	done

	for file in "${files[@]}"; do
		if [ -e "$file" ]; then
			command grep "${args[@]}" "$pattern" "$file"
		else
			echo "[-] 파일이 존재하지 않습니다: $file"
		fi
	done
}


############################
# 파일 정보 검색 함수
############################

ls_file() {
	local file="$1"
	local perms_num owner
	if [ -e "$file" ]; then
		echo "[파일 정보] $file"
		ls -al "$file" 2>/dev/null
		perm_check "$file" 2>/dev/null
	else
		echo "파일이 존재하지 않습니다."
	fi
}

############################
# 문자열 검색 함수
############################

grep_file() {
	local file="$1"
	local string="$2"
	if [ -e "$file" ]; then
		echo "[검색 결과] $file - $string"
		grep -- "$string" "$file" 2>/dev/null
	else
		echo "파일이 존재하지 않습니다."
	fi
}


############################
# 프로세스 확인 함수
############################

ps_ef(){
	local command="$1"
	result=$(ps -ef | grep $command | grep -v 'grep' | wc -l)
	if [ $result -ne 0 ]; then
		ps -ef | grep "$command" | grep -v 'grep'
	else
		echo "$command 프로세스가 비실행 중 입니다."
	fi
}


############################################################
# 항목 별 함수
############################################################
U-01() {
	local num="U-01"
	local title="/etc/passwd 파일 확인"
	local result="확인필요"
	local contents ref

	cmd1=$(ls_file /etc/passwd)
	cmd2=$(grep_file /etc/passwd test)
	cmd3=$(ps_ef "telnet")

	append_to_contents "$cmd1"
	append_to_contents "$cmd2"
	append_to_contents "$cmd3"
	
	ref=$(cat <<EOF
[참고 - 진단기준, 결과 값 출력]
 양호 : 원격 터미널 서비스를 사용하지 않거나, 사용 시 root 직접 접속을 차단한 경우 
 취약 : 원격 터미널 서비스 사용 시 root 직접 접속을 허용한 경우 
 취약 1. : Telnet 사용 시, /etc/default/login 파일에 CONSOLE=/dev/console이 없거나 주석처리 되어있을 경우 
 취약 2. : SSH 사용 시, /etc/ssh/sshd_config 파일에 PermitRootLogin yes로 설정되어 있을 경우 
******* 참고 사항 *******
 1. 'auth [user_unknown=ignore success=ok ignore=ignore default=bad] pam_securetty.so' 해당 설정 양호로 진단 (주석처리 주의)
EOF
)
	write_contents "$num" "$title" "$result" "$contents" "$ref"
}


U-02() {
	local num="U-02"
	local title="/usr/bin/gpasswd 권한 확인"
	local result="확인필요"
	local contents ref
	
	cmd1=$(ls_file /usr/bin/gpasswd)
	cmd2=$(owner_YN /usr/bin/gpasswd root)
	cmd3=$(perm_YN /usr/bin/gpasswd 0755)
	cmd4=$(perm_YN /usr/bin/gpasswd 4777)

	append_to_contents "$cmd1"
	multi_YN "$cmd2" "$cmd3" "$cmd4"
	
	write_contents "$num" "$title" "$result" "$contents" "$ref"
}


U-03() {
	local num="U-03"
	local title="/etc/test 파일 확인"
	local result="확인필요"
	local contents ref
	
	cmd1=$(ls_file /etc/test)
	cmd2=$(grep_file /etc/test test)

	append_to_contents "$cmd1"
	append_to_contents "$cmd2"
	
	write_contents "$num" "$title" "$result" "$contents" "$ref"
}













U-00(){
	local num=""
	local title=""
	local result="확인필요"
	local contents ref
	
	cmd1=$(perm_check "/etc/passwd")
	cmd2=$(perm_check_dir "/tmp")
	
	append_to_contents "$cmd1"
	append_to_contents "$cmd2"

	write_contents "$num" "$title" "$result" "$contents" "$ref"
}







############################################################
# 함수 실행
############################################################
START_ITEM


U-01
U-02
U-03








END_ITEM

############################################################
# 서버 기본 정보 출력
############################################################

KERNEL=`uname -a`
PS=`ps -ef`
UE=`env`
if command -v ip &>/dev/null; then
	IPCHECK=`ip addr show`
elif command -v ifconfig &>/dev/null; then
	IPCHECK=`ifconfig`
else
	IPCHECK="IP 확인 명령어가 없습니다."
fi
if command -v netstat &>/dev/null; then
	NETSTAT=`netstat -an | egrep -i "LISTEN|ESTABLISHED"`
	NETSTATR=`netstat -rn`
elif command -v ss &>/dev/null; then
	NETSTAT=`ss -tuln`
elif command -v ip &>/dev/null; then
	NETSTATR=`ip route`
else
	IPCHECK="네트워크 확인 명령어가 없습니다."
fi

echo_info "Kernel Information" "uname -a" "$KERNEL"
echo_info "IP Information" "ifconfig, ip addr show" "$IPCHECK"
echo_info "Network Status" "netstat -an, ss -tuln" "$NETSTAT"
echo_info "Routing Information" "netstat -rn, ip route" "$NETSTATR"
echo_info "Process Status" "ps -ef" "$PS"
echo_info "User Env" "env" "$UE"
