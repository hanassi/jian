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
# ctx.awk 함수
#######################
run_ctx_awk() {
  local PAT="$1"
  local B="${2:-0}"
  local A="${3:-0}"
  local FILE="$4"

  awk -v PAT="$PAT" -v B="$B" -v A="$A" '
  BEGIN {
      PAT = tolower(PAT)
  }
  {
      buffer[NR] = $0
      if (index(tolower($0), PAT) > 0) {
          start = NR - B
          end = NR + A
          for (i = (start > 1 ? start : 1); i <= end; i++) {
              if (i in buffer) print buffer[i]
          }
      }
  }
  ' "$FILE"
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
elif command -v ip >/dev/null 2>&1; then
  ip addr show | grep 'inet ' | awk '{print $2}' | cut -d/ -f1 | grep -v '^127'
elif command -v ifconfig >/dev/null 2>&1; then
  ifconfig | grep 'inet ' | grep -v '127.0.0.1' | awk '{print $2}'
else
  echo "네트워크 정보 확인 불가"
fi

HOSTNAME=$(cat /etc/hostname 2>/dev/null || echo "unknown")

CREATE_FILE="[Lyn_secure]Spring_boot_Tomcat_${HOSTNAME}_${OS}_${IP}.txt"


#######################
# (화면출력) 헤더
#######################
echo "$LINE"
center ""
center "Security Inspection of Spring Boot Tomcat (Unix ver.)"
center "Version : 1.4"
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
print_title "Spring Boot Tomcat Security Check"
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
if command -v ifconfig >/dev/null 2>&1; then
    ifconfig -a >> "$CREATE_FILE"
else
    ip addr show >> "$CREATE_FILE"
fi
echo "" >> $CREATE_FILE
echo "[Network Status]" >> $CREATE_FILE
if command -v netstat >/dev/null 2>&1; then
    netstat -an | egrep -i "LISTEN|ESTABLISHED" >> "$CREATE_FILE"
elif command -v ss >/dev/null 2>&1; then
    ss -ant | egrep -i "LISTEN|ESTABLISHED" >> "$CREATE_FILE"
else
    echo "네트워크 상태 확인 명령(netstat/ss)을 찾을 수 없습니다." >> "$CREATE_FILE"
fi
echo "" >> $CREATE_FILE
echo "[Routing Information]" >> $CREATE_FILE
if command -v netstat >/dev/null 2>&1; then
    netstat -rn >> "$CREATE_FILE"
elif command -v ip >/dev/null 2>&1; then
    ip route show >> "$CREATE_FILE"
else
    echo "라우팅 테이블 확인 명령(netstat/ip)을 찾을 수 없습니다." >> "$CREATE_FILE"
fi
echo "" >> $CREATE_FILE
echo "[Process Status]" >> $CREATE_FILE
if command -v ps > /dev/null 2>&1; then
    ps -ef >> $CREATE_FILE
else
    top -b -n 1 >> $CREATE_FILE
fi
echo "" >> $CREATE_FILE
echo "[User Environment]" >> $CREATE_FILE
env >> $CREATE_FILE
echo "" >> $CREATE_FILE

print_title "System Information Query End"
print_title "Security Check START"



center_line "Spring Boot 프로젝트 탐색 시작"
center_line "Spring Boot 프로젝트 탐색 시작" >> $CREATE_FILE 2>&1


#FOUND_PATH=$(find . -type f \( -name "application.yml" -o -name "application.properties" \) -path "*/src/main/resources/*" | head -n 1)

#FOUND_PATH=$(find / \
#  \( -path /proc -o -path /sys -o -path /dev -o -path /run -o -path /var/run \) -prune -o \
#  -type f \( -name "application.yml" -o -name "application.yaml" -o -name "application.properties" \
#           -o -name "pom.xml" -o -name "build.gradle" \
#           -o -name "SecurityConfig.java" -o -name "WebMvcConfig.java" -o -name "CustomErrorController.java" \) \
#  -print)


FILES_TO_FIND=(
  "application.yml"
  "application.yaml"
  "application.properties"
  "pom.xml"
  "build.gradle"
  "SecurityConfig.java"
  "WebMvcConfig.java"
  "CustomErrorController.java"
)

# find 명령어 조건 조합
find_conditions=()
for f in "${FILES_TO_FIND[@]}"; do
  find_conditions+=( -name "$f" -o )
done
# 마지막 -o 제거
unset 'find_conditions[${#find_conditions[@]}-1]'

# 1) find로 루트부터 파일 찾기 (특정 경로 제외)
FOUND_PATH=$(find / \
  \( -path /proc -o -path /sys -o -path /dev -o -path /run -o -path /var/run \) -prune -o \
  -type f \( "${find_conditions[@]}" \) -print 2>/dev/null)

# 2) 빈 값이면 JAR 내부 탐색 수행
if [ -z "$FOUND_PATH" ]; then
  echo "외부 파일 못 찾음. JAR 내부 탐색 시작..."

  # JAR 파일 경로를 검색 (예: /app 혹은 /target 등 적절히 변경)
  JAR_FILES=$(find / -type f -name "*.jar" 2>/dev/null)

  jar_found_files=()
  for jar in $JAR_FILES; do
    for target_file in "${FILES_TO_FIND[@]}"; do
      # jar tf 로 파일 목록을 확인 후 해당 파일명이 있는지 grep
      if jar tf "$jar" 2>/dev/null | grep -q "^$target_file$"; then
        jar_found_files+=("$jar:$target_file")
      fi
    done
  done

  if [ ${#jar_found_files[@]} -gt 0 ]; then
    FOUND_PATH=$(printf "%s\n" "${jar_found_files[@]}")
  else
    FOUND_PATH=""
  fi
fi


if [ -z "$FOUND_PATH" ]; then
	echo "[!] application.yml 또는 application.properties 파일을 찾을 수 없습니다."
	echo "[!] application.yml 또는 application.properties 파일을 찾을 수 없습니다." >> $CREATE_FILE 2>&1
#	exit 1
fi

# 빌드 파일 경로만 추출
BUILD_FILE_PATHS=$(echo "$FOUND_PATH" | grep -E '/(pom\.xml|build\.gradle)$')

# 디버깅용 출력 (원하면 주석 처리)
echo "[+] 빌드 파일 목록:"
echo "$BUILD_FILE_PATHS"

# 임시 디렉토리 생성
mkdir -p Lyn_tmp

# 프로젝트별 파일 출력
echo "[+] 프로젝트 설정 파일 목록 :"
while read -r file; do
	file_name=$(basename $file)
	if [ -f "$file" ]; then
		echo "$file"
		echo "[+] $file" >> $CREATE_FILE 2>&1
		echo "[+] $file" >> "./Lyn_tmp/$file_name" 2>&1
		cat "$file" >> "./Lyn_tmp/$file_name" 2>&1
	else
		echo "[!] $file 파일 없음"
		echo "[!] $file 파일 없음" >> $CREATE_FILE 2>&1
	fi
	echo " " >> $CREATE_FILE 2>&1
done <<< "$FOUND_PATH"


center_line "설정 파일 출력 완료"
echo "$LINE1"
center_line "설정 파일 출력 완료" >> $CREATE_FILE 2>&1
echo "$LINE1" >> $CREATE_FILE 2>&1




#######################
# 점검
#######################

WAS_01 (){
echo "$LINE2" >> $CREATE_FILE 2>&1
echo "[WAS-01] 관리자 콘솔 관리" >> $CREATE_FILE 2>&1
echo "$LINE2" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

if [ -f "./Lyn_tmp/SecurityConfig.java" ]; then
	echo "[+] SecurityConfig.java 설정 확인" >> $CREATE_FILE 2>&1
	run_ctx_awk "antMatchers" 4 4 "./Lyn_tmp/SecurityConfig.java" | grep -v "#" >> $CREATE_FILE 2>&1
else
	echo "[!] SecurityConfig.java 파일 없음" >> $CREATE_FILE 2>&1
fi
echo "" >> $CREATE_FILE 2>&1

if [ -f "./Lyn_tmp/application.properties" ]; then
	echo "[+] application.properties 설정 확인" >> $CREATE_FILE 2>&1
	run_ctx_awk "management.server.port" 4 4 "./Lyn_tmp/application.properties" | grep -v "#" >> $CREATE_FILE 2>&1
else
	echo "[!] application.properties 파일 없음" >> $CREATE_FILE 2>&1
fi
echo "" >> $CREATE_FILE 2>&1

if [ -f "./Lyn_tmp/application_yml" -o -f "./Lyn_tmp/application_yaml" ]; then
	echo "[+] application_yml 설정 확인" >> $CREATE_FILE 2>&1
	run_ctx_awk "management" 4 4 "./Lyn_tmp/application_yml" | grep -v "#" >> $CREATE_FILE 2>&1
	run_ctx_awk "management" 4 4 "./Lyn_tmp/application_yaml" | grep -v "#" >> $CREATE_FILE 2>&1
else
	echo "[!] application_yml 파일 없음" >> $CREATE_FILE 2>&1
fi
echo "" >> $CREATE_FILE 2>&1


echo "$LINE2" >> $CREATE_FILE 2>&1
echo "[참고 사항]
※ Unix 및 Windows 공통
(관리자 페이지 접근 제어 확인)
Spring Security 구성 클래스에서 IP 접근제어 확인
※ Unix 및 Windows 공통
(관리자 페이지 포트 확인)
application.properties 파일을 사용하는경우 설정 확인
※ Unix 및 Windows 공통
(관리자 페이지 포트 확인)
application.yml 파일을 사용하는 경우 설정 확인
" >> $CREATE_FILE 2>&1

echo "[진단 기준]
※ Unix 및 Windows 공통
양호: 유추하기 어려운 포트로 변경하여 사용하고 관리자 페이지 접근제한 하는 경우
취약: 유추하기 쉬운 포트를 사용하고 관리자 페이지 접근제한 하지 않는 경우
" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
}


WAS_02 (){
echo "$LINE2" >> $CREATE_FILE 2>&1
echo "[WAS-02] 관리자 default 계정명 변경" >> $CREATE_FILE 2>&1
echo "$LINE2" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

if [ -f "./Lyn_tmp/SecurityConfig.java" ]; then
	echo "[+] SecurityConfig.java 설정 확인" >> $CREATE_FILE 2>&1
	run_ctx_awk "inMemoryAuthentication" 4 4 "./Lyn_tmp/SecurityConfig.java" | grep -v "#" >> $CREATE_FILE 2>&1
else
	echo "[!] SecurityConfig.java 파일 없음" >> $CREATE_FILE 2>&1
fi
echo "" >> $CREATE_FILE 2>&1

echo "$LINE2" >> $CREATE_FILE 2>&1
echo "[참고 사항]
※ Unix 및 Windows 공통
Spring Security 구성 클래스에서 계정명 확인
" >> $CREATE_FILE 2>&1

echo "[진단 기준]
※ Unix 및 Windows 공통
양호: 기본 계정을 사용하지 않거나 유추하기 어려운 계정을 사용하는 경우 
취약: 기본 계정을 사용하거나 유추하기 쉬운 계정을 사용하는 경우
" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
}


WAS_03 (){
echo "$LINE2" >> $CREATE_FILE 2>&1
echo "[WAS-03] 관리자 패스워드 관리" >> $CREATE_FILE 2>&1
echo "$LINE2" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

if [ -f "./Lyn_tmp/SecurityConfig.java" ]; then
	echo "[+] SecurityConfig.java 설정 확인" >> $CREATE_FILE 2>&1
	run_ctx_awk "inMemoryAuthentication" 4 4 "./Lyn_tmp/SecurityConfig.java" | grep -v "#" >> $CREATE_FILE 2>&1
else
	echo "[!] SecurityConfig.java 파일 없음" >> $CREATE_FILE 2>&1
fi
echo "" >> $CREATE_FILE 2>&1

echo "$LINE2" >> $CREATE_FILE 2>&1
echo "[참고 사항]
※ Unix 및 Windows 공통
Spring Security 구성 클래스에서 패스워드 확인
" >> $CREATE_FILE 2>&1

echo "[진단 기준]
※ Unix 및 Windows 공통
양호: 알파벳/숫자/특수문자 혼용 8자 이상, 동일문자 연속 4회 이상 사용 금지, 계정명과 동일하지 않고 유추하기 힘든 패스워드로 설정되어 있는 경우
취약: 패스워드 길이가 8자 이하 이며, 계정명과 동일하거나 유추하기 쉬운 패스워드 설정이 되어 있는 경우 
" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
}


WAS_04 (){
echo "$LINE2" >> $CREATE_FILE 2>&1
echo "[WAS-04] 패스워드 파일 관리" >> $CREATE_FILE 2>&1
echo "$LINE2" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

if [ -f "./Lyn_tmp/application.properties" ]; then
	echo "[+] application.properties 설정 확인" >> $CREATE_FILE 2>&1
	run_ctx_awk "spring.security.user" 4 4 "./Lyn_tmp/application.properties" | grep -v "#" >> $CREATE_FILE 2>&1
else
	echo "[!] application.properties 파일 없음" >> $CREATE_FILE 2>&1
fi
echo "" >> $CREATE_FILE 2>&1

echo "$LINE2" >> $CREATE_FILE 2>&1
echo "[참고 사항]
※ Unix 및 Windows 공통
Spring Security 구성 클래스를 사용하는경우 N/A
※ Unix 의 경우
권한 750(drwxr-x---) , 640(rw-r-----)
========================================================
※ Windows 의 경우
 F : 모든권한 , RX : 읽기 및 실행권한 , W : 쓰기권한
========================================================
※ Unix 및 Windows 공통
application.properties 파일을 사용하는 경우 계정확인
" >> $CREATE_FILE 2>&1


echo "[진단 기준]
※ Unix 의 경우
양호: 계정정보 파일이 전용계정 소유이고 각각 750/640 이하의 권한일 경우
취약: 계정정보 파일이 전용계정 소유가 아니거나 각각 750/640 초과의 권한일 경우
========================================================
※ Windows 의 경우
양호: 계정정보 파일 권한에 Everyone이 존재하거나 User의 쓰기 권한이 없을 경우
취약: 계정정보 파일 권한에 Everyone이 존재하거나 User의 쓰기 권한이 존재할 경우
" >> $CREATE_FILE 2>&1

echo " " >> $CREATE_FILE 2>&1
}

WAS_05 (){
echo "$LINE2" >> $CREATE_FILE 2>&1
echo "[WAS-05] 패스워드 파일 암호화" >> $CREATE_FILE 2>&1
echo "$LINE2" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

if [ -f "./Lyn_tmp/SecurityConfig.java" ]; then
	echo "[+] SecurityConfig.java 설정 확인" >> $CREATE_FILE 2>&1
	run_ctx_awk "inMemoryAuthentication" 4 4 "./Lyn_tmp/SecurityConfig.java" | grep -v "#" >> $CREATE_FILE 2>&1
else
	echo "[!] SecurityConfig.java 파일 없음" >> $CREATE_FILE 2>&1
fi
echo "" >> $CREATE_FILE 2>&1

if [ -f "./Lyn_tmp/application.properties" ]; then
	echo "[+] application.properties 설정 확인" >> $CREATE_FILE 2>&1
	run_ctx_awk "spring.security.user" 4 4 "./Lyn_tmp/application.properties" | grep -v "#" >> $CREATE_FILE 2>&1
else
	echo "[!] application.properties 파일 없음" >> $CREATE_FILE 2>&1
fi
echo "" >> $CREATE_FILE 2>&1

echo "$LINE2" >> $CREATE_FILE 2>&1
echo "[참고 사항]
※ Unix 및 Windows 공통
Spring Security 구성 클래스를 사용하는 경우 패스워드 확인

{bcrypt} 는 BCrypt 해싱 알고리즘을 사용하고 있음을 의미 
{noop} 은 암호화되지 않았음을 의미
※ Unix 및 Windows 공통
application.properties 파일을 사용하는 경우 패스워드 확인

" >> $CREATE_FILE 2>&1


echo "[진단 기준]
※ Unix 및 Windows 공통
양호: 패스워드 파일에 패스워드가 암호화되어 저장되어 있을 경우
취약: 패스워드 파일에 패스워드가 평문으로 저장되어 있을 경우
" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
}


WAS_06 (){
echo "$LINE2" >> $CREATE_FILE 2>&1
echo "[WAS-06] 디렉터리 쓰기 권한 관리" >> $CREATE_FILE 2>&1
echo "$LINE2" >> $CREATE_FILE 2>&1

while read -r path; do
	PROJECT_PATH=$(dirname "$path")
	if [ -d "$PROJECT_PATH" ]; then
		echo "[+] 프로젝트 경로: $PROJECT_PATH" >> $CREATE_FILE 2>&1
		ls -alR "$PROJECT_PATH" >> $CREATE_FILE 2>&1
	else
		echo "[!] 프로젝트 경로 없음: $PROJECT_PATH" >> $CREATE_FILE 2>&1
	fi

	echo "" >> $CREATE_FILE 2>&1
done <<< "$BUILD_FILE_PATHS"

echo "$LINE2" >> $CREATE_FILE 2>&1
echo "[참고 사항]
※ Unix 의 경우
권한 750(drwxr-x---) , 640(rw-r-----)
" >> $CREATE_FILE 2>&1

echo "[진단 기준]
※ Unix 의 경우
양호: 루트 디렉터리가 전용계정 소유이고 각각 750/640 이하의 권한일 경우 
취약: 루트 디렉터리가 전용계정 소유가 아니거나 각각 750/640 초과의 권한일 경우
========================================================
※ Windows 의 경우
양호: 루트 디렉터리 권한에 Everyone이 존재하지 않거나 User의 쓰기 권한이 없을 경우 
취약: 루트 디렉터리 권한에 Everyone이 존재하거나 User의 쓰기 권한이 존재할 경우
" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
}


WAS_07 (){
echo "$LINE2" >> $CREATE_FILE 2>&1
echo "[WAS-07] 설정 파일 권한 관리" >> $CREATE_FILE 2>&1
echo "$LINE2" >> $CREATE_FILE 2>&1

while read -r path; do
	PROJECT_PATH=$(dirname "$path")
	if [ -d "$PROJECT_PATH" ]; then
		echo "[+] 프로젝트 경로: $PROJECT_PATH" >> $CREATE_FILE 2>&1
		ls -al "$PROJECT_PATH/src/main/resources" >> $CREATE_FILE 2>&1
	else
		echo "[!] 프로젝트 경로 없음: $PROJECT_PATH" >> $CREATE_FILE 2>&1
	fi

	echo "" >> $CREATE_FILE 2>&1
done <<< "$BUILD_FILE_PATHS"


echo "$LINE2" >> $CREATE_FILE 2>&1
echo "[참고 사항]
※ Unix 의 경우
권한 750(drwxr-x---) , 640(rw-r-----)
========================================================
※ Windows 의 경우
 F : 모든권한 , RX : 읽기 및 실행권한 , W : 쓰기권한
========================================================
※ Unix 및 Windows 공통
주요설정파일 : application.properties , application.yml
" >> $CREATE_FILE 2>&1

echo "[진단 기준]
※ Unix 의 경우
양호: 설정 파일이 전용계정 소유이고 각각 750/640 이하의 권한일 경우
취약: 설정 파일이 전용계정 소유가 아니거나 각각 750/640 초과의 권한일 경우
" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
}


WAS_08 (){
echo "$LINE2" >> $CREATE_FILE 2>&1
echo "[WAS-08] 로그 디렉터리/파일 권한 관리" >> $CREATE_FILE 2>&1
echo "$LINE2" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

if [ -f "./Lyn_tmp/application.properties" ]; then
	echo "[+] application.properties 설정 확인" >> $CREATE_FILE 2>&1
	run_ctx_awk "logging.config" 4 4 "./Lyn_tmp/application.properties" | grep -v "#" >> $CREATE_FILE 2>&1
else
	echo "[!] application.properties 파일 없음" >> $CREATE_FILE 2>&1
fi
echo "" >> $CREATE_FILE 2>&1

if [ -f "./Lyn_tmp/application_yml" -o -f "./Lyn_tmp/application_yaml" ]; then
	echo "[+] application_yml 설정 확인" >> $CREATE_FILE 2>&1
	run_ctx_awk "logging.config" 4 4 "./Lyn_tmp/application_yml" | grep -v "#" >> $CREATE_FILE 2>&1
	run_ctx_awk "logging.config" 4 4 "./Lyn_tmp/application_yaml" | grep -v "#" >> $CREATE_FILE 2>&1
else
	echo "[!] application_yml 파일 없음" >> $CREATE_FILE 2>&1
fi
echo "" >> $CREATE_FILE 2>&1

echo "$LINE2" >> $CREATE_FILE 2>&1
echo "[참고 사항]
※ Unix 의 경우
권한 750(drwxr-x---) , 640(rw-r-----)
========================================================
※ Windows 의 경우
 F : 모든권한 , RX : 읽기 및 실행권한 , W : 쓰기권한
※ Unix 및 Windows 공통
(로그 설정 확인)
logback.xml 또는 logback-spring.xml 에서 로그 설정 확인 
오픈소스로 log4j2 를 사용하는 경우가 많으므로 log4j2.xml 에서 로그 설정 확인

" >> $CREATE_FILE 2>&1


echo "[진단 기준]
※ Unix 의 경우
양호: 로그 디렉터리가 전용계정 소유이고 각각 750/640 이하의 권한일 경우 
취약: 로그 디렉터리가 전용계정 소유가 아니거나 각각 750/640 초과의 권한일 경우
" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
}


WAS_09 (){
echo "$LINE2" >> $CREATE_FILE 2>&1
echo "[WAS-09] 디렉터리 검색 기능 제거" >> $CREATE_FILE 2>&1
echo "$LINE2" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

if [ -f "./Lyn_tmp/WebMvcConfig.java" ]; then
	echo "[+] WebMvcConfig.java 설정 확인" >> $CREATE_FILE 2>&1
	run_ctx_awk "addResourceLocations" 4 4 "./Lyn_tmp/WebMvcConfig.java" | grep -v "#" >> $CREATE_FILE 2>&1
else
	echo "[!] WebMvcConfig.java 파일 없음" >> $CREATE_FILE 2>&1
fi
echo "" >> $CREATE_FILE 2>&1

echo "$LINE2" >> $CREATE_FILE 2>&1
echo "[참고 사항]
※ Unix 및 Windows 공통
addResourceLocations() 메서드를 사용하여 위치를 등록하고 
addResourceHandler() 메서드를 사용하여 URL 패턴을 등록하므로 해당 메서드 확인 
" >> $CREATE_FILE 2>&1


echo "[진단 기준]
※ Unix 및 Windows 공통
양호: 디렉터리 설정 값이 없거나 false인 경우
취약: 디렉터리 설정 값이 true인 경우
" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
}


WAS_10 (){
echo "$LINE2" >> $CREATE_FILE 2>&1
echo "[WAS-10] 에러 메시지 관리" >> $CREATE_FILE 2>&1
echo "$LINE2" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

if [ -f "./Lyn_tmp/application.properties" ]; then
	echo "[+] application.properties 설정 확인" >> $CREATE_FILE 2>&1
	run_ctx_awk "server.error.path" 4 4 "./Lyn_tmp/application.properties" | grep -v "#" >> $CREATE_FILE 2>&1
else
	echo "[!] application.properties 파일 없음" >> $CREATE_FILE 2>&1
fi
echo "" >> $CREATE_FILE 2>&1

if [ -f "./Lyn_tmp/CustomErrorController.java" ]; then
	echo "[+] CustomErrorController.java 설정 확인" >> $CREATE_FILE 2>&1
	run_ctx_awk "handleError" 4 4 "./Lyn_tmp/CustomErrorController.java" | grep -v "#" >> $CREATE_FILE 2>&1
else
	echo "[!] CustomErrorController.java 파일 없음" >> $CREATE_FILE 2>&1
fi
echo "" >> $CREATE_FILE 2>&1

echo "$LINE2" >> $CREATE_FILE 2>&1
echo "[참고 사항]
※ Unix 및 Windows 공통
ErrorController 클래스에서 handleError() 메서드로 에러페이지를 지정하고
application.properties 또는 application.yml 파일에서 server.error.path 속성을 설정하므로 
해당 클래스와 파일에서 확인
" >> $CREATE_FILE 2>&1


echo "[진단 기준]
※ Unix 및 Windows 공통
양호: 지정된 에러 페이지 설정이 되어있는 경우 
취약: 지정된 에러 페이지 설정이 되어있지 않은 경우
" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
}


WAS_11 (){
echo "$LINE2" >> $CREATE_FILE 2>&1
echo "[WAS-11] 응답 메시지 관리" >> $CREATE_FILE 2>&1
echo "$LINE2" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

if [ -f "./Lyn_tmp/application.properties" ]; then
	echo "[+] application.properties 설정 확인" >> $CREATE_FILE 2>&1
	run_ctx_awk "server.tomcat.server-header" 4 4 "./Lyn_tmp/application.properties" | grep -v "#" >> $CREATE_FILE 2>&1
else
	echo "[!] application.properties 파일 없음" >> $CREATE_FILE 2>&1
fi
echo "" >> $CREATE_FILE 2>&1

echo "$LINE2" >> $CREATE_FILE 2>&1
echo "[참고 사항]
※ Unix 및 Windows 공통
application.properties 파일에서 server.tomcat.server-header 확인
" >> $CREATE_FILE 2>&1


echo "[진단 기준]
※ Unix 및 Windows 공통
양호: 응답 메시지 설정이 안전하게 되어있는 경우 
취약: 응답 메시지 설정이 안전하게 되어있지 않는 경우
" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
}


WAS_12 (){
echo "$LINE2" >> $CREATE_FILE 2>&1
echo "[WAS-12] 세션 타임아웃 설정" >> $CREATE_FILE 2>&1
echo "$LINE2" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

if [ -f "./Lyn_tmp/application.properties" ]; then
	echo "[+] application.properties 설정 확인" >> $CREATE_FILE 2>&1
	run_ctx_awk "server.servlet.session.timeout" 4 4 "./Lyn_tmp/application.properties" | grep -v "#" >> $CREATE_FILE 2>&1
else
	echo "[!] application.properties 파일 없음" >> $CREATE_FILE 2>&1
fi
echo "" >> $CREATE_FILE 2>&1

echo "$LINE2" >> $CREATE_FILE 2>&1
echo "[참고 사항]
※ Unix 및 Windows 공통
application.properties 파일에서 server.servlet.session.timeout 확인
" >> $CREATE_FILE 2>&1

echo "[진단 기준]
※ Unix 및 Windows 공통
양호: Session Timeout 설정이 30 미만인 경우 
취약: Session Timeout 설정이 30 이상인 경우
" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
}


WAS_13 (){
echo "$LINE2" >> $CREATE_FILE 2>&1
echo "[WAS-13] sample 디렉터리 삭제" >> $CREATE_FILE 2>&1
echo "$LINE2" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

while read -r path; do
	PROJECT_PATH=$(dirname "$path")
	if [ -d "$PROJECT_PATH" ]; then
		echo "[+] 프로젝트 경로: $PROJECT_PATH" >> $CREATE_FILE 2>&1

		# 찾고자 하는 디렉토리 이름 배열
		for sample_dir in examples sample webdav docs; do
			match_dirs=$(find "$PROJECT_PATH" -type d -name "$sample_dir" 2>/dev/null)

			if [ -n "$match_dirs" ]; then
				while read -r dir; do
					ls -ld "$dir" >> $CREATE_FILE 2>&1
				done <<< "$match_dirs"
			else
				echo "[!] $sample_dir 디렉토리 없음" >> $CREATE_FILE 2>&1
			fi
		done
	else
		echo "[!] 프로젝트 경로 없음: $PROJECT_PATH" >> $CREATE_FILE 2>&1
	fi

	echo "" >> $CREATE_FILE 2>&1
done <<< "$BUILD_FILE_PATHS"


echo "$LINE2" >> $CREATE_FILE 2>&1
echo "[참고 사항]
※ Unix 및 Windows 공통
불필요한 디렉터리 : examples , sample , webdav , docs 등 
" >> $CREATE_FILE 2>&1

echo "[진단 기준]
※ Unix 및 Windows 공통
양호: Sample 설치 경로가 삭제된 경우 
취약: Sample 설치 경로가 존재하는 경우 
" >> $CREATE_FILE 2>&1

echo " " >> $CREATE_FILE 2>&1
}


WAS_14 (){
echo "$LINE2" >> $CREATE_FILE 2>&1
echo "[WAS-14] 프로세스 관리 기능 삭제" >> $CREATE_FILE 2>&1
echo "$LINE2" >> $CREATE_FILE 2>&1

echo "[진단 기준]N/A" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
}


WAS_15 (){
echo "$LINE2" >> $CREATE_FILE 2>&1
echo "[WAS-15] 보안 패치" >> $CREATE_FILE 2>&1
echo "$LINE2" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1

if [ -f "./Lyn_tmp/build.gradle" ]; then
	echo "[+] build.gradle 설정 확인" >> $CREATE_FILE 2>&1
	cat "./Lyn_tmp/build.gradle" | grep -v "#" >> $CREATE_FILE 2>&1
else
	echo "[!] build.gradle 파일 없음" >> $CREATE_FILE 2>&1
fi
echo "" >> $CREATE_FILE 2>&1

if [ -f "./Lyn_tmp/pom.xml" ]; then
	echo "[+] pom.xml 설정 확인" >> $CREATE_FILE 2>&1
	cat "./Lyn_tmp/pom.xml" | grep -v "#" >> $CREATE_FILE 2>&1
else
	echo "[!] pom.xml 파일 없음" >> $CREATE_FILE 2>&1
fi
echo "" >> $CREATE_FILE 2>&1

echo "$LINE2" >> $CREATE_FILE 2>&1
echo "[참고 사항]
※ Unix 및 Windows 공통
pom.xml 또는 build.gradle 파일에서 버전 확인
" >> $CREATE_FILE 2>&1

echo "[진단 기준]
※ Unix 및 Windows 공통
양호: 버전 및 패치 업그레이드가 되어 있는 경우 
취약: 버전 및 패치 업그레이드를 하지 않는 경우 
" >> $CREATE_FILE 2>&1
echo " " >> $CREATE_FILE 2>&1
}





WAS_01
WAS_02
WAS_03
WAS_04
WAS_05
WAS_06
WAS_07
WAS_08
WAS_09
WAS_10
WAS_11
WAS_12
WAS_13
WAS_14
WAS_15



#######################
# 마무리 출력
#######################
echo "Spring Boot Tomcat Security Check END"
echo "$LINE1"
echo "☞ 스크립트 작업이 완료되었습니다."
echo ""
echo "☞ 스크립트 결과 파일을 보안담당자에게 전달 바랍니다."
echo "☞ 스크립트 관련 오류 및 문의사항은 린시큐어 직원에게 부탁드립니다."
echo "☞ 감사합니다."
echo "$LINE1"
echo ""
echo "$LINE2"

tar -cvf $CREATE_FILE.tar $CREATE_FILE ./Lyn_tmp/ > /dev/null 2>&1
rm -rf $CREATE_FILE
rm -rf ./Lyn_tmp/