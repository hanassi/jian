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

# default.conf 경로 유추 (nginx.conf 안에서 include 되는 경우가 많음)
NGINX_D_CONF=$(grep -Po 'include\s+\K.*default\.conf' "$NGINX_CONF" 2>/dev/null | head -n 1)
files=$(grep include /etc/nginx/nginx.conf | grep '\.conf' | awk '{print $2}' | tr -d ';')

###### 여기 수정해야함 *.conf
echo "$file" | while read -r "$file" ; do
	if [ -f "$file" ] ; then
		NGINX_D_CONF="$file"
	else
		echo "Nginx Default 파일이 없습니다." >> $CREATE_FILE 2>&1
	fi
done

# 출력
echo "nginx.conf 경로:        $NGINX_CONF"
echo "default.conf 경로:      $NGINX_D_CONF"
echo "access log 경로:        $NGINX_LOG"



#if [ `find / -xdev -type d -name "nginx" | wc -l` -gt 2 ]
#	then
#		NGINX_HOME=`find / -xdev -name "nginx.conf" | grep /etc |rev |cut -d '/' -f2- |rev`
#		NGINX_CONF=$NGINX_HOME/nginx.conf
#		NGINX_D_CONF=$NGINX_HOME/conf.d/default.conf
#		NGINX_LOG=`find / -xdev -name "access.log" | grep /nginx |rev |cut -d '/' -f2- |rev`
#		if [ `cat $NGINX_D_CONF | grep -i root | grep -v "#" | head -1 | wc -l` -eq 0 ]
#		then
#				Nginx_ROOT=`cat $NGINX_CONF | grep -i root | grep -v "#" | head -1 |rev |cut -d' ' -f1 |rev |cut -d';' -f1`
#		else
#				Nginx_ROOT=`cat $NGINX_D_CONF | grep -i root | grep -v "#" | head -1 |rev |cut -d' ' -f1 |rev |cut -d';' -f1`
#		fi
#		#nginx -v 입력 시 스크립트 루핑 현상이 생김으로 nginx 실행 경로를 통해 확인해야함으로 변수 선언
#		Nginx_nginx=`find / -name "nginx" | grep /sbin`
#fi		
#			
#
#if [ "$NGINX_HOME" == "" ]
#	then 
#		echo $WEB_NAME "경로를 찾지 못하였음으로 수동으로 입력하십시오."
#		while true
#		do
#			ps -ef | grep nginx
#			echo "아래 예제와 같이" $WEB_NAME "설치 디렉터리를 입력하십시오."
#			echo -n " (ex. /etc/nginx) : "
#			read nginx
#			if [ $nginx ]
#				then
#					if [ -d $nginx ]
#						then
#							NGINX_HOME=$nginx
#							NGINX_CONF=$NGINX_HOME/nginx.conf
#							NGINX_D_CONF=$NGINX_HOME/conf.d/default.conf
#							# NGINX_LOG=`find / -xdev -name "access.log" | grep /nginx |rev |cut -d '/' -f2- |rev`
#							if [ `cat $NGINX_D_CONF | grep -i root | grep -v "#" | head -1 | wc -l` -eq 0 ]
#								then
#									Nginx_ROOT=`cat $NGINX_CONF | grep -i root | grep -v "#" | head -1 |rev |cut -d' ' -f1 |rev |cut -d';' -f1`
#								else
#									Nginx_ROOT=`cat $NGINX_D_CONF | grep -i root | grep -v "#" | head -1 |rev |cut -d' ' -f1 |rev |cut -d';' -f1`
#							fi
#									# nginx -v 입력 시 스크립트 루핑 현상이 생김으로 nginx 실행 경로를 통해 확인해야함으로 변수 선언
#									Nginx_nginx=`find / -name "nginx" | grep /sbin`
#							break
#						else
#							echo "	입력하신 디렉터리가 존재하지 않습니다. 다시 입력하여 주십시오."
#							echo "	"
#					fi
#				else
#					echo "	잘못 입력하셨습니다. 다시 입력하여 주십시오.	"
#					echo " "
#			fi
#		done
#				
#		while true
#		do
#			echo "아래 예제와 같이" $WAS_NAME " 로그 디렉터리를 입력하십시오."
#			echo -n " (ex. /var/log/nginx) : "
#			read NGINX_LOG
#			if [ $NGINX_LOG ]
#				then
#					if [ -d $NGINX_LOG ]
#						then
#							break
#					else
#						echo "	입력하신 디렉터리가 존재하지 않습니다. 다시 입력하여 주십시오."
#						echo "	"
#					fi
#				else
#					echo "	잘못 입력하셨습니다. 다시 입력하여 주십시오.	"
#					echo " "
#			fi
#		done
#fi


	
#================================================================================
# Nginx 진단 시작
#================================================================================

echo "설치 경로가 정확하지 않을 경우 스크립트가 정상 작동되지 않습니다."
echo "결과가 비정상적인 경우 컨설턴트에게 문의주세요."
echo ""
echo ""
echo ""
echo $WEB_NAME"스크립트가 시작 됩니다. 잠시만 기다려주세요. (1~3분 소요 예정)."
echo ""
echo ""
echo START TIME : $START_TIME
echo START TIME : $START_TIME																>> $CREATE_FILE 2>&1
echo ""
echo ""
echo "※※※※스크립트 결과 맨 아래에 설정파일 전체를 출력한 결과가 있습니다. 참고하셔서 진단하세요.※※※※"					>> $CREATE_FILE 2>&1
echo ""
echo ""
echo ""
echo "[WEB-01] 데몬관리"
echo "[WEB-01] 데몬관리"																		>> $CREATE_FILE 2>&1
echo "[START]"																				>> $CREATE_FILE 2>&1
echo "============================================="										>> $CREATE_FILE 2>&1
echo "[+] Nginx 점검현황"  																		>> $CREATE_FILE 2>&1
ps -ef |grep nginx																			>> $CREATE_FILE 2>&1
echo "============================================="										>> $CREATE_FILE 2>&1
echo "[END]"																				>> $CREATE_FILE 2>&1
echo ""																						>> $CREATE_FILE 2>&1
echo ""																						>> $CREATE_FILE 2>&1
echo "[진단기준]"																				>> $CREATE_FILE 2>&1
echo "양호: Nginx의 프로세스가 root 계정 외의 전용 계정으로 구동" 											>> $CREATE_FILE 2>&1
echo "취약: Nginx의 프로세스가 root 계정으로 사용되는 경우"												>> $CREATE_FILE 2>&1
echo ""																						>> $CREATE_FILE 2>&1
echo "[참고사항]"																				>> $CREATE_FILE 2>&1
echo "※ 설정 값이 없거나 추가적인 내용 확인이 필요한 경우 설정 파일에서 다시한번 확인 필요!!"							>> $CREATE_FILE 2>&1
echo "※ nginx.conf 내 User [user] [group]; 설정 값 확인"											>> $CREATE_FILE 2>&1
echo "============================================="										>> $CREATE_FILE 2>&1
echo "============================================="										>> $CREATE_FILE 2>&1

echo ""																						>> $CREATE_FILE 2>&1
echo ""																						>> $CREATE_FILE 2>&1
echo ""																						>> $CREATE_FILE 2>&1

echo "[WEB-02] 관리서버 디렉터리 권한 설정"
echo "[WEB-02] 관리서버 디렉터리 권한 설정"															>> $CREATE_FILE 2>&1
echo "[START]"																				>> $CREATE_FILE 2>&1
echo "============================================="										>> $CREATE_FILE 2>&1
echo "[+] Nginx 점검현황"  																	>> $CREATE_FILE 2>&1
ls -dl $NGINX_HOME																			>> $CREATE_FILE 2>&1
echo "============================================="										>> $CREATE_FILE 2>&1
echo "[END]"																					>> $CREATE_FILE 2>&1
echo ""																						>> $CREATE_FILE 2>&1
echo ""																						>> $CREATE_FILE 2>&1
echo "[진단기준]"																				>> $CREATE_FILE 2>&1
echo "양호: 관리 서버 디렉토리 권한이 750 이하의 권한일 경우" 												>> $CREATE_FILE 2>&1
echo "취약: 관리 서버 디렉토리 권한이 750 초과의 권한일 경우"												>> $CREATE_FILE 2>&1
echo ""																						>> $CREATE_FILE 2>&1
echo "[참고사항]"																				>> $CREATE_FILE 2>&1
echo "※ 권한 750(rwxr-x---)"																	>> $CREATE_FILE 2>&1
echo "============================================="										>> $CREATE_FILE 2>&1
echo "============================================="										>> $CREATE_FILE 2>&1

echo ""																						>> $CREATE_FILE 2>&1
echo ""																						>> $CREATE_FILE 2>&1
echo ""																						>> $CREATE_FILE 2>&1


echo "[WEB-03] 설정파일 권한 설정"
echo "[WEB-03] 설정파일 권한 설정"																	>> $CREATE_FILE 2>&1
echo "[START]"																				>> $CREATE_FILE 2>&1
echo "============================================"											>> $CREATE_FILE 2>&1
echo "[+] Nginx 점검현황"  																	>> $CREATE_FILE 2>&1
ls -dl $NGINX_CONF																			>> $CREATE_FILE 2>&1
echo "============================================="										>> $CREATE_FILE 2>&1
echo "[END]"																				>> $CREATE_FILE 2>&1
echo ""																						>> $CREATE_FILE 2>&1
echo ""																						>> $CREATE_FILE 2>&1
echo "[진단기준]"																				>> $CREATE_FILE 2>&1
echo "양호: 전용 Web Server 계정 소유, 600 또는 700 이하 권한일 경우" 										>> $CREATE_FILE 2>&1
echo "취약: 전용 Web Server 계정 소유가 아니거나, 600 또는 700 초과 권한일 경우"									>> $CREATE_FILE 2>&1
echo ""																						>> $CREATE_FILE 2>&1
echo "[참고사항]"																				>> $CREATE_FILE 2>&1
echo "※ 권한 600(rw-------) , 700(rwx------)"													>> $CREATE_FILE 2>&1
echo "============================================="										>> $CREATE_FILE 2>&1
echo "============================================="										>> $CREATE_FILE 2>&1

echo ""																						>> $CREATE_FILE 2>&1
echo ""																						>> $CREATE_FILE 2>&1
echo ""																						>> $CREATE_FILE 2>&1


echo "[WEB-04] 디렉터리 검색 기능 제거"
echo "[WEB-04] 디렉터리 검색 기능 제거"																>> $CREATE_FILE 2>&1
echo "[START]"																				>> $CREATE_FILE 2>&1
echo "============================================"											>> $CREATE_FILE 2>&1
echo "[+] Nginx 점검현황"  																	>> $CREATE_FILE 2>&1
if [ `cat $NGINX_CONF |grep "autoindex" |grep -v "#" | wc -l` -eq 0 ]
        then
                if [ `cat $NGINX_D_CONF |grep "autoindex" |grep -v "#" | wc -l` -eq 0 ]
                        then
                                echo "autoindex 설정값이없습니다" 									>> $CREATE_FILE 2>&1
                        else
                                cat $NGINX_D_CONF | awk -f ctx.awk PAT='autoindex' B=4 A=4 |grep -v "#"	>> $CREATE_FILE 2>&1
                fi
        else
                cat $NGINX_CONF | awk -f ctx.awk PAT='autoindex' B=4 A=4 |grep -v "#"					>> $CREATE_FILE 2>&1

fi
echo "============================================="										>> $CREATE_FILE 2>&1
echo "[END]"																				>> $CREATE_FILE 2>&1
echo ""																						>> $CREATE_FILE 2>&1
echo ""																						>> $CREATE_FILE 2>&1
echo "[진단기준]"																				>> $CREATE_FILE 2>&1
echo "양호 : autoindex off 옵션이 설정되어 있거나 autoindex 옵션이 없는 경우" 								>> $CREATE_FILE 2>&1
echo "취약 : autoindex on 옵션이 설정되어 있는 경우"													>> $CREATE_FILE 2>&1
echo ""																						>> $CREATE_FILE 2>&1
echo "[참고사항]"																				>> $CREATE_FILE 2>&1
echo "※ 설정 값이 없거나 추가적인 내용 확인이 필요한 경우 설정 파일에서 다시한번 확인 필요!!"							>> $CREATE_FILE 2>&1
echo "※ nginx.conf 또는 default.conf 내 location /[디렉터리명]에서 autoindex 확인"					>> $CREATE_FILE 2>&1
echo "============================================="										>> $CREATE_FILE 2>&1
echo "============================================="										>> $CREATE_FILE 2>&1

echo ""																						>> $CREATE_FILE 2>&1
echo ""																						>> $CREATE_FILE 2>&1
echo ""																						>> $CREATE_FILE 2>&1


echo "[WEB-05] 로그 디렉터리/파일 권한 설정"
echo "[WEB-05] 로그 디렉터리/파일 권한 설정"															>> $CREATE_FILE 2>&1
echo "[START]"																				>> $CREATE_FILE 2>&1
echo "============================================"											>> $CREATE_FILE 2>&1
echo "[+] Nginx 점검현황"  																	>> $CREATE_FILE 2>&1
echo "(Log Directory)"																		>> $CREATE_FILE 2>&1
if [ `ls -dl $NGINX_LOG | wc -l` -eq 0 ]
        then
                echo "로그 디렉터리가 존재하지 않음" 													>> $CREATE_FILE 2>&1
        else
                ls -dl $NGINX_LOG 															>> $CREATE_FILE 2>&1
fi
echo ""																						>> $CREATE_FILE 2>&1
echo "(Access Log 및 Error Log)"																>> $CREATE_FILE 2>&1
if [ `ls -dl $NGINX_LOG/*.log | wc -l` -eq 0 ]
        then
                echo "로그 파일이 존재하지 않음" 													>> $CREATE_FILE 2>&1
        else
                ls -dl $NGINX_LOG/*.log														>> $CREATE_FILE 2>&1
fi
echo "============================================="										>> $CREATE_FILE 2>&1
echo "[END]"																				>> $CREATE_FILE 2>&1
echo ""																						>> $CREATE_FILE 2>&1
echo ""																						>> $CREATE_FILE 2>&1
echo "[진단기준]"																				>> $CREATE_FILE 2>&1
echo "양호 : 로그 디렉터리/파일이 전용계정 소유이고 각각 750/640 이하의 권한일 경우" 								>> $CREATE_FILE 2>&1
echo "취약 : 로그 디렉터리/파일이 전용계정 소유가 아니거나 각각 750/640 초과의 권한일 경우"								>> $CREATE_FILE 2>&1
echo ""																						>> $CREATE_FILE 2>&1
echo "[참고사항]"																				>> $CREATE_FILE 2>&1
echo "※ 권한 750(drwxr-x---) , 640(rw-r-----)"												>> $CREATE_FILE 2>&1
echo "============================================="										>> $CREATE_FILE 2>&1
echo "============================================="										>> $CREATE_FILE 2>&1

echo ""																						>> $CREATE_FILE 2>&1
echo ""																						>> $CREATE_FILE 2>&1
echo ""																						>> $CREATE_FILE 2>&1

echo "[WEB-06] 로그 설정"
echo "[WEB-06] 로그 설정"																		>> $CREATE_FILE 2>&1
echo "[START]"																				>> $CREATE_FILE 2>&1
echo "============================================"											>> $CREATE_FILE 2>&1
echo "[+] Nginx 점검현황"  																	>> $CREATE_FILE 2>&1
echo "(Access_log 확인)"																		>> $CREATE_FILE 2>&1
if [ `cat $NGINX_CONF |grep "access_log" |grep -v "#" | wc -l` -eq 0 ]
        then
                if [ `cat $NGINX_D_CONF |grep "access_log" |grep -v "#" | wc -l` -eq 0 ]
                        then
                                echo "access_log 설정값이없습니다" 								>> $CREATE_FILE 2>&1
                        else
                                cat $NGINX_D_CONF | awk -f ctx.awk PAT='access_log' B=4 A=4 |grep -v "#"	>> $CREATE_FILE 2>&1
                fi
        else
                cat $NGINX_CONF | awk -f ctx.awk PAT='access_log' B=4 A=4 |grep -v "#" 					>> $CREATE_FILE 2>&1

fi
echo ""																						>> $CREATE_FILE 2>&1
echo "(error_log 확인)"																		>> $CREATE_FILE 2>&1
if [ `cat $NGINX_CONF |grep "error_log" |grep -v "#" | wc -l` -eq 0 ]
        then
                if [ `cat $NGINX_D_CONF |grep "error_log" |grep -v "#" | wc -l` -eq 0 ]
                        then
                                echo "error_log 설정값이없습니다" 									>> $CREATE_FILE 2>&1
                        else
                                cat $NGINX_D_CONF | awk -f ctx.awk PAT='error_log' B=4 A=4 |grep -v "#"	>> $CREATE_FILE 2>&1
                fi
        else
                cat $NGINX_CONF | awk -f ctx.awk PAT='error_log' B=4 A=4 |grep -v "#" 					>> $CREATE_FILE 2>&1

fi
echo "============================================="										>> $CREATE_FILE 2>&1
echo "[END]"																				>> $CREATE_FILE 2>&1
echo ""																						>> $CREATE_FILE 2>&1
echo ""																						>> $CREATE_FILE 2>&1
echo "[진단기준]"																				>> $CREATE_FILE 2>&1
echo "양호 : access_log, error_log 로그 기록 설정이 되어있는 경우" 										>> $CREATE_FILE 2>&1
echo "취약 : access_log, error_log 로그 기록 설정이 되어있지 않는 경우"										>> $CREATE_FILE 2>&1
echo ""																						>> $CREATE_FILE 2>&1
echo "[참고사항]"																				>> $CREATE_FILE 2>&1
echo "※ 설정 값이 없거나 추가적인 내용 확인이 필요한 경우 설정 파일에서 다시한번 확인 필요!!"							>> $CREATE_FILE 2>&1
echo "※ nginx.conf 내에서 access_log 및 error_log 확인"											>> $CREATE_FILE 2>&1
echo "============================================="										>> $CREATE_FILE 2>&1
echo "============================================="										>> $CREATE_FILE 2>&1

echo ""																						>> $CREATE_FILE 2>&1
echo ""																						>> $CREATE_FILE 2>&1
echo ""																						>> $CREATE_FILE 2>&1


echo "[WEB-07] 로그 포맷/레벨 설정"
echo "[WEB-07] 로그 포맷/레벨 설정"																>> $CREATE_FILE 2>&1
echo "[START]"																				>> $CREATE_FILE 2>&1
echo "============================================"											>> $CREATE_FILE 2>&1
echo "[+] Nginx 점검현황"  																	>> $CREATE_FILE 2>&1
echo "(로그 포맷 확인)"																			>> $CREATE_FILE 2>&1
if [ `cat $NGINX_CONF |grep "access_log" |grep -v "#" | wc -l` -eq 0 ]
        then
                if [ `cat $NGINX_D_CONF |grep "access_log" |grep -v "#" | wc -l` -eq 0 ]
                        then
                                echo "access_log 설정값이없습니다" 								>> $CREATE_FILE 2>&1
                        else
                                cat $NGINX_D_CONF | awk -f ctx.awk PAT='access_log' B=4 A=4 |grep -v "#"	>> $CREATE_FILE 2>&1
                fi
        else
                cat $NGINX_CONF | awk -f ctx.awk PAT='access_log' B=4 A=4 |grep -v "#" 					>> $CREATE_FILE 2>&1

fi
echo ""																						>> $CREATE_FILE 2>&1
echo "(로그 레벨 확인)"																			>> $CREATE_FILE 2>&1
if [ `cat $NGINX_CONF |grep "error_log" |grep -v "#" | wc -l` -eq 0 ]
        then
                if [ `cat $NGINX_D_CONF |grep "error_log" |grep -v "#" | wc -l` -eq 0 ]
                        then
                                echo "error_log 설정값이없습니다" 									>> $CREATE_FILE 2>&1
                        else
                                cat $NGINX_D_CONF | awk -f ctx.awk PAT='error_log' B=4 A=4 |grep -v "#"	>> $CREATE_FILE 2>&1
                fi
        else
                cat $NGINX_CONF | awk -f ctx.awk PAT='error_log' B=4 A=4 |grep -v "#" 					>> $CREATE_FILE 2>&1

fi
echo "============================================="										>> $CREATE_FILE 2>&1
echo "[END]"																				>> $CREATE_FILE 2>&1
echo ""																						>> $CREATE_FILE 2>&1
echo ""																						>> $CREATE_FILE 2>&1
echo "[로그 포맷 진단기준]"																		>> $CREATE_FILE 2>&1
echo "양호 : access log의 로그 포맷이 Combined 설정인 경우" 											>> $CREATE_FILE 2>&1
echo "취약 : access log의 로그 포맷이 Combined 설정이 아닌 경우"											>> $CREATE_FILE 2>&1
echo ""																						>> $CREATE_FILE 2>&1
echo "[로그 레벨 진단기준]"																		>> $CREATE_FILE 2>&1
echo "양호 : 로그 수집 레벨 관리가 warn,notice,info,debug 단계로 설정된 경우"								>> $CREATE_FILE 2>&1
echo "취약 : 로그 수집 레벨 관리가 Emerg,alert,crit,error 단계로 설정된 경우"								>> $CREATE_FILE 2>&1
echo ""																						>> $CREATE_FILE 2>&1
echo "[참고사항]"																				>> $CREATE_FILE 2>&1
echo "※ 설정 값이 없거나 추가적인 내용 확인이 필요한 경우 설정 파일에서 다시한번 확인 필요!!"							>> $CREATE_FILE 2>&1
echo "※ nginx.conf 내에서 access_log 및 error_log 확인"											>> $CREATE_FILE 2>&1
echo ""																						>> $CREATE_FILE 2>&1
echo ""																						>> $CREATE_FILE 2>&1
echo "Emerg - 불안정한 시스템 상황"	 															>> $CREATE_FILE 2>&1
echo "alert - 즉각적인 조치 필요" 																	>> $CREATE_FILE 2>&1
echo "crit - 중대한 에러" 																		>> $CREATE_FILE 2>&1
echo "error - 비교적 중대하지 않은 에러" 															>> $CREATE_FILE 2>&1
echo "warn - 경고" 																			>> $CREATE_FILE 2>&1
echo "notice - 중대한 것은 아닌 일반적인 메시지" 														>> $CREATE_FILE 2>&1
echo "info - 정보"	 																		>> $CREATE_FILE 2>&1
echo "debug - 디버그 레벨"																		>> $CREATE_FILE 2>&1
echo "============================================="										>> $CREATE_FILE 2>&1
echo "============================================="										>> $CREATE_FILE 2>&1

echo ""																						>> $CREATE_FILE 2>&1
echo ""																						>> $CREATE_FILE 2>&1
echo ""																						>> $CREATE_FILE 2>&1

echo "[WEB-08] 로그 저장 주기"
echo "[WEB-08] 로그 저장 주기"																	>> $CREATE_FILE 2>&1
echo "[START]"																				>> $CREATE_FILE 2>&1
echo "============================================"											>> $CREATE_FILE 2>&1
echo "[+] Nginx 점검현황"  																	>> $CREATE_FILE 2>&1
echo "담당자 인터뷰 진행"																			>> $CREATE_FILE 2>&1
echo "============================================="										>> $CREATE_FILE 2>&1
echo "[END]"																				>> $CREATE_FILE 2>&1
echo ""																						>> $CREATE_FILE 2>&1
echo ""																						>> $CREATE_FILE 2>&1
echo "[진단기준]"																				>> $CREATE_FILE 2>&1
echo "로그 6개월 이상 보관인 경우 양호" 																>> $CREATE_FILE 2>&1
echo "로그 6개월 이상 보관이 아닌 경우 취약"															>> $CREATE_FILE 2>&1
echo ""																						>> $CREATE_FILE 2>&1
echo "============================================="										>> $CREATE_FILE 2>&1
echo "============================================="										>> $CREATE_FILE 2>&1

echo ""																						>> $CREATE_FILE 2>&1
echo ""																						>> $CREATE_FILE 2>&1
echo ""																						>> $CREATE_FILE 2>&1

echo "[WEB-09] 헤더 정보 노출 방지"
echo "[WEB-09] 헤더 정보 노출 방지"																>> $CREATE_FILE 2>&1
echo "[START]"																				>> $CREATE_FILE 2>&1
echo "============================================"											>> $CREATE_FILE 2>&1
echo "[+] Nginx 점검현황"  																	>> $CREATE_FILE 2>&1
if [ `cat $NGINX_CONF |grep "server_tokens" | grep -v "#" | wc -l` -eq 0 ]
        then
                if [ `cat $NGINX_D_CONF |grep "server_tokens" |grep -v "#" | wc -l` -eq 0 ]
                        then
                                echo "server_tokens 설정 값이 없습니다" 							>> $CREATE_FILE 2>&1
                        else
                                cat $NGINX_D_CONF | awk -f ctx.awk PAT='server_tokens' B=4 A=4 |grep -v "#"	>> $CREATE_FILE 2>&1
                fi
        else
                cat $NGINX_CONF | awk -f ctx.awk PAT='server_tokens' B=4 A=4 |grep -v "#" 					>> $CREATE_FILE 2>&1

fi
echo "============================================="										>> $CREATE_FILE 2>&1
echo "[END]"																				>> $CREATE_FILE 2>&1
echo ""																						>> $CREATE_FILE 2>&1
echo ""																						>> $CREATE_FILE 2>&1
echo "[진단기준]"																				>> $CREATE_FILE 2>&1
echo "양호 : server_tokens 설정이 Off 설정인 경우" 													>> $CREATE_FILE 2>&1
echo "취약 : server_tokens 설정이 적용되어 있지 않거나 On 설정인 경우"										>> $CREATE_FILE 2>&1
echo ""																						>> $CREATE_FILE 2>&1
echo "[참고사항]"																				>> $CREATE_FILE 2>&1
echo "※ 설정 값이 없거나 추가적인 내용 확인이 필요한 경우 설정 파일에서 다시한번 확인 필요!!"							>> $CREATE_FILE 2>&1
echo "※ nginx.conf 또는 default.conf 내에서 server_tokens 확인"									>> $CREATE_FILE 2>&1
echo "※ ServerTokens 옵션은 Nginx 1.3 이상에서 사용 가능"											>> $CREATE_FILE 2>&1
echo "※ ServerTokens 옵션은 http, server, location 절에 모두 설정 가능"								>> $CREATE_FILE 2>&1
echo "============================================="										>> $CREATE_FILE 2>&1
echo "============================================="										>> $CREATE_FILE 2>&1

echo ""																						>> $CREATE_FILE 2>&1
echo ""																						>> $CREATE_FILE 2>&1
echo ""																						>> $CREATE_FILE 2>&1

echo "[WEB-10] HTTP Method 제한"
echo "[WEB-10] HTTP Method 제한"																>> $CREATE_FILE 2>&1
echo "[START]"																				>> $CREATE_FILE 2>&1
echo "============================================"											>> $CREATE_FILE 2>&1
echo "[+] Nginx 점검현황"  																	>> $CREATE_FILE 2>&1
echo "(limit_except 확인)"  																	>> $CREATE_FILE 2>&1
if [ `cat $NGINX_CONF |grep "limit" |grep -v "#" | wc -l` -eq 0 ]
        then
                if [ `cat $NGINX_D_CONF |grep "limit" |grep -v "#" | wc -l` -eq 0 ]
                        then
                                echo "limit_except 설정 값이 없습니다" 							>> $CREATE_FILE 2>&1
                        else
                                cat $NGINX_D_CONF | awk -f ctx.awk PAT='limit_except' B=4 A=4 |grep -v "#"		>> $CREATE_FILE 2>&1
                fi
        else
                cat $NGINX_CONF | awk -f ctx.awk PAT='limit_except' B=4 A=4 |grep -v "#" 						>> $CREATE_FILE 2>&1

fi
echo ""																						>> $CREATE_FILE 2>&1
echo "(Dav 모듈 사용 확인)"  																	>> $CREATE_FILE 2>&1
if [ `cat $NGINX_CONF |grep "dav_methods" |grep -v "#" | wc -l` -eq 0 ]
        then
                if [ `cat $NGINX_D_CONF |grep "dav_methods" |grep -v "#" | wc -l` -eq 0 ]
                        then
                                echo "dav_methods 설정 값이 없습니다" 								>> $CREATE_FILE 2>&1
                        else
                                cat $NGINX_D_CONF | awk -f ctx.awk PAT='dav_methods' B=4 A=4 |grep -v "#"		>> $CREATE_FILE 2>&1
                fi
        else
                cat $NGINX_CONF | awk -f ctx.awk PAT='dav_methods' B=4 A=4 |grep -v "#"							>> $CREATE_FILE 2>&1

fi
echo "============================================="										>> $CREATE_FILE 2>&1
echo "[END]"																				>> $CREATE_FILE 2>&1
echo ""																						>> $CREATE_FILE 2>&1
echo ""																						>> $CREATE_FILE 2>&1
echo "[진단기준]"																				>> $CREATE_FILE 2>&1
echo "양호 : limit_except 옵션을 이용하여 HTTP Method를 제한하는 경우" 									>> $CREATE_FILE 2>&1
echo "취약 : limit_except 옵션을 이용하여 HTTP Method를 제한하지 않는 경우"									>> $CREATE_FILE 2>&1
echo ""																						>> $CREATE_FILE 2>&1
echo "[참고사항]"																				>> $CREATE_FILE 2>&1
echo "※ 설정 값이 없거나 추가적인 내용 확인이 필요한 경우 설정 파일에서 다시한번 확인 필요!!"							>> $CREATE_FILE 2>&1
echo "※ nginx.conf 또는 default.conf 내에서 location 설정 마다 limit_except 확인"					>> $CREATE_FILE 2>&1
echo "※ GET, POST만 허용 권고, HEAD는 상황에 따라서 허용"												>> $CREATE_FILE 2>&1
echo "※ Dav 모듈 사용 할 경우 취약으로 판단"															>> $CREATE_FILE 2>&1
echo "============================================="										>> $CREATE_FILE 2>&1
echo "============================================="										>> $CREATE_FILE 2>&1

echo ""																						>> $CREATE_FILE 2>&1
echo ""																						>> $CREATE_FILE 2>&1
echo ""																						>> $CREATE_FILE 2>&1


echo "[WEB-11] 불필요한 페이지 존재"
echo "[WEB-11] 불필요한 페이지 존재"																>> $CREATE_FILE 2>&1
echo "[START]"																				>> $CREATE_FILE 2>&1
echo "============================================"											>> $CREATE_FILE 2>&1
echo "[+] Nginx 점검현황"  																	>> $CREATE_FILE 2>&1
if [ `ls -al $Nginx_ROOT | wc -l` -eq 0 ]
        then
                echo "루트 디렉터리가 존재하지 않음" 													>> $CREATE_FILE 2>&1
        else
                ls -dl $Nginx_ROOT 															>> $CREATE_FILE 2>&1
                ls -al $Nginx_ROOT 															>> $CREATE_FILE 2>&1
fi
echo "============================================="										>> $CREATE_FILE 2>&1
echo "[END]"																				>> $CREATE_FILE 2>&1
echo ""																						>> $CREATE_FILE 2>&1
echo ""																						>> $CREATE_FILE 2>&1
echo "[진단기준]"																				>> $CREATE_FILE 2>&1
echo "sample, manual, test, cgi-bin 등 불필요한 파일이 존재하지 않는 경우 양호" 							>> $CREATE_FILE 2>&1
echo "sample, manual, test, cgi-bin 등 불필요한 파일이 존재하는 경우 취약"								>> $CREATE_FILE 2>&1
echo ""																						>> $CREATE_FILE 2>&1
echo "============================================="										>> $CREATE_FILE 2>&1
echo "============================================="										>> $CREATE_FILE 2>&1

echo ""																						>> $CREATE_FILE 2>&1
echo ""																						>> $CREATE_FILE 2>&1
echo ""																						>> $CREATE_FILE 2>&1


echo "[WEB-12] SSL v3.0 POODLE 취약점"
echo "[WEB-12] SSL v3.0 POODLE 취약점"															>> $CREATE_FILE 2>&1
echo "[START]"																				>> $CREATE_FILE 2>&1
echo "============================================"											>> $CREATE_FILE 2>&1
echo "[+] Nginx 점검현황"  																	>> $CREATE_FILE 2>&1
if [ `cat $NGINX_CONF |grep "ssl_protocols" |grep -v "#" | wc -l` -eq 0 ]
        then
                if [ `cat $NGINX_D_CONF |grep "ssl_protocols" |grep -v "#" | wc -l` -eq 0 ]
                        then
                                echo "ssl_protocols 설정 값이 없습니다" 							>> $CREATE_FILE 2>&1
                        else
                                cat $NGINX_D_CONF | awk -f ctx.awk PAT='ssl_protocols' B=4 A=4 |grep -v "#"	>> $CREATE_FILE 2>&1
                fi
        else
                cat $NGINX_CONF | awk -f ctx.awk PAT='ssl_protocols' B=4 A=4 |grep -v "#" 				>> $CREATE_FILE 2>&1

fi
echo "============================================="										>> $CREATE_FILE 2>&1
echo "[END]"																				>> $CREATE_FILE 2>&1
echo ""																						>> $CREATE_FILE 2>&1
echo ""																						>> $CREATE_FILE 2>&1
echo "[진단기준]"																				>> $CREATE_FILE 2>&1
echo "양호 : TLSv1.2 이상 버전을 사용하는 경우" 														>> $CREATE_FILE 2>&1
echo "취약 : TLSv1.2 이하 버전을 사용하는 경우"															>> $CREATE_FILE 2>&1
echo ""																						>> $CREATE_FILE 2>&1
echo "[참고사항]"																				>> $CREATE_FILE 2>&1
echo "※ 설정 값이 없거나 추가적인 내용 확인이 필요한 경우 설정 파일에서 다시한번 확인 필요!!"							>> $CREATE_FILE 2>&1
echo "※ nginx.conf 또는 default.conf 내에서 ssl_protocols 확인"									>> $CREATE_FILE 2>&1
echo "============================================="										>> $CREATE_FILE 2>&1
echo "============================================="										>> $CREATE_FILE 2>&1

echo ""																						>> $CREATE_FILE 2>&1
echo ""																						>> $CREATE_FILE 2>&1
echo ""																						>> $CREATE_FILE 2>&1

echo "[WEB-13] 에러 페이지 설정"
echo "[WEB-13] 에러 페이지 설정"																	>> $CREATE_FILE 2>&1
echo "[START]"																				>> $CREATE_FILE 2>&1
echo "============================================"											>> $CREATE_FILE 2>&1
echo "[+] Nginx 점검현황"  																	>> $CREATE_FILE 2>&1
if [ `cat $NGINX_CONF |grep "error_page" |grep -v "#" | wc -l` -eq 0 ]
        then
                if [ `cat $NGINX_D_CONF |grep "error_page" |grep -v "#" | wc -l` -eq 0 ]
                        then
                                echo "error_page 설정 값이 없습니다" 								>> $CREATE_FILE 2>&1
                        else
                                cat $NGINX_D_CONF | awk -f ctx.awk PAT='error_page' B=4 A=4 |grep -v "#"	>> $CREATE_FILE 2>&1
                fi
        else
                cat $NGINX_CONF | awk -f ctx.awk PAT='error_page' B=4 A=4 |grep -v "#" 					>> $CREATE_FILE 2>&1

fi
echo "============================================="										>> $CREATE_FILE 2>&1
echo "[END]"																				>> $CREATE_FILE 2>&1
echo ""																						>> $CREATE_FILE 2>&1
echo ""																						>> $CREATE_FILE 2>&1
echo "[진단기준]"																				>> $CREATE_FILE 2>&1
echo "양호 : error_page 설정을 이용하여 에러 메시지 출력 파일 설정이 적절한 경우" 									>> $CREATE_FILE 2>&1
echo "취약 : error_page 설정을 이용하여 에러 메시지 출력 파일 설정이 되어있지 않은 경우"								>> $CREATE_FILE 2>&1
echo "부분취약 : error_page 설정을 이용하여 에러 메시지 출력 파일 설정이 일부만 되어있는 경우"							>> $CREATE_FILE 2>&1
echo ""																						>> $CREATE_FILE 2>&1
echo "[참고사항]"																				>> $CREATE_FILE 2>&1
echo "※ 설정 값이 없거나 추가적인 내용 확인이 필요한 경우 설정 파일에서 다시한번 확인 필요!!"							>> $CREATE_FILE 2>&1
echo "※ nginx.conf 또는 default.conf 내에서 error_page 확인"										>> $CREATE_FILE 2>&1
echo "※ 에러 메시지 출력 파일은 동일하게 설정"															>> $CREATE_FILE 2>&1
echo "※ Error 400, 401, 402, 403, 404, 500에 대한 설정"											>> $CREATE_FILE 2>&1
echo "============================================="										>> $CREATE_FILE 2>&1
echo "============================================="										>> $CREATE_FILE 2>&1

echo ""																						>> $CREATE_FILE 2>&1
echo ""																						>> $CREATE_FILE 2>&1
echo ""																						>> $CREATE_FILE 2>&1

echo "[WEB-14] 보안 패치 적용"
echo "[WEB-14] 보안 패치 적용"																	>> $CREATE_FILE 2>&1
echo "[START]"																				>> $CREATE_FILE 2>&1
echo "============================================"											>> $CREATE_FILE 2>&1
echo "[+] Nginx 점검현황"  																	>> $CREATE_FILE 2>&1
$Nginx_nginx -v																				>> $CREATE_FILE 2>&1
# nginx -v 입력 시 스크립트 루핑 현상이 생김으로 nginx 실행 경로를 통해 확인해야함으로 변수 선언
echo "============================================="										>> $CREATE_FILE 2>&1
echo "[END]"																				>> $CREATE_FILE 2>&1
echo ""																						>> $CREATE_FILE 2>&1
echo ""																						>> $CREATE_FILE 2>&1
echo "[진단기준]"																				>> $CREATE_FILE 2>&1
echo "양호 : 안정된 최신 버전을 사용하는 경우" 															>> $CREATE_FILE 2>&1
echo "취약 : 안정된 최신 버전을 사용하지 않는 경우"															>> $CREATE_FILE 2>&1
echo ""																						>> $CREATE_FILE 2>&1
echo "[참고사항]"																				>> $CREATE_FILE 2>&1
echo "※ Nginx의 보안패치 참고 사이트:http://nginx.org/en/security_advisories.html"					>> $CREATE_FILE 2>&1
echo "============================================="										>> $CREATE_FILE 2>&1
echo "============================================="										>> $CREATE_FILE 2>&1

echo ""																						>> $CREATE_FILE 2>&1
echo ""																						>> $CREATE_FILE 2>&1
echo ""																						>> $CREATE_FILE 2>&1

echo "[WEB-15] FollowSymLinks 옵션 비활성화"
echo "[WEB-15] FollowSymLinks 옵션 비활성화"														>> $CREATE_FILE 2>&1
echo "[START]"																				>> $CREATE_FILE 2>&1
echo "============================================"											>> $CREATE_FILE 2>&1
echo "[+] Nginx 점검현황"  						 											>> $CREATE_FILE 2>&1
echo "N/A"																					>> $CREATE_FILE 2>&1
echo "============================================="										>> $CREATE_FILE 2>&1
echo "[END]"																				>> $CREATE_FILE 2>&1
echo ""																						>> $CREATE_FILE 2>&1
echo "============================================="										>> $CREATE_FILE 2>&1
echo "============================================="										>> $CREATE_FILE 2>&1

echo ""																						>> $CREATE_FILE 2>&1
echo ""																						>> $CREATE_FILE 2>&1
echo ""																						>> $CREATE_FILE 2>&1

echo "[WEB-16] MultiViews 옵션 비활성화"
echo "[WEB-16] MultiViews 옵션 비활성화"															>> $CREATE_FILE 2>&1
echo "[START]"																				>> $CREATE_FILE 2>&1
echo "============================================"											>> $CREATE_FILE 2>&1
echo "[+] Nginx 점검현황"  																	>> $CREATE_FILE 2>&1
echo "N/A" 																					>> $CREATE_FILE 2>&1
echo "============================================="										>> $CREATE_FILE 2>&1
echo "[END]"																				>> $CREATE_FILE 2>&1
echo ""																						>> $CREATE_FILE 2>&1
echo "============================================="										>> $CREATE_FILE 2>&1
echo "============================================="										>> $CREATE_FILE 2>&1

echo ""																						>> $CREATE_FILE 2>&1
echo ""																						>> $CREATE_FILE 2>&1
echo ""																						>> $CREATE_FILE 2>&1

echo "[WEB-17] SSI(Server Side Includes) 사용 제한"
echo "[WEB-17] SSI(Server Side Includes) 사용 제한"											>> $CREATE_FILE 2>&1
echo "[START]"																				>> $CREATE_FILE 2>&1
echo "============================================"											>> $CREATE_FILE 2>&1
echo "[+] Nginx 점검현황"  																	>> $CREATE_FILE 2>&1
echo "N/A" 																					>> $CREATE_FILE 2>&1
echo "============================================="										>> $CREATE_FILE 2>&1
echo "[END]"																				>> $CREATE_FILE 2>&1
echo ""																						>> $CREATE_FILE 2>&1
echo "============================================="										>> $CREATE_FILE 2>&1
echo "============================================="										>> $CREATE_FILE 2>&1

echo ""																						>> $CREATE_FILE 2>&1
echo ""																						>> $CREATE_FILE 2>&1
echo ""																						>> $CREATE_FILE 2>&1

echo "============================================="										>> $CREATE_FILE 2>&1
echo "[nginx.conf] 출력"																		>> $CREATE_FILE 2>&1
echo ""																						>> $CREATE_FILE 2>&1
cat $NGINX_CONF																				>> $CREATE_FILE 2>&1
echo "============================================="										>> $CREATE_FILE 2>&1
echo ""																						>> $CREATE_FILE 2>&1
echo "================  ============================="										>> $CREATE_FILE 2>&1
echo "[default.conf] 출력 (결과 없을 경우 파일 존재하지 않음)"												>> $CREATE_FILE 2>&1
echo ""																						>> $CREATE_FILE 2>&1
cat $NGINX_D_CONF																			>> $CREATE_FILE 2>&1
echo "============================================="										>> $CREATE_FILE 2>&1

echo $WEB_NAME"스크립트가 종료 되었습니다. 잠시만 기다려주세요."
 
unset NGINX_HOME
unset NGINX_CONF
unset NGINX_D_CONF
unset NGINX_LOG
unset Nginx_ROOT
unset WEB_NAME
unset Nginx_nginx


#================================================================================
# Nginx 스크립트 종료
#================================================================================








#================================================================================
# 결과 파일 정리
#================================================================================


tar -cvf $CREATE_FILE.tar $CREATE_FILE


unset RESULT_FILE
unset TAR_FILE
unset HOST_NAME
unset DATE_STR
unset TIME_STR
unset START_TIME
unset IP
unset locale_utf8
unset locale_utf_8
unset locale_euckr
unset locale_KR

echo "스크립트가 종료되었습니다. 결과파일을 전달해주세요."