#!/bin/bash

locale_utf8=`locale -a | grep -i 'ko_KR.utf8' | wc -l`
locale_utf_8=`locale -a | grep -i 'ko_KR.UTF-8' | wc -l`
locale_euckr=`locale -a | grep -i 'ko_KR.euckr' | wc -l`
locale_KR=`locale -a | grep ko_KR | grep -v euckr | grep -v utf8 | wc -l`

#if [ $locale_utf8 -ne 0 ]
#then
#	export LANG=ko_KR.utf8
#elif [ $locale_utf_8 -ne 0 ]
#then
#	export LANG=ko_KR.UTF-8
#elif [ $locale_euckr -ne 0 ]
#then
#	export LANG=ko_KR.euckr
#elif [ $locale_KR -ne 0 ]
#then
#	export LANG=ko_KR
#else
#	export LANG=C
#fi

LANG=C
export LANG

OS=`uname -s`


if [ $OS = Linux ]
	then
		#alias echo='echo -e'
		IP=`hostname -I | sed 's/ //g'`
fi

if [ $OS = SunOS ]
	then
		IP=`ifconfig -a | grep broadcast | cut -f 2 -d ' '`
fi

if [ $OS = AIX ]
	 then
		IP=`ifconfig en0 | grep 'inet' | awk '{print $2}'`
fi

if [ $OS = HP-UX ]
	then
		IP=`ifconfig lan0 | grep 'inet' | awk '{print $2)'`
fi


alias ls=ls


CREATE_FILE=[Lyn_secure]`hostname`"_"$OS"_"$IP"_"`date +%m%d`.txt
CHECK_FILE=`ls ./"$CREATE_FILE" 2>/dev/null | wc -l`

perm_check() {
    unset FUNC_FILE
    unset PERM
    unset NUM
    unset PERM_CHECK
    unset OWNER_FUNC_fRESULT
    unset PERM_FUNC_RESULT
    unset VALUE

    FUNC_FILE=$1
    PERM=`ls -al $FUNC_FILE | awk '{print $1}'`
    OWNER_FUNC_RESULT=`ls -al $FUNC_FILE | awk '{print $3}'`
    PERM=`expr "$PERM" : '.\(.*\)' | sed -e "s/-/A/g"`;

    while :
    do
        NUM=`echo $PERM | awk '{print length($0)}'`

        if [ $NUM -eq 0 ]
            then
                break
        fi

        PERM_CHECK=`expr "$PERM" : '\(...\).*'`
        PERM=`expr "$PERM" : '...\(.*\)'`

        if [ "$PERM_CHECK" = "rwx" -o "$PERM_CHECK" = "rws" -o "$PERM_CHECK" = "rwS" ]
            then
                VALUE="7"
        fi

        if [ "$PERM_CHECK" = "rwA" ]
            then
                VALUE="6"
        fi

        if [ "$PERM_CHECK" = "rAx" -o "$PERM_CHECK" = "rAs" -o "$PERM_CHECK" = "rAS" ]
            then
                VALUE="5"
        fi

        if [ "$PERM_CHECK" = "rAA" ]
            then
                VALUE="4"
        fi

        if [ "$PERM_CHECK" = "Awx" -o "$PERM_CHECK" = "Aws" -o "$PERM_CHECK" = "AwS" ]
            then
                VALUE="3"
        fi

        if [ "$PERM_CHECK" = "AwA" ]
            then
                VALUE="2"
        fi

        if [ "$PERM_CHECK" = "AAx" -o "$PERM_CHECK" = "AAs" -o "$PERM_CHECK" = "AAS" ]
            then
                VALUE="1"
        fi

        if [ "$PERM_CHECK" = "AAA" ]
            then
                VALUE="0"
        fi

        PERM_FUNC_RESULT=$PERM_FUNC_RESULT" "$VALUE
    done

    PERM_FUNC_RESULT=$PERM_FUNC_RESULT" "$OWNER_FUNC_RESULT

    return
}

perm_check_dir() {
    unset FUNC_FILE
    unset PERM
    unset OWNER_FUNC_RESULT
    unset NUM
    unset PERM_CHECK
    unset PERM_FUNC_RESULT
    unset VALUE

    FUNC_FILE=$1

    PERM=`ls -alLd $FUNC_FILE | awk '{print $1}'`
    OWNER_FUNC_RESULT=`ls -alLd $FUNC_FILE | awk '{print $3}'`
    PERM=`expr "$PERM" : '.\(.*\)' | sed -e "s/-/A/g"` 

    while :
    do
        NUM=`echo $PERM | awk '{print length($0)}'`

        if [ $NUM -eq 0 ]
            then
                break
        fi

        PERM_CHECK=`expr "$PERM" : '\(...\).*'`
        PERM=`expr "$PERM" : '...\(.*\)'` 	

        if [ "$PERM_CHECK" = "rwx" -o "$PERM_CHECK" = "rws" -o "$PERM_CHECK" = "rwS" ]
            then
                VALUE="7"
        fi

        if [ "$PERM_CHECK" = "rwA" ]
            then
                VALUE="6"
        fi

        if [ "$PERM_CHECK" = "rAx" -o "$PERM_CHECK" = "rAs" -o "$PERM_CHECK" = "rAS" ]
            then
                VALUE="5"
        fi

        if [ "$PERM_CHECK" = "rAA" ]
            then
                VALUE="4"
        fi

        if [ "$PERM_CHECK" = "Awx" -o "$PERM_CHECK" = "Aws" -o "$PERM_CHECK" = "AwS" ]
            then
                VALUE="3"
        fi

        if [ "$PERM_CHECK" = "AwA" ]
            then
                VALUE="2"
        fi

        if [ "$PERM_CHECK" = "AAx" -o "$PERM_CHECK" = "AAs" -o "$PERM_CHECK" = "AAS" ]
            then
                VALUE="1"
        fi

        if [ "$PERM_CHECK" = "AAA" ]
            then
                VALUE="0"
        fi

        PERM_FUNC_RESULT=$PERM_FUNC_RESULT" "$VALUE
    done

    PERM_FUNC_RESULT=$PERM_FUNC_RESULT" "$OWNER_FUNC_RESULT

    return
}

#######################
# 파일 존재여부 체크 함수
#######################
file_check() {
    if [ -e "$1" ]; then
        return 0
    else
        return 1
    fi
}

echo "" >> $CREATE_FILE 2>&1
echo "###########################################################################"
echo "#																			#"
echo "#   				Security Inspection of Server(Unix ver.)			    #"
echo "#			  					Version : 1.3								#"
echo "#					Copyright 2025, Lyn Secure All right Reserved			#"
echo "#						ALL RIGHTS RESERVED.								#"
echo "#																			#"
echo "###########################################################################"
echo "------------------------------------------------------------"
echo "----------------   진단 전 주의사항    -------------------------"
echo "-----   반드시 Super 유저 권한에서 진단을 시작해야 합니다!   ---------"
echo "------------------------------------------------------------"
echo "===========================================================" >> $CREATE_FILE 2>&1
echo "==============   UNIX/Linux Security Check   ==============" >> $CREATE_FILE 2>&1
echo "===========================================================" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "***********************************************************" >> $CREATE_FILE 2>&1
echo "*****************   INFO_CHKSTART   ***********************" >> $CREATE_FILE 2>&1
echo "***********************************************************" >> $CREATE_FILE 2>&1
echo "-----------------   Start Time   --------------------------" >> $CREATE_FILE 2>&1
date >> $CREATE_FILE 2>&1
echo "-----------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "===========================================================" >> $CREATE_FILE 2>&1
echo "===========   System Information Query Start   ============" >> $CREATE_FILE 2>&1
echo "===========================================================" >> $CREATE_FILE 2>&1
echo "--------------------   Kernel Information   ---------------" >> $CREATE_FILE 2>&1
KERNEL=`uname -a` >> $CREATE_FILE 2>&1
echo "$KERNEL" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "-------------------   IP Information   --------------------" >> $CREATE_FILE 2>&1
IFCONFIG=`ifconfig -a` >> $CREATE_FILE 2>&1
echo "$IFCONFIG" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "-----------------   Network Status   ----------------------" >> $CREATE_FILE 2>&1
NETSTAT=`netstat -an | egrep -i "LISTEN|ESTABLISHED"` >> $CREATE_FILE 2>&1
echo "$NETSTAT" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "----------------   Routing Information   ------------------" >> $CREATE_FILE 2>&1
NETSTATR=`netstat -rn` >> $CREATE_FILE 2>&1
echo "$NETSTATR" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "---------------   Process Status   ------------------------" >> $CREATE_FILE 2>&1
PS=`ps -ef` >> $CREATE_FILE 2>&1
echo "$PS" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "------------------   User Env   ---------------------------" >> $CREATE_FILE 2>&1
UE=`env` >> $CREATE_FILE 2>&1
echo "$UE" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "===========================================================" >> $CREATE_FILE 2>&1
echo "============   System Information Query End   =============" >> $CREATE_FILE 2>&1
echo "===========================================================" >> $CREATE_FILE 2>&1
echo "****************************************************" >> $CREATE_FILE 2>&1
echo "******************   INFO_CHK END  *****************" >> $CREATE_FILE 2>&1
echo "****************************************************" >> $CREATE_FILE 2>&1
echo "===========================================================" >> $CREATE_FILE 2>&1
echo "================   Security Check START   =================" >> $CREATE_FILE 2>&1
echo "===========================================================" >> $CREATE_FILE 2>&1

mkdir Lyn_tmp

File_load="/etc/passwd /etc/shadow /etc/hosts /etc/group /etc/services /etc/pam.d/login /etc/pam.d/login.defs /etc/pam.d/system-auth /etc/inetd.conf /etc/xinetd.conf /etc/hosts.equiv /etc/httpd/conf/httpd.conf /etc/vsftpd/vsftpd.conf /etc/vsftpd/user_list /etc/proftpd.conf /etc/at.allow /etc/at.deny /etc/cron.allow /etc/cron.deny /etc/snmp/snmpd.conf /etc/snmpdv3.conf /etc/mail/sendmail.cf /etc/mail/access /etc/ssh/sshd_config /etc/named.conf /etc/issue.net /etc/banners/ftp.msg /etc/securetty /etc/security/pwquality.conf"
count=0
for File_load_list in $File_load
	do
		if [ -f $File_load_list ]
		then
			count=$((count + 1))
			echo "===========================================" >> ./Lyn_tmp/`hostname`_file_data.txt
			echo "[File-$count]" $File_load_list >> ./Lyn_tmp/`hostname`_file_data.txt
			echo "===========================================" >> ./Lyn_tmp/`hostname`_file_data.txt
			cat $File_load_list >> ./Lyn_tmp/`hostname`_file_data.txt
			echo "" >> ./Lyn_tmp/`hostname`_file_data.txt
			echo "" >> ./Lyn_tmp/`hostname`_file_data.txt
			echo "" >> ./Lyn_tmp/`hostname`_file_data.txt
			echo "" >> ./Lyn_tmp/`hostname`_file_data.txt
		fi
done
unset File_load
unset File_load_list

U-01(){
echo "[U-01] root 계정 원격 접속 제한"
echo "[U-01] root 계정 원격 접속 제한" >> $CREATE_FILE 2>&1
echo "[U-01_START]" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
echo "[+] Telnet 프로세스 확인" >> $CREATE_FILE 2>&1
telnet_ps=`ps -ef | grep 'telnet' | grep -v 'grep' | wc -l`
if [ $telnet_ps -ne 0 ]
then
	ps -ef | grep 'telnet' | grep -v 'grep' >> $CREATE_FILE 2>&1
else
	echo "[+] Telnet 프로세스가 비실행 중 입니다." >> $CREATE_FILE 2>&1
fi
echo "" >> $CREATE_FILE 2>&1


case $OS in
	SunOS)
	echo "[+] /etc/default/login 확인" >> $CREATE_FILE 2>&1
	login_set=`cat /etc/default/login | grep CONSOLE | grep -v \# | wc -l`
	if [ $login_set -ne 0 ]
	then
		cat /etc/default/login | grep CONSOLE | grep -v \# >> $CREATE_FILE 2>&1 >> $CREATE_FILE 2>&1
	else
		echo "[+] 해당 설정이 존재하지 않습니다." >> $CREATE_FILE 2>&1
	fi
	echo "" >> $CREATE_FILE 2>&1	
	;;
	
	Linux)
	echo "[+] pts/x 확인" >> $CREATE_FILE 2>&1
	if file_check "/etc/securetty"; then
		cat /etc/securetty | grep -E "pts" >> $CREATE_FILE 2>&1
	else
		echo "/etc/securetty 파일이 존재하지 않습니다." >> $CREATE_FILE 2>&1
	fi
	echo "" >> $CREATE_FILE 2>&1	
	echo "[+] pam_securetty.so 확인" >> $CREATE_FILE 2>&1
	pam_chk=`cat /etc/pam.d/login | grep -E "pam_securetty" | grep -v \# | wc -l`
	if [ $pam_chk -ne 0 ]
	then
		cat /etc/pam.d/login | grep -E "pam_securetty" | grep -v \# >> $CREATE_FILE 2>&1
	else
		echo "[+] pam_securetty 모듈이 주석처리 되어있거나 설정 값이 존재하지 않습니다." >> $CREATE_FILE 2>&1	
	fi
	echo "" >> $CREATE_FILE 2>&1
	;;
	
	AIX)
	rlogin_chk=`cat /etc/security/user | grep rlogin | grep -v \# | wc -l`
	if [ $rlogin_chk -ne 0 ]
	then
		cat /etc/security/user | grep rlogin | grep -v \#
	else
		echo "[+] rlogin 설정이 true로 설정되어 있거나, 주석처리되어 있습니다." >> $CREATE_FILE 2>&1
	fi
	echo "" >> $CREATE_FILE 2>&1	
	;;
	
	HP-UX)
	console_chk=`cat /etc/securetty | grep console | grep -v \# | wc -l`
	if [ $console_chk -ne 0 ]
	then
		cat /etc/securetty | grep console | grep -v \# >> $CREATE_FILE 2>&1
	else
		echo "[+] console 설정이 주석처리 되어있습니다." >> $CREATE_FILE 2>&1
	fi
	echo "" >> $CREATE_FILE 2>&1	
	;;
esac

echo "[+] SSH 프로세스 확인" >> $CREATE_FILE 2>&1
ssh_ps=`ps -ef | grep 'ssh' | grep -v 'grep' | wc -l`
if [ $ssh_ps -ne 0 ]
then
	ps -ef | grep ssh | grep -v 'grep' | head -3 >> $CREATE_FILE 2>&1
	echo "" >> $CREATE_FILE 2>&1
else
	echo "[+] ssh 프로토콜이 비활성화되어 있습니다." >> $CREATE_FILE 2>&1
	echo "" >> $CREATE_FILE 2>&1
fi

ssh_permit=`cat /etc/ssh/sshd_config | grep PermitRootLogin | grep -v '^#' | wc -l`
if [ $ssh_permit -ne 0 ]
then
	echo "[+] /etc/ssh/sshd 설정 현황(PermitRootLogin)" >> $CREATE_FILE 2>&1
	cat /etc/ssh/sshd_config | grep PermitRootLogin | grep -v '^#' >> $CREATE_FILE 2>&1
	echo "" >> $CREATE_FILE 2>&1
else
	echo "[+] /etc/ssh/sshd 설정 현황(PermitRootLogin)" >> $CREATE_FILE 2>&1
	echo "해당 설정이 존재하지 않습니다." >> $CREATE_FILE 2>&1
	echo "" >> $CREATE_FILE 2>&1
fi
echo "" >> $CREATE_FILE 2>&1
echo "[U-01_END]" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
echo "[참고 - 진단기준, 결과 값 출력]" >> $CREATE_FILE 2>&1
echo " 양호 : 원격 터미널 서비스를 사용하지 않거나, 사용 시 root 직접 접속을 차단한 경우 " >> $CREATE_FILE 2>&1
echo " 취약 : 원격 터미널 서비스 사용 시 root 직접 접속을 허용한 경우 " >> $CREATE_FILE 2>&1
echo " 취약 1. : Telnet 사용 시, /etc/default/login 파일에 CONSOLE=/dev/console이 없거나 주석처리 되어있을 경우 " >> $CREATE_FILE 2>&1
echo " 취약 2. : SSH 사용 시, /etc/ssh/sshd_config 파일에 PermitRootLogin yes로 설정되어 있을 경우 " >> $CREATE_FILE 2>&1
echo "******* 참고 사항 *******" >> $CREATE_FILE 2>&1
echo " 1. 'auth [user_unknown=ignore success=ok ignore=ignore default=bad] pam_securetty.so' 해당 설정 양호로 진단 (주석처리 주의)" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1

unset telnet_ps
unset login_set
unset console_chk
unset pts_chk
unset pam_chk
unset rlogin_chk
unset ssh_ps
unset ssh_permit
}

U-02(){
echo "[U-02] 패스워드 복잡성 설정"
echo "[U-02] 패스워드 복잡성 설정" >> $CREATE_FILE 2>&1
echo "[U-02_START]" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
case $OS in
	AIX)
		echo "/etc/security/user 현황" >> $CREATE_FILE 2>&1
		echo "[*] minlen 패스워드의 최소 길이" >> $CREATE_FILE 2>&1
		cat /etc/security/user | grep minlen >> $CREATE_FILE 2>&1
		echo "" >> $CREATE_FILE 2>&1
		echo "[*] minalpha 패스워드에 들어가는 알파벳 문자의 최소 개수" >> $CREATE_FILE 2>&1
		cat /etc/security/user | grep minalpha >> $CREATE_FILE 2>&1
		echo "" >> $CREATE_FILE 2>&1
		echo "[*] minother 패스워드에 알파벳을 제외하고 포함해야되는 문자의 개수" >> $CREATE_FILE 2>&1
		cat /etc/security/user | grep minother >> $CREATE_FILE 2>&1
		echo "" >> $CREATE_FILE 2>&1
	;;

	HP-UX)
		echo "1. /etc/default/security 현황" >> $CREATE_FILE 2>&1
		echo "[*] MIN_PASSWORD_LENGTH 최소 패스워드 길이 " >> $CREATE_FILE 2>&1
		cat /etc/default/security | grep MIN_PASSWORD_LENGTH >> $CREATE_FILE 2>&1
		echo "" >> $CREATE_FILE 2>&1
		echo "[*] PASSWORD_MIN_LOWER_CASE_CHARS 최소 소문자 개수 " >> $CREATE_FILE 2>&1
		cat /etc/default/security | grep PASSWORD_MIN_LOWER_CASE_CHARS >> $CREATE_FILE 2>&1
		echo "" >> $CREATE_FILE 2>&1
		echo "[*] PASSWORD_MIN_UPPER_CASE_CHARS 최소 대문자 개수 " >> $CREATE_FILE 2>&1
		cat /etc/default/security | grep PASSWORD_MIN_UPPER_CASE_CHARS >> $CREATE_FILE 2>&1
		echo "" >> $CREATE_FILE 2>&1
		echo "[*] PASSWORD_MIN_DIGIT_CHARS 최소 숫자 개수 " >> $CREATE_FILE 2>&1
		cat /etc/default/security | grep PASSWORD_MIN_DIGIT_CHARS >> $CREATE_FILE 2>&1
		echo "" >> $CREATE_FILE 2>&1
		echo "[*] PASSWORD_MIN_SPECIAL_CHARS 최소 특수문자 개수 " >> $CREATE_FILE 2>&1
		cat /etc/default/security | grep PASSWORD_MIN_SPECIAL_CHARS >> $CREATE_FILE 2>&1
		echo "" >> $CREATE_FILE 2>&1
		echo "2. /etc/default/security 현황" >> $CREATE_FILE 2>&1
		cat /tcb/files/auth/system/default >> $CREATE_FILE 2>&1
		echo "" >> $CREATE_FILE 2>&1
	;;
	
	Linux)
		echo "[+] 1. /etc/pam.d/system-auth 현황" >> $CREATE_FILE 2>&1
		if file_check "/etc/pam.d/system-auth"; then
			cat /etc/pam.d/system-auth | grep password >> $CREATE_FILE 2>&1
		else
			echo "파일이 존재하지 않습니다." >> $CREATE_FILE 2>&1
		fi
		echo "" >> $CREATE_FILE 2>&1
		
		echo "[+] 2. /etc/pam.d/common-password 현황" >> $CREATE_FILE 2>&1
		if file_check "/etc/pam.d/common-password"; then
			cat /etc/pam.d/common-password | grep password >> $CREATE_FILE 2>&1
		else
			echo "파일이 존재하지 않습니다." >> $CREATE_FILE 2>&1
		fi
		echo "" >> $CREATE_FILE 2>&1
		
		echo "[+] 3. 현황 : /etc/security/pwquality.conf 상세 내용" >> $CREATE_FILE 2>&1
		cat /etc/security/pwquality.conf | egrep "minlen|dcredit|ucredit|lcredit|ocredit|minclass">> $CREATE_FILE 2>&1
		echo "" >> $CREATE_FILE 2>&1
		
		echo "[+] 4. 현황 : /etc/login.defs 상세 내용" >> $CREATE_FILE 2>&1
		if file_check "/etc/login.defs"; then
			cat /etc/login.defs | grep PASS >> $CREATE_FILE 2>&1
		else
			echo "파일이 존재하지 않습니다." >> $CREATE_FILE 2>&1
		fi
		echo "" >> $CREATE_FILE 2>&1
	;;

	SunOS)
		echo "[+] 1. /etc/default/passwd 현황" >> $CREATE_FILE 2>&1
		echo "[*] MINALPHA 최소 알파벳 문자 수 (디폴트 값: 2)" >> $CREATE_FILE 2>&1
		cat /etc/default/passwd | grep MINALPHA >> $CREATE_FILE 2>&1
		echo "" >> $CREATE_FILE 2>&1
		echo "[*] MINDIGIT 최소 숫자 수 (디폴트는 없음)" >> $CREATE_FILE 2>&1
		cat /etc/default/passwd | grep MINDIGIT >> $CREATE_FILE 2>&1
		echo "" >> $CREATE_FILE 2>&1
		echo "[*] MINLOWER 최소 소문자 수 (디폴트는 없음)" >> $CREATE_FILE 2>&1
		cat /etc/default/passwd | grep MINLOWER >> $CREATE_FILE 2>&1
		echo "" >> $CREATE_FILE 2>&1
		echo "[*] MINNONALPHA 최소 숫자+특수문자 수 (디폴트는 1, MINDIGIT 과 MINSPECIAL 함께 사용 불가)" >> $CREATE_FILE 2>&1
		cat /etc/default/passwd | grep MINNONALPHA >> $CREATE_FILE 2>&1
		echo "" >> $CREATE_FILE 2>&1
		echo "[*] MINSPECIAL 최소 특수문자 수 (디폴트는 없음)" >> $CREATE_FILE 2>&1
		cat /etc/default/passwd | grep MINSPECIAL >> $CREATE_FILE 2>&1
		echo "" >> $CREATE_FILE 2>&1
		echo "[*] MINUPPER 최소 대문자 수 (디폴트는 없음)" >> $CREATE_FILE 2>&1
		cat /etc/default/passwd | grep MINUPPER >> $CREATE_FILE 2>&1
		echo "" >> $CREATE_FILE 2>&1
		echo "[*] PASSLENGTH 패스워드 최소 길이 " >> $CREATE_FILE 2>&1
		cat /etc/default/passwd | grep PASSLENGTH >> $CREATE_FILE 2>&1
		echo "" >> $CREATE_FILE 2>&1
		echo "[+] 2. /etc/default/passwd 현황" >> $CREATE_FILE 2>&1
		cat /etc/security/policy.conf >> $CREATE_FILE 2>&1
		echo "" >> $CREATE_FILE 2>&1
	;;
esac
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "[U-02_END]" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
echo "[참고 - 진단기준, 결과 값 출력]" >> $CREATE_FILE 2>&1
echo "[*] 주석처리 주의 " >> $CREATE_FILE 2>&1
echo "[*] ※ 정책 기준: 영문 숫자 특수문자 2개 조합 시 10자리 이상, 3개 조합 시 8자리 이상, 패스워드 변경 기간 90일 이하" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
case $OS in 
	Linux)
		echo "[*] 1-1.참고 : /etc/pam.d/system-auth 진단" >> $CREATE_FILE 2>&1	
		echo "[*] 1-2.예시: password requisite pam_cracklib.so try_first_pass retry=3 type= minlen=8 dcredit=-1 ucredit=-1 lcredit=-1 ocredit=-1" >> $CREATE_FILE 2>&1
		echo "[*] 2-1.참고 : /etc/pam.d/common-password 진단" >> $CREATE_FILE 2>&1
		echo "[*] 2-2.패스워드 길이 확인 : password [success=2 default=ignore] pam_unix.so obscure sha512 minlen=8" >> $CREATE_FILE 2>&1
		echo "2-3.패스워드 복잡도 확인 : password requisite pam_pwquality.so retry=3 lcredit=-1 ucredit=-1 dcredit=-1 ocredit=-1" >> $CREATE_FILE 2>&1
		echo "[*] 3-1.참고 : /etc/security/pwquality.conf 진단" >> $CREATE_FILE 2>&1
		echo "[*] 3-2.예시 : lcredit, ucredit, dcredit, ocredit 값 확인" >> $CREATE_FILE 2>&1
esac
echo " * 양호 기준 : 패스워드 최소길이 8자리 이상, 영문·숫자·특수문자 최소 입력 기능이 설정된 경우 또는 내부 정책에 맞게 설정된 경우" >> $CREATE_FILE 2>&1
echo " * 취약 기준 : 패스워드 최소길이 8자리 이상, 영문·숫자·특수문자 최소 입력 기능이 설정된 경우" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
}

U-03(){
echo "[U-03] 계정 잠금 임계값 설정"
echo "[U-03] 계정 잠금 임계값 설정" >> $CREATE_FILE 2>&1
echo "[U-03_START]" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
case $OS in
		AIX)
			echo "[+] 1. 현황 : /etc/security/user 설정 " >> $CREATE_FILE 2>&1
			cat /etc/security/user | grep -i loginretries >> $CREATE_FILE 2>&1
			echo "" >> $CREATE_FILE 2>&1
		;;

		HP-UX)
			echo "[+] 1. 현황 : Trust Mode 일 경우" >> $CREATE_FILE 2>&1
			cat /tcb/files/auth/system/default | grep u_maxtries >> $CREATE_FILE 2>&1
			echo "" >> $CREATE_FILE 2>&1
			echo "[+] 2. 현황 : Non Trust Mode 일 경우" >> $CREATE_FILE 2>&1
			cat /etc/default/security | grep -i MAXTRIES >> $CREATE_FILE 2>&1
			cat /var/adm/userdb/* | grep -i MAXTRIES >> $CREATE_FILE 2>&1
			echo "" >> $CREATE_FILE 2>&1
			;;
		Linux)
			echo "[+] 1. 현황 : /etc/pam.d/password-auth" >> $CREATE_FILE 2>&1
			cat /etc/pam.d/password-auth >> $CREATE_FILE 2>&1
			echo "" >> $CREATE_FILE 2>&1
			echo "[+] 2. 현황 : /etc/pam.d/common-auth" >> $CREATE_FILE 2>&1
			if [ -f /etc/pam.d/common-auth ]; then
				cat /etc/pam.d/common-auth >> $CREATE_FILE 2>&1
			else
				echo "/etc/pam.d/common-auth 파일이 존재하지 않습니다." >> $CREATE_FILE 2>&1
			fi
			echo "" >> $CREATE_FILE 2>&1
			echo "[+] 3. 현황 : /etc/pam.d/system-auth" >> $CREATE_FILE 2>&1
			cat /etc/pam.d/system-auth >> $CREATE_FILE 2>&1
			echo "" >> $CREATE_FILE 2>&1
			echo "[+] 4. 8/9 버전 인경우 : /etc/security/faillock.conf " >> $CREATE_FILE 2>&1
			cat /etc/security/faillock.conf >> $CREATE_FILE 2>&1
			echo "" >> $CREATE_FILE 2>&1
			;;
		SunOS)
			echo "[+] 1. 현황 : /etc/security/policy.conf" >> $CREATE_FILE 2>&1
			cat /etc/security/policy.conf | grep -i RETRIES >> $CREATE_FILE 2>&1
			echo "" >> $CREATE_FILE 2>&1
			echo "[+] 2. 현황 : /etc/default/login" >> $CREATE_FILE 2>&1
			cat /etc/default/login | grep -i RETRIES >> $CREATE_FILE 2>&1
			echo "" >> $CREATE_FILE 2>&1
			;;
	esac
echo "" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
echo "[U-03_END]" >> $CREATE_FILE 2>&1
echo "[참고 - 진단기준, 결과 값 출력]" >> $CREATE_FILE 2>&1
case $OS in
		AIX)
			echo "[*] 판단기준(양호) : loginretries가 설정 되어 있을 경우" >> $CREATE_FILE 2>&1
			echo "[*] 판단기준(취약) : loginretries가 설정 되어 있지 않을 경우 (단, root 제외)" >> $CREATE_FILE 2>&1
			echo "" >> $CREATE_FILE 2>&1
			;;
		HP-UX)
			echo "[*] 판단기준(양호) : u_maxtries(Trusted Mode) 또는 AUTH_MAXTRIES(Non Trusted Mode)가 설정되어 있을 경우" >> $CREATE_FILE 2>&1
			echo "[*] 판단기준(취약) :  u_maxtries(Trusted Mode) 또는 AUTH_MAXTRIES(Non Trusted Mode)가 설정되어 있지 않을 경우" >> $CREATE_FILE 2>&1
			echo "" >> $CREATE_FILE 2>&1
			;;
		Linux)
			echo "[*] 판단기준(양호) : /etc/pam.d/password-auth 파일과 /etc/pam.d/system-auth 파일에 계정 잠금 임계값 설정이 존재하는 경우" >> $CREATE_FILE 2>&1
			echo "[*] 판단기준(취약) : /etc/pam.d/password-auth 파일과 /etc/pam.d/system-auth 파일에 계정 잠금 임계값 설정이 존재하지 않는 경우" >> $CREATE_FILE 2>&1
			echo "" >> $CREATE_FILE 2>&1
			echo "=== 판단 기준 참고 ===" >> $CREATE_FILE 2>&1
			echo "(1) pam_faillock.so 활용 시" >> $CREATE_FILE 2>&1
			echo "auth     required       pam_faillock.so preauth silent audit deny=3 unlock_time=600" >> $CREATE_FILE 2>&1
			echo "auth     [success=1 default=ignore]     pam_unix.so nullok_secure" >> $CREATE_FILE 2>&1
			echo "auth     [default=die]  pam_faillock.so authfail audit deny=3 unlock_time=600" >> $CREATE_FILE 2>&1
			echo "account  required       pam_faillock.so" >> $CREATE_FILE 2>&1
			echo "" >> $CREATE_FILE 2>&1
			echo "(2) pam_tally2.so 활용 시" >> $CREATE_FILE 2>&1
			echo "auth        required      pam_tally2.so deny=5 onerr=fail unlock_time=600" >> $CREATE_FILE 2>&1
			echo "account     required      pam_tally2.so" >> $CREATE_FILE 2>&1
			echo "" >> $CREATE_FILE 2>&1
			echo "(3) pam_tally.so 활용 시" >> $CREATE_FILE 2>&1
			echo "auth        required      pam_tally.so deny=5 onerr=fail unlock_time=600" >> $CREATE_FILE 2>&1
			echo "account     required      pam_tally.so" >> $CREATE_FILE 2>&1
			echo "" >> $CREATE_FILE 2>&1
			echo "(4) RHEL 8 경우" >> $CREATE_FILE 2>&1
			echo "/etc/security/faillock.conf 우선 적용" >> $CREATE_FILE 2>&1
			echo "deny = 5" >> $CREATE_FILE 2>&1
			echo "unlock_time = 600" >> $CREATE_FILE 2>&1
			echo "" >> $CREATE_FILE 2>&1
			echo "=================" >> $CREATE_FILE 2>&1
			;;
		SunOS)
			echo "[*] 판단기준(양호) : /etc/security/policy.conf 파일과 /etc/default/login 파일에 계정 잠금 임계값 설정이 존재하는 경우" >> $CREATE_FILE 2>&1
			echo "[*] 판단기준(취약) : /etc/security/policy.conf 파일과 /etc/default/login 파일에 계정 잠금 임계값 설정이 존재하지 않는 경우" >> $CREATE_FILE 2>&1
			echo "" >> $CREATE_FILE 2>&1
			;;
	esac
echo "=============================================" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
}

U-04(){
echo "[U-04] 패스워드 파일 보호"
echo "[U-04] 패스워드 파일 보호" >> $CREATE_FILE 2>&1
echo "[U-04_START]" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
echo "[+] 현황" >> $CREATE_FILE 2>&1

case $OS in
		SunOS)
			echo "[+] 1. 현황 : ls -al /etc/passwd /etc/shadow" >> $CREATE_FILE 2>&1
			ls -al /etc/passwd /etc/shadow  >> $CREATE_FILE 2>&1
			echo "" >> $CREATE_FILE 2>&1
			echo "[+] 2. 현황 : /etc/passwd" >> $CREATE_FILE 2>&1
			cat /etc/passwd >> $CREATE_FILE 2>&1
			echo "" >> $CREATE_FILE 2>&1
			echo "[+] 3. 현황 : /etc/shadow" >> $CREATE_FILE 2>&1
			cat /etc/shadow >> $CREATE_FILE 2>&1
			echo "" >> $CREATE_FILE 2>&1
			;;
		Linux)
			echo "[+] 1. 현황 : ls -al /etc/passwd /etc/shadow" >> $CREATE_FILE 2>&1
			ls -al /etc/passwd /etc/shadow  >> $CREATE_FILE 2>&1
			echo "" >> $CREATE_FILE 2>&1
			echo "[+] 2. 현황 : /etc/passwd 상세 내용" >> $CREATE_FILE 2>&1
			cat /etc/passwd >> $CREATE_FILE 2>&1
			echo "" >> $CREATE_FILE 2>&1
			echo "[+] 3. 현황 : /etc/shadow 상세 내용" >> $CREATE_FILE 2>&1
			cat /etc/shadow >> $CREATE_FILE 2>&1
			echo "" >> $CREATE_FILE 2>&1
			;;
		AIX)
			echo "[+] 1. 현황 : ls -al /etc/passwd /etc/shadow /etc/security/passwd" >> $CREATE_FILE 2>&1
			ls -al /etc/passwd /etc/shadow /etc/security/passwd >> $CREATE_FILE 2>&1
			echo "" >> $CREATE_FILE 2>&1
			echo "[+] 2. 현황 : cat /etc/passwd" >> $CREATE_FILE 2>&1
			cat /etc/passwd >> $CREATE_FILE 2>&1
			echo "" >> $CREATE_FILE 2>&1
			echo "[+] 3. 현황 : /etc/shadow" >> $CREATE_FILE 2>&1
			cat /etc/shadow >> $CREATE_FILE 2>&1
			echo "" >> $CREATE_FILE 2>&1
			echo "[+] 4. 현황 : /etc/security/passwd" >> $CREATE_FILE 2>&1
			cat /etc/security/passwd >> $CREATE_FILE 2>&1
			echo "" >> $CREATE_FILE 2>&1
			;;
		HP-UX)
			echo "[+] 1. 현황 : ls -al /etc/passwd /etc/shadow" >> $CREATE_FILE 2>&1
			ls -al /etc/passwd /etc/shadow  >> $CREATE_FILE 2>&1
			echo "" >> $CREATE_FILE 2>&1
			echo "[+] 2. 현황 : cat /etc/passwd" >> $CREATE_FILE 2>&1
			cat /etc/passwd >> $CREATE_FILE 2>&1
			echo "" >> $CREATE_FILE 2>&1
			echo "[+] 3. 현황 : cat /etc/shadow" >> $CREATE_FILE 2>&1
			cat /etc/shadow >> $CREATE_FILE 2>&1
			echo "" >> $CREATE_FILE 2>&1
			echo "[+] 4. 현황 : cat /tcb/files/auth" >> $CREATE_FILE 2>&1
			cat /tcb/files/auth >> $CREATE_FILE 2>&1
			echo "" >> $CREATE_FILE 2>&1
			;;
	esac

echo "[U-04_END]" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
echo "[참고 - 진단기준, 결과 값 출력]" >> $CREATE_FILE 2>&1
echo "[*] 두번째 필드가 x 표시되어 있는지 확인" >> $CREATE_FILE 2>&1
echo " * 양호 - shadow 패스워드를 사용하거나, 패스워드를 암호화하여 저장하는 경우" >> $CREATE_FILE 2>&1
echo " * 취약 - shadow 패스워드를 사용하지 않고, 패스워드를 암호화하여 저장하지 앟는 경우" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
}

U-44(){
echo "[U-44] root 이외의 UID가 ‘0’금지"
echo "[U-44] root 이외의 UID가 ‘0’금지" >> $CREATE_FILE 2>&1
echo "[U-44_START]" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
passwdUID=`cat /etc/passwd | awk -F: '{ print $3 }'`

echo "[+] 1. 현황 : /etc/passwd에서 UID 추출" >> $CREATE_FILE 2>&1
awk -F: '{print $1 " = " $3}' /etc/passwd >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1

for pt1 in $passwdUID
do
	for gt1 in $passwdUID
	do
		if [ $pt1 -eq $gt1 ]
			then
				count2=`expr $count2 + 1`
		fi
	done
done
echo "[+] 2. 국정원 점검용 GID 최소한의 사용자만 등록되어 있는지 확인 (GID가 0인 계정 추출)" >> $CREATE_FILE 2>&1
awk -F: '$4==0 { print $1 " -> GID=" $4 }' /etc/passwd >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
echo "[U-44_END]" >> $CREATE_FILE 2>&1
echo "[참고 - 진단기준, 결과 값 출력]" >> $CREATE_FILE 2>&1
echo " * 양호 조건 : root 계정과 동일한 UID를 갖는 계정이 존재하지 않는 경우" >> $CREATE_FILE 2>&1
echo " * 취약 조건 : root 계정과 동일한 UID를 갖는 계정이 존재하는 경우" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1

unset passwdUID

}

U-45(){
echo "[U-45] root 계정 su 제한"
echo "[U-45] root 계정 su 제한" >> $CREATE_FILE 2>&1
echo "[U-45_START]" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
case $OS in
	SunOS)
		echo "[+] 1. 현황 : /usr/bin/su 여부 " >> $CREATE_FILE 2>&1
		if [ -s /usr/bin/su ]
		then
			echo "[+] /usr/bin/su 확인 " >> $CREATE_FILE 2>&1
			ls -al /usr/bin/su >> $CREATE_FILE 2>&1
			sunsugroup=`ls -al /usr/bin/su | awk '{print $4}'`;
			echo "" >> $CREATE_FILE 2>&1
		else
			echo "[+] /usr/bin/su 파일을 찾을 수 없습니다."     		>> $CREATE_FILE 2>&1
			echo "" >> $CREATE_FILE 2>&1
		fi
		echo "[+] 2. 현황 : su파일의 group 확인 " >> $CREATE_FILE 2>&1
		cat /etc/group | grep -w $sunsugroup >> $CREATE_FILE 2>&1
		echo "" >> $CREATE_FILE 2>&1
		;;
		
	Linux)
		echo "[+] 1. 현황 : /etc/pam.d/su 설정 확인" >> $CREATE_FILE 2>&1
		cat /etc/pam.d/su >> $CREATE_FILE 2>&1
		echo "" >> $CREATE_FILE 2>&1
		echo "[+] 2. 현황 : /bin/su의 others 여부" >> $CREATE_FILE 2>&1
		if [ -s /bin/su ]
		then
			echo "[+] /bin/su의 others 확인" >> $CREATE_FILE 2>&1
			ls -al /bin/su >> $CREATE_FILE 2>&1
			echo "" >> $CREATE_FILE 2>&1
		else
			echo "[+] /bin/su 파일을 찾을 수 없습니다." >> $CREATE_FILE 2>&1
			echo "" >> $CREATE_FILE 2>&1
		fi
		echo "[+] 3. 현황 : group 확인" >> $CREATE_FILE 2>&1
		cat /etc/group >> $CREATE_FILE 2>&1
		;;
	
	AIX)
	echo "[+] 1. 현황 : /etc/security/user 파읠의 sugroups 설정 확인 " >> $CREATE_FILE 2>&1
	cat /etc/security/user >> $CREATE_FILE 2>&1
	echo "" >> $CREATE_FILE 2>&1
	echo "[+] 2. 현황 : /usr/bin/su 여부 " >> $CREATE_FILE 2>&1
	if [ -s /usr/bin/su ]
		then
			echo "[+] /usr/bin/su 확인 " >> $CREATE_FILE 2>&1
			ls -al /usr/bin/su   >> $CREATE_FILE 2>&1	
			echo "" >> $CREATE_FILE 2>&1
		else
			echo "[+] /usr/bin/su 파일을 찾을 수 없습니다." >> $CREATE_FILE 2>&1
			echo "" >> $CREATE_FILE 2>&1
	fi
	echo "[+] 3. 현황 : group 확인" >> $CREATE_FILE 2>&1
	cat /etc/group >> $CREATE_FILE 2>&1	
	;;
	
	HP-UX)
	echo "[+] 1. 현황 : /etc/defualt/security의 SU_ROOT_GROUP 설정값 확인" >> $CREATE_FILE 2>&1
	cat /etc/default/security >> $CREATE_FILE 2>&1
	echo "" >> $CREATE_FILE 2>&1

	echo "[+] 2. 현황 : /usr/bin/su의 others 여부" >> $CREATE_FILE 2>&1
	if [ -s /usr/bin/su ]
		then
			echo "[+] /usr/bin/su의 others 확인" >> $CREATE_FILE 2>&1
			ls -al /usr/bin/su >> $CREATE_FILE 2>&1
		else
			echo "[+] /usr/bin/su 파일을 찾을 수 없습니다." >> $CREATE_FILE 2>&1
	fi
	echo "[+] 3. 현황 : group 확인" >> $CREATE_FILE 2>&1
	cat /etc/group >> $CREATE_FILE 2>&1
	;;
esac
echo "=============================================" >> $CREATE_FILE 2>&1
echo "[U-45_END]" >> $CREATE_FILE 2>&1
echo "[참고 - 진단기준, 결과 값 출력]" >> $CREATE_FILE 2>&1
case $OS in
	SunOS)
		echo "[*] 판단기준(양호) : /usr/bin/su 명령어에 others 실행 권한이 없고, 소유자 그룹이 적절하게 설정된 경우" >> $CREATE_FILE 2>&1
		echo "[*] 판단기준(취약) : /usr/bin/su 명령어에 others 실행 권한이 있거나, 소유자 그룹이 부적절하게 설정된 경우" >> $CREATE_FILE 2>&1
		echo "" >> $CREATE_FILE 2>&1
		;;
	Linux)
		echo "[*] 판단기준(양호) : /etc/pam.d/su 파일에 auth required pam_wheel.so use_uid 라인이 존재하는 경우" >> $CREATE_FILE 2>&1
		echo "[*] 판단기준(취약) : /etc/pam.d/su 파일에 auth required pam_wheel.so use_uid 라인이 존재하지 않거나 주석 처리 되어 있는 경우" >> $CREATE_FILE 2>&1
		echo "" >> $CREATE_FILE 2>&1
		;;
	
	AIX)
		echo "[*] 판단기준(양호) : root : 'sugroups' 에 su 를 허용할 그룹 지정 시 양호 (root: 가 없을 시 default 설정 확인)" >> $CREATE_FILE 2>&1
		echo "[*] 판단기준(취약) : root : 'sugroups' 에 ALL 이면 취약 (root: 가 없을 시 default 설정 확인)" >> $CREATE_FILE 2>&1
		echo "" >> $CREATE_FILE 2>&1
		;;
	
	HP-UX)
		echo "[*] 판단기준(양호) : /etc/default/security 파일에서 SU_ROOT_GROUP 파라미터에 su 명령어를 사용할 그룹이 지정되어 있을 시" >> $CREATE_FILE 2>&1
		echo "[*] 판단기준(취약) : /etc/default/security 파일에서 SU_ROOT_GROUP 파라미터에 su 명령어를 사용할 그룹이 지정되어 있지 않거나 ALL 이면 취약" >> $CREATE_FILE 2>&1
		echo "" >> $CREATE_FILE 2>&1
		;;
esac
echo "=============================================" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
}

U-46(){
echo "[U-46] 패스워드 최소 길이 설정"
echo "[U-46] 패스워드 최소 길이 설정" >> $CREATE_FILE 2>&1
echo "[U-46_START]" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
case $OS in
	AIX)
		echo "[+] /etc/security/user 현황" >> $CREATE_FILE 2>&1
		echo "[*] minlen 패스워드의 최소 길이" >> $CREATE_FILE 2>&1
		cat /etc/security/user | grep minlen >> $CREATE_FILE 2>&1
		echo "" >> $CREATE_FILE 2>&1
	;;

	HP-UX)
		echo "1. /etc/default/security 현황" >> $CREATE_FILE 2>&1
		echo "[*] MIN_PASSWORD_LENGTH 최소 패스워드 길이 " >> $CREATE_FILE 2>&1
		cat /etc/default/security | grep MIN_PASSWORD_LENGTH >> $CREATE_FILE 2>&1
		echo "" >> $CREATE_FILE 2>&1
		echo "2. /etc/default/security 현황" >> $CREATE_FILE 2>&1
		cat /tcb/files/auth/system/default >> $CREATE_FILE 2>&1
		echo "" >> $CREATE_FILE 2>&1
	;;
	
	Linux)
		echo "[+] 1. /etc/pam.d/system-auth 현황" >> $CREATE_FILE 2>&1
		cat /etc/pam.d/system-auth >> $CREATE_FILE 2>&1
		echo "" >> $CREATE_FILE 2>&1
		echo "[+] 2. /etc/pam.d/common-password 현황" >> $CREATE_FILE 2>&1
		cat /etc/pam.d/common-password >> $CREATE_FILE 2>&1
		echo "" >> $CREATE_FILE 2>&1
		echo "[+] 3. 현황 : /etc/security/pwquality.conf 상세 내용" >> $CREATE_FILE 2>&1
		cat /etc/security/pwquality.conf >> $CREATE_FILE 2>&1
		echo "" >> $CREATE_FILE 2>&1
		echo "[+] 4. 현황 : /etc/login.defs 상세 내용" >> $CREATE_FILE 2>&1
		cat /etc/login.defs >> $CREATE_FILE 2>&1
		echo "" >> $CREATE_FILE 2>&1
		echo "[+] 4-1. 현황 : PASS_MIN_LEN 내용" >> $CREATE_FILE 2>&1
		cat /etc/login.defs | grep PASS_MIN_LEN >> $CREATE_FILE 2>&1
		echo "" >> $CREATE_FILE 2>&1
	;;

	SunOS)
		echo "[+] 1. /etc/default/passwd 현황" >> $CREATE_FILE 2>&1
		echo "[*] PASSLENGTH 패스워드 최소 길이 " >> $CREATE_FILE 2>&1
		cat /etc/default/passwd | grep PASSLENGTH
		echo "" >> $CREATE_FILE 2>&1
		echo "[+] 2. /etc/default/passwd 현황" >> $CREATE_FILE 2>&1
		cat /etc/security/policy.conf >> $CREATE_FILE 2>&1
		echo "" >> $CREATE_FILE 2>&1
	;;
esac
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "[U-46_END]" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
echo "[참고 - 진단기준, 결과 값 출력]" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo " * 양호 기준 : 패스워드 최소 길이가 8자 이상으로 설정되어 있는 경우" >> $CREATE_FILE 2>&1
echo " * 취약 기준 : 패스워드 최소 길이가 8자 미만으로 설정되어 있는 경우 " >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
}

U-47(){
echo "[U-47] 패스워드 최대 사용기간 설정"
echo "[U-47] 패스워드 최대 사용기간 설정" >> $CREATE_FILE 2>&1
echo "[U-47_START]" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
case $OS in
	AIX)
		echo "[+] /etc/security/user 현황" >> $CREATE_FILE 2>&1
		echo "[*] maxage 패스워드 변경 후 사용할 수 있는 최대 기간(단위: 주)" >> $CREATE_FILE 2>&1
		cat /etc/security/user | grep maxage >> $CREATE_FILE 2>&1
		echo "" >> $CREATE_FILE 2>&1
	;;

	HP-UX)
		echo "1. /etc/default/security 현황" >> $CREATE_FILE 2>&1
		echo "[*] PASSWORD_MAXDAYS 패스워드 유효 기간(단위: 일) " >> $CREATE_FILE 2>&1
		cat /etc/default/security | grep PASSWORD_MAXDAYS >> $CREATE_FILE 2>&1
		echo "" >> $CREATE_FILE 2>&1
		echo "2. /etc/default/security 현황" >> $CREATE_FILE 2>&1
		cat /tcb/files/auth/system/default >> $CREATE_FILE 2>&1
		echo "" >> $CREATE_FILE 2>&1
	;;
	
	Linux)
		echo "[+] 1. /etc/pam.d/system-auth 현황" >> $CREATE_FILE 2>&1
		cat /etc/pam.d/system-auth >> $CREATE_FILE 2>&1
		echo "" >> $CREATE_FILE 2>&1
		echo "[+] 2. /etc/pam.d/common-password 현황" >> $CREATE_FILE 2>&1
		if file_check "/etc/pam.d/common-password"; then
			cat /etc/pam.d/common-password >> $CREATE_FILE 2>&1
		else
			echo "파일이 존재하지 않습니다." >> $CREATE_FILE 2>&1
		fi
		echo "" >> $CREATE_FILE 2>&1
		echo "[+] 3. 현황 : /etc/security/pwquality.conf 상세 내용" >> $CREATE_FILE 2>&1
		cat /etc/security/pwquality.conf >> $CREATE_FILE 2>&1
		echo "" >> $CREATE_FILE 2>&1
		echo "[+] 4. 현황 : /etc/login.defs 상세 내용" >> $CREATE_FILE 2>&1
		cat /etc/login.defs >> $CREATE_FILE 2>&1
		echo "" >> $CREATE_FILE 2>&1
		echo "[+] 4-1. 현황 : PASS_MAX_DAYS 내용" >> $CREATE_FILE 2>&1
		cat /etc/login.defs | grep PASS_MAX_DAYS >> $CREATE_FILE 2>&1
		echo "" >> $CREATE_FILE 2>&1
	;;

	SunOS)
		echo "[+] 1. /etc/default/passwd 현황" >> $CREATE_FILE 2>&1
		echo "[*] MAXWEEKS 패스워드 유효기간(단위: 주) " >> $CREATE_FILE 2>&1
		cat /etc/default/passwd | grep MAXWEEKS
		echo "" >> $CREATE_FILE 2>&1
		echo "[+] 2. /etc/default/passwd 현황" >> $CREATE_FILE 2>&1
		cat /etc/security/policy.conf >> $CREATE_FILE 2>&1
		echo "" >> $CREATE_FILE 2>&1
	;;
esac
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "[U-47_END]" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
echo "[참고 - 진단기준, 결과 값 출력]" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo " * 양호 기준 : 패스워드 최대 사용기간이 90일(12주) 이하로 설정되어 있는 경우" >> $CREATE_FILE 2>&1
echo " * 취약 기준 : 패스워드 최대 사용기간이 90일(12주) 이하로 설정되어 있지 않는 경우" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
}

U-48(){
echo "[U-48] 패스워드 최소 사용기간 설정"
echo "[U-48] 패스워드 최소 사용기간 설정" >> $CREATE_FILE 2>&1
echo "[U-48_START]" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
case $OS in
	AIX)
		echo "[+] /etc/security/user 현황" >> $CREATE_FILE 2>&1
		echo "[*] minage 패스워드 변경 후 사용해야 하는 최소 기간" >> $CREATE_FILE 2>&1
		cat /etc/security/user | grep minage >> $CREATE_FILE 2>&1
		echo "" >> $CREATE_FILE 2>&1
	;;

	HP-UX)
		echo "1. /etc/default/security 현황" >> $CREATE_FILE 2>&1
		echo "[*] MINDAYS 패스워드 변경 후 사용해야 하는 최소 기간 " >> $CREATE_FILE 2>&1
		cat /etc/default/security | grep PASSWORD_MINDAYS >> $CREATE_FILE 2>&1
		echo "" >> $CREATE_FILE 2>&1
		echo "2. /etc/default/security 현황" >> $CREATE_FILE 2>&1
		cat /tcb/files/auth/system/default >> $CREATE_FILE 2>&1
		echo "" >> $CREATE_FILE 2>&1
	;;
	
	Linux)
		echo "[+] 1. /etc/pam.d/system-auth 현황" >> $CREATE_FILE 2>&1
		cat /etc/pam.d/system-auth >> $CREATE_FILE 2>&1
		echo "" >> $CREATE_FILE 2>&1
		echo "[+] 2. /etc/pam.d/common-password 현황" >> $CREATE_FILE 2>&1
		if file_check "/etc/pam.d/common-password"; then
			cat /etc/pam.d/common-password >> $CREATE_FILE 2>&1
		else
			echo "파일이 존재하지 않습니다." >> $CREATE_FILE 2>&1
		fi
		echo "" >> $CREATE_FILE 2>&1
		echo "[+] 3. 현황 : /etc/security/pwquality.conf 상세 내용" >> $CREATE_FILE 2>&1
		cat /etc/security/pwquality.conf >> $CREATE_FILE 2>&1
		echo "" >> $CREATE_FILE 2>&1
		echo "[+] 4. 현황 : /etc/login.defs 상세 내용" >> $CREATE_FILE 2>&1
		cat /etc/login.defs >> $CREATE_FILE 2>&1
		echo "" >> $CREATE_FILE 2>&1
		echo "[+] 4-1. 현황 : PASS_MIN_DAYS 내용" >> $CREATE_FILE 2>&1
		cat /etc/login.defs | grep PASS_MIN_DAYS >> $CREATE_FILE 2>&1
		echo "" >> $CREATE_FILE 2>&1
	;;

	SunOS)
		echo "[+] 1. /etc/default/passwd 현황" >> $CREATE_FILE 2>&1
		echo "[*] MINWEEKS 패스워드 변경 후 사용해야 하는 최소 기간 " >> $CREATE_FILE 2>&1
		cat /etc/default/security | grep PASSWORD_MINWEEKS >> $CREATE_FILE 2>&1
		echo "" >> $CREATE_FILE 2>&1
		echo "[+] 2. /etc/default/passwd 현황" >> $CREATE_FILE 2>&1
		cat /etc/security/policy.conf >> $CREATE_FILE 2>&1
		echo "" >> $CREATE_FILE 2>&1
	;;
esac
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "[U-48_END]" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
echo "[참고 - 진단기준, 결과 값 출력]" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo " * 양호 기준 : 영문 숫자 특수문자 2개 조합 시 10자리 이상, 3개 조합 시 8자리 이상, 패스워드 변경 기간 90일 이하 또는 내부 정책에 맞게 설정된 경우" >> $CREATE_FILE 2>&1
echo " * 취약 기준 : 비밀번호 조합규칙 및 길이 미흡, 패스워드 변경 기간 90 이상인 경우" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
}

U-49(){
echo "[U-49] 불필요한 계정 제거"
echo "[U-49] 불필요한 계정 제거" >> $CREATE_FILE 2>&1
echo "[U-49_START]" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
	echo "[+] 1. 현황 : /etc/passwd 내 활성화 계정만 출력함" >> $CREATE_FILE 2>&1
	cat /etc/passwd | awk -F":" '{print $1 "\t" $7}' | egrep -Evi "nologin|false" >> $CREATE_FILE 2>&1
	echo "" >> $CREATE_FILE 2>&1
	echo "[+] 2. 현황 : 전체 계정의 접속 기록 중 활성화 계정만 출력함" >> $CREATE_FILE 2>&1
	a=`cat /etc/passwd | egrep -Evi "nologin|false" | awk -F":" '{print $1}'`
	for file in $a
	do 
		echo $file >> $CREATE_FILE 2>&1
		echo "" >> $CREATE_FILE 2>&1
		#head -2 하는 이유는 첫줄은 공백이 올수도 있어서 2줄로 잡았음
		last $file | head -2 >> $CREATE_FILE 2>&1
		echo "" >> $CREATE_FILE 2>&1
		chage -l $file >> $CREATE_FILE 2>&1
		echo "" >> $CREATE_FILE 2>&1
	done
echo "=============================================" >> $CREATE_FILE 2>&1
echo "[U-49_END]" >> $CREATE_FILE 2>&1
echo "[참고 - 진단기준, 결과 값 출력]" >> $CREATE_FILE 2>&1
echo " * 양호 조건 : 분기별 1회 이상 로그인 한 기록이 있고, 비밀번호를 변경하고 있는 경우" >> $CREATE_FILE 2>&1
echo " * 취약 조건 : 분기별 1회 이상 로그인 한 기록이 없거나, 비밀번호를 변경하지 않은 경우" >> $CREATE_FILE 2>&1
echo "[*] 기준에 부합하지 않는 계정 존재 확인 (분기별 1회 이상 로그인 또는 패스워드 변경)" >> $CREATE_FILE 2>&1
echo "[*] 마지막 로그인 시간 확인" >> $CREATE_FILE 2>&1
echo "[*] 마지막 패스워드 변경 시간 확인" >> $CREATE_FILE 2>&1

echo "=============================================" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1

unset =a
}

U-50(){
echo "[U-50] 관리자 그룹에 최소한의 계정 포함"
echo "[U-50] 관리자 그룹에 최소한의 계정 포함" >> $CREATE_FILE 2>&1
echo "[U-50_START]" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
echo "[+] 1. 현황 : root가 포함된 group 확인" >> $CREATE_FILE 2>&1
cat /etc/group | grep root >> $CREATE_FILE 2>&1 
echo "" >> $CREATE_FILE 2>&1
echo "[+] 2. 현황 : /etc/group 파일 확인" >> $CREATE_FILE 2>&1
cat /etc/group >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
echo "[U-50_END]" >> $CREATE_FILE 2>&1
echo "[참고 - 진단기준, 결과 값 출력]" >> $CREATE_FILE 2>&1
echo " * 양호 조건 : 관리자 그룹에 불필요한 관리자 계정이 없을 경우" >> $CREATE_FILE 2>&1
echo " * 취약 조건 : 관리자 그룹에 불필요한 관리자 계정이 있을 경우" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
}

U-51(){
echo "[U-51] 계정이 존재하지 않는 GID 금지"
echo "[U-51] 계정이 존재하지 않는 GID 금지" >> $CREATE_FILE 2>&1
echo "[U-51_START]" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
echo "[+] 1. 현황 : /etc/group 그룹 확인"  >> $CREATE_FILE 2>&1
cat /etc/group >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "[+] 2. 현황 : /etc/passwd 확인" >> $CREATE_FILE 2>&1
cat /etc/passwd >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
if [ $OS = Linux ]
then 
	echo "[+] 3. 현황 : /etc/gshadow 확인" >> $CREATE_FILE 2>&1	
	cat /etc/gshadow >> $CREATE_FILE 2>&1
	echo "" >> $CREATE_FILE 2>&1
fi
echo "=============================================" >> $CREATE_FILE 2>&1
echo "[U-51_END]" >> $CREATE_FILE 2>&1
echo "[참고 - 진단기준, 결과 값 출력]" >> $CREATE_FILE 2>&1
echo " * 양호 조건 : 구성원이 존재하지 않는 GID가 존재하지 않는 경우" >> $CREATE_FILE 2>&1
echo " * 취약 조건 : 구성원이 존재하지 않는 GID가 존재하는 경우" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
}

U-52(){
echo "[U-52] 동일한 UID 금지"
echo "[U-52] 동일한 UID 금지" >> $CREATE_FILE 2>&1
echo "[U-52_START]" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
passwdUID=`cat /etc/passwd | awk -F: '{ print $3 }'`
count2=0

echo "[+] 1. 현황 : /etc/passwd에서 UID 추출" >> $CREATE_FILE 2>&1
awk -F: '{print $1 " = " $3}' /etc/passwd >> $CREATE_FILE 2>&1
for pt1 in $passwdUID
do
	for gt1 in $passwdUID
	do
		if [ $pt1 -eq $gt1 ]
			then
				count2=`expr $count2 + 1`
		fi
	done
done
echo "" >> $CREATE_FILE 2>&1
echo "[+] 2. 중복된 UID 확인" >> $CREATE_FILE 2>&1
if [ $count2 -eq `cat /etc/passwd | wc -l` ]
	then
		echo "" >> $CREATE_FILE 2>&1
		echo "[+] 중복된 UID가 존재하지 않습니다." >> $CREATE_FILE 2>&1
	else
		echo "" >> $CREATE_FILE 2>&1
		echo "[+] 중복된 UID가 존재합니다." >> $CREATE_FILE 2>&1
fi

echo "" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
echo "[U-52_END]" >> $CREATE_FILE 2>&1
echo "[참고 - 진단기준, 결과 값 출력]" >> $CREATE_FILE 2>&1
echo " * 양호 조건 : 동일한 UID로 설정된 사용자 계정이 존재하지 않는 경우" >> $CREATE_FILE 2>&1
echo " * 취약 조건 : 동일한 UID로 설정된 사용자 계정이 존재하는 경우" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1


unset passwdUID
unset count2
}

U-53(){
echo "[U-53] 사용자 shell 점검"
echo "[U-53] 사용자 shell 점검" >> $CREATE_FILE 2>&1
echo "[U-53_START]" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
echo "[+] 활성화 계정 중 불필요한 계정 확인." >> $CREATE_FILE 2>&1
cat /etc/passwd | awk -F":" '{print $1 "\t" $7}' | egrep -Evi "nologin|false" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
echo "[U-53_END]" >> $CREATE_FILE 2>&1
echo "[참고 - 진단기준, 결과 값 출력]" >> $CREATE_FILE 2>&1
echo " * 양호 조건 : 로그인이 필요하지 않은 계정에 /bin/false(nologin) 등이 부여된 경우" >> $CREATE_FILE 2>&1
echo " * 취약 조건 : 로그인이 필요하지 않은 계정에 shell이 부여된 경우" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
}

U-54(){
echo "[U-54] Session Timeout 설정"
echo "[U-54] Session Timeout 설정" >> $CREATE_FILE 2>&1
echo "[U-54_START]" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
etc_profile_list="/etc/profile /etc/default/login"
csh_profile_list="/etc/csh.login /etc/csh.cshrc"

for etc_file_chk in $etc_profile_list
do
	if [ -f $etc_file_chk ]
	then
		echo "[+]" $etc_file_chk "설정 확인" >> $CREATE_FILE 2>&1
		cat $etc_file_chk | egrep -i 'TIMEOUT|TMOUT' >> $CREATE_FILE 2>&1
		echo "" >> $CREATE_FILE 2>&1
	else
		echo "[+] 관련 설정이 존재하지 않습니다." >> $CREATE_FILE 2>&1
		echo "" >> $CREATE_FILE 2>&1
	fi
done

for pass_list_check in $passwd_list
	do 
	if [ -f `cat $pass_list_check | grep "csh" | grep -v 'grep'` ]
	then 
		for csh_file_chk in $csh_profile_list
		do
		if [ -f $csh_file_chk ]
		then
			echo "[+]" $csh_file_chk "설정 확인" >> $CREATE_FILE 2>&1
			cat $csh_file_chk | grep -i 'autologout' >> $CREATE_FILE 2>&1
			echo "" >> $CREATE_FILE 2>&1
		else 
			echo "[+] 관련 설정이 존재하지 않습니다." >> $CREATE_FILE 2>&1
			echo "" >> $CREATE_FILE 2>&1
		fi
		done
	else
		echo "[+] csh 계정이 존재하지 않습니다." >> $CREATE_FILE 2>&1
		echo "" >> $CREATE_FILE 2>&1
	fi
done
echo "" >> $CREATE_FILE 2>&1
echo "[U-54_END]" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
echo "[참고 - 진단기준, 결과 값 출력]" >> $CREATE_FILE 2>&1
echo " * 양호 조건 : 세션 타임아웃 값이 600초 이하(10분)로 설정 되어 있을 경우" >> $CREATE_FILE 2>&1
echo " * 취약 조건 :  세션 타임아웃 값이 600초 이하(10분)로 설정 되어 있지 않을 경우 (아래 내용 중 해당사항이 있는 경우)" >> $CREATE_FILE 2>&1
echo "************************************************" >> $CREATE_FILE 2>&1
echo "1) 내부 규정에 세션 종료 시간이 명시되어있는 경우" >> $CREATE_FILE 2>&1
echo "    - 세션 타임아웃이 내부 규정에 명시된 세션 종료 시간보다 초과 설정 시 취약으로 진단" >> $CREATE_FILE 2>&1
echo "2) 내부 규정에 세션 종료시간이 명시되어 있지 않을 경우" >> $CREATE_FILE 2>&1
echo "    - 세션타임아웃이 10분 초과 설정 시 취약으로 진단" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1


unset pass_list_check
unset csh_profile_list
unset etc_profile_list
unset etc_file_chk
unset csh_file_chk
}

U-05(){
echo "[U-05] root 홈, 패스 디렉터리 권한 및 패스 설정"
echo "[U-05] root 홈, 패스 디렉터리 권한 및 패스 설정" >> $CREATE_FILE 2>&1
echo "[U-05_START]" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
echo "[+] 현황 : PATH 환경변수 확인" >> $CREATE_FILE 2>&1
echo $PATH >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
echo "[U-05_END]" >> $CREATE_FILE 2>&1
echo "[참고 - 진단기준, 결과 값 출력]" >> $CREATE_FILE 2>&1
echo " * 양호 조건 : PATH 환경변수에 “.” 이 맨 앞이나 중간에 포함되지 않은 경우" >> $CREATE_FILE 2>&1
echo " * 취약 조건 : PATH 환경변수에 “.” 이 맨 앞이나 중간에 포함되어 있는 경우" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
}

U-06(){
echo "[U-06] 파일 및 디렉터리 소유자 설정"
echo "[U-06] 파일 및 디렉터리 소유자 설정" >> $CREATE_FILE 2>&1
echo "[U-06_START]" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1

usercheck=`find / \
\( -path /proc -o -path /sys -o -path /dev -o -path /run -o -path /var/run \) -prune -o \
-type f -a -nouser -print 2>/dev/null`
groupcheck=`find / \
\( -path /proc -o -path /sys -o -path /dev -o -path /run -o -path /var/run \) -prune -o \
-type f -a -nogroup -print 2>/dev/null`


echo "[+] 소유자가 존재하지 않는 파일 출력" >> $CREATE_FILE 2>&1
if [ -n "$usercheck" ]; then
    echo "$usercheck" | while read -r file; do
    ls -al "$file" >> $CREATE_FILE 2>&1
	done
else
    echo "소유자가 존재하지 않는 파일이 존재하지 않습니다." >> $CREATE_FILE 2>&1
fi
echo "" >> $CREATE_FILE 2>&1


echo "[+] 소유자 그룹이 존재하지 않는 파일 출력" >> $CREATE_FILE 2>&1
if [ -n "$groupcheck" ]; then
    echo "$groupcheck" | while read -r file; do
    ls -al "$file" >> $CREATE_FILE 2>&1
	done
else
    echo "소유자가 존재하지 않는 파일이 존재하지 않습니다." >> $CREATE_FILE 2>&1
fi
echo "" >> $CREATE_FILE 2>&1

unset usercheck
unset groupcheck
unset file

echo "=============================================" >> $CREATE_FILE 2>&1
echo "[U-06_END]" >> $CREATE_FILE 2>&1
echo "[참고 - 진단기준, 결과 값 출력]" >> $CREATE_FILE 2>&1
echo " * 양호 조건 : 존재하지 않는 소유자 및 그룹 권한을 가진 파일 또는 디렉터리 존재" >> $CREATE_FILE 2>&1
echo " * 취약 조건 : 소유자가 존재하지 않는 파일 디렉토리 중 중요한 파일인지 확인" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1

unset file
}

U-07(){
echo "[U-07] /etc/passwd 파일 소유자 및 권한 설정"
echo "[U-07] /etc/passwd 파일 소유자 및 권한 설정" >> $CREATE_FILE 2>&1
echo "[U-07_START]" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
Systemfile_list="/etc/passwd /etc/security/passwd"

for Check_SystemFile in $Systemfile_list
	do
		if [ -f $Check_SystemFile ]
		then
		echo "" >> $CREATE_FILE 2>&1
		echo "[+]" $Check_SystemFile >> $CREATE_FILE 2>&1
		ls -laR $Check_SystemFile >> $CREATE_FILE 2>&1
		fi
	done


echo "" >> $CREATE_FILE 2>&1
echo "[U-07_END]" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
echo "[참고 - 진단기준, 결과 값 출력]" >> $CREATE_FILE 2>&1
echo "1. /etc/passwd 권한: 644, 소유자 root" >> $CREATE_FILE 2>&1
echo "1-2. /etc/security/passwd 권한: 644, 소유자 root" >> $CREATE_FILE 2>&1
echo "*** 존재하고있는 파일 및 디렉터리만 출력 ***" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1

unset Systemfile_list
unset Check_SystemFile
}

U-08(){
echo "[U-08] /etc/shadow 파일 소유자 및 권한 설정"
echo "[U-08] /etc/shadow 파일 소유자 및 권한 설정" >> $CREATE_FILE 2>&1
echo "[U-08_START]" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
Systemfile_list="/etc/shadow"

for Check_SystemFile in $Systemfile_list
	do
		if [ -f $Check_SystemFile ]
		then
		echo "" >> $CREATE_FILE 2>&1
		echo "[+]" $Check_SystemFile >> $CREATE_FILE 2>&1
		ls -laR $Check_SystemFile >> $CREATE_FILE 2>&1
		fi
	done


echo "" >> $CREATE_FILE 2>&1
echo "[U-08_END]" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
echo "[참고 - 진단기준, 결과 값 출력]" >> $CREATE_FILE 2>&1
echo "1. /etc/shadow 권한: 400, 소유자 root " >> $CREATE_FILE 2>&1
echo "*** 존재하고있는 파일 및 디렉터리만 출력 ***" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1

unset Systemfile_list
unset Check_SystemFile
}

U-09(){
echo "[U-09] /etc/hosts 파일 소유자 및 권한 설정"
echo "[U-09] /etc/hosts 파일 소유자 및 권한 설정" >> $CREATE_FILE 2>&1
echo "[U-09_START]" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
Systemfile_list="/etc/hosts"

for Check_SystemFile in $Systemfile_list
	do
		if [ -f $Check_SystemFile ]
		then
		echo "" >> $CREATE_FILE 2>&1
		echo "[+]" $Check_SystemFile >> $CREATE_FILE 2>&1
		ls -laR $Check_SystemFile >> $CREATE_FILE 2>&1
		fi
	done


echo "" >> $CREATE_FILE 2>&1
echo "[U-09_END]" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
echo "[참고 - 진단기준, 결과 값 출력]" >> $CREATE_FILE 2>&1
echo "1. /etc/hosts 권한: 600, 소유자 root" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1


unset Systemfile_list
unset Check_SystemFile
}

U-10(){
echo "[U-10] /etc/(x)inetd.conf 파일 소유자 및 권한 설정"
echo "[U-10] /etc/(x)inetd.conf 파일 소유자 및 권한 설정" >> $CREATE_FILE 2>&1
echo "[U-10_START]" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
Systemfile_list="/etc/inetd.conf /etc/xinetd.conf"

for Check_SystemFile in $Systemfile_list
	do
		if [ -f $Check_SystemFile ]; then
			echo "" >> $CREATE_FILE 2>&1
			echo "[+]" $Check_SystemFile >> $CREATE_FILE 2>&1
			ls -laR $Check_SystemFile >> $CREATE_FILE 2>&1
		else
			echo "파일이 존재하지 않습니다. $Check_SystemFile" >> $CREATE_FILE 2>&1
		fi
	done
echo "" >> $CREATE_FILE 2>&1
echo "[U-10_END]" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
echo "[참고 - 진단기준, 결과 값 출력]" >> $CREATE_FILE 2>&1
echo "1. /etc/(x)inetd.conf 권한: 600, 소유자 root" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1

unset Systemfile_list
unset Check_SystemFile
}

U-11(){
echo "[U-11] /etc/syslog.conf 파일 소유자 및 권한 설정"
echo "[U-11] /etc/syslog.conf 파일 소유자 및 권한 설정" >> $CREATE_FILE 2>&1
echo "[U-11_START]" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
Systemfile_list="/etc/syslog.conf /etc/rsyslog.conf"

for Check_SystemFile in $Systemfile_list
	do
		if [ -f $Check_SystemFile ]; then
			echo "" >> $CREATE_FILE 2>&1
			echo "[+]" $Check_SystemFile >> $CREATE_FILE 2>&1
			ls -laR $Check_SystemFile >> $CREATE_FILE 2>&1
		else
			echo "파일이 존재하지 않습니다. $Check_SystemFile" >> $CREATE_FILE 2>&1
		fi
	done


echo "" >> $CREATE_FILE 2>&1
echo "[U-11_END]" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
echo "[참고 - 진단기준, 결과 값 출력]" >> $CREATE_FILE 2>&1
echo "1. /etc/(r)syslog.conf 권한: 640, 소유자 root" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1

unset Systemfile_list
unset Check_SystemFile
}

U-12(){
echo "[U-12] /etc/services 파일 소유자 및 권한 설정"
echo "[U-12] /etc/services 파일 소유자 및 권한 설정" >> $CREATE_FILE 2>&1
echo "[U-12_START]" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
Systemfile_list="/etc/services"

for Check_SystemFile in $Systemfile_list
	do
		if [ -f $Check_SystemFile ]; then
			echo "" >> $CREATE_FILE 2>&1
			echo "[+]" $Check_SystemFile >> $CREATE_FILE 2>&1
			ls -laR $Check_SystemFile >> $CREATE_FILE 2>&1
		else
			echo "파일이 존재하지 않습니다. $Check_SystemFile" >> $CREATE_FILE 2>&1		
		fi
	done
echo "" >> $CREATE_FILE 2>&1
echo "[U-12_END]" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
echo "[참고 - 진단기준, 결과 값 출력]" >> $CREATE_FILE 2>&1
echo "1. /etc/services 권한:  644, 소유자 root" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1

unset Systemfile_list
unset Check_SystemFile
}

U-13(){
echo "[U-13] SUID, SGID, Sticky bit 설정 파일 점검"
echo "[U-13] SUID, SGID, Sticky bit 설정 파일 점검" >> $CREATE_FILE 2>&1
echo "[U-13_START]" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
filecheck=`find / \
\( -path /proc -o -path /sys -o -path /dev -o -path /run -o -path /var/run \) -prune -o \
-user root -type f \( -perm -04000 -o -perm -02000 \) -print 2>/dev/null | head -5`

echo "[+] SUID, SGID, Sticky bit가 설정된 파일 출력(최대 5개)" >> $CREATE_FILE 2>&1
if [ -n "$filecheck" ]; then
    echo "$filecheck" | while read -r file; do
    ls -al "$file" >> $CREATE_FILE 2>&1
	done
else
    echo "SUID, SGID, Sticky bit가 설정된 파일이 존재하지 않습니다." >> $CREATE_FILE 2>&1
fi
echo "" >> $CREATE_FILE 2>&1

echo "=============================================" >> $CREATE_FILE 2>&1
echo "[U-13_END]" >> $CREATE_FILE 2>&1
echo "[참고 - 진단기준, 결과 값 출력]" >> $CREATE_FILE 2>&1
echo " * 양호 조건 : 불필요하게 SUID ,SGID가 설정된 파일이 없을 경우 판단 불가 시 4750(업무상 용도 포함)" >> $CREATE_FILE 2>&1
echo " * 취약 조건 : 불필요하게 SUID ,SGID가 설정된 파일이 있을 경우" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1

unset filecheck
unset file
}

U-14(){
echo "[U-14] 사용자, 시스템 시작파일 및 환경파일 소유자 및 권한 설정"
echo "[U-14] 사용자, 시스템 시작파일 및 환경파일 소유자 및 권한 설정" >> $CREATE_FILE 2>&1
echo "[U-14_START]" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
HOMEDIRS=`cat /etc/passwd | awk -F":" 'length($6) > 0 {print $6}' | grep -wv "\/" | sort -u`
echo "[+] 1. 현황 : 환경변수 파일 확인" >> $CREATE_FILE 2>&1
for file in $HOMEDIRS
do
	ls -al $file/.profile $file/.cshrc $file/.kshrc $file/.login $file/.bash_profile $file/.bashrc $file/.bash_login $file/.xinitrc $file/.xsession $file/.login $file/.exrc $file/.netrc 2>/dev/null | grep -v "No such file or directory" >> $CREATE_FILE
	echo "" >> $CREATE_FILE 2>&1
done
echo "=============================================" >> $CREATE_FILE 2>&1
echo "[U-14_END]" >> $CREATE_FILE 2>&1
echo "[참고 - 진단기준, 결과 값 출력]" >> $CREATE_FILE 2>&1
echo " * 양호 조건 : 홈 디렉터리 환경변수 파일 소유자가 root 또는, 해당 계정으로 지정되어 있고, 홈 디렉터리 환경변수 파일에 root와 소유자만 쓰기 권한이 부여
된 경우" >> $CREATE_FILE 2>&1
echo " * 취약 조건 : 홈 디렉터리 환경변수 파일 소유자가 root 또는, 해당 계정으로 지정되지 않고, 홈 디렉터리 환경변수 파일에 root와 소유자 외에 쓰기 권한이 
부여된 경우" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1

unset file
unset HOMEDIRS
}

U-15(){
echo "[U-15] world writable 파일 점검"
echo "[U-15] world writable 파일 점검" >> $CREATE_FILE 2>&1
echo "[U-15_START]" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
#HOMEDIR=`egrep -v 'nologin|false' /etc/passwd | awk -F":" '{print $6}' | grep -wv "/" | uniq`
#echo "[+] 홈 디렉터리 내 불필요한 파일 확인" >> $CREATE_FILE 2>&1
#	for dir in $HOMEDIR
		#do 
		#	test_wc=`find $dir -perm -2 -type f | wc -l`
		#	if [ $test_wc -gt 0 ]
		#	then
		#		echo $dir >> $CREATE_FILE 2>&1
	#			echo "<------------" >> $CREATE_FILE 2>&1
#				find $HOMEDIR -perm -2 -type f -exec ls -alL {} \; 2>/dev/null >> $CREATE_FILE 2>&1
#				echo "------------>" >> $CREATE_FILE 2>&1
#				echo "" >> $CREATE_FILE 2>&1
#			else
#				echo $dir " 디렉토리가 없습니다."
#			fi
#	done
	#find $HOMEDIR -perm -2 -type f -exec ls -alL {} \; 2>/dev/null >> $CREATE_FILE 2>&1
	#개선20220118
#for file in `find $HOMEDIR -perm -2 -type f | head -5`
#do
#	ls -al  ${file}
#done


#2025 루트 디렉토리 검색으로 변경하고
#echo "[+] 과도한 권한 파일 확인" >> $CREATE_FILE 2>&1
#find / . ! \( \( -path '/proc' -o -path '/sys' \) -prune \) -type f -perm -2 -exec ls -l {} \;>> $CREATE_FILE 2>&1

# timeout 5는 5초 실행 후 명령어 종료. centos만 검증되어 주석처리함
# timeout 5 find / . ! \( \( -path '/proc' -o -path '/sys' \) -prune \) -type f -perm -2 -exec ls -l {} \;

filecheck=`find / \
\( -path /proc -o -path /sys -o -path /dev -o -path /run -o -path /var/run \) -prune -o \
-type f -perm -2 -print`

echo "[+] world writable 파일 확인" >> $CREATE_FILE 2>&1
if [ -n "$filecheck" ]; then
    echo "$filecheck" | while read -r file; do
    ls -al "$file" >> $CREATE_FILE 2>&1
	done
else
    echo "파일이 존재하지 않습니다." >> $CREATE_FILE 2>&1
fi
echo "" >> $CREATE_FILE 2>&1

echo "=============================================" >> $CREATE_FILE 2>&1
echo "[U-15_END]" >> $CREATE_FILE 2>&1
echo "[참고 - 진단기준, 결과 값 출력]" >> $CREATE_FILE 2>&1
echo " * 양호 조건 : 불필요한 world writable 파일이 존재하지 않는 경우 & others에 쓰기권한 없으면 양호" >> $CREATE_FILE 2>&1
echo " * 취약 조건 : 불필요한 world writable 파일이 존재하는 경우" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1

unset HOMEDIR
unset file
unset filecheck
}

U-16(){
echo "[U-16] /dev에 존재하지 않는 device 파일 점검"
echo "[U-16] /dev에 존재하지 않는 device 파일 점검" >> $CREATE_FILE 2>&1
echo "[U-16_START]" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
devcheck=`find /dev -type f | head -5`
for file in $devcheck
do
	if [ -f $devcheck ]
	then 
		echo "[+] 현황 : find /dev -type f -exec ls -l {} \;" >> $CREATE_FILE 2>&1
		ls -al  ${file} >> $CREATE_FILE 2>&1
		echo "" >> $CREATE_FILE 2>&1
	else
		echo "[+] 불필요한 파일이 존재하지 않습니다." >> $CREATE_FILE 2>&1
		echo "" >> $CREATE_FILE 2>&1
	fi
done
echo "" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
echo "[U-16_END]" >> $CREATE_FILE 2>&1
echo "[참고 - 진단기준, 결과 값 출력]" >> $CREATE_FILE 2>&1
echo " * 양호 조건 : /dev 경로에 존재하지 않는 device 파일이 없는 경우" >> $CREATE_FILE 2>&1
echo " * 취약 조건 : /dev 경로에 존재하지 않는 불필요한 device 파일이 있는 경우  " >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1


unset devcheck
unset file
}

U-17(){
echo "[U-17] $HOME/.rhosts, hosts.equiv 사용 금지"
echo "[U-17] $HOME/.rhosts, hosts.equiv 사용 금지" >> $CREATE_FILE 2>&1
echo "[U-17_START]" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
filelist="/etc/hosts.equiv $HOME/.rhosts"

for filelist_check in $filelist
	do
		if [ -f $filelist_check ]
		then
			echo "[+]" $filelist_check "존재여부" >> $CREATE_FILE 2>&1
			ls -al $filelist_check >> $CREATE_FILE 2>&1
			echo "[+]" $filelist_check "설정 확인" >> $CREATE_FILE 2>&1
			cat $filelist_check >> $CREATE_FILE 2>&1
		else
			echo "[+] 관련 설정이 존재하지 않습니다." >> $CREATE_FILE 2>&1
		fi
	done
echo "[U-17_END]" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
echo "[참고 - 진단기준, 결과 값 출력]" >> $CREATE_FILE 2>&1
echo "[*] 미출력 시 파일이 미존재" >> $CREATE_FILE 2>&1
echo " * 양호 조건 : ogin, shell, exec 서비스를 사용하지 않거나, 사용 시 아래와 같은 설정이 적용된 경우" >> $CREATE_FILE 2>&1
echo " * 양호 조건 1 : 1. /etc/hosts.equiv 및 $HOME/.rhosts 파일 소유자가 root 또는, 해당 계정인 경우 " >> $CREATE_FILE 2>&1
echo " * 양호 조건 2 : 2. /etc/hosts.equiv 및 $HOME/.rhosts 파일 권한이 600 이하인 경우 " >> $CREATE_FILE 2>&1
echo " * 양호 조건 3 : 3. /etc/hosts.equiv 및 $HOME/.rhosts 파일 설정에 ‘+’ 설정이 없는 경우" >> $CREATE_FILE 2>&1
echo " * 취약 조건 : login, shell, exec 서비스를 사용하고, 위와 같은 설정이 적용되지 않은 경우" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1

unset filelist
unset filelist_check
}

U-18(){
echo "[U-18] 접속 IP 및 포트 제한"
echo "[U-18] 접속 IP 및 포트 제한" >> $CREATE_FILE 2>&1
echo "[U-18_START]" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
hosts_file(){
	if file_check "$1"; then
		echo "[*] 파일 존재여부 체크" >> $CREATE_FILE 2>&1
		ls -la "$1" >> $CREATE_FILE 2>&1
		
		echo "[*] 파일 내 적절한 설정 체크" >> $CREATE_FILE 2>&1
		cat "$1" >> $CREATE_FILE 2>&1
	else
		echo "$1 파일이 존재하지 않습니다." >> $CREATE_FILE 2>&1
	fi
	echo "" >> $CREATE_FILE 2>&1
}
echo "[+] /etc/hosts.allow" >> $CREATE_FILE 2>&1
hosts_file "/etc/hosts.allow"

echo "[+] /etc/hosts.deny" >> $CREATE_FILE 2>&1
hosts_file "/etc/hosts.deny"

echo "" >> $CREATE_FILE 2>&1
echo "[U-18_END]" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
echo "[참고 - 진단기준, 결과 값 출력]" >> $CREATE_FILE 2>&1
echo " * 양호 조건 : 시스템 서비스로의 접근통제가 적절하게 수행되고 있을 경우 (방화벽, tcp-wrapper, 3rd-party 제품 등을 활용) 또는 예시( /etc/hosts.allow - sshd : IP주소 (접근을 허용할 호스트) && /etc/hosts.deny - ALL:ALL (ALL Deny 설정))" >> $CREATE_FILE 2>&1
echo " * 취약 조건 : 시스템 서비스로의 접근통제가 적절하게 수행되고 있지 않을 경우 또는 관련설정 없을 시 " >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
}

U-55(){
echo "[U-55] hosts.lpd 파일 소유자 및 권한 설정"
echo "[U-55] hosts.lpd 파일 소유자 및 권한 설정" >> $CREATE_FILE 2>&1
echo "[U-55_START]" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
Systemfile_list="/etc/host.lpd /etc/hosts.lpd"

for Check_SystemFile in $Systemfile_list
	do
		if [ -f $Check_SystemFile ]
		then
		echo "" >> $CREATE_FILE 2>&1
		echo "[+]" $Check_SystemFile >> $CREATE_FILE 2>&1
		ls -laR $Check_SystemFile >> $CREATE_FILE 2>&1
		fi
	done

echo "" >> $CREATE_FILE 2>&1
echo "[U-55_END]" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
echo "[참고 - 진단기준, 결과 값 출력]" >> $CREATE_FILE 2>&1
echo "1. /etc/hosts.lpd 권한: 600, 소유자 root" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1


unset Systemfile_list
unset Check_SystemFile

}

U-56(){
echo "[U-56] UMASK 설정 관리"
echo "[U-56] UMASK 설정 관리" >> $CREATE_FILE 2>&1
echo "[U-56_START]" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
echo "[+] 1. 현황 : /etc/security/user 설정 " >> $CREATE_FILE 2>&1
if file_check "/etc/security/user"; then
	cat /etc/security/user | grep -i UMASK | grep -v 'grep' >> $CREATE_FILE 2>&1
else
	echo "파일이 존재하지 않습니다." >> $CREATE_FILE 2>&1
fi
echo "" >> $CREATE_FILE 2>&1

echo "[+] 2. 현황 : /etc/profile" >> $CREATE_FILE 2>&1
cat /etc/profile | grep -i UMASK | grep -v 'grep' >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1

echo "[+] 3. 현황 : 모든 계정의 홈 디렉토리 내 .profile .*shrc 확인" >> $CREATE_FILE 2>&1
for file in $HOMEDIRS
do 
	echo $file >> $CREATE_FILE 2>&1
	cat $file/.profile | grep -i UMASK | grep -v 'grep' >> $CREATE_FILE 2>&1
	cat $file/.*shrc | grep -i UMASK | grep -v 'grep' >> $CREATE_FILE 2>&1
done
echo "" >> $CREATE_FILE 2>&1

echo "[+] 4. 현황 : 현재 접속 계정 UMASK 설정" >> $CREATE_FILE 2>&1
umask >> $CREATE_FILE 2>&1

echo "" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
echo "[U-56_END]" >> $CREATE_FILE 2>&1
echo "[참고 - 진단기준, 결과 값 출력]" >> $CREATE_FILE 2>&1
echo " * 양호 조건 : 모든 계정의 umask 값과 설정 파일 등에 적용된 umask값이 022 이상인 경우" >> $CREATE_FILE 2>&1
echo " * 취약 조건 : umask값이나 설정 파일 등에 적용된 umask값이 022미만인 계정이 존재하는 경우" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
}

U-57(){
echo "[U-57] 홈디렉토리 소유자 및 권한 설정"
echo "[U-57] 홈디렉토리 소유자 및 권한 설정" >> $CREATE_FILE 2>&1
echo "[U-57_START]" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
HOMEDIRS=`cat /etc/passwd | awk -F":" 'length($6) > 0 {print $6}' | grep -wv "\/" | sort -u`     

echo "[+] 소유자 별 홈 디렉터리 확인 (소유자 @ 홈디렉토리 < 형태이며, 중복 홈 디렉터리와 소유자별 디렉터리 일치하는지 확인)" >> $CREATE_FILE 2>&1
cat /etc/passwd | awk -F":" '{print $1 " @ " $6}' | grep -v "\/\>" | sort -u >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1

echo "[+] 홈 디렉토리의 권한 확인 (불필요한 others 쓰기권한)" >> $CREATE_FILE 2>&1
for dir in $HOMEDIRS
do
	ls -dal $dir 2>/dev/null | grep '\d.........' >> $CREATE_FILE 2>&1
done
echo "" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
echo "[U-57_END]" >> $CREATE_FILE 2>&1
echo "[참고 - 진단기준, 결과 값 출력]" >> $CREATE_FILE 2>&1
echo " * 양호 조건 : 홈 디렉터리의 소유자와 실 사용자가 일치하고, 계정간 중복 홈 디렉터리가 존재하지 않고, 불필요한 others 쓰기 권한이 없는 경우" >> $CREATE_FILE 2>&1
echo " * 취약 조건 : 홈 디렉터리의 소유자와 실 사용자가 일치하지 않거나, 계정간 중복 홈 디렉터리가 존재하거나, 불필요한 others 쓰기 권한이 있는 경우" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1

unset HOMEDIRS
}

U-58(){
echo "[U-58] 홈디렉토리로 지정한 디렉토리의 존재 관리"
echo "[U-58] 홈디렉토리로 지정한 디렉토리의 존재 관리" >> $CREATE_FILE 2>&1
echo "[U-58_START]" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1

echo "[+] 소유자 별 홈 디렉터리 확인 (소유자 @ 홈디렉토리 < 형태이며, 중복 홈 디렉터리와 소유자별 디렉터리 일치하는지 확인)" >> $CREATE_FILE 2>&1
cat /etc/passwd | awk -F":" '{print $1 " @ " $6}' | grep -v "\/\>" | sort -u >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "[+] 홈 디렉토리의 권한 확인 (불필요한 others 쓰기권한)" >> $CREATE_FILE 2>&1
HOMEDIRS=`cat /etc/passwd | awk -F":" 'length($6) > 0 {print $6}' | grep -wv "\/" | sort -u`     
for dir in $HOMEDIRS
do
	ls -dal $dir 2>/dev/null | grep '\d.........' >> $CREATE_FILE 2>&1
done
echo "=============================================" >> $CREATE_FILE 2>&1
echo "[U-58_END]" >> $CREATE_FILE 2>&1
echo "[참고 - 진단기준, 결과 값 출력]" >> $CREATE_FILE 2>&1
echo " * 양호 조건 : 홈 디렉터리가 존재하지 않는 계정이 발견되지 않는 경우" >> $CREATE_FILE 2>&1
echo " * 취약 조건 : 홈 디렉터리가 존재하지 않는 계정이 발견된 경우" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1

unset HOMEDIRS
}

U-59(){
echo "[U-59] 숨겨진 파일 및 디렉토리 검색 및 제거"
echo "[U-59] 숨겨진 파일 및 디렉토리 검색 및 제거" >> $CREATE_FILE 2>&1
echo "[U-59_START]" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
filecheck=`find / \
\( -path /proc -o -path /sys -o -path /dev -o -path /run -o -path /var/run \) -prune -o \
-type f -name ".*" -print 2>/dev/null | head -5`
dircheck=`find / \
\( -path /proc -o -path /sys -o -path /dev -o -path /run -o -path /var/run \) -prune -o \
-type d -name ".*" -print 2>/dev/null | head -5`

echo "[+] 1. 현황 : 불필요한 숨김 파일 확인(최대 5개)" >> $CREATE_FILE 2>&1
if [ -n "$filecheck" ]; then
    echo "$filecheck" | while read -r file; do
    ls -al "$file" >> $CREATE_FILE 2>&1
	done
else
    echo "파일이 존재하지 않습니다." >> $CREATE_FILE 2>&1
fi
echo "" >> $CREATE_FILE 2>&1

echo "[+] 2. 현황 : 불필요한 숨김 디렉토리 확인(최대 5개)" >> $CREATE_FILE 2>&1
if [ -n "$dircheck" ]; then
    echo "$dircheck" >> $CREATE_FILE 2>&1
else
    echo "파일이 존재하지 않습니다." >> $CREATE_FILE 2>&1
fi


echo "=============================================" >> $CREATE_FILE 2>&1
echo "[U-59_END]" >> $CREATE_FILE 2>&1
echo "[참고 - 진단기준, 결과 값 출력]" >> $CREATE_FILE 2>&1
echo " * 양호 조건 : 불필요한 숨김 파일이 존재하지 않을 경우" >> $CREATE_FILE 2>&1
echo " * 취약 조건 : 불필요한 숨김 파일이 존재하는 경우" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1

unset dircheck
unset filecheck
unset file
}

U-19(){
echo "[U-19] finger 서비스 비활성화"
echo "[U-19] finger 서비스 비활성화" >> $CREATE_FILE 2>&1
echo "[U-19_START]" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1

#echo "[+]" inetd 활성화 서비스 목록 >> $CREATE_FILE 2>&1
if [ -f /etc/inetd.conf ]
then
	inetd_services="finger"
	for inetd_chk in $inetd_services
	do
		ps -ef | grep $inetd_chk | grep -v 'grep'\# >> $CREATE_FILE 2>&1
		echo "" >> $CREATE_FILE 2>&1
		cat /etc/inetd.conf | grep $inetd_chk | grep -v 'grep'\# >> $CREATE_FILE 2>&1
		echo "" >> $CREATE_FILE 2>&1
	done
	if [ `cat /etc/inetd.conf | grep $inetd_chk | grep -v 'grep' \# | wc -l` -eq 0 ]
	then
		echo "[+] 해당 서비스가 비활성화되어 있습니다." >> $CREATE_FILE 2>&1
		echo "" >> $CREATE_FILE 2>&1
	fi
else
	echo "[+] 해당 서비스가 비활성화되어 있습니다." >> $CREATE_FILE 2>&1
	echo "" >> $CREATE_FILE 2>&1
fi
echo "" >> $CREATE_FILE 2>&1

echo "[+] xinetd 활성화 서비스 목록" >> $CREATE_FILE 2>&1
if [ -e /etc/xinetd ]
then
	xinetd_serivces=`ls /etc/xinetd.d/*`
	for xinetd_chk in $xinetd_serivces
	do
		echo "[*]" $xinetd_chk >> $CREATE_FILE 2>&1
		ps -ef | grep $xinetd_chk | grep -v 'grep'\# >> $CREATE_FILE 2>&1
		echo "" >> $CREATE_FILE 2>&1
		cat $xinetd_chk | grep disable | grep -i no >> $CREATE_FILE 2>&1
		echo "" >> $CREATE_FILE 2>&1
	done
	if [ `cat $xinetd_chk | grep disable | grep -i no` -eq 0 ]
	then
		echo "[+] 활성화 서비스가 존재하지 않습니다." >> $CREATE_FILE 2>&1
		echo "" >> $CREATE_FILE 2>&1
	fi
else
	echo "[+] xinetd 디렉터리가 존재하지 않습니다." >> $CREATE_FILE 2>&1
	echo "" >> $CREATE_FILE 2>&1
fi




echo "" >> $CREATE_FILE 2>&1
echo "[U-19_END]" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
echo "[참고 - 진단기준, 결과 값 출력]" >> $CREATE_FILE 2>&1
echo " * 양호 조건 : 아래의 항목 중 해당사항이 없는경우" >> $CREATE_FILE 2>&1
echo " * 취약 조건 : 아래의 항목 중 해당하는 조건이 있는 경우" >> $CREATE_FILE 2>&1
echo "*********************************************" >> $CREATE_FILE 2>&1
echo "1. finger 서비스 활성화" >> $CREATE_FILE 2>&1
echo "*********************************************" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1

unset xinetd_serivces
unset inetd_services
unset xinetd_chk
unset inetd_chk
}

FTP_ftp_Check=`ps -ef | grep ftp | grep -v 'grep'| wc -l`
FTP_vsftpd_Check=`ps -ef | grep vsftpd | grep -v 'grep' | wc -l`
FTP_proftpd_Check=`ps -ef | grep proftpd | grep -v 'grep' | wc -l`
## FTP 설정 파일 리스트
FTPUSERS_FILE_LIST="/etc/ftpusers /etc/ftpd/ftpusers /etc/vsftpd/ftpusers /etc/vsftpd/user_list /etc/vsftpd.ftpusers /etc/vsftpd.user_list"


U-20(){
echo "[U-20] Anonymous FTP 비활성화"
echo "[U-20] Anonymous FTP 비활성화" >> $CREATE_FILE 2>&1
echo "[U-20_START]" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
echo "[+] FTP 서비스 활성화 확인 " >> $CREATE_FILE 2>&1
if [ $FTP_ftp_Check -ne 0 ]
then
	echo " [+] FTP 서비스가 활성화 중입니다." >> $CREATE_FILE 2>&1
	echo " [+]  vsftpd : " $FTP_vsftpd_Check >> $CREATE_FILE 2>&1
	echo " [+]  proftpd : " $FTP_proftpd_Check >> $CREATE_FILE 2>&1
	echo " [*] 활성화(1), 비활성화(0)" >> $CREATE_FILE 2>&1
	echo "" >> $CREATE_FILE 2>&1
	echo " [*] 이외 ftp 확인" >> $CREATE_FILE 2>&1
	ps -ef | grep ftp | grep -v 'grep' >> $CREATE_FILE 2>&1
	echo "" >> $CREATE_FILE 2>&1
	
	echo "[+] 1. FTP 기본계정 로그인 쉘" >> $CREATE_FILE 2>&1
	cat /etc/passwd | grep -iE "ftp|Anonymous" >> $CREATE_FILE 2>&1
	echo "" >> $CREATE_FILE 2>&1
	## FTP 설정파일 경로정보 지속적인 업데이트 필요(테스트 환경 기준으로 지정된 경로정보만 우선적으로 추가)
	FTP_CONF_LIST="/etc/proftpd.conf /etc/vsftpd/vsftpd.conf"
	echo "[+] 2. FTP 설정 현황" >> $CREATE_FILE 2>&1
	for FTP_CONF_FILES in $FTP_CONF_LIST
		do
			if [ -f $FTP_CONF_FILES ]
			then
			echo "[+]" $FTP_CONF_FILES >> $CREATE_FILE 2>&1
			cat $FTP_CONF_FILES | grep -i anonymous | grep -v \# >> $CREATE_FILE 2>&1
			## 해당 설정 값이 존재하지 않을 경우(주석처리된 경우도 포함) 출력되는 로직
			FTP_CONF_NONE=`cat $FTP_CONF_FILES | grep -i anonymous | grep -v \# | wc -l`
			if [ $FTP_CONF_NONE -eq 0 ]
			then
				echo "[+] 해당 설정이 존재하지 않습니다. " >> $CREATE_FILE 2>&1
				echo "** 해당 설정이 주석처리된 것으로 예상되며, 추가 확인 필요 " >> $CREATE_FILE 2>&1
			fi
		fi
	done

else
	echo " FTP 서비스가 비활성화되어 있습니다. " >> $CREATE_FILE 2>&1
fi



echo "" >> $CREATE_FILE 2>&1
echo "[U-20_END]" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
echo "[*] FTP 포트 활성화 확인 " >> $CREATE_FILE 2>&1
netstat -na | grep -w "21" | grep "LISTEN" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "[참고 - 진단기준, 결과 값 출력]" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo " * 양호 기준 : 익명 FTP 사용 설정이 비활성화되어 있거나(AND), FTP 기본 계정 로그인 쉘이 비활성화(false/nologin)되어 있는 경우" >> $CREATE_FILE 2>&1
echo " * 취약 기준 : 익명 FTP 사용 설정이 활성화되어 있거나(AND), FTP 기본 계정 로그인 쉘이 활성화(shell)되어 있는 경우" >> $CREATE_FILE 2>&1
echo " *** 결과 파일이 출력된다는 것은 해당 서비스가 활성화(Active-Running) 상태이기 때문에 출력되는 것으로 알고 계시면 됩니다." >> $CREATE_FILE 2>&1
echo " *** default Settings value : #anonymous_enable=YES " >> $CREATE_FILE 2>&1
echo " 결과 값이 출력되지 않을 경우 주석처리된 것일 수도 있어 취약으로 진단 " >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1



unset FTP_CONF_FILES
unset FTP_CONF_LIST
}

U-21(){
echo "[U-21] r 계열 서비스 비활성화"
echo "[U-21] r 계열 서비스 비활성화" >> $CREATE_FILE 2>&1
echo "[U-21_START]" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1

#echo "[+]" inetd 활성화 서비스 목록 >> $CREATE_FILE 2>&1
if [ -f /etc/inetd.conf ]
then
	inetd_services="rexec rlogin rsh"
	for inetd_chk in $inetd_services
	do
		ps -ef | grep $inetd_chk | grep -v 'grep'\# >> $CREATE_FILE 2>&1
		cat /etc/inetd.conf | grep $inetd_chk | grep -v 'grep'\# >> $CREATE_FILE 2>&1
	done
	if [ `cat /etc/inetd.conf | grep $inetd_chk | grep -v 'grep' \# | wc -l` -eq 0 ]
	then
		echo "[+] 해당 서비스가 비활성화되어 있습니다." >> $CREATE_FILE 2>&1
		echo ""
	fi
else
	echo "[+] 해당 서비스가 비활성화되어 있습니다." >> $CREATE_FILE 2>&1
	echo "" >> $CREATE_FILE 2>&1
fi
echo "" >> $CREATE_FILE 2>&1

echo "[+] xinetd 활성화 서비스 목록" >> $CREATE_FILE 2>&1
if [ -e /etc/xinetd ]
then
	xinetd_serivces=`ls /etc/xinetd.d/*`
	for xinetd_chk in $xinetd_serivces
	do
		echo "[*]" $xinetd_chk >> $CREATE_FILE 2>&1
		ps -ef | grep $xinetd_chk | grep -v 'grep'\# >> $CREATE_FILE 2>&1
		cat $xinetd_chk | grep disable | grep -i no >> $CREATE_FILE 2>&1
		echo "" >> $CREATE_FILE 2>&1
	done
	if [ `cat $xinetd_chk | grep disable | grep -i no` -eq 0 ]
	then
		echo "[+] 활성화 서비스가 존재하지 않습니다." >> $CREATE_FILE 2>&1
		echo "" >> $CREATE_FILE 2>&1
	fi
else
	echo "[+] xinetd 디렉터리가 존재하지 않습니다." >> $CREATE_FILE 2>&1
	echo "" >> $CREATE_FILE 2>&1
fi




echo "" >> $CREATE_FILE 2>&1
echo "[U-21_END]" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
echo "[참고 - 진단기준, 결과 값 출력]" >> $CREATE_FILE 2>&1
echo " * 양호 조건 : 아래의 항목 중 해당사항이 없는경우" >> $CREATE_FILE 2>&1
echo " * 취약 조건 : 아래의 항목 중 해당하는 조건이 있는 경우" >> $CREATE_FILE 2>&1
echo "*********************************************" >> $CREATE_FILE 2>&1
echo "1. rexec, rlogin, rsh 서비스 활성화" >> $CREATE_FILE 2>&1
echo "[*] 프로세스 구동여부 더블체크" >> $CREATE_FILE 2>&1
echo "*********************************************" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1


unset xinetd_serivces
unset inetd_services
unset xinetd_chk
unset inetd_chk
}

U-22(){
echo "[U-22] cron 파일 소유자 및 권한설정"
echo "[U-22] cron 파일 소유자 및 권한설정" >> $CREATE_FILE 2>&1
echo "[U-22_START]" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
Crontab_settingfiles_List="/var/spool/cron/crontabs/* /var/spool/cron/crontab/* /etc/cron.d/cron*  /etc/cron* /etc/at.* /var/adm/cron/at* /etc/cron.d/at.*"
for Crontab_file_check in $Crontab_settingfiles_List
	do
		if [ -e $Crontab_file_check ]
		then
			echo "[+]" $Crontab_file_check >> $CREATE_FILE 2>&1
			ls -laLd $Crontab_file_check >> $CREATE_FILE 2>&1
			echo "" >> $CREATE_FILE 2>&1
		fi
	done


echo "" >> $CREATE_FILE 2>&1
echo "[U-22_END]" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
echo "[참고 - 진단기준, 결과 값 출력]" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo " * 양호 기준 1. : crontab 파일의 other 권한에 읽기, 쓰기 권한이 존재하지 않는 경우" >> $CREATE_FILE 2>&1
echo " * 양호 기준 2. : 접근제어파일(*.allow, *.deny) 소유자가 root이고, 권한이 640이하로 설정된 경우" >> $CREATE_FILE 2>&1
echo " * 취약 기준 : 양호 기준 1,2 중 하나라도 부합하는 경우" >> $CREATE_FILE 2>&1
echo "*** cron.deny, cron.allow 둘 다 없는 경우 수정권한은 슈퍼유저(root)만 가능(양호로 진단) ***" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1


unset Crontab_file_check
unset Crontab_settingfiles_List
}

SMTP_Sendmail_Check=`ps -ef | grep sendmail | grep -v 'grep' | wc -l`

U-23(){
echo "[U-23] Dos 공격에 취약한 서비스 비활성화"
echo "[U-23] Dos 공격에 취약한 서비스 비활성화" >> $CREATE_FILE 2>&1
echo "[U-23_START]" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
case $OS in
	SunOS)
		echo "[+] 1-1. 현황(Solaris 9버전 이하) : ps -ef | egrep 'echo|discard|daytime|chargen' 없으면 양호" >> $CREATE_FILE 2>&1
		ps -ef | egrep "echo|discard|daytime|chargen" >> $CREATE_FILE 2>&1
		echo "" >> $CREATE_FILE 2>&1
		echo "[+] 1-2. 현황(Solaris 9버전 이하) : /etc/inetd.conf | egrep 'echo|discard|daytime|chargen' 확인하여 해당 서비스 주석 확인" >> $CREATE_FILE 2>&1
		cat /etc/inetd.conf | egrep "echo|discard|daytime|chargen" >> $CREATE_FILE 2>&1
		echo "" >> $CREATE_FILE 2>&1
		echo "[+] 1-3. 현황(Solaris 10버전 이상) : 서비스 비활성화(disable) 확인, 결과 없으면 양호" >> $CREATE_FILE 2>&1
		svcs -a | egrep "echo|discard|daytime|chargen" >> $CREATE_FILE 2>&1
		echo " " >> $CREATE_FILE 2>&1
		;;
	Linux)
		echo "[+] 1. 현황 : ls -al /etc/xinetd.d" >> $CREATE_FILE 2>&1
		if file_check "/etc/xinetd.d"; then
			ls -al /etc/xinetd.d >> $CREATE_FILE 2>&1
			echo "" >> $CREATE_FILE 2>&1 
			echo "[+] 2. 설정파일 확인 (Disable=yes 설정시 양호)" >> $CREATE_FILE 2>&1
			echo "[+] 2-1. 현황 : chargen 확인 " >> $CREATE_FILE 2>&1
			cat /etc/xinetd.d/chargen >> $CREATE_FILE 2>&1
			echo "" >> $CREATE_FILE 2>&1 
			cat /etc/xinetd.d/chargen-dgram >> $CREATE_FILE 2>&1
			echo "" >> $CREATE_FILE 2>&1 
			echo "[+] 2-2. 현황 : daytime 확인 " >> $CREATE_FILE 2>&1
			cat /etc/xinetd.d/daytime >> $CREATE_FILE 2>&1
			echo "" >> $CREATE_FILE 2>&1 
			cat /etc/xinetd.d/daytime-dgram >> $CREATE_FILE 2>&1
			echo "" >> $CREATE_FILE 2>&1 
			echo "[+] 2-3. 현황 : discard 확인 " >> $CREATE_FILE 2>&1
			cat /etc/xinetd.d/discard >> $CREATE_FILE 2>&1
			echo "" >> $CREATE_FILE 2>&1 
			cat /etc/xinetd.d/discard-dgram >> $CREATE_FILE 2>&1
			echo "" >> $CREATE_FILE 2>&1 
			echo "[+] 2-4. 현황 : echo 확인 " >> $CREATE_FILE 2>&1
			cat /etc/xinetd.d/echo >> $CREATE_FILE 2>&1
			echo "" >> $CREATE_FILE 2>&1 
			cat /etc/xinetd.d/echo-dgram >> $CREATE_FILE 2>&1
			echo "" >> $CREATE_FILE 2>&1
		else
			echo "파일이 존재하지 않습니다." >> $CREATE_FILE 2>&1
		fi
		;;
	AIX | HP-UX)
		echo "[+] 1. 현황 : /etc/inetd.conf 확인하여 해당 서비스 주석 확인" >> $CREATE_FILE 2>&1
		cat /etc/inetd.conf >> $CREATE_FILE 2>&1
		echo "" >> $CREATE_FILE 2>&1
		;;
esac
echo "" >> $CREATE_FILE 2>&1
echo "[U-23_END]" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
echo "[참고 - 진단기준, 결과 값 출력]" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo " * 양호 기준 : echo, discard, daytime, chargen 서비스가 비활성화 되어있거나 결과값이 없을경우에 양호" >> $CREATE_FILE 2>&1
echo " * 취약 기준 : 미사용 중인 서비스로 구동 중이거나, 불필요하게 서비스가 구동 중인 경우" >> $CREATE_FILE 2>&1

echo "[*] Sendmail 구동 시 프로세스 출력 값(예시)" >> $CREATE_FILE 2>&1
echo "  root      29202      1  0 Dec12 ?        00:00:00 sendmail: accepting connections" >> $CREATE_FILE 2>&1
echo "  smmsp     29213      1  0 Dec12 ?        00:00:00 sendmail: Queue runner@01:00:00 for /var/spool/clientmqueue" >> $CREATE_FILE 2>&1
echo " *** 결과 파일이 출력된다는 것은 해당 서비스가 활성화(Active-Running) 상태이기 때문에 출력되는 것으로 알고 계시면 됩니다." >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
}

U-24(){
echo "[U-24] NFS 서비스 비활성화"
echo "[U-24] NFS 서비스 비활성화" >> $CREATE_FILE 2>&1
echo "[U-24_START]" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
echo "[+] 1. 현황 : nfs|mountd|statd 서비스 확인" >> $CREATE_FILE 2>&1
ps -ef | egrep "nfs|statd|mountd" | grep -v 'grep' >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1

case $OS in
	SunOS)
		echo "[+] 1-2. 현황(Solaris 10버전 이상) : nfs|mountd|statd 서비스 확인" >> $CREATE_FILE 2>&1
		inetadm | egrep "nfs|statd|lockd" >> $CREATE_FILE 2>&1
		echo " " >> $CREATE_FILE 2>&1
		;;
	Linux)
		echo "[+] 2. 참고 : service nfs status 실행(NFS 프로세스의 Status 필드 inactive면 양호) " >> $CREATE_FILE 2>&1
		service nfs status >> $CREATE_FILE 2>&1
		echo " " >> $CREATE_FILE 2>&1
esac
echo "" >> $CREATE_FILE 2>&1
echo "[U-24_END]" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
case $OS in
	Linux)
		echo "[+] 2. 참고 : service nfs status 실행(NFS 프로세스의 Status 필드 inactive면 양호) " >> $CREATE_FILE 2>&1
		echo "" >> $CREATE_FILE 2>&1
esac
echo "[참고 - 진단기준, 결과 값 출력]" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo " * 양호 기준 : 불필요한 NFS 서비스 관련 데몬이 비활성화 되어 있는 경우" >> $CREATE_FILE 2>&1
echo " * 취약 기준 : 불필요한 NFS 서비스 관련 데몬이 활성화 되어 있는 경우" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1

}

NFS_Check_01=`ps -ef | grep nfs | grep -v 'grep' | wc -l`

U-25(){
echo "[U-25] NFS 접근 통제"
echo "[U-25] NFS 접근 통제" >> $CREATE_FILE 2>&1
echo "[U-25_START]" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
unix_nfs_check="/etc/dfs/dfstab /etc/dfs/sharetab /etc/exports /etc/vfstab"
echo "showmount -e" >> $CREATE_FILE 2>&1
showmount -e >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1

if [ $NFS_Check_01 -ne 0 ]
then
	echo "[+] NFS 서비스가 활성화되어 있습니다." >> $CREATE_FILE 2>&1
	echo "" >> $CREATE_FILE 2>&1
		if [ -f /etc/dfs/dfstab ]
		then
			echo "1.cat /etc/dfs/dfstab" 			>> $CREATE_FILE 2>&1
			cat /etc/dfs/dfstab 		 			>> $CREATE_FILE 2>&1
			echo " " 				  	 			>> $CREATE_FILE 2>&1
			echo "2.ls -laL /etc/dfs/dfstab"	 	>> $CREATE_FILE 2>&1
			ls -laL /etc/dfs/dfstab 	 			>> $CREATE_FILE 2>&1
			
			echo "1.cat /etc/dfs/dfstab"  			>> unix_nfs_check
			cat /etc/dfs/dfstab 		 			>> unix_nfs_check
			echo " " 				  	 			>> unix_nfs_check
			echo "2.ls -laL /etc/dfs/dfstab"		>> unix_nfs_check
			ls -laL /etc/dfs/dfstab 	 			>> unix_nfs_check
		fi	
	
		if [ -f /etc/exports ]	
		then
			echo "" >> $CREATE_FILE 2>&1		
			echo "1.cat /etc/exports" 	 			>> $CREATE_FILE 2>&1
			cat /etc/exports 			 			>> $CREATE_FILE 2>&1
			echo " " 				  	 			>> $CREATE_FILE 2>&1
			echo "2.ls -laL /etc/exports" 			>> $CREATE_FILE 2>&1
			ls -laL /etc/exports 		 			>> $CREATE_FILE 2>&1
			
			echo "1.cat /etc/exports" 	 			>> unix_nfs_check
			cat /etc/exports 			 			>> unix_nfs_check
			echo " " 				  	 			>> unix_nfs_check
			echo "2.ls -laL /etc/exports" 			>> unix_nfs_check
			ls -laL /etc/exports		 			>> unix_nfs_check
		fi	
	
		if [ -f /etc/dfs/sharetab ]	
		then	
			echo "" >> $CREATE_FILE 2>&1
			echo "1.cat /etc/dfs/sharetab"	 		>> $CREATE_FILE 2>&1
			cat /etc/dfs/sharetab 		 	 		>> $CREATE_FILE 2>&1
			echo " "					 	 		>> $CREATE_FILE 2>&1
			echo "2.ls -laL /etc/dfs/sharetab"		>> $CREATE_FILE 2>&1
			ls -laL /etc/dfs/sharetab  		 		>> $CREATE_FILE 2>&1
			echo " "					 	 		>> $CREATE_FILE 2>&1
			echo "1.cat /etc/dfs/sharetab"	 		>> unix_nfs_check
			cat /etc/dfs/sharetab 		 	 		>> unix_nfs_check
			echo " " 					 	 		>> unix_nfs_check
			echo "2.ls -laL /etc/dfs/sharetab" 		>> unix_nfs_check
			ls -laL /etc/dfs/sharetab 	 	 		>> unix_nfs_check
			echo " " 					 	 		>> unix_nfs_check
		fi

		if [ -f /etc/vfstab ]
		then
			echo "" >> $CREATE_FILE 2>&1
			echo "1.cat /etc/vfstab" 				>> $CREATE_FILE 2>&1
			cat /etc/vfstab 						>> $CREATE_FILE 2>&1
			echo " " 								>> $CREATE_FILE 2>&1
			echo "2.ls -laL /etc/vfstab"			>> $CREATE_FILE 2>&1
			ls -laL /etc/vfstab 					>> $CREATE_FILE 2>&1
			echo " " 								>> $CREATE_FILE 2>&1
			echo "1.cat /etc/vfstab" 				>> unix_nfs_check
			echo "#cat /etc/vfstab" 				>> unix_nfs_check
			cat /etc/vfstab 						>> unix_nfs_check
			echo " " 								>> unix_nfs_check
			echo "2.ls -laL /etc/vfstab"			>> unix_nfs_check
			ls -laL /etc/vfstab 					>> unix_nfs_check
			echo " " 								>> unix_nfs_check
		fi

		if [ -f unix_nfs_check ]
		then
			echo "[+]NFS 파일(/etc/export 및 /etc/dfs/dfstab)존재함(수동점검)" >> $CREATE_FILE 2>&1	
			rm -f ./unix_nfs_check
		else
			echo "[+]NFS 파일(/etc/export 및 /etc/dfs/dfstab)존재하지 않음" >> $CREATE_FILE 2>&1	
		fi
else
	echo "[+] NFS 서비스가 비활성화되어 있습니다." >> $CREATE_FILE 2>&1
fi

echo "" >> $CREATE_FILE 2>&1
echo "[U-25_END]" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
echo "[참고 - 진단기준, 결과 값 출력]" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo " * 양호 기준 : NFS 미사용 또는 설정 파일 조회 시 everyone에 대해 제한한 경우" >> $CREATE_FILE 2>&1
echo " * 취약 기준 : 1. NFS 사용하며, everyone에 대해 제한하지 않은 경우 / 2. NFS 설정 파일 내에 읽기/쓰기 권한 정의 등의 적절한 접근 통제 설정이 없을 경우 / 3. NFS 설정 파일의 접근권한이 소유자가 root가 아니고, 권한이 644보다 높게 부여된 경우" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1


unset unix_nfs_check
}

U-26(){
echo "[U-26] automountd 제거"
echo "[U-26] automountd 제거" >> $CREATE_FILE 2>&1
echo "[U-26_START]" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
pscheck=`ps -ef | egrep 'autofs|automount' | grep -v 'grep' | wc -l`

case $OS in
	SunOS|AIX|Linux)
	if [ $pscheck -ne 0 ]
	then
		echo "[+] automountd 또는 autofs 가 활성화 되어있습니다." >> $CREATE_FILE 2>&1
		ps -ef | egrep 'autofs|automount' | grep -v 'grep' >> $CREATE_FILE 2>&1
	else
		echo "[+] automountd 와 autofs 가 비활성화 되어있습니다." >> $CREATE_FILE 2>&1
	fi
	;;
	HP-UX)
	if [ $pscheck -ne 0 ]
	then
		echo "[+] automountd 또는 autofs 가 활성화 되어있습니다." >> $CREATE_FILE 2>&1
		ps -ef | egrep 'autofs|automount' | grep -v 'grep' >> $CREATE_FILE 2>&1
		echo "" >> $CREATE_FILE 2>&1
		echo "[+] AUTOFS 값 확인" >> $CREATE_FILE 2>&1
		cat /etc/rc.config.d/nfsconf | grep -i 'AUTOFS' >> $CREATE_FILE 2>&1
		echo "" >> $CREATE_FILE 2>&1
	else
		echo "[+] automountd 와 autofs 가 비활성화 되어있습니다." >> $CREATE_FILE 2>&1
	fi
	;;
esac
echo "[U-26_END]" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
echo "[참고 - 진단기준, 결과 값 출력]" >> $CREATE_FILE 2>&1
echo " * 양호 조건 : 불필요한 autmountd 서비스가 비활성화된 경우" >> $CREATE_FILE 2>&1
echo " * 취약 조건 : 취약한 버전의 automountd 서비스가 불필요하게 활성화된 경우 / HP-UX 같은 경우 automount가 활성화된 경우 AUTOFS 값이 1인 경우 취약 " >> $CREATE_FILE 2>&1
echo " *** 결과 값이 출력되지 않을 경우 미구동 중인 것으로 판단" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1

unset pscheck

}

U-27(){
echo "[U-27] RPC 서비스 확인"
echo "[U-27] RPC 서비스 확인" >> $CREATE_FILE 2>&1
echo "[U-27_START]" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
rpc_list="rpc.cmsd rpc.ttdbserverd sadmind rusersd walld sprayd rstatd rpc.nisd rexd rpc.pcnfsd rpc.statd rpc.ypupdated rpc.rquotad kcms_server cachefsd"

	echo "[+] 1. rpc 프로세스 현황" >> $CREATE_FILE 2>&1
	ps -ef | grep $rpc_list 2>/dev/null | grep -v 'grep' >> $CREATE_FILE 2>&1
	echo "[*] 출력값 존재 시 취약" >> $CREATE_FILE 2>&1
	echo "" >> $CREATE_FILE 2>&1

	echo "[+] 2. rpc 서비스 현황" >> $CREATE_FILE 2>&1
	rpcinfo -p | grep $rpc_list 2>/dev/nul | grep -v 'grep' >> $CREATE_FILE 2>&1
	echo "[*] 출력값 존재 시 취약" >> $CREATE_FILE 2>&1
	echo "" >> $CREATE_FILE 2>&1

	echo "[+] 3. inetd.conf 확인" >> $CREATE_FILE 2>&1
	if [ -e "/etc/inetd.conf" ]; then
		cat /etc/inetd.conf | grep $rpc_list | grep -v 'grep' >> $CREATE_FILE 2>&1
    else
        echo "파일이 존재하지 않습니다. /etc/inetd.conf" >> $CREATE_FILE 2>&1
    fi
	echo "[*] 출력값 존재 시 취약" >> $CREATE_FILE 2>&1
	echo "" >> $CREATE_FILE 2>&1


echo "[U-27_END]" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
echo "[참고 - 진단기준, 결과 값 출력]" >> $CREATE_FILE 2>&1
echo " 양호 : 불필요한 RPC 관련 서비스가 존재하지 않으면 양호 (업무상 사용시 예외)" >> $CREATE_FILE 2>&1
echo " 취약 : 불필요한 RPC 관련 서비스가 존재하면 취약" >> $CREATE_FILE 2>&1
echo " 참고 목록 : rpc.cmsd rpc.ttdbserverd sadmind rusersd walld sprayd rstatd rpc.nisd rexd rpc.pcnfsd rpc.statd rpc.ypupdated rpc.rquotad kcms_server cachefsd" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1

unset rpc_list
}

U-28(){
echo "[U-28] NIS, NIS+ 점검"
echo "[U-28] NIS, NIS+ 점검" >> $CREATE_FILE 2>&1
echo "[U-28_START]" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1

echo "[+] NIS 서비스, NIS+ 서비스 활성화 확인" >> $CREATE_FILE 2>&1

if [ `ps -ef | egrep "ypserv|ypbind|ypxfrd|rpc.yppasswdd|rpc.ypupdated" | grep -v 'grep' | wc -l` -eq 0 ]
then
	echo "[+] 해당 서비스가 비활성화되어 있습니다." >> $CREATE_FILE 2>&1
	echo "" >> $CREATE_FILE 2>&1
else
	ps -ef | egrep "ypserv|ypbind|ypxfrd|rpc.yppasswdd|rpc.ypupdated" | grep -v 'grep' >> $CREATE_FILE 2>&1
	echo "" >> $CREATE_FILE 2>&1
fi


echo "" >> $CREATE_FILE 2>&1
echo "[U-28_END]" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
echo "[참고 - 진단기준, 결과 값 출력]" >> $CREATE_FILE 2>&1
echo " * 양호 조건 : 아래의 항목 중 해당사항이 없는경우" >> $CREATE_FILE 2>&1
echo " * 취약 조건 : 아래의 항목 중 해당하는 조건이 있는 경우" >> $CREATE_FILE 2>&1
echo "*********************************************" >> $CREATE_FILE 2>&1
echo "1. NIS, NIS+ 서비스 활성화" >> $CREATE_FILE 2>&1
echo "[*] 프로세스 구동여부 더블체크" >> $CREATE_FILE 2>&1
echo "*********************************************" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
}

U-29(){
echo "[U-29] tftp, talk 서비스 비활성화"
echo "[U-29] tftp, talk 서비스 비활성화" >> $CREATE_FILE 2>&1
echo "[U-29_START]" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1

echo "[+] inetd 활성화 서비스 목록" >> $CREATE_FILE 2>&1
if [ -f /etc/inetd.conf ]
then
	inetd_services="tftp talk ntalk"
	for inetd_chk in $inetd_services
	do
		ps -ef | grep $inetd_chk | grep -v 'grep'\# >> $CREATE_FILE 2>&1
		cat /etc/inetd.conf | grep $inetd_chk | grep -v 'grep'\# >> $CREATE_FILE 2>&1
	done
	if [ `cat /etc/inetd.conf | grep $inetd_chk | grep -v 'grep' \# | wc -l` -eq 0 ]
	then
		echo "[+] 해당 서비스가 비활성화되어 있습니다." >> $CREATE_FILE 2>&1
		echo "" >> $CREATE_FILE 2>&1
	fi
else
	echo "[+] 해당 서비스가 비활성화되어 있습니다." >> $CREATE_FILE 2>&1
	echo "" >> $CREATE_FILE 2>&1
fi
echo "" >> $CREATE_FILE 2>&1

echo "[+] xinetd 활성화 서비스 목록" >> $CREATE_FILE 2>&1
if [ -e /etc/xinetd ]
then
	xinetd_serivces=`ls /etc/xinetd.d/*`
	for xinetd_chk in $xinetd_serivces
	do
		echo "[*]" $xinetd_chk >> $CREATE_FILE 2>&1
		ps -ef | grep $xinetd_chk | grep -v 'grep'\# >> $CREATE_FILE 2>&1
		cat $xinetd_chk | grep disable | grep -i no >> $CREATE_FILE 2>&1
		echo "" >> $CREATE_FILE 2>&1
	done
	if [ `cat $xinetd_chk | grep disable | grep -i no` -eq 0 ]
	then
		echo "[+] 활성화 서비스가 존재하지 않습니다." >> $CREATE_FILE 2>&1
		echo "" >> $CREATE_FILE 2>&1
	fi
else
	echo "[+] xinetd 디렉터리가 존재하지 않습니다." >> $CREATE_FILE 2>&1
	echo "" >> $CREATE_FILE 2>&1
fi



echo "" >> $CREATE_FILE 2>&1
echo "[U-29_END]" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
echo "[참고 - 진단기준, 결과 값 출력]" >> $CREATE_FILE 2>&1
echo " * 양호 조건 : 아래의 항목 중 해당사항이 없는경우" >> $CREATE_FILE 2>&1
echo " * 취약 조건 : 아래의 항목 중 해당하는 조건이 있는 경우" >> $CREATE_FILE 2>&1
echo "*********************************************" >> $CREATE_FILE 2>&1
echo "1. tftp, talk, ntalk 서비스가 불필요하게 활성화된 경우" >> $CREATE_FILE 2>&1
echo "2. finger 서비스 활성화" >> $CREATE_FILE 2>&1
echo "3. rexec, rlogin, rsh 서비스 활성화" >> $CREATE_FILE 2>&1
echo "4. DoS 공격에 취약한 echo, discard, daytime, chargen 서비스 활성화" >> $CREATE_FILE 2>&1
echo "5. NIS, NIS+ 서비스 활성화" >> $CREATE_FILE 2>&1
echo "[*] 프로세스 구동여부 더블체크" >> $CREATE_FILE 2>&1
echo "*********************************************" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1

unset xinetd_serivces
unset inetd_services
unset xinetd_chk
unset inetd_chk
}

sendmail_conf_list="/etc/mail/sendmail.cf /etc/sendmail.cf"

U-30(){
echo "[U-30] Sendmail 버전 점검"
echo "[U-30] Sendmail 버전 점검" >> $CREATE_FILE 2>&1
echo "[U-30_START]" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
if [ $SMTP_Sendmail_Check -ne 0 ]
	then
		echo "[+] Sendamil 서비스가 활성화 중입니다." >> $CREATE_FILE 2>&1
		echo "*** 기본적으로 비활성화되어있는 서비스로 불필요 여부 확인필요 요망 " >> $CREATE_FILE 2>&1
		echo "" >> $CREATE_FILE 2>&1
		echo "[+] Sendmail 버전 정보" >> $CREATE_FILE 2>&1
		for Check_sendmail in $sendmail_conf_list
		do
			if [ -f $Check_sendmail ]
			then
				echo "[+]" $Check_sendmail >> $CREATE_FILE 2>&1
				cat $Check_sendmail | grep DZ >> $CREATE_FILE 2>&1
				echo "" >> $CREATE_FILE 2>&1
			fi
		done	
	else
		echo "[+] Sendmail 서비스가 비활성화되어 있습니다. " >> $CREATE_FILE 2>&1
		echo "" >> $CREATE_FILE 2>&1
fi

echo "" >> $CREATE_FILE 2>&1
echo "[U-30_END]" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
echo "[*] SMTP 포트 확인(참고) " >> $CREATE_FILE 2>&1
netstat -na | grep -w "25" | grep "LISTEN" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "[참고 - 진단기준, 결과 값 출력]" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo " * 양호 기준 : SMTP 서비스 버전이 최신 버전일 경우 또는 금융회사 내부 규정에 따라 패치 검토 및 패치를 수행하고 있는 경우" >> $CREATE_FILE 2>&1
echo " * 취약 기준 : SMTP 서비스 버전이 최신이 아닐 경우 또는 금융회사 내부 규정의 패치 관리 절차를 준수하지 않은 경우" >> $CREATE_FILE 2>&1
echo " ****** Sendmail Release List ******" >> $CREATE_FILE 2>&1
echo "  - 8.17.1/8.17.1  2021/08/17" >> $CREATE_FILE 2>&1
echo "  - 8.16.2/8.16.2 202X/XX/XX" >> $CREATE_FILE 2>&1
echo "  - 8.16.1/8.16.1 2020/07/05" >> $CREATE_FILE 2>&1
echo "  - 8.15.2/8.15.2 2015/07/03" >> $CREATE_FILE 2>&1
echo "  - 8.15.1/8.15.1 2014/12/06" >> $CREATE_FILE 2>&1
echo "  - 8.14.7/8.14.7 2013/04/21" >> $CREATE_FILE 2>&1
echo "  - 8.14.6/8.14.6 2012/12/23" >> $CREATE_FILE 2>&1
echo " ***********************************" >> $CREATE_FILE 2>&1
echo " 참고 출처 : https://ftp.sendmail.org/RELEASE_NOTES" >> $CREATE_FILE 2>&1
echo " 버전정보는 상시로 업데이트 될 수 있으니 진단 진행할 때 마다 체크필요" >> $CREATE_FILE 2>&1
echo " *** 결과 파일이 출력된다는 것은 해당 서비스가 활성화(Active-Running) 상태이기 때문에 출력되는 것으로 알고 계시면 됩니다." >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1

}

U-31(){
echo "[U-31] 스팸 메일 릴레이 제한"
echo "[U-31] 스팸 메일 릴레이 제한" >> $CREATE_FILE 2>&1
echo "[U-31_START]" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
if [ $SMTP_Sendmail_Check -ne 0 ]
	then
		echo "[+] Sendamil 서비스가 활성화 중입니다." >> $CREATE_FILE 2>&1
		echo "*** 기본적으로 비활성화되어있는 서비스로 불필요 여부 확인필요 요망 " >> $CREATE_FILE 2>&1
		echo "" >> $CREATE_FILE 2>&1
		echo "[+] Sendmail 버전 정보" >> $CREATE_FILE 2>&1
			for Check_sendmail in $sendmail_conf_list
			do
				if [ -f $Check_sendmail ]
				then
					cat $Check_sendmail | grep DZ >> $CREATE_FILE 2>&1
					echo "" >> $CREATE_FILE 2>&1
					echo "[+]" $Check_sendmail >> $CREATE_FILE 2>&1
					cat $Check_sendmail | grep "R$\*" | grep -i "Relaying" >> $CREATE_FILE 2>&1
					echo "" >> $CREATE_FILE 2>&1
				fi
			done			
	else
		echo "[+] Sendmail 서비스가 비활성화되어 있습니다. " >> $CREATE_FILE 2>&1
		echo "" >> $CREATE_FILE 2>&1
fi

echo "" >> $CREATE_FILE 2>&1
echo "[U-31_END]" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
echo "[*] SMTP 포트 확인(참고) " >> $CREATE_FILE 2>&1
netstat -na | grep -w "25" | grep "LISTEN" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "[참고 - 진단기준, 결과 값 출력]" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo " * 양호 기준 1. : sendmail 버전 8.9 이상인 경우 양호(디폴트로 스팸 메일 릴레이 방지 설정이 되어 있음) " >> $CREATE_FILE 2>&1
echo " * 양호 기준 2. : 스팸 메일 릴레이 방지 설정을 했을 경우" >> $CREATE_FILE 2>&1
echo " ** 양호 기준 설정 예시 ** " >> $CREATE_FILE 2>&1
echo " R\$*                     $#error $@ 5.7.1 $: "550 Relaying denied"" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo " * 취약 기준 : 스팸 메일 릴레이 방지 설정이 적용되지 않은 경우(해당 설정이 주석처리 된 경우)" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo " *** 결과 파일이 출력된다는 것은 해당 서비스가 활성화(Active-Running) 상태이기 때문에 출력되는 것으로 알고 계시면 됩니다." >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
}

U-32(){
echo "[U-32] 일반사용자의 Sendmail 실행 방지"
echo "[U-32] 일반사용자의 Sendmail 실행 방지" >> $CREATE_FILE 2>&1
echo "[U-32_START]" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
if [ $SMTP_Sendmail_Check -ne 0 ]
	then
		echo "[+] Sendamil 서비스가 활성화 중입니다." >> $CREATE_FILE 2>&1
		echo "*** 기본적으로 비활성화되어있는 서비스로 불필요 여부 확인필요 요망 " >> $CREATE_FILE 2>&1
		echo "" >> $CREATE_FILE 2>&1
		for Check_sendmail in $sendmail_conf_list
		do
			if [ -f $Check_sendmail ]
			then
				echo "[+]" $Check_sendmail >> $CREATE_FILE 2>&1
				cat $Check_sendmail | grep -i "PrivacyOptions" >> $CREATE_FILE 2>&1
				echo "" >> $CREATE_FILE 2>&1
			fi
		done
	else
		echo "[+] Sendmail 서비스가 비활성화되어 있습니다. " >> $CREATE_FILE 2>&1
		echo "" >> $CREATE_FILE 2>&1
fi

echo "" >> $CREATE_FILE 2>&1
echo "[U-32_END]" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
echo "[*] SMTP 포트 확인(참고) " >> $CREATE_FILE 2>&1
netstat -na | grep -w "25" | grep "LISTEN" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1

echo "[참고 - 진단기준, 결과 값 출력]" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo " * 양호 기준 : PrivacyOptions 에 restrictqrun 설정 존재하는 경우" >> $CREATE_FILE 2>&1
echo " * 취약 기준 : PrivacyOptions 에 restrictqrun 설정 존재하지 않는 경우" >> $CREATE_FILE 2>&1
echo " *** 결과 파일이 출력된다는 것은 해당 서비스가 활성화(Active-Running) 상태이기 때문에 출력되는 것으로 알고 계시면 됩니다." >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1


unset Check_sendmail
}

DNS_Check=`ps -ef | grep named | grep -v 'grep' | wc -l`
DNS_Conf_list="/etc/named.boot /etc/named.conf /etc/bind/named.boot /etc/bind/named.conf /etc/bind/named.conf.options"

U-33(){
echo "[U-33] DNS 보안 버전 패치"
echo "[U-33] DNS 보안 버전 패치" >> $CREATE_FILE 2>&1
echo "[U-33_START]" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
if [ $DNS_Check -ne 0 ]
	then
		echo "[+] DNS 서비스가 활성화 중입니다." >> $CREATE_FILE 2>&1
		echo "*** 기본적으로 비활성화되어있는 서비스로 DNS 서비스 활성화 시 필요성 여부 확인필요 요망 " >> $CREATE_FILE 2>&1
		echo "" >> $CREATE_FILE 2>&1
		echo "[+] DNS 프로세스 실행 확인" >> $CREATE_FILE 2>&1
		ps -ef | grep "named" | grep -v 'grep' >> $CREATE_FILE 2>&1
		echo "" >> $CREATE_FILE 2>&1
		echo "[+] DNS 버전 확인" >> $CREATE_FILE 2>&1
		named -v >> $CREATE_FILE 2>&1
		echo "" >> $CREATE_FILE 2>&1
		echo "[+] DNS 취약점 쿼리 전송 결과 " >> $CREATE_FILE 2>&1
		dig @localhost +short porttest.dns-oarc.net TXT
		echo "" >> $CREATE_FILE 2>&1
	else
		echo "[+] DNS 서비스가 비활성화되어 있습니다. " >> $CREATE_FILE 2>&1
		echo "" >> $CREATE_FILE 2>&1

fi


echo "" >> $CREATE_FILE 2>&1
echo "[U-33_END]" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
echo "[*] DNS 포트 확인(참고) " >> $CREATE_FILE 2>&1
netstat -na | grep -w "53" | grep "LISTEN" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "[참고 - 진단기준, 결과 값 출력]" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo " * 양호 기준 : 알려진 취약점이 없는 DNS 버전을 사용하는 경우(쿼리 결과 값이 없는 경우 포함)" >> $CREATE_FILE 2>&1
echo " * 양호 기준 : dig @localhost +short porttest.dns-oarc.net TXT 명령 결과가 다음과 같은 경우
     z.y.x.w.v.u.t.s.r.q.p.o.n.m.l.k.j.i.h.g.f.e.d.c.b.a.pt.dns-oarc.net.
     "IP-of-GOOD is GOOD: 26 queries in 2.0 seconds from 26 ports with std dev 17685.51"" >> $CREATE_FILE 2>&1
echo " * 취약 기준 :  dig @localhost +short porttest.dns-oarc.net TXT 명령 결과가 다음과 같은 경우
     porttest.y.x.w.v.u.t.s.r.q.p.o.n.m.l.k.j.i.h.g.f.e.d.c.b.a.pt.dns-oarc.net.
     "해당서버IP is POOR: 26 queries in 3.6 seconds from 1 ports with std dev 0"" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
}

U-34(){
echo "[U-34] DNS Zone Transfer 설정"
echo "[U-34] DNS Zone Transfer 설정" >> $CREATE_FILE 2>&1
echo "[U-34_START]" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
if [ $DNS_Check -ne 0 ]
	then
		echo "[+] DNS 서비스가 활성화 중입니다." >> $CREATE_FILE 2>&1
		echo "*** 기본적으로 비활성화되어있는 서비스로 DNS 서비스 활성화 시 필요성 여부 확인필요 요망 " >> $CREATE_FILE 2>&1
		echo "" >> $CREATE_FILE 2>&1
		echo "[+] DNS 프로세스 실행 확인" >> $CREATE_FILE 2>&1
		ps -ef | grep "named" | grep -v 'grep' >> $CREATE_FILE 2>&1
		echo "" >> $CREATE_FILE 2>&1
		echo "[+] DNS zone Transfer 설정 확인(파일명 하단에 출력값 없으면 양호)" >> $CREATE_FILE 2>&1
		zone_value="allow-transfer xfrnets"
		for Check_DNS_conf in $DNS_Conf_list
		do
			if [ -f $Check_DNS_conf ]
			then
				echo " [*]" $Check_DNS_conf >> $CREATE_FILE 2>&1
				echo "" >> $CREATE_FILE 2>&1
				for check_zone in $zone_value
				do
					grep "$check_zone" $Check_DNS_conf >> $CREATE_FILE 2>&1
					echo "" >> $CREATE_FILE 2>&1
				done
			fi
		done
	else
		echo "[+] DNS 서비스가 비활성화되어 있습니다. " >> $CREATE_FILE 2>&1
		echo "" >> $CREATE_FILE 2>&1
fi


echo "" >> $CREATE_FILE 2>&1
echo "[U-34_END]" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
echo "[*] DNS 포트 확인(참고) " >> $CREATE_FILE 2>&1
netstat -na | grep -w "53" | grep "LISTEN" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "[참고 - 진단기준, 결과 값 출력]" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo " * 양호 기준 : DNS 서비스 미사용 또는, Zone Transfer를 허가된 사용자에게만 허용한 경우" >> $CREATE_FILE 2>&1
echo " * 취약 기준 : DNS 서비스를 사용하며 Zone Transfer를 모든 사용자에게 허용한 경우" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1


unset zone_value
unset check_zone
}

web_ps_check=`ps -ef | grep httpd | grep -v 'grep' | wc -l`

U-35(){
echo "[U-35] 웹서비스 디렉토리 리스팅 제거"
echo "[U-35] 웹서비스 디렉토리 리스팅 제거" >> $CREATE_FILE 2>&1
echo "[U-35_START]" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
if [ $web_ps_check -ne 0 ]
then
	echo "[+] apache 서비스가 구동중 입니다." >> $CREATE_FILE 2>&1
case $OS in
		Linux)
		# Linux httpd Daemon path
		httpd_daemon=`ps -ef | grep httpd | awk '{print $8}' | grep -v grep | grep /httpd$ | sort | head -1`
		apache2_daemon=`ps -ef | grep apache | awk '{print $8}' | grep -v grep | grep /apache2$ | sort | head -1`
		
		if file_check $httpd_daemon ; then
			# httpd root Directory
			$httpd_daemon -V | grep -E "(HTTPD\_ROOT)" | tr '"' '\n' | sed -n 2p >> ./Lyn_tmp/httpd_root.txt
			
			# httpd conf Directory
			$httpd_daemon -V | grep -E "(HTTPD\_ROOT|SERVER\_CONFIG\_FILE)" | tr '"' '\n' | sed -n 5p >> ./Lyn_tmp/httpd_conf.txt
			
			# save httpd Directory path
			httpd_root=`cat ./Lyn_tmp/httpd_root.txt`
			httpd_conf=`cat ./Lyn_tmp/httpd_conf.txt`
			
			# Path Inforamtion into Parameter
			echo "[+] 1. 설정파일 현황" >> $CREATE_FILE 2>&1
			cat $httpd_root/conf/httpd.conf >> ./Lyn_tmp/httpd_conf.txt
			cat $httpd_root/conf/httpd.conf | grep -i Indexes >> $CREATE_FILE 2>&1
		else
			echo "httpd 데몬이 비실행 중입니다." >> ./Lyn_tmp/httpd_root.txt
		fi

		if file_check $apache2_daemon ; then
			# httpd root Directory
			$apache2_daemon -V | grep -E "(HTTPD\_ROOT)" | tr '"' '\n' | sed -n 2p >> ./Lyn_tmp/apache2_conf.txt
			
			# httpd conf Directory
			$apache2_daemon -V | grep -E "(HTTPD\_ROOT|SERVER\_CONFIG\_FILE)" | tr '"' '\n' | sed -n 5p >> ./Lyn_tmp/apache2_conf.txt
			
			# save httpd Directory path
			apache2_root=`cat ./Lyn_tmp/apache2_root.txt`
			apache2_conf=`cat ./Lyn_tmp/apache2_conf.txt`
			
			# Path Inforamtion into Parameter
			echo "[+] 1. 설정파일 현황" >> $CREATE_FILE 2>&1
			cat $apache2_root/apache2.conf >> ./Lyn_tmp/apache2_conf.txt
			cat $apache2_root/apache2.conf | grep -i Indexes >> $CREATE_FILE 2>&1
		else
			echo "Apache2 데몬이 비실행 중입니다." >> ./Lyn_tmp/apache2_conf.txt
		fi
		;;
		
	
		SunOS | AIX | HP-UX)
		#path_config
		#web_command_path=`find / -name apachectl | head -1`
		web_command_path=`find / \
		\( -path /proc -o -path /sys -o -path /dev -o -path /run -o -path /var/run \) -prune -o \
		-name apachectl -print 2>/dev/null | head -1`
		
		# httpd root Directory
		$web_command_path -V | grep -E "(HTTPD\_ROOT)" | tr '"' '\n' | sed -n 2p >> ./Lyn_tmp/httpd_root.txt
		apache2 -V | grep -E "(HTTPD\_ROOT)" | tr '"' '\n' | sed -n 2p >> ./Lyn_tmp/apache2_root.txt
		
		# httpd conf Directory
		$web_command_path -V | grep -E "(HTTPD\_ROOT|SERVER\_CONFIG\_FILE)" | tr '"' '\n' | sed -n 5p > ./Lyn_tmp/httpd_conf.txt
		apache2 -V | grep -E "(HTTPD\_ROOT|SERVER\_CONFIG\_FILE)" | tr '"' '\n' | sed -n 5p >> ./Lyn_tmp/apache2_conf.txt
		
		# Create httpd Directory File
		httpd_root=`cat ./Lyn_tmp/httpd_root.txt`
		httpd_conf=`cat ./Lyn_tmp/httpd_conf.txt`
		apache2_root=`cat ./Lyn_tmp/apache2_root.txt`
		apache2_conf=`cat ./Lyn_tmp/apache2_conf.txt`
	
		# Path Inforamtion into Parameter
		cat $httpd_root/conf/httpd.conf >> ./Lyn_tmp/httpd_conf.txt
		echo "[+] 설정파일 현황" >> $CREATE_FILE 2>&1
		cat $httpd_root/conf/httpd.conf | grep -i Indexes >> $CREATE_FILE 2>&1
		cat $apache2_root/apache2.conf >> ./Lyn_tmp/apache2_conf.txt
		cat $apache2_root/apache2.conf | grep -i Indexes >> $CREATE_FILE 2>&1
		;;
	
esac
else 
	echo "[+] apache 서비스가 존재하지 않거나 구동중이지 않습니다." >> $CREATE_FILE 2>&1
fi
echo "[U-35_END]" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
echo "[참고 - 진단기준, 결과 값 출력]" >> $CREATE_FILE 2>&1
echo " * 양호 조건 : 디렉터리 리스팅이 불가능할 경우" >> $CREATE_FILE 2>&1
echo " * 취약 조건 : httpd.conf 파일 내의 Options에서 Indexes 옵션이 있을 경우" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
}

U-36(){
echo "[U-36] 웹서비스 웹 프로세스 권한 제한"
echo "[U-36] 웹서비스 웹 프로세스 권한 제한" >> $CREATE_FILE 2>&1
echo "[U-36_START]" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1

if [ $web_ps_check -ne 0 ]
then
	echo "[+] apache 서비스가 구동중 입니다." >> $CREATE_FILE 2>&1
	echo "[+] 현황 확인" >> $CREATE_FILE 2>&1
	cat ./Lyn_tmp/httpd_conf.txt | grep -i "user" | grep -v "\#" | egrep -v "^LoadModule|LogFormat|IfModule|UserDir"	>> $CREATE_FILE 2>&1
	echo "" >> $CREATE_FILE 2>&1
	cat ./Lyn_tmp/httpd_conf.txt | grep -i "group" | grep -v "\#" | egrep -v "^LoadModule|LogFormat|IfModule|UserDir"	>> $CREATE_FILE 2>&1
	echo "" >> $CREATE_FILE 2>&1
	cat ./Lyn_tmp/apache2_conf.txt | grep -i "user" | grep -v "\#" | egrep -v "^LoadModule|LogFormat|IfModule|UserDir"	>> $CREATE_FILE 2>&1
	echo "" >> $CREATE_FILE 2>&1
	cat ./Lyn_tmp/apache2_conf.txt | grep -i "group" | grep -v "\#" | egrep -v "^LoadModule|LogFormat|IfModule|UserDir"	>> $CREATE_FILE 2>&1
	echo "" >> $CREATE_FILE 2>&1
	echo "[+] 미출력 시 미설정" >> $CREATE_FILE 2>&1

else
	echo "apache 서비스가 존재하지 않거나 구동중이지 않습니다." >> $CREATE_FILE 2>&1
	echo "" >> $CREATE_FILE 2>&1
fi

echo "[U-36_END]" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
echo "[참고 - 진단기준, 결과 값 출력]" >> $CREATE_FILE 2>&1
echo " * 양호 조건 : Apache 프로세스의 계정이 적절하게 설정되어 있을 경우" >> $CREATE_FILE 2>&1
echo " * 취약 조건 : Apache 설정 파일인 httpd.conf 파일 내 user, group 설정이 root인 경우" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
}

U-37(){
echo "[U-37] 웹서비스 상위 디렉토리 접근 금지"
echo "[U-37] 웹서비스 상위 디렉토리 접근 금지" >> $CREATE_FILE 2>&1
echo "[U-37_START]" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
if [ $web_ps_check -ne 0 ]
then
	echo "[+] apache 서비스가 구동중 입니다." >> $CREATE_FILE 2>&1
	echo "참고 : Apache 2.048보다 높은 버전일 경우 양호" >> $CREATE_FILE 2>&1
	echo "" >> $CREATE_FILE 2>&1
	echo "[+] 1. 버전확인(rpm -qa | httpd)" >> $CREATE_FILE 2>&1
	rpm -qa 2>/dev/null | httpd >> $CREATE_FILE 2>&1
	echo "" >> $CREATE_FILE 2>&1
	echo "[+] 2. 버전확인(dpkg -l | grep apache)" >> $CREATE_FILE 2>&1
	dpkg -l 2>/dev/null | grep apache >> $CREATE_FILE 2>&1
	echo "" >> $CREATE_FILE 2>&1
	echo "[+] 3. 버전확인(httpd -v)" >> $CREATE_FILE 2>&1
	httpd -v 2>/dev/null >> $CREATE_FILE 2>&1
	echo "" >> $CREATE_FILE 2>&1
	echo "[+] 4. allowoverride 설정 확인 (authconfig | none 옵션 시 양호)" >> $CREATE_FILE 2>&1
	cat ./Lyn_tmp/apache2_conf.txt | grep -i allowoverride >> $CREATE_FILE 2>&1
	cat ./Lyn_tmp/httpd_conf.txt| grep -i allowoverride >> $CREATE_FILE 2>&1
	echo "" >> $CREATE_FILE 2>&1
else 
	echo "[+] apache 서비스가 존재하지 않거나 구동중이지 않습니다." >> $CREATE_FILE 2>&1
	echo "" >> $CREATE_FILE 2>&1
fi
echo "[U-37_END]" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
echo "[참고 - 진단기준, 결과 값 출력]" >> $CREATE_FILE 2>&1
echo " * 양호 조건 : Directory Traversal 취약점이 발견되지 않은 Apache 버전을 사용하고 있을 경우" >> $CREATE_FILE 2>&1
echo " * 취약 조건 : Directory Traversal 취약점이 발견된 Apache 버전을 사용하고 있을 경우" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
}

U-38(){
echo "[U-38] 웹서비스 불필요한 파일 제거"
echo "[U-38] 웹서비스 불필요한 파일 제거"  >> $CREATE_FILE 2>&1
echo "[U-38_START]"  >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
apache_dirs=$(find / \
\( -path /proc -o -path /sys -o -path /dev -o -path /run -o -path /var/run \) -prune -o \
-type d \( -iname manual -o -iname cgi-bin -o -iname sample \) -print 2>/dev/null | grep -iE 'apache|httpd')

manual_dirs=$(echo "$apache_dirs" | grep -i '/manual$')
cgi_bin_dirs=$(echo "$apache_dirs" | grep -i '/cgi-bin$')
sample_dirs=$(echo "$apache_dirs" | grep -i '/sample$')


if [ "$web_ps_check" -ne 0 ]; then
    echo "[+] apache 서비스가 구동중 입니다." >> $CREATE_FILE 2>&1
    echo "" >> $CREATE_FILE 2>&1

    if [ -n "$manual_dirs" ]; then
        echo "[+] 1. 현황 : manual 디렉터리 출력" >> $CREATE_FILE 2>&1
        echo "$manual_dirs" | while read -r file; do
            echo "$file" >> $CREATE_FILE 2>&1
            ls -al "$file" >> $CREATE_FILE 2>&1
            echo "" >> $CREATE_FILE 2>&1
        done
    else
        echo "[+] 1. 현황 : manual 디렉터리 없음" >> $CREATE_FILE 2>&1
        echo "" >> $CREATE_FILE 2>&1
    fi

    if [ -n "$cgi_bin_dirs" ]; then
        echo "[+] 2. 현황 : cgi-bin 디렉터리 출력" >> $CREATE_FILE 2>&1
        echo "[*] 2-1. 참고 : default apache cgi-bin 경로는 OS 및 버전 마다 다르니 개인이 판단" >> $CREATE_FILE 2>&1
        echo "$cgi_bin_dirs" | while read -r file; do 
            echo "$file" >> $CREATE_FILE 2>&1
            ls -al "$file" >> $CREATE_FILE 2>&1
            echo "" >> $CREATE_FILE 2>&1
        done
    else
        echo "[+] 2. 현황 : cgi-bin 디렉터리 없음" >> $CREATE_FILE 2>&1
        echo "" >> $CREATE_FILE 2>&1
    fi

    if [ -n "$sample_dirs" ]; then
        echo "[+] 3. 현황 : sample 디렉터리 출력" >> $CREATE_FILE 2>&1
        echo "$sample_dirs" | while read -r file; do
            echo "$file" >> $CREATE_FILE 2>&1
            ls -al "$file" >> $CREATE_FILE 2>&1
            echo "" >> $CREATE_FILE 2>&1
        done
    else
        echo "[+] 3. 현황 : sample 디렉터리 없음" >> $CREATE_FILE 2>&1
    fi
else
    echo "apache 서비스가 존재하지 않거나 구동중이지 않습니다." >> $CREATE_FILE 2>&1
fi

echo "" >> $CREATE_FILE 2>&1
echo "[U-38_END]" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
echo "[참고 - 진단기준, 결과 값 출력]" >> $CREATE_FILE 2>&1
echo " * 양호 조건 : 불필요한 파일이 존재하지 않을 경우" >> $CREATE_FILE 2>&1
echo " * 1. 취약 조건 : 디폴트 cgi-bin이 존재할 경우" >> $CREATE_FILE 2>&1
echo " * 2. 취약 조건 : 임시 파일, 백업 파일 등이 존재할 경우" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1

unset apache_dirs
unset manual_dirs
unset cgi_bin_dirs
unset sample_dirs
unset file
}

U-39(){
echo "[U-39] 웹서비스 링크 사용 금지"
echo "[U-39] 웹서비스 링크 사용 금지" >> $CREATE_FILE 2>&1
echo "[U-39_START]" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1

if [ $web_ps_check -ne 0 ]
then
	echo "[+] apache 서비스가 구동중 입니다." >> $CREATE_FILE 2>&1
	echo "[+] 현황 확인" >> $CREATE_FILE 2>&1
	cat ./Lyn_tmp/httpd_conf.txt | egrep -i "<Directory |FollowSymLinks|</Directory" | grep -v 'grep'\#	>> $CREATE_FILE 2>&1
	cat ./Lyn_tmp/apache2_conf.txt | egrep -i "<Directory |FollowSymLinks|</Directory" | grep -v 'grep'\#	>> $CREATE_FILE 2>&1
	echo "" >> $CREATE_FILE 2>&1
	echo "[+] 미출력 시 미설정" >> $CREATE_FILE 2>&1

else
	echo "apache 서비스가 존재하지 않거나 구동중이지 않습니다." >> $CREATE_FILE 2>&1
	echo "" >> $CREATE_FILE 2>&1

fi
echo "" >> $CREATE_FILE 2>&1
echo "[U-39_END]" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
echo "[참고 - 진단기준, 결과 값 출력]" >> $CREATE_FILE 2>&1
echo " * 양호 조건 : 취약 요건에 해당사항이 없는 경우" >> $CREATE_FILE 2>&1
echo " * 취약 조건 : 1. Apache Options에 불필요하게 FollowSymLinks 설정이 되어 있는 경우" >> $CREATE_FILE 2>&1
echo " * 취약 조건 : 2. Apache Options에 FollowSymLinks 설정이 되어 있고 업무적으로 사용하는 경우라도 중요 디렉터리 혹은 파일에 링크가 설정 되어 있는 경우" >> $CREATE_FILE 2>&1
echo " ** 참고 : FollowSymLinks 존재하지 않을 경우 상위 디렉터리에서 상속 받거나, OS 버전에 따라 FollowSymLinks가 없어도 기본 값으로 활성화되어 있을 수 있어 명확하게 비활성화 할 수 있도록 아래와 같이 설정 필요" >> $CREATE_FILE 2>&1
echo " ** -FollowSymLinks (Apache 2도 마찬가지) " >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
}

U-40(){
echo "[U-40] 웹서비스 파일 업로드 및 다운로드 제한"
echo "[U-40] 웹서비스 파일 업로드 및 다운로드 제한" >> $CREATE_FILE 2>&1
echo "[U-40_START]" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1

if [ $web_ps_check -ne 0 ]
then
	echo "[+] apache 서비스가 구동중 입니다." >> $CREATE_FILE 2>&1
	echo "[+] 현황 확인" >> $CREATE_FILE 2>&1
	cat ./Lyn_tmp/apache2_conf.txt | egrep -i "<Directory |LimitRequestBody|</Directory>" >> $CREATE_FILE 2>&1
	echo "" >> $CREATE_FILE 2>&1
	cat ./Lyn_tmp/httpd_conf.txt | egrep -i "<Directory |LimitRequestBody|</Directory>" >> $CREATE_FILE 2>&1
	echo "" >> $CREATE_FILE 2>&1
	echo "[+] 미출력 시 미설정" >> $CREATE_FILE 2>&1

else
	echo "apache 서비스가 존재하지 않거나 구동중이지 않습니다." >> $CREATE_FILE 2>&1
	echo "" >> $CREATE_FILE 2>&1
fi
echo "[U-40_END]" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
echo "[참고 - 진단기준, 결과 값 출력]" >> $CREATE_FILE 2>&1
echo " * 양호 조건 : httpd.conf 파일 내 디렉터리 설정에 LimitRequestBody 값 설정이 되어 있을 경우" >> $CREATE_FILE 2>&1
echo " * 취약 조건 : httpd.conf 파일 내 디렉터리 설정에 LimitRequestBody 값 설정이 안되어 있을 경우" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
}

U-41(){
echo "[U-41] 웹서비스 영역의 분리"
echo "[U-41] 웹서비스 영역의 분리" >> $CREATE_FILE 2>&1
echo "[U-41_START]" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1

if [ $web_ps_check -ne 0 ]
then
	echo "[+] apache 서비스가 구동중 입니다." >> $CREATE_FILE 2>&1
	echo "[+] 현황 확인" >> $CREATE_FILE 2>&1
	cat ./Lyn_tmp/httpd_conf.txt | grep "DocumentRoot" | grep -v 'grep'\#	>> $CREATE_FILE 2>&1
	cat ./Lyn_tmp/apache2_conf.txt | grep "ServerRoot" | grep -v 'grep'\#	>> $CREATE_FILE 2>&1
	echo "" >> $CREATE_FILE 2>&1
	echo "[+] 미출력 시 미설정" >> $CREATE_FILE 2>&1

else
	echo "apache 서비스가 존재하지 않거나 구동중이지 않습니다." >> $CREATE_FILE 2>&1
fi

echo "[U-41_END]" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
echo "[참고 - 진단기준, 결과 값 출력]" >> $CREATE_FILE 2>&1
echo " * 양호 조건 : 웹 서비스 경로 중 "/" 등 기타 업무와 영역이 분리되지 않은 경로 또는 불필요한 경로가 존재하지 않을 경우" >> $CREATE_FILE 2>&1
echo " * 취약 조건 : 웹 서비스 경로 중 "/" 등 기타 업무와 영역이 분리되지 않은 경로 또는 불필요한 경로가 존재하는 경우" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
}

U-60(){
echo "[U-60] ssh 원격접속 허용"
echo "[U-60] ssh 원격접속 허용" >> $CREATE_FILE 2>&1
echo "[U-60_START]" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1

if [ `ps -ef | grep sshd | grep -v "grep" | wc -l` -eq 0 ]
then
	echo "[+] 1. 현황 : sshd 서비스 데몬이 동작하지 않습니다."  >> $CREATE_FILE 2>&1
else
	echo "[+] 1. 현황 : ssh 서비스 확인(PS)" >> $CREATE_FILE 2>&1
	ps -ef | grep sshd | grep -v "grep"           >> $CREATE_FILE 2>&1
fi
echo "" >> $CREATE_FILE 2>&1	

case $OS in
	SunOS)
		echo "[+] 1-2. 현황 : ssh 서비스 확인(SOL9 이하)" >> $CREATE_FILE 2>&1
		cat /etc/inetd.conf | grep ssh >> $CREATE_FILE 2>&1
		echo " " >> $CREATE_FILE 2>&1
		echo "[+] 1-3. 현황 : ssh 서비스 확인(SOL10 이상)" >> $CREATE_FILE 2>&1
		svcs -a | grep ssh >> $CREATE_FILE 2>&1
		echo " " >> $CREATE_FILE 2>&1
	;;
	Linux)
		echo "[+] 1-1. 현황 : ssh 서비스 확인" >> $CREATE_FILE 2>&1
		service sshd status >> $CREATE_FILE 2>&1
		echo " " >> $CREATE_FILE 2>&1
		echo "[+] 1-2. 현황 : ssh 서비스 확인(CentOS7)" >> $CREATE_FILE 2>&1
		systemctl status ssh >> $CREATE_FILE 2>&1
		echo "" >> $CREATE_FILE 2>&1
	;;
esac

echo "[U-60_END]" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
echo "[참고 - 진단기준, 결과 값 출력]" >> $CREATE_FILE 2>&1
echo " * 양호 조건 :  원격 접속 시 SSH 프로토콜을 사용하는 경우 (※ ssh, telnet이 동시에 설치되어 있는 경우 취약한 것으로 평가됨)" >> $CREATE_FILE 2>&1
echo " * 취약 조건 : 원격 접속 시 Telnet, FTP 등 안전하지 않은 프로토콜을 사용하는 경우" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
}

U-61(){
echo "[U-61] ftp 서비스 확인"
echo "[U-61] ftp 서비스 확인" >> $CREATE_FILE 2>&1
echo "[U-61_START]" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
echo "[+] FTP 서비스 활성화 확인 " >> $CREATE_FILE 2>&1
if [ $FTP_ftp_Check -ne 0 ]
then
	echo " [+] FTP 서비스가 활성화 중입니다." >> $CREATE_FILE 2>&1
	echo " [+]  vsftpd : " $FTP_vsftpd_Check >> $CREATE_FILE 2>&1
	echo " [+]  proftpd : " $FTP_proftpd_Check >> $CREATE_FILE 2>&1
	echo " [*] 활성화(1), 비활성화(0)" >> $CREATE_FILE 2>&1
	echo "" >> $CREATE_FILE 2>&1
	echo " [*] 이외 ftp 확인" >> $CREATE_FILE 2>&1
	ps -ef | grep ftp | grep -v 'grep' >> $CREATE_FILE 2>&1
	echo "" >> $CREATE_FILE 2>&1
else
	echo " FTP 서비스가 비활성화되어 있습니다. " >> $CREATE_FILE 2>&1
	echo "" >> $CREATE_FILE 2>&1
fi

echo "[+] SFTP 설정 현황" >> $CREATE_FILE 2>&1
cat /etc/ssh/sshd_config | grep -i subsystem | grep sftp >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "[U-61_END]" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
echo "[*] FTP 포트 활성화 확인 " >> $CREATE_FILE 2>&1
netstat -na | grep -w "21" | grep "LISTEN" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "[참고 - 진단기준, 결과 값 출력]" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "** 양호 기준(1),(2) 중 하나라도 부합할 경우 취약으로 진단" >> $CREATE_FILE 2>&1
echo " * 양호 기준(1) : FTP 서비스가 비활성화되어 있는 경우" >> $CREATE_FILE 2>&1
echo " * 양호 기준(2) : SFTP 서비스가 활성화되어 있는 경우, 사용자 접속 설정이 별도로 들어가있는 경우" >> $CREATE_FILE 2>&1
echo "** 취약 기준(1),(2),(3) 중 하나라도 해당되는 경우 취약으로 진단" >> $CREATE_FILE 2>&1
echo " * 취약 기준(1) : 불필요하게 FTP 서비스가 활성화되어 있는 경우, FTP 서비스가 활성화되어 있는 경우, SFTP 서비스 접속 설정이 별도로 적용되어있지 않는 경우" >> $CREATE_FILE 2>&1
echo " * 취약 기준(2) : FTP 서비스가 활성화되어 있는 경우" >> $CREATE_FILE 2>&1
echo " * 취약 기준(3) : SFTP 서비스 접속 설정이 별도로 적용되어있지 않는 경우" >> $CREATE_FILE 2>&1
echo " *** 결과 파일이 출력된다는 것은 해당 서비스가 활성화(Active-Running) 상태이기 때문에 출력되는 것으로 알고 계시면 됩니다." >> $CREATE_FILE 2>&1
echo " '[+] SFTP 설정 현황'에서 출력되는 설정 값이 주석처리되어있지 않다면 별도 설정적용이 존재하지 않는 것으로 진단(취약) " >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1

}

U-62(){
echo "[U-62] ftp 계정 shell 제한"
echo "[U-62] ftp 계정 shell 제한" >> $CREATE_FILE 2>&1
echo "[U-62_START]" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1

echo "[+] FTP 계정 확인 " >> $CREATE_FILE 2>&1
cat /etc/passwd | grep ftp >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "[U-62_END]" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
echo "[*] FTP 포트 활성화 확인 " >> $CREATE_FILE 2>&1
netstat -na | grep -w "21" | grep "LISTEN" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "[참고 - 진단기준, 결과 값 출력]" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo " * 양호 기준 : ftp 계정의 shell 이 /bin/false로 부여되어 있는 경우" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
}

U-63(){
echo "[U-63] Ftpusers 파일 소유자 및 권한 설정"
echo "[U-63] Ftpusers 파일 소유자 및 권한 설정" >> $CREATE_FILE 2>&1
echo "[U-63_START]" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
echo "[+] FTP 서비스 활성화 확인 " >> $CREATE_FILE 2>&1
if [ $FTP_ftp_Check -ne 0 ]
then
	echo " [+] FTP 서비스가 활성화 중입니다." >> $CREATE_FILE 2>&1
	echo " [+]  vsftpd : " $FTP_vsftpd_Check >> $CREATE_FILE 2>&1
	echo " [+]  proftpd : " $FTP_proftpd_Check >> $CREATE_FILE 2>&1
	echo " [*] 활성화(1), 비활성화(0)" >> $CREATE_FILE 2>&1
	echo "" >> $CREATE_FILE 2>&1
	echo " [*] 이외 ftp 확인" >> $CREATE_FILE 2>&1
	ps -ef | grep ftp | grep -v 'grep' >> $CREATE_FILE 2>&1
	echo "" >> $CREATE_FILE 2>&1
	
	## 존재하는 파일에 대해서만 결과 파일 출력
	for Check_FTP_USERS in $FTPUSERS_FILE_LIST
		do
			if [ -f $Check_FTP_USERS ]
			then
			echo "" >> $CREATE_FILE 2>&1
			echo "[+]" $Check_FTP_USERS >> $CREATE_FILE 2>&1
			ls -la $Check_FTP_USERS >> $CREATE_FILE 2>&1
			else
			echo "[+]" $Check_FTP_USERS >> $CREATE_FILE 2>&1
			echo "" >> $CREATE_FILE 2>&1
			echo "[+] 파일이 존재하지 않습니다." >> $CREATE_FILE 2>&1
			fi
		done
else
	echo "[+] FTP 서비스가 비활성화되어 있습니다. " >> $CREATE_FILE 2>&1
fi



echo "" >> $CREATE_FILE 2>&1
echo "[U-63_END]" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
echo "[*] FTP 포트 활성화 확인 " >> $CREATE_FILE 2>&1
netstat -na | grep -w "21" | grep "LISTEN" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "[참고 - 진단기준, 결과 값 출력]" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo " * 양호 기준 : ftpusers 파일의 소유자가 root이고, 권한이 640 이하인 경우" >> $CREATE_FILE 2>&1
echo " * 취약 기준 : ftpusers 파일의 소유자가 root가 아니거나, 권한이 640 이하가 아닌 경우" >> $CREATE_FILE 2>&1
echo " *** 결과 파일이 출력된다는 것은 해당 서비스가 활성화(Active-Running) 상태이기 때문에 출력되는 것으로 알고 계시면 됩니다." >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1


unset Check_FTP_USERS
}

U-64(){
echo "[U-64] Ftpusers 파일 설정"
echo "[U-64] Ftpusers 파일 설정" >> $CREATE_FILE 2>&1
echo "[U-64_START]" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
echo "[+] FTP 서비스 활성화 확인 " >> $CREATE_FILE 2>&1
if [ $FTP_ftp_Check -ne 0 ]
then
	echo " [+] FTP 서비스가 활성화 중입니다." >> $CREATE_FILE 2>&1
	echo " [+]  vsftpd : " $FTP_vsftpd_Check >> $CREATE_FILE 2>&1
	echo " [+]  proftpd : " $FTP_proftpd_Check >> $CREATE_FILE 2>&1
	echo " [*] 활성화(1), 비활성화(0)" >> $CREATE_FILE 2>&1
	echo "" >> $CREATE_FILE 2>&1
	echo " [*] 이외 ftp 확인" >> $CREATE_FILE 2>&1
	ps -ef | grep ftp | grep -v 'grep' >> $CREATE_FILE 2>&1
	echo "" >> $CREATE_FILE 2>&1
	
	for Check_FTP_USERS in $FTPUSERS_FILE_LIST
		do
			if [ -f $Check_FTP_USERS ]
			then
				echo "" >> $CREATE_FILE 2>&1
				echo "[+]" $Check_FTP_USERS >> $CREATE_FILE 2>&1
				echo "" >> $CREATE_FILE 2>&1
				cat $Check_FTP_USERS >> $CREATE_FILE 2>&1
			else
				echo "[+]" $Check_FTP_USERS >> $CREATE_FILE 2>&1
				echo "[+] 파일이 존재하지 않습니다." >> $CREATE_FILE 2>&1
			fi
		done

else
	echo "[+] FTP 서비스가 비활성화되어 있습니다. " >> $CREATE_FILE 2>&1

fi


echo "" >> $CREATE_FILE 2>&1
echo "[U-64_END]" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
echo "[참고 - 진단기준, 결과 값 출력]" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo " * 양호 기준 : ftpusers 파일이 존재하고, ftpusers 파일 안에 시스템 계정(root)이 존재할 경우" >> $CREATE_FILE 2>&1
echo " * 취약 기준 : ftpusers 파일이 없거나, ftpusers 파일 안에 시스템 계정 미존재 혹은 주석처리 되어 있을 경우" >> $CREATE_FILE 2>&1
echo " *** 결과 파일이 출력된다는 것은 해당 서비스가 활성화(Active-Running) 상태이기 때문에 출력되는 것으로 알고 계시면 됩니다." >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1

}

U-65(){
echo "[U-65] at 파일 소유자 및 권한 설정"
echo "[U-65] at 파일 소유자 및 권한 설정" >> $CREATE_FILE 2>&1
echo "[U-65_START]" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
Crontab_settingfiles_List="/etc/at.* /var/adm/cron/at* /etc/cron.d/at.*"
for Crontab_file_check in $Crontab_settingfiles_List
	do
		if [ -e $Crontab_file_check ]
		then
		echo "" >> $CREATE_FILE 2>&1
		echo "[+]" $Crontab_file_check >> $CREATE_FILE 2>&1
		ls -laLd $Crontab_file_check >> $CREATE_FILE 2>&1
		else
		echo "[+] at 접근제어 파일이 존재하지 않음"  >> $CREATE_FILE 2>&1
		fi
	done
echo "" >> $CREATE_FILE 2>&1
echo "[U-65_END]" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
echo "[참고 - 진단기준, 결과 값 출력]" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo " * 양호 기준 1. : at 명령어 권한 750 이하 " >> $CREATE_FILE 2>&1
echo " * 양호 기준 2. : 접근제어파일(*.allow, *.deny) 소유자가 root이고, 권한이 640이하로 설정된 경우" >> $CREATE_FILE 2>&1
echo " * 취약 기준 : 양호 기준 1,2 중 하나라도 부합하는 경우" >> $CREATE_FILE 2>&1
echo "*** cron.deny, cron.allow 둘 다 없는 경우 수정권한은 슈퍼유저(root)만 가능(양호로 진단) ***" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1

unset Crontab_file_check
unset Crontab_settingfiles_List
}

SNMP_Service_Check=`ps -ef | grep snmp | grep -v 'grep' | wc -l`
SNMP_TRAP_Service_Check=`ps -ef | grep snmptrapd | grep -v 'grep' | wc -l`

U-66(){
echo "[U-66] SNMP 서비스 구동 점검"
echo "[U-66] SNMP 서비스 구동 점검" >> $CREATE_FILE 2>&1
echo "[U-66_START]" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
if [ $SNMP_Service_Check = 1 ] || [ $SNMP_TRAP_Service_Check = 1 ]
then
	echo "[+] SNMP 서비스가 활성화 중입니다." >> $CREATE_FILE 2>&1
	ps -ef | grep snmp | grep -v 'grep'	>> $CREATE_FILE 2>&1
	echo "[*] 위 서비스 활성화 여부 확인" >> $CREATE_FILE 2>&1

else
	echo "[+] SNMP 서비스가 비활성화되어 있습니다." >> $CREATE_FILE 2>&1
fi

echo "" >> $CREATE_FILE 2>&1
echo "[U-66_END]" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
echo "[참고 - 진단기준, 결과 값 출력]" >> $CREATE_FILE 2>&1
echo " * 양호 : SNMP 서비스를 사용하지 않거나, 사용 목적에 맞게 서비스를 사용하고 있는 경우" >> $CREATE_FILE 2>&1
echo " * 취약 : SNMP 서비스를 불필요하게 활성화되어 있는 경우" >> $CREATE_FILE 2>&1
echo " *** 결과 파일이 출력된다는 것은 해당 서비스가 활성화(Active-Running) 상태이기 때문에 출력되는 것으로 알고 계시면 됩니다." >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
}

U-67(){
echo "[U-67] SNMP 서비스 커뮤니티스트링의 복잡성 설정"
echo "[U-67] SNMP 서비스 커뮤니티스트링의 복잡성 설정" >> $CREATE_FILE 2>&1
echo "[U-67_START]" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
if [ $SNMP_Service_Check = 1 ] || [ $SNMP_TRAP_Service_Check = 1 ]
	then
	 echo "[+] SNMP 서비스가 활성화 중입니다." >> $CREATE_FILE 2>&1
	 ## SNMP 설정 파일 생성 예측 경로 리스트업
	 SNMP_CONF_LIST="/etc/snmpd.conf /etc/snmp/snmpd.conf /etc/snmp/conf/snmpd.conf /etc/snmptrapd.conf /etc/snmp/conf/snmptrapd.conf /etc/snmpdv3.conf /etc/SnmpAgent.d/snmpd.conf /etc/sma/snmp/snmpd.conf /var/sma_snmp/snmpd.conf /etc/net-snmp/snmpd.conf /var/net-snmp/snmpd.conf /etc/net-snmp/snmp/snmp_conf /var/lib/net-snmp/snmpd.conf /usr/share/snmp/snmpd.conf /etc/snmp/snmp.conf /etc/clsnmp.conf"
	 echo "[+] SNMP/SNMPTRAP 서비스 활성화 현황" >> $CREATE_FILE 2>&1
	 ps -ef | grep snmp | grep -v 'grep'	>> $CREATE_FILE 2>&1
	 ps -ef | grep snmptrapd | grep -v 'grep' >> $CREATE_FILE 2>&1
	 echo "" >> $CREATE_FILE 2>&1
	 echo "[+] 현황" >> $CREATE_FILE 2>&1
	 ## 파일이 존재하는 경로 값 정보만 추출
	 for Check_FILES in $SNMP_CONF_LIST
		do
			if [ -f $Check_FILES ]
			then
			echo "[+]" $Check_FILES >> $CREATE_FILE 2>&1
			echo "" >> $CREATE_FILE 2>&1
			## Community String 값 추출
			cat $Check_FILES | grep -Ei "community" | grep -v 'grep'\# >> $CREATE_FILE 2>&1
			## 설정 값이 없을 경우 해당 설정 파일에 대한 설정 현황 출력("하단에 설정 값이 존재하지 않습니다." 로직으로 이동)
			NOT_SET=`cat $Check_FILES | grep -iE "community" | grep -v 'grep'\# | wc -l`
			if [ $NOT_SET -eq 0 ]
			then
				echo "[+] 설정 값이 존재하지 않습니다." >> $CREATE_FILE 2>&1
		fi
		
		## SNMPv3 보안 수준 확인
		echo "[+] SNMPv3 보안 관련 설정 검사 (createUser, rouser, authPriv)" >> $CREATE_FILE 2>&1
		echo "※ SNMPv3 항목은 '전자금융기반시설 보안 취약점 평가 기준(제2025호-1호), SRV-001'에 근거하여 산출된 값으로 " >> $CREATE_FILE 2>&1
		echo "   SNMPv3를 사용하며, 보안레벨 설정이 authpriv로 되어있지 않을 경우 보안상 취약할 수 있으니 담당자와 협의하여 판단할 것을 권고함." >> $CREATE_FILE 2>&1
		grep -Ei "createUser|rouser|authPriv" $Check_FILES >> $CREATE_FILE 2>&1
		echo "" >> $CREATE_FILE 2>&1
	fi
done
	 echo "" >> $CREATE_FILE 2>&1
	else
	 echo "[+] SNMP 서비스가 비활성화되어 있습니다." >> $CREATE_FILE 2>&1
fi
echo "" >> $CREATE_FILE 2>&1
echo "[U-67_END]" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
echo "[참고 - 진단기준, 결과 값 출력]" >> $CREATE_FILE 2>&1
echo "양호 조건 1과 2 모두 충족하거나(or) 조건 3만 충족하는 경우 양호로 진단" >> $CREATE_FILE 2>&1
echo " * 양호 조건 1 : Commnity String 값이 Public이나 Private로 설정되어있지 않는 경우" >> $CREATE_FILE 2>&1
echo " * 양호 조건 2 : Commnity String 값의 복잡도 설정이 적용되어있는 경우(2가지 조합 10자리 이상, 3가지 조합 8자리 이상)" >> $CREATE_FILE 2>&1
echo " * 양호 조건 3 : SNMP v3 사용하고 있으며, 비밀번호 복잡도 설정 충족되는 경우" >> $CREATE_FILE 2>&1
echo " * 취약      : Community String 값이 Public이나 Private로 설정되어 있거나, 복잡도 충족이 안되는 경우 " >> $CREATE_FILE 2>&1
echo " ** SNMPv3 보안설정은 noAuthNoPriv(인증 X, 암호화 X), authNoPriv(인증 O, 암호화 X), authPriv(인증 O, 암호화 O)으로 구분" >> $CREATE_FILE 2>&1
echo " *** 결과 파일이 출력된다는 것은 해당 서비스가 활성화(Active-Running) 상태이기 때문에 출력되는 것으로 알고 계시면 됩니다." >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1

unset SNMP_CONF_LIST
unset Check_FILES
}

U-68(){
echo "[U-68] 로그온 시 경고 메시지 제공"
echo "[U-68] 로그온 시 경고 메시지 제공" >> $CREATE_FILE 2>&1
echo "[U-68_START]" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
	case $OS in
		SunOS)
			echo "[+] 1. 현황 : 서버 로그인 메시지 설정 /etc/motd " >> $CREATE_FILE 2>&1
			cat /etc/motd >> $CREATE_FILE 2>&1
			echo "" >> $CREATE_FILE 2>&1
			echo "[+] 2-3. 현황 : Telnet 배너 설정 /etc/default/telnetd " >> $CREATE_FILE 2>&1
			cat /etc/default/telnetd | grep BANNER >> $CREATE_FILE 2>&1
			echo "" >> $CREATE_FILE 2>&1
			echo "[+] 3-3. 현황 : TFP 배너 설정 /etc/default/ftpd " >> $CREATE_FILE 2>&1
			cat /etc/default/ftpd | grep BANNER >> $CREATE_FILE 2>&1
			echo "" >> $CREATE_FILE 2>&1
			echo "[+] 4-3. 현황 : SMTP 배너 설정 /etc/mail/sendmail.cf " >> $CREATE_FILE 2>&1
			cat /etc/mail/sendmail.cf | grep -i "GreetingMessage" >> $CREATE_FILE 2>&1
			echo "" >> $CREATE_FILE 2>&1
			echo "[+] 5-3. 현황 : DNS 배너 설정 /etc/named.conf " >> $CREATE_FILE 2>&1
			cat /etc/named.conf >> $CREATE_FILE 2>&1
			echo "" >> $CREATE_FILE 2>&1
		;;
		Linux)
			echo "[+] 1. 현황 : issue 확인" >> $CREATE_FILE 2>&1
			ls -al /etc/issue >> $CREATE_FILE 2>&1
			echo "" >> $CREATE_FILE 2>&1
			cat /etc/issue >> $CREATE_FILE 2>&1
			echo "" >> $CREATE_FILE 2>&1
			echo "[+] 2. 현황 : issue.net 확인 " >> $CREATE_FILE 2>&1
			ls -al /etc/issue.net >> $CREATE_FILE 2>&1
			echo "" >> $CREATE_FILE 2>&1
			cat /etc/issue.net >> $CREATE_FILE 2>&1
			echo "" >> $CREATE_FILE 2>&1
			echo "[+] 3. 현황 : /etc/motd 확인" >> $CREATE_FILE 2>&1
			ls -al /etc/motd >> $CREATE_FILE 2>&1
			echo "" >> $CREATE_FILE 2>&1
			cat /etc/motd >> $CREATE_FILE 2>&1
			echo "" >> $CREATE_FILE 2>&1
		;;
		AIX)
			echo "[+] 1. 현황 : 서버 로그인 메시지 설정 /etc/motd " >> $CREATE_FILE 2>&1
			cat /etc/motd >> $CREATE_FILE 2>&1
			echo "" >> $CREATE_FILE 2>&1
			echo "[+] 2. 현황 : Telnet 배너 설정 /etc/security/login.cfg " >> $CREATE_FILE 2>&1
			cat /etc/security/login.cfg >> $CREATE_FILE 2>&1
			echo "" >> $CREATE_FILE 2>&1
			echo "[+] 3. 현황 : TFP 배너 설정 /etc/default/ftpd " >> $CREATE_FILE 2>&1
			cat /etc/default/ftpd >> $CREATE_FILE 2>&1
			echo "" >> $CREATE_FILE 2>&1
			echo "[+] 4. 현황 : SMTP 배너 설정 /etc/mail/sendmail.cf " >> $CREATE_FILE 2>&1
			cat /etc/mail/sendmail.cf | grep -i "GreetingMessage" >> $CREATE_FILE 2>&1
			echo "" >> $CREATE_FILE 2>&1
			echo "[+] 5. 현황 : DNS 배너 설정 /etc/named.conf " >> $CREATE_FILE 2>&1
			cat /etc/named.conf >> $CREATE_FILE 2>&1
			echo "" >> $CREATE_FILE 2>&1
		;;
		HP-UX)
			echo "[+] 1. 현황 : 서버 로그인 메시지 설정 /etc/motd " >> $CREATE_FILE 2>&1
			cat /etc/motd >> $CREATE_FILE 2>&1
			echo "" >> $CREATE_FILE 2>&1
			echo "[+] 2. 현황 : Telnet 배너 설정 /etc/issue.net" >> $CREATE_FILE 2>&1
			cat /etc/issue.net >> $CREATE_FILE 2>&1
			echo "" >> $CREATE_FILE 2>&1
			echo "[+] 3. 현황 : TFP 배너 설정 /etc/default/ftpd " >> $CREATE_FILE 2>&1
			cat /etc/vsftpd/vsftpd.conf | grep banner >> $CREATE_FILE 2>&1
			echo "" >> $CREATE_FILE 2>&1
			echo "[+] 4. 현황 : SMTP 배너 설정 /etc/mail/sendmail.cf " >> $CREATE_FILE 2>&1
			cat /etc/mail/sendmail.cf | grep -i "GreetingMessage" >> $CREATE_FILE 2>&1
			echo "" >> $CREATE_FILE 2>&1
			echo "[+] 5-3. 현황 : DNS 배너 설정 /etc/named.conf " >> $CREATE_FILE 2>&1
			cat /etc/named.conf >> $CREATE_FILE 2>&1
			echo "" >> $CREATE_FILE 2>&1
		;;
	esac


echo "[U-68_END]" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
echo "[참고 - 진단기준, 결과 값 출력]" >> $CREATE_FILE 2>&1
echo " * 양호 조건 : 시스템 사용 주의사항을 출력하는 경우" >> $CREATE_FILE 2>&1
echo " * 취약 조건 : 시스템 사용 주의사항 미출력 또는 표시 문구 내에 시스템 버전 정보가 노출되는 경우" >> $CREATE_FILE 2>&1
	case $OS in
		SunOS)
			echo "[*] 2-1. 참고 : TELNET 서비스 상태는 SRV-026의 참고" >> $CREATE_FILE 2>&1
			echo "[*] 2-2. 참고 : netstat -na | grep 23" >> $CREATE_FILE 2>&1
			netstat -na | grep *.23 >> $CREATE_FILE 2>&1
			echo "" >> $CREATE_FILE 2>&1
			echo "[*] 3-1. 참고 : FTP 서비스 상태는 SRV-037 항목 참고" >> $CREATE_FILE 2>&1
			echo "[*] 3-2. 참고 : netstat -na | grep 21" >> $CREATE_FILE 2>&1
			netstat -na | grep *.21 >> $CREATE_FILE 2>&1
			echo "" >> $CREATE_FILE 2>&1
			echo "[*] 4-1. 참고 : SMTP 서비스 상태는 SRV-004 항목 참고" >> $CREATE_FILE 2>&1
			echo "[*] 4-2. 참고 : netstat -na | grep 161" >> $CREATE_FILE 2>&1
			netstat -na | grep *.161 >> $CREATE_FILE 2>&1
			echo "" >> $CREATE_FILE 2>&1
			echo "[*] 5-1. 참고 : DNS 서비스 상태는 50번 항목 참고" >> $CREATE_FILE 2>&1
			echo "[*] 5-2. 참고 : netstat -na | grep 53" >> $CREATE_FILE 2>&1
			netstat -na | grep *.53 >> $CREATE_FILE 2>&1
			echo "" >> $CREATE_FILE 2>&1
		;;
		AIX)
			echo "[*] 2-1. 참고 : TELNET 서비스 상태는 SRV-026의 참고" >> $CREATE_FILE 2>&1
			echo "[*] 2-2. 참고 : netstat -na | grep 23" >> $CREATE_FILE 2>&1
			netstat -na | grep *.23 >> $CREATE_FILE 2>&1
			echo "" >> $CREATE_FILE 2>&1
			echo "[*] 3-1. 참고 : FTP 서비스 상태는 SRV-037 항목 참고" >> $CREATE_FILE 2>&1
			echo "[*] 3-2. 참고 : netstat -na | grep 21" >> $CREATE_FILE 2>&1
			netstat -na | grep *.21 >> $CREATE_FILE 2>&1
			echo "" >> $CREATE_FILE 2>&1
			echo "[*] 4-1. 참고 : SMTP 서비스 상태는 SRV-004 항목 참고" >> $CREATE_FILE 2>&1
			echo "[*] 4-2. 참고 : netstat -na | grep 161" >> $CREATE_FILE 2>&1
			netstat -na | grep *.161 >> $CREATE_FILE 2>&1
			echo "" >> $CREATE_FILE 2>&1
			echo "[*] 5-1. 참고 : DNS 서비스 상태는 50번 항목 참고" >> $CREATE_FILE 2>&1
			echo "[*] 5-2. 참고 : netstat -na | grep 53" >> $CREATE_FILE 2>&1
			netstat -na | grep *.53 >> $CREATE_FILE 2>&1
			echo "" >> $CREATE_FILE 2>&1
		;;
		HP-UX)
			echo "[*] 2-1. 참고 : TELNET 서비스 상태는 SRV-026의 참고" >> $CREATE_FILE 2>&1
			echo "[*] 2-2. 참고 : netstat -na | grep 23" >> $CREATE_FILE 2>&1
			netstat -na | grep *.23 >> $CREATE_FILE 2>&1
			echo "" >> $CREATE_FILE 2>&1
			echo "[*] 3-1. 참고 : FTP 서비스 상태는 SRV-037 항목 참고" >> $CREATE_FILE 2>&1
			echo "[*] 3-2. 참고 : netstat -na | grep 21" >> $CREATE_FILE 2>&1
			netstat -na | grep *.21 >> $CREATE_FILE 2>&1
			echo "" >> $CREATE_FILE 2>&1
			echo "[*] 4-1. 참고 : SMTP 서비스 상태는 SRV-004 항목 참고" >> $CREATE_FILE 2>&1
			echo "[*] 4-2. 참고 : netstat -na | grep 161" >> $CREATE_FILE 2>&1
			netstat -na | grep *.161 >> $CREATE_FILE 2>&1
			echo "" >> $CREATE_FILE 2>&1
			echo "[*] 5-1. 참고 : DNS 서비스 상태는 50번 항목 참고" >> $CREATE_FILE 2>&1
			echo "[*] 5-2. 참고 : netstat -na | grep 53" >> $CREATE_FILE 2>&1
			netstat -na | grep *.53 >> $CREATE_FILE 2>&1
			echo "" >> $CREATE_FILE 2>&1
		;;
esac
echo "=============================================" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
}

U-69(){
echo "[U-69] NFS 설정파일 접근 제한"
echo "[U-69] NFS 설정파일 접근 제한" >> $CREATE_FILE 2>&1
echo "[U-69_START]" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
unix_nfs_check="/etc/dfs/dfstab /etc/exports /etc/dfs/sharetab /etc/vfstab"

if [ $NFS_Check_01 -ne 0 ]
then
	echo "[+] NFS 서비스가 활성화되어 있습니다." >> $CREATE_FILE 2>&1
	echo "" >> $CREATE_FILE 2>&1
		if [ -f /etc/dfs/dfstab ]
		then
			echo "ls -laL /etc/dfs/dfstab"	 	>> $CREATE_FILE 2>&1
			ls -laL /etc/dfs/dfstab 	 			>> $CREATE_FILE 2>&1
			echo " " 				  	 			>> unix_nfs_check
			echo "ls -laL /etc/dfs/dfstab"		>> unix_nfs_check
			ls -laL /etc/dfs/dfstab 	 			>> unix_nfs_check
		fi	
	
		if [ -f /etc/exports ]	
		then
			echo "" >> $CREATE_FILE 2>&1		
			echo "ls -laL /etc/exports" 			>> $CREATE_FILE 2>&1
			ls -laL /etc/exports 		 			>> $CREATE_FILE 2>&1
			echo " " 				  	 			>> unix_nfs_check
			echo "ls -laL /etc/exports" 			>> unix_nfs_check
			ls -laL /etc/exports		 			>> unix_nfs_check
		fi	
	
		if [ -f /etc/dfs/sharetab ]	
		then	
			echo "" >> $CREATE_FILE 2>&1
			echo "ls -laL /etc/dfs/sharetab"		>> $CREATE_FILE 2>&1
			ls -laL /etc/dfs/sharetab  		 		>> $CREATE_FILE 2>&1
			echo " "					 	 		>> $CREATE_FILE 2>&1
			echo "ls -laL /etc/dfs/sharetab" 		>> unix_nfs_check
			ls -laL /etc/dfs/sharetab 	 	 		>> unix_nfs_check
			echo " " 					 	 		>> unix_nfs_check
		fi

		if [ -f /etc/vfstab ]
		then
			echo "" >> $CREATE_FILE 2>&1
			echo "ls -laL /etc/vfstab"			>> $CREATE_FILE 2>&1
			ls -laL /etc/vfstab 					>> $CREATE_FILE 2>&1
			echo " " 								>> $CREATE_FILE 2>&1
			echo "ls -laL /etc/vfstab"			>> unix_nfs_check
			ls -laL /etc/vfstab 					>> unix_nfs_check
			echo " " 								>> unix_nfs_check
		fi

		if [ -f unix_nfs_check ]
		then
			echo "[+]NFS 파일(/etc/export 및 /etc/dfs/dfstab)존재함(수동점검)" >> $CREATE_FILE 2>&1	
			rm -f ./unix_nfs_check
		else
			echo "[+]NFS 파일(/etc/export 및 /etc/dfs/dfstab)존재하지 않음" >> $CREATE_FILE 2>&1	
		fi
else
	echo "[+] NFS 서비스가 비활성화되어 있습니다." >> $CREATE_FILE 2>&1
fi



echo "" >> $CREATE_FILE 2>&1
echo "[U-69_END]" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
echo "[참고 - 진단기준, 결과 값 출력]" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo " * 양호 기준 : /etc/dfs/dfstab 가 없거나 퍼미션이 644이하인 경우" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1


unset unix_nfs_check
unset check_nfs
}

U-70(){
echo "[U-70] expn, vrfy 명령어 제한"
echo "[U-70] expn, vrfy 명령어 제한" >> $CREATE_FILE 2>&1
echo "[U-70_START]" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
if [ $SMTP_Sendmail_Check -ne 0 ]
	then
		echo "[+] Sendmail 서비스가 활성화 중입니다." >> $CREATE_FILE 2>&1
		echo "*** 기본적으로 비활성화되어있는 서비스로 불필요 여부 확인 필요 요망 " >> $CREATE_FILE 2>&1
		echo "" >> $CREATE_FILE 2>&1
		for Check_sendmail in $sendmail_conf_list
		do
				if [ -f $Check_sendmail ]
				then
				echo "[+]" $Check_sendmail >> $CREATE_FILE 2>&1
				cat $Check_sendmail | grep -i "PrivacyOptions" >> $CREATE_FILE 2>&1
				fi
			done	
	else
		echo "[+] Sendmail 서비스가 비활성화되어 있습니다. " >> $CREATE_FILE 2>&1

fi

echo "" >> $CREATE_FILE 2>&1
echo "[U-70_END]" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
echo "[*] SMTP 포트 확인(참고) " >> $CREATE_FILE 2>&1
netstat -na | grep -w "25" | grep "LISTEN" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "[참고 - 진단기준, 결과 값 출력]" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo " * 양호 기준 : noexpn과 novrfy 또는 goaway가 설정되어있는 경우" >> $CREATE_FILE 2>&1
echo " * 취약 기준 : noexpn과 novrfy 또는 goaway가 설정되어있지 않는 경우" >> $CREATE_FILE 2>&1
echo " *** 결과 파일이 출력된다는 것은 해당 서비스가 활성화(Active-Running) 상태이기 때문에 출력되는 것으로 알고 계시면 됩니다." >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1

unset sendmail_conf_list
unset Check_sendmail
}

U-71(){
echo "[U-71] Apache 웹 서비스 정보 숨김"
echo "[U-71] Apache 웹 서비스 정보 숨김" >> $CREATE_FILE 2>&1
echo "[U-71_START]" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1

if [ $web_ps_check -ne 0 ]
then
	echo "[+] apache 서비스가 구동중 입니다." >> $CREATE_FILE 2>&1
	echo "[+] 현황 확인" >> $CREATE_FILE 2>&1
	cat ./Lyn_tmp/httpd_conf.txt | egrep -i "ServerTokens" | grep -v 'grep'\#	>> $CREATE_FILE 2>&1
	cat ./Lyn_tmp/httpd_conf.txt | egrep -i "ServerSignature" | grep -v 'grep'\#	>> $CREATE_FILE 2>&1
	cat ./Lyn_tmp/apache2_conf.txt | egrep -i "ServerTokens" | grep -v 'grep'\#	>> $CREATE_FILE 2>&1
	cat ./Lyn_tmp/apache2_conf.txt | egrep -i "ServerSignature" | grep -v 'grep'\#	>> $CREATE_FILE 2>&1
else
	echo "apache 서비스가 존재하지 않거나 구동중이지 않습니다." >> $CREATE_FILE 2>&1
fi

echo "[U-71_END]" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
echo "[참고 - 진단기준, 결과 값 출력]" >> $CREATE_FILE 2>&1
echo " * 양호 조건 : ServerTokens Prod, ServerSignature Off로 설정되어있는 경우" >> $CREATE_FILE 2>&1
echo " * 취약 조건 : ServerTokens Prod, ServerSignature Off로 설정되어있지 않은 경우" >> $CREATE_FILE 2>&1
echo " * 참고 : 서비스명 + 버전 정보가 노출되는 경우 취약" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
}

U-42(){
echo "[U-42] 최신 보안패치 및 벤더 권고사항 적용"
echo "[U-42] 최신 보안패치 및 벤더 권고사항 적용" >> $CREATE_FILE 2>&1
echo "[U-42_START]" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
	case $OS in
		SunOS)
			echo "[+] 1-1. 현황(SOL10 이하에서만 가능) : showrev -p" >> $CREATE_FILE 2>&1
			showrev -p >> $CREATE_FILE 2>&1
			echo "" >> $CREATE_FILE 2>&1
			echo "[+] 1-2. 현황(SOL11에서만 가능) : pkg list" >> $CREATE_FILE 2>&1
			pkg list >> $CREATE_FILE 2>&1
			;;
		Linux)
			echo "[+] 1. 현황 : 패치 확인" >> $CREATE_FILE 2>&1
			rpm -qa | grep "kernel" >> $CREATE_FILE 2>&1
			echo "" >> $CREATE_FILE 2>&1
			echo "[+] 2. 현황 : uname -r" >> $CREATE_FILE 2>&1
			uname -r >> $CREATE_FILE 2>&1
			echo "" >> $CREATE_FILE 2>&1
			echo "[+] 3. OS버전 확인" >> $CREATE_FILE 2>&1
			hostnamectl | grep Operating >> $CREATE_FILE 2>&1
			echo "" >> $CREATE_FILE 2>&1
			;;
		AIX)
			echo "[+] 1. 현황 : 패치확인" >> $CREATE_FILE 2>&1
			oslevel -s >> $CREATE_FILE 2>&1
			echo "" >> $CREATE_FILE 2>&1
			echo "[+] 2. 현황 : OS버전 확인" >> $CREATE_FILE 2>&1
			instfix -i >> $CREATE_FILE 2>&1
			echo "" >> $CREATE_FILE 2>&1
			echo "[+] 3. 현황 : 설치 패키지 확인" >> $CREATE_FILE 2>&1
			lslpp -l >> $CREATE_FILE 2>&1
			echo "" >> $CREATE_FILE 2>&1
			;;
		HP-UX)
			echo "[+] 1. 현황 : 패치확인" >> $CREATE_FILE 2>&1
			swlist >> $CREATE_FILE 2>&1
			echo "" >> $CREATE_FILE 2>&1
			;;
	esac
echo "=============================================" >> $CREATE_FILE 2>&1
echo "[U-42_END]" >> $CREATE_FILE 2>&1
echo "[참고 - 진단기준, 결과 값 출력]" >> $CREATE_FILE 2>&1
echo " * 양호 조건 : 패치 적용 정책을 수립하여 주기적으로 패치관리를 하고 있으며, 패치 관련 내용을 확인하고 적용했을 경우" >> $CREATE_FILE 2>&1
echo " * 취약 조건 : 패치 적용 정책을 수립하지 않고 주기적으로 패치관리를 하지 않거나 패치 관련 내용을 확인하지 않고 적용하지 않았을 경우" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
}

U-43(){
echo "[U-43] 로그의 정기적 검토 및 보고"
echo "[U-43] 로그의 정기적 검토 및 보고" >> $CREATE_FILE 2>&1
echo "[U-43_START]" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
echo "[*] 인터뷰 필요" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
echo "[U-43_END]" >> $CREATE_FILE 2>&1
echo "[참고 - 진단기준, 결과 값 출력]" >> $CREATE_FILE 2>&1
echo " * 양호 조건 : 로그 기록에 대해 정기적 검토, 분석, 보고서 작성 및 보고 등의 절차를 수행하고 있을 경우" >> $CREATE_FILE 2>&1
echo " * 취약 조건 : 로그 기록에 대해 정기적 검토가 이루어지지 않을 경우" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
}

U-72(){
echo "[U-72] 정책에 따른 시스템 로깅 설정"
echo "[U-72] 정책에 따른 시스템 로깅 설정" >> $CREATE_FILE 2>&1
echo "[U-72_START]" >> $CREATE_FILE 2>&1
echo "=============================================" >> $CREATE_FILE 2>&1
log_check="/etc/syslog.conf /etc/rsyslog.conf"

echo "[+] 1. 현황 : syslog (rsyslog)" >> $CREATE_FILE 2>&1
ps -ef | grep 'syslog' | grep -v 'grep' >> $CREATE_FILE 2>&1

for log_check_list in $log_check
do
	echo "[+] 1-2. 현황 : /etc/syslog.conf (/etc/rsyslog.conf)여부" >> $CREATE_FILE 2>&1
	if [ -f $log_check_list ] 
	then
		echo "[+]" $log_check_list >> $CREATE_FILE 2>&1
		cat $log_check_list >> $CREATE_FILE 2>&1
	else
		echo "[+] 파일이 존재하지 않습니다." >> $CREATE_FILE 2>&1
		echo "" >> $CREATE_FILE 2>&1
	fi
done

case $OS in
	Linux)
		echo "[+] 1-3. [Ubuntu]현황 : /etc/rsyslog.d/50-default.conf 여부" >> $CREATE_FILE 2>&1
		if [ -f /etc/rsyslog.d/50-default.conf ] 
		then
			echo "[+] /etc/rsyslog.d/50-default.conf 확인" >> $CREATE_FILE 2>&1
			cat /etc/rsyslog.d/50-default.conf >> $CREATE_FILE 2>&1
			echo "" >> $CREATE_FILE 2>&1
		else
			echo "[+] /etc/rsyslog.conf 파일 없음" >> $CREATE_FILE 2>&1
			echo "" >> $CREATE_FILE 2>&1
		fi
	;;
	SunOS)
		echo "[+] 1-3. 현황 : /etc/default/su 파일 확인" >> $CREATE_FILE 2>&1
		cat /etc/default/su | egrep "SULOG|SYSLOG" >> $CREATE_FILE 2>&1
		echo "" >> $CREATE_FILE 2>&1
	;;
esac
echo "=============================================" >> $CREATE_FILE 2>&1
echo "[U-72_END]" >> $CREATE_FILE 2>&1
echo "[참고 - 진단기준, 결과 값 출력]" >> $CREATE_FILE 2>&1
case $OS in
	AIX | HP-UX)
		echo "[*] 판단기준(양호) : syslog 로그 기록 정책이 내부 정책에 부합하게 설정되어 있는 경우" >> $CREATE_FILE 2>&1
		echo "[*] 판단기준(취약) : syslog 로그 기록 정책이 내부 정책에 부합하게 설정되지 않은 경우" >> $CREATE_FILE 2>&1
		echo "" >> $CREATE_FILE 2>&1
	;;
	SunOS)
		echo "[*] 판단기준(양호) : 1. syslog 로그 기록 정책이 내부 정책에 부합하게 설정되어 있는 경우" >> $CREATE_FILE 2>&1
		echo "[*] 판단기준(양호) : 2. syslog 설정에서 auth 또는 authpriv 가 활성화된 경우 (su 명령 로그)" >> $CREATE_FILE 2>&1
		echo "[*] 판단기준(양호) : 3. /etc/default/su 파일 내 SULOG=[로그 경로] 와 SYSLOG=YES가 설정된 경우" >> $CREATE_FILE 2>&1
		echo "" >> $CREATE_FILE 2>&1
		echo "[*] 판단기준(취약) : 1. syslog 로그 기록 정책이 내부 정책에 부합하게 설정되지 않은 경우" >> $CREATE_FILE 2>&1
		echo "[*] 판단기준(취약) : 2. syslog 설정에서 auth 또는 authpriv 가 활성화되지 않은 경우(su 명령 로그)" >> $CREATE_FILE 2>&1
		echo "[*] 판단기준(취약) : 3. /etc/default/su 파일 내 SULOG=[로그 경로] 와 SYSLOG=YES가 설정되지 않은 경우" >> $CREATE_FILE 2>&1
		echo "" >> $CREATE_FILE 2>&1
	;;
	Linux)
		echo "[*] 판단기준(양호) : 1. syslog 로그 기록 정책이 내부 정책에 부합하게 설정되어 있는 경우" >> $CREATE_FILE 2>&1
		echo "[*] 판단기준(양호) : 2. syslog 설정에서 auth 또는 authpriv 가 활성화된 경우 (su 명령 로그)" >> $CREATE_FILE 2>&1
		echo "[*] 판단기준(취약) : 1. syslog 로그 기록 정책이 내부 정책에 부합하게 설정되지 않은 경우" >> $CREATE_FILE 2>&1
		echo "[*] 판단기준(취약) : 2. syslog 설정에서 auth 또는 authpriv 가 활성화되지 않은 경우(su 명령 로그)" >> $CREATE_FILE 2>&1
		echo "" >> $CREATE_FILE 2>&1
	;;
esac
echo "=============================================" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
unset log_check_list
unset log_check
}

U-01
U-02
U-03
U-04
U-44
U-45
U-46
U-47
U-48
U-49
U-50
U-51
U-52
U-53
U-54
U-05
U-06
U-07
U-08
U-09
U-10
U-11
U-12
U-13
U-14
U-15
U-16
U-17
U-18
U-55
U-56
U-57
U-58
U-59
U-19
U-20
U-21
U-22
U-23
U-24
U-25
U-26
U-27
U-28
U-29
U-30
U-31
U-32
U-33
U-34
unset DNS_Conf_list
unset DNS_Check
U-35
U-36
U-37
U-38
U-39
U-40
U-41
U-60
U-61
U-62
U-63
U-64
unset FTP_ftp_Check
unset FTP_vsftpd_Check
unset FTP_proftpd_Check
unset FTPUSERS_FILE_LIST
U-65
U-66
U-67
unset SNMP_Service_Check
unset SNMP_TRAP_Service_Check
U-68
U-69
unset NFS_Check_01
U-70
unset sendmail_conf_list
unset SMTP_Sendmail_Check
U-71
unset web_ps_check
U-42
U-43
U-72








echo "UNIX/Linux Security Check END"
echo "==============================================================="
echo "☞ UNIX 스크립트 작업이 완료되었습니다."
echo "" >> $CREATE_FILE 2>&1
echo "☞ 스크립트 결과 파일을 보안담당자에게 전달 바랍니다."
echo "" >> $CREATE_FILE 2>&1
echo "☞ 스크립트 관련 오류 및 문의사항은 린시큐어 직원에게 부탁드립니다."  >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "☞ 감사합니다."  >> $CREATE_FILE 2>&1
echo "===============================================================" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo ">>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>" >> $CREATE_FILE 2>&1
echo "Reference info." >> $CREATE_FILE 2>&1
echo "<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "****************************************************************" >> $CREATE_FILE 2>&1
echo "********************   INFO_CHKSTART   *************************" >> $CREATE_FILE 2>&1
echo "****************************************************************" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "==============================" >> $CREATE_FILE 2>&1
echo "System Information Query Start" 							  >> $CREATE_FILE 2>&1
echo "==============================" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "------------------   Kernel Information   ---------------------" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
uname -a >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "---------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "-------------------   IP Information   ------------------------" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
ifconfig -a >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "---------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "-------------------   Network Status   ------------------------" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
netstat -an | egrep -i "LISTEN|ESTABLISHED" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "---------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "-------------------   Routing Information   -------------------" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
netstat -rn >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "---------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "-------------------   Process Status   ------------------------" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
ps -ef >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "-------------------   User Env   -----------------------------" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
env >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "--------------------------------------------------------------" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "============================" >> $CREATE_FILE 2>&1
echo "System Information Query End" 							   >> $CREATE_FILE 2>&1
echo "============================" >> $CREATE_FILE 2>&1
echo "" >> $CREATE_FILE 2>&1
echo "*************************************************************" >> $CREATE_FILE 2>&1
echo "***************************   INFO_CHKEND   *****************" >> $CREATE_FILE 2>&1
echo "*************************************************************" >> $CREATE_FILE 2>&1


tar -cvf $CREATE_FILE.tar $CREATE_FILE ./Lyn_tmp/ 
rm -rf ./Lyn_tmp/
rm -rf $CREATE_FILE

#unset locale_utf8
#unset locale_utf_8
#unset locale_euckr
#unset locale_KR
#unset CREATE_FILE