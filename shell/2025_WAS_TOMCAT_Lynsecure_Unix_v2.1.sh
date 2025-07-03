#!/bin/sh
#################################################################################
#																				#
#   					Security Inspection of WAS server						#
#   					Version : v2.1											#
#						COPYRIGHT(c) 2023-2025, Lyn Secure Co. 			  		#
#						ALL RIGHTS RESERVED.									#
#																				#
#################################################################################
#
#
# v2.0 설명 (2023.03.30)
# WAS 스크립트 작성
# 종류 : Tomcat  
# 
# 
#
# 
# 
# ==============================================================================#
#

#================================================================================
# 구동 체크 후 스크립트 실행 
#================================================================================


HOST_NAME=`hostname`
DATE_STR=`date +"20%y%m%d"`
TIME_STR=`date +%H%m`
START_TIME=`date +'%Y-%m-%d_%H:%m:%S'`
IP=`hostname -I | sed 's/ //g'`

if [ `ps -ef |grep "tomcat" | wc -l` -gt 1 ]
	then
	 echo "tomcat 구동 중"
else
	echo "tomcat 미구동 중"
	
fi


locale_utf8=`locale -a | grep -i 'ko_KR.utf8' | wc -l`
locale_utf_8=`locale -a | grep -i 'ko_KR.UTF-8' | wc -l`
locale_euckr=`locale -a | grep -i 'ko_KR.euckr' | wc -l`
locale_KR=`locale -a | grep ko_KR | grep -v euckr | grep -v utf8 | wc -l`

if [ $locale_utf8 -ne 0 ]
then
	export LANG=ko_KR.utf8
elif [ $locale_utf_8 -ne 0 ]
then
	export LANG=ko_KR.UTF-8
elif [ $locale_euckr -ne 0 ]
then
	export LANG=ko_KR.euckr
elif [ $locale_KR -ne 0 ]
then
	export LANG=ko_KR
else
	export LANG=C
fi




echo "=============================================	"								
echo  			  "스크립트 진행 중 입니다."													
echo  			  "잠시만 기다려 주세요." 													
echo "============================================="



#================================================================================
# Tomcat 스크립트 시작
#================================================================================


WAS_NAME="Tomcat"


RESULT_FILE=$WAS_NAME"_"$HOST_NAME"_"$IP"_"$DATE_STR"_"$TIME_STR".txt"

TAR_FILE=$WAS_NAME"_"$HOST_NAME"_"$IP"_"$DATE_STR"_"$TIME_STR".tar"


#================================================================================
# Tomcat 변수 설정 
#================================================================================

if [ `find / -name "server.xml" | grep -i tomcat | wc -l` -ge 1 ]
	then
		Tomcat_HOME=`find / -name "server.xml" | grep -i conf/ |rev |cut -d '/' -f3- |rev`
		Tomcat_CONF=$Tomcat_HOME/conf
		Tomcat_ROOT=$Tomcat_HOME/webapps
		Tomcat_LOG=$Tomcat_HOME/logs
fi	


if [ "$Tomcat_HOME" == "" ]
		then
			echo $WAS_NAME "경로를 찾지 못하였음으로 수동으로 입력하십시오."
			while true
			do
				ps -ef | grep tomcat
				echo "아래 예제와 같이" $WAS_NAME "설치 디렉터리를 입력하십시오."
				echo -n " (ex. /usr/local/lib/tomcat) : "
				read tomcat
				if [ $tomcat ]
					then
						if [ -d $tomcat ]
							then
								Tomcat_HOME=$tomcat
								Tomcat_CONF=$Tomcat_HOME/conf
								Tomcat_ROOT=$Tomcat_HOME/webapps
								break
							else
								echo "	입력하신 디렉터리가 존재하지 않습니다. 다시 입력하여 주십시오."
								echo "	"
						fi
				else
					echo "	잘못 입력하셨습니다. 다시 입력하여 주십시오.	"
					echo " "
				fi
			done
			while true
			do
				echo "아래 예제와 같이" $WAS_NAME " 로그 디렉터리를 입력하십시오."
				echo -n " (ex. /usr/local/lib/tomcat/logs) : "
				read Tomcat_LOG
				if [ $Tomcat_LOG ]
					then
						if [ -d $Tomcat_LOG ]
							then
								break
							else
								echo "	입력하신 디렉터리가 존재하지 않습니다. 다시 입력하여 주십시오."
								echo "	"
						fi
				else
					echo "	잘못 입력하셨습니다. 다시 입력하여 주십시오.	"
					echo " "
				fi
			done
fi

#================================================================================
# Tomcat 진단 시작
#================================================================================

echo "설치 경로가 정확하지 않을 경우 스크립트가 정상 작동되지 않습니다."
echo "결과가 비정상적인 경우 컨설턴트에게 문의주세요."
echo ""
echo ""
echo ""
echo $WAS_NAME"스크립트가 시작 됩니다. 잠시만 기다려주세요. (1~3분 소요 예정)."
echo ""
echo ""
echo START TIME : $START_TIME
echo START TIME : $START_TIME																>> $RESULT_FILE 2>&1
echo ""
echo ""
echo "※※※※스크립트 결과 맨 아래에 설정파일 전체를 출력한 결과가 있습니다. 참고하셔서 진단하세요.※※※※"					>> $RESULT_FILE 2>&1
echo ""
echo ""
echo ""
echo "[WAS-01] 관리자 콘솔 관리"
echo "[WAS-01] 관리자 콘솔 관리"																	>> $RESULT_FILE 2>&1
echo "[START]"																				>> $RESULT_FILE 2>&1
echo "============================================="										>> $RESULT_FILE 2>&1
echo "[+] Tomcat 점검현황"  																	>> $RESULT_FILE 2>&1
echo "(Tomcat 관리자 콘솔 확인)"																	>> $RESULT_FILE 2>&1
if [ `ls -al $Tomcat_ROOT | wc -l` -eq 0 ]
        then
                echo "루트경로에 파일이 존재하지 않음" 												>> $RESULT_FILE 2>&1					
        else
                ls -al $Tomcat_ROOT															>> $RESULT_FILE 2>&1						
fi
echo ""																						>> $RESULT_FILE 2>&1
echo "(Tomcat 포트 확인)"																		>> $RESULT_FILE 2>&1
if [ `cat $Tomcat_CONF/server.xml |grep -i "Connector" | wc -l` -eq 0 ]
        then
                echo "Connector port 설정값이없습니다" 											>> $RESULT_FILE 2>&1
        else
                cat $Tomcat_CONF/server.xml | awk -f ctx.awk PAT='Connector' B=4 A=4 |grep -v "#" 		>> $RESULT_FILE 2>&1

fi
echo "============================================="										>> $RESULT_FILE 2>&1
echo "[END]"																				>> $RESULT_FILE 2>&1
echo ""																						>> $RESULT_FILE 2>&1
echo ""																						>> $RESULT_FILE 2>&1
echo "[진단기준]"																				>> $RESULT_FILE 2>&1
echo "양호 : 유추하기 어려운 포트로 변경하여 사용하고 불필요한 관리자 콘솔을 사용하지 않는 경우" 							>> $RESULT_FILE 2>&1
echo "취약 : 유추하기 쉬운 포트를 사용하고 불필요한 관리자 콘솔을 사용하는 경우"										>> $RESULT_FILE 2>&1
echo ""																						>> $RESULT_FILE 2>&1
echo "[참고사항]"																				>> $RESULT_FILE 2>&1
echo "※ 설정 값이 없거나 추가적인 내용 확인이 필요한 경우 설정 파일에서 다시한번 확인 필요!!"							>> $RESULT_FILE 2>&1
echo "※ admin , manager 디렉터리 및 default 8080 사용 중인 경우 취약"									>> $RESULT_FILE 2>&1
echo "※ server.xml 내 설정된 connector port 확인"												>> $RESULT_FILE 2>&1
echo "============================================="										>> $RESULT_FILE 2>&1
echo "============================================="										>> $RESULT_FILE 2>&1

echo ""																						>> $RESULT_FILE 2>&1
echo ""																						>> $RESULT_FILE 2>&1
echo ""																						>> $RESULT_FILE 2>&1

echo "[WAS-02] 관리자 default 계정명 변경"
echo "[WAS-02] 관리자 default 계정명 변경"															>> $RESULT_FILE 2>&1
echo "[START]"																				>> $RESULT_FILE 2>&1
echo "============================================="										>> $RESULT_FILE 2>&1
echo "[+] Tomcat 점검현황"  																	>> $RESULT_FILE 2>&1
if [ `cat $Tomcat_CONF/tomcat-users.xml | wc -l` -eq 0 ]
        then
                echo "tomcat-users.xml 파일이 없습니다" 											>> $RESULT_FILE 2>&1						
        else
                cat $Tomcat_CONF/tomcat-users.xml 											>> $RESULT_FILE 2>&1					

fi
echo "============================================="										>> $RESULT_FILE 2>&1
echo "[END]"																				>> $RESULT_FILE 2>&1
echo ""																						>> $RESULT_FILE 2>&1
echo ""																						>> $RESULT_FILE 2>&1
echo "[진단기준]"																				>> $RESULT_FILE 2>&1
echo "양호 : default 유저와 패스워드를 삭제 또는 주석처리 되어 있는 경우" 										>> $RESULT_FILE 2>&1
echo "취약 : default 유저와 패스워드를 삭제 또는 주석처리 되어 있지않는 경우"										>> $RESULT_FILE 2>&1
echo ""																						>> $RESULT_FILE 2>&1
echo "[참고사항]"																				>> $RESULT_FILE 2>&1
echo "※ 설정 값이 없거나 추가적인 내용 확인이 필요한 경우 설정 파일에서 다시한번 확인 필요!!"							>> $RESULT_FILE 2>&1
echo "※ tomcat-users.xml 내 설정된 rolename 및 username 확인"										>> $RESULT_FILE 2>&1
echo "============================================="										>> $RESULT_FILE 2>&1
echo "============================================="										>> $RESULT_FILE 2>&1

echo ""																						>> $RESULT_FILE 2>&1
echo ""																						>> $RESULT_FILE 2>&1
echo ""																						>> $RESULT_FILE 2>&1


echo "[WAS-03] 관리자 패스워드 관리"
echo "[WAS-03] 관리자 패스워드 관리"																>> $RESULT_FILE 2>&1
echo "[START]"																				>> $RESULT_FILE 2>&1
echo "============================================"											>> $RESULT_FILE 2>&1
echo "[+] Tomcat 점검현황"  																	>> $RESULT_FILE 2>&1
if [ `cat $Tomcat_CONF/tomcat-users.xml |grep -i "manager-gui" | wc -l` -eq 0 ]
        then
                echo "manager-gui 설정 값이 없습니다" 												>> $RESULT_FILE 2>&1
        else
                cat $Tomcat_CONF/tomcat-users.xml | awk -f ctx.awk PAT='manager-gui' B=4 A=4 |grep -v "#" 	>> $RESULT_FILE 2>&1

fi
echo "============================================="										>> $RESULT_FILE 2>&1
echo "[END]"																				>> $RESULT_FILE 2>&1
echo ""																						>> $RESULT_FILE 2>&1
echo ""																						>> $RESULT_FILE 2>&1
echo "[진단기준]"																				>> $RESULT_FILE 2>&1
echo "양호 : 알파벳/숫자/특수문자 혼용 8자 이상, 동일문자 연속 4회 이상 사용 금지" 									>> $RESULT_FILE 2>&1
echo "양호 : 계정명과 동일하지 않고 유추하기 힘든 패스워드로 설정되어 있는 경우" 										>> $RESULT_FILE 2>&1
echo "취약 : 패스워드 길이가 8자 이하 이며, 계정명과 동일하거나 유추하기 쉬운 패스워드 설정이 되어 있는 경우"					>> $RESULT_FILE 2>&1
echo ""																						>> $RESULT_FILE 2>&1
echo "[참고사항]"																				>> $RESULT_FILE 2>&1
echo "※ 설정 값이 없거나 추가적인 내용 확인이 필요한 경우 설정 파일에서 다시한번 확인 필요!!"							>> $RESULT_FILE 2>&1
echo "※ tomcat-users.xml 내 설정된 manager-gui 확인"												>> $RESULT_FILE 2>&1
echo "============================================="										>> $RESULT_FILE 2>&1
echo "============================================="										>> $RESULT_FILE 2>&1

echo ""																						>> $RESULT_FILE 2>&1
echo ""																						>> $RESULT_FILE 2>&1
echo ""																						>> $RESULT_FILE 2>&1


echo "[WAS-04] 패스워드 파일 관리"
echo "[WAS-04] 패스워드 파일 관리"																	>> $RESULT_FILE 2>&1
echo "[START]"																				>> $RESULT_FILE 2>&1
echo "============================================"											>> $RESULT_FILE 2>&1
echo "[+] Tomcat 점검현황"  																	>> $RESULT_FILE 2>&1
if [ `ls -al $Tomcat_CONF/tomcat-users.xml | wc -l` -eq 0 ]
        then
                echo "tomcat-users.xml 파일이 존재하지 않음" 										>> $RESULT_FILE 2>&1					
        else
                ls -dl $Tomcat_CONF/tomcat-users.xml										>> $RESULT_FILE 2>&1						
fi
echo "============================================="										>> $RESULT_FILE 2>&1
echo "[END]"																				>> $RESULT_FILE 2>&1
echo ""																						>> $RESULT_FILE 2>&1
echo ""																						>> $RESULT_FILE 2>&1
echo "[진단기준]"																				>> $RESULT_FILE 2>&1
echo "tomcat-users.xml 파일이 전용계정 소유이고 각각 750/640 이하의 권한일 경우 양호" 							>> $RESULT_FILE 2>&1
echo "tomcat-users.xml 파일이 전용계정 소유가 아니거나 각각 750/640 초과의 권한일 취약"							>> $RESULT_FILE 2>&1
echo ""																						>> $RESULT_FILE 2>&1
echo "[참고사항]"																				>> $RESULT_FILE 2>&1
echo "※ 권한 750(drwxr-x---) , 640(rw-r-----)"												>> $RESULT_FILE 2>&1
echo "============================================="										>> $RESULT_FILE 2>&1
echo "============================================="										>> $RESULT_FILE 2>&1


echo ""																						>> $RESULT_FILE 2>&1
echo ""																						>> $RESULT_FILE 2>&1
echo ""																						>> $RESULT_FILE 2>&1



echo "[WAS-05] 패스워드 파일 암호화"
echo "[WAS-05] 패스워드 파일 암호화"																>> $RESULT_FILE 2>&1
echo "[START]"																				>> $RESULT_FILE 2>&1
echo "============================================"											>> $RESULT_FILE 2>&1
echo "[+] Tomcat 점검현황"  																	>> $RESULT_FILE 2>&1
echo "(tomcat-users.xml 확인)"																>> $RESULT_FILE 2>&1
if [ `cat $Tomcat_CONF/tomcat-users.xml |grep -i "username" | wc -l` -eq 0 ]
        then
                echo "username 설정 값이 없습니다" 												>> $RESULT_FILE 2>&1
        else
                cat $Tomcat_CONF/tomcat-users.xml | awk -f ctx.awk PAT='username' B=4 A=4 |grep -v "#" 						>> $RESULT_FILE 2>&1

fi
echo ""																						>> $RESULT_FILE 2>&1
echo "(server.xml 확인)"																		>> $RESULT_FILE 2>&1
if [ `cat $Tomcat_CONF/tomcat-users.xml |grep -i "digest" | wc -l` -eq 0 ]
        then
                echo "digest 설정 값이 없습니다" 													>> $RESULT_FILE 2>&1
        else
                cat $Tomcat_CONF/tomcat-users.xml | awk -f ctx.awk PAT='digest' B=4 A=4 |grep -v "#" 						>> $RESULT_FILE 2>&1

fi
if [ `cat $Tomcat_CONF/tomcat-users.xml |grep -i "algorithm" | wc -l` -eq 0 ]
        then
                echo "algorithm 설정 값이 없습니다" 												>> $RESULT_FILE 2>&1
        else
                cat $Tomcat_CONF/tomcat-users.xml | awk -f ctx.awk PAT='algorithm' B=4 A=4 |grep -v "#" 					>> $RESULT_FILE 2>&1

fi
echo "============================================="										>> $RESULT_FILE 2>&1
echo "[END]"																				>> $RESULT_FILE 2>&1
echo ""																						>> $RESULT_FILE 2>&1
echo ""																						>> $RESULT_FILE 2>&1
echo "[진단기준]"																				>> $RESULT_FILE 2>&1
echo "양호 : 패스워드 파일에 패스워드가 암호화되어 저장되어 있을 경우" 											>> $RESULT_FILE 2>&1
echo "취약 : 패스워드 파일에 패스워드가 평문으로 저장되어 있을 경우"												>> $RESULT_FILE 2>&1
echo ""																						>> $RESULT_FILE 2>&1
echo "[참고사항]"																				>> $RESULT_FILE 2>&1
echo "※ 설정 값이 없거나 추가적인 내용 확인이 필요한 경우 설정 파일에서 다시한번 확인 필요!!"							>> $RESULT_FILE 2>&1
echo "※ tomcat-users.xml 내 설정된 username의 password=[암호화값] 확인"								>> $RESULT_FILE 2>&1
echo "※ server.xml 내 설정된 digest=[암호 알고리즘] 또는 algorithm=[암호 알고리즘] 확인"					>> $RESULT_FILE 2>&1
echo "============================================="										>> $RESULT_FILE 2>&1
echo "============================================="										>> $RESULT_FILE 2>&1


echo ""																						>> $RESULT_FILE 2>&1
echo ""																						>> $RESULT_FILE 2>&1
echo ""																						>> $RESULT_FILE 2>&1


echo "[WAS-06] 디렉터리 쓰기 권한 관리"
echo "[WAS-06] 디렉터리 쓰기 권한 관리"																>> $RESULT_FILE 2>&1
echo "[START]"																				>> $RESULT_FILE 2>&1
echo "============================================"											>> $RESULT_FILE 2>&1
echo "[+] Tomcat 점검현황"  																	>> $RESULT_FILE 2>&1
if [ `ls -al $Tomcat_ROOT | wc -l` -eq 0 ]
        then
                echo "루트 경로가 존재하지 않음" 													>> $RESULT_FILE 2>&1					
        else
                ls -dl $Tomcat_ROOT															>> $RESULT_FILE 2>&1						
fi
echo "============================================="										>> $RESULT_FILE 2>&1
echo "[END]"																				>> $RESULT_FILE 2>&1
echo ""																						>> $RESULT_FILE 2>&1
echo ""																						>> $RESULT_FILE 2>&1
echo "[진단기준]"																				>> $RESULT_FILE 2>&1
echo "루트 디렉터리가 전용계정 소유이고 각각 750/640 이하의 권한일 경우 양호" 									>> $RESULT_FILE 2>&1
echo "루트 디렉터리가 전용계정 소유가 아니거나 각각 750/640 초과의 권한일 취약"									>> $RESULT_FILE 2>&1
echo ""																						>> $RESULT_FILE 2>&1
echo "[참고사항]"																				>> $RESULT_FILE 2>&1
echo "※ 권한 750(drwxr-x---) , 640(rw-r-----)"												>> $RESULT_FILE 2>&1
echo "============================================="										>> $RESULT_FILE 2>&1
echo "============================================="										>> $RESULT_FILE 2>&1


echo ""																						>> $RESULT_FILE 2>&1
echo ""																						>> $RESULT_FILE 2>&1
echo ""																						>> $RESULT_FILE 2>&1



echo "[WAS-07] 설정 파일 권한 관리"
echo "[WAS-07] 설정 파일 권한 관리"																>> $RESULT_FILE 2>&1
echo "[START]"																				>> $RESULT_FILE 2>&1
echo "============================================"											>> $RESULT_FILE 2>&1
echo "[+] Tomcat 점검현황"  																	>> $RESULT_FILE 2>&1
if [ `ls -al $Tomcat_CONF | wc -l` -eq 0 ]
        then
                echo "설정 파일이 존재하지 않음" 													>> $RESULT_FILE 2>&1					
        else
                ls -dl $Tomcat_CONF															>> $RESULT_FILE 2>&1						
fi
echo "============================================="										>> $RESULT_FILE 2>&1
echo "[END]"																				>> $RESULT_FILE 2>&1
echo ""																						>> $RESULT_FILE 2>&1
echo ""																						>> $RESULT_FILE 2>&1
echo "[진단기준]"																				>> $RESULT_FILE 2>&1
echo "설정 파일이 전용계정 소유이고 각각 750/640 이하의 권한일 경우 양호" 										>> $RESULT_FILE 2>&1
echo "설정 파일이 전용계정 소유가 아니거나 각각 750/640 초과의 권한일 취약"										>> $RESULT_FILE 2>&1
echo ""																						>> $RESULT_FILE 2>&1
echo "[참고사항]"																				>> $RESULT_FILE 2>&1
echo "※ 권한 750(drwxr-x---) , 640(rw-r-----)"												>> $RESULT_FILE 2>&1
echo "※ server.xml , web.xml , tomcat-users.xml 이외에도 전체 설정 파일 권한 확인 필요"					>> $RESULT_FILE 2>&1
echo "============================================="										>> $RESULT_FILE 2>&1
echo "============================================="										>> $RESULT_FILE 2>&1


echo ""																						>> $RESULT_FILE 2>&1
echo ""																						>> $RESULT_FILE 2>&1
echo ""																						>> $RESULT_FILE 2>&1


echo "[WAS-08] 로그 디렉터리/파일 권한 관리"
echo "[WAS-08] 로그 디렉터리/파일 권한 관리"															>> $RESULT_FILE 2>&1
echo "[START]"																				>> $RESULT_FILE 2>&1
echo "============================================"											>> $RESULT_FILE 2>&1
echo "[+] Tomcat 점검현황"  																	>> $RESULT_FILE 2>&1
echo "(로그 디렉터리)"																			>> $RESULT_FILE 2>&1
if [ `ls -al $Tomcat_LOG | wc -l` -eq 0 ]
        then
                echo "로그 디렉터리가 존재하지 않음" 													>> $RESULT_FILE 2>&1					
        else
                ls -dl $Tomcat_LOG															>> $RESULT_FILE 2>&1						
fi
echo "" 																					>> $RESULT_FILE 2>&1	
echo "(로그 파일)"																				>> $RESULT_FILE 2>&1
if [ `ls -al $Tomcat_LOG/* | wc -l` -eq 0 ]
        then
                echo "로그 파일이 존재하지 않음" 													>> $RESULT_FILE 2>&1					
        else
                ls -dl $Tomcat_LOG/*														>> $RESULT_FILE 2>&1						
fi
echo "============================================="										>> $RESULT_FILE 2>&1
echo "[END]"																				>> $RESULT_FILE 2>&1
echo ""																						>> $RESULT_FILE 2>&1
echo ""																						>> $RESULT_FILE 2>&1
echo "[진단기준]"																				>> $RESULT_FILE 2>&1
echo "양호 : 로그 디렉터리/파일이 전용계정 소유이고 각각 750/640 이하의 권한일 경우" 								>> $RESULT_FILE 2>&1
echo "취약 : 로그 디렉터리/파일이 전용계정 소유가 아니거나 각각 750/640 초과의 권한일 경우"								>> $RESULT_FILE 2>&1
echo ""																						>> $RESULT_FILE 2>&1
echo "[참고사항]"																				>> $RESULT_FILE 2>&1
echo "※ 권한 750(drwxr-x---) , 640(rw-r-----)"												>> $RESULT_FILE 2>&1
echo "============================================="										>> $RESULT_FILE 2>&1
echo "============================================="										>> $RESULT_FILE 2>&1


echo ""																						>> $RESULT_FILE 2>&1
echo ""																						>> $RESULT_FILE 2>&1
echo ""																						>> $RESULT_FILE 2>&1


echo "[WAS-09] 디렉터리 검색 기능 제거"
echo "[WAS-09] 디렉터리 검색 기능 제거"																>> $RESULT_FILE 2>&1
echo "[START]"																				>> $RESULT_FILE 2>&1
echo "============================================"											>> $RESULT_FILE 2>&1
echo "[+] Tomcat 점검현황"  																	>> $RESULT_FILE 2>&1
if [ `cat $Tomcat_CONF/web.xml |grep -i "listings" | wc -l` -eq 0 ]
        then
                echo "listings 설정 값이 없습니다" 												>> $RESULT_FILE 2>&1
        else
                cat $Tomcat_CONF/web.xml | awk -f ctx.awk PAT='listings' B=4 A=4 |grep -v "#" 								>> $RESULT_FILE 2>&1

fi
echo "============================================="										>> $RESULT_FILE 2>&1
echo "[END]"																				>> $RESULT_FILE 2>&1
echo ""																						>> $RESULT_FILE 2>&1
echo ""																						>> $RESULT_FILE 2>&1
echo "[진단기준]"																				>> $RESULT_FILE 2>&1
echo "양호 : listings 설정이 false 인 경우" 														>> $RESULT_FILE 2>&1
echo "취약 : listings 설정이 true 인 경우"															>> $RESULT_FILE 2>&1
echo ""																						>> $RESULT_FILE 2>&1
echo "[참고사항]"																				>> $RESULT_FILE 2>&1
echo "※ 설정 값이 없거나 추가적인 내용 확인이 필요한 경우 설정 파일에서 다시한번 확인 필요!!"							>> $RESULT_FILE 2>&1
echo "※ web.xml 파일 내에서 listings 확인"														>> $RESULT_FILE 2>&1
echo "============================================="										>> $RESULT_FILE 2>&1
echo "============================================="										>> $RESULT_FILE 2>&1


echo ""																						>> $RESULT_FILE 2>&1
echo ""																						>> $RESULT_FILE 2>&1
echo ""																						>> $RESULT_FILE 2>&1


echo "[WAS-10] 에러 메시지 관리"
echo "[WAS-10] 에러 메시지 관리"																	>> $RESULT_FILE 2>&1
echo "[START]"																				>> $RESULT_FILE 2>&1
echo "============================================"											>> $RESULT_FILE 2>&1
echo "[+] Tomcat 점검현황"  																	>> $RESULT_FILE 2>&1
if [ `cat $Tomcat_CONF/web.xml |grep -i "error-code" | wc -l` -eq 0 ]
        then
                echo "error-code 설정 값이 없습니다" 												>> $RESULT_FILE 2>&1
        else
                cat $Tomcat_CONF/web.xml | awk -f ctx.awk PAT='error-code' B=4 A=4 |grep -v "#"			>> $RESULT_FILE 2>&1

fi
echo "============================================="										>> $RESULT_FILE 2>&1
echo "[END]"																				>> $RESULT_FILE 2>&1
echo ""																						>> $RESULT_FILE 2>&1
echo ""																						>> $RESULT_FILE 2>&1
echo "[진단기준]"																				>> $RESULT_FILE 2>&1
echo "양호 : 지정된 에러 페이지 설정이 되어있는 경우" 														>> $RESULT_FILE 2>&1
echo "취약 : 지정된 에러 페이지 설정이 되어있지 않은 경우"													>> $RESULT_FILE 2>&1
echo ""																						>> $RESULT_FILE 2>&1
echo "[참고사항]"																				>> $RESULT_FILE 2>&1
echo "※ 설정 값이 없거나 추가적인 내용 확인이 필요한 경우 설정 파일에서 다시한번 확인 필요!!"							>> $RESULT_FILE 2>&1
echo "※ web.xml 파일 내에서 error-code 설정 확인"													>> $RESULT_FILE 2>&1
echo "※ 에러 메시지 출력 파일은 동일하게 설정"															>> $RESULT_FILE 2>&1
echo "※ Error 400, 401, 402, 403, 404, 500에 대한 설정"											>> $RESULT_FILE 2>&1
echo "============================================="										>> $RESULT_FILE 2>&1
echo "============================================="										>> $RESULT_FILE 2>&1


echo ""																						>> $RESULT_FILE 2>&1
echo ""																						>> $RESULT_FILE 2>&1
echo ""																						>> $RESULT_FILE 2>&1



echo "[WAS-11] 응답 메시지 관리"
echo "[WAS-11] 응답 메시지 관리"																	>> $RESULT_FILE 2>&1
echo "[START]"																				>> $RESULT_FILE 2>&1
echo "============================================"											>> $RESULT_FILE 2>&1
echo "[+] Tomcat 점검현황"  																	>> $RESULT_FILE 2>&1
if [ `cat $Tomcat_CONF/server.xml |grep -i "connector" | wc -l` -eq 0 ]
        then
                echo "connector port 설정 값이 없습니다" 											>> $RESULT_FILE 2>&1
        else
                cat $Tomcat_CONF/server.xml | awk -f ctx.awk PAT='connector' B=4 A=4 |grep -v "#"							>> $RESULT_FILE 2>&1

fi
echo "============================================="										>> $RESULT_FILE 2>&1
echo "[END]"																				>> $RESULT_FILE 2>&1
echo ""																						>> $RESULT_FILE 2>&1
echo ""																						>> $RESULT_FILE 2>&1
echo "[진단기준]"																				>> $RESULT_FILE 2>&1
echo "양호 : 응답 메시지 설정이 안전하게 되어있는 경우" 														>> $RESULT_FILE 2>&1
echo "취약 : 응답 메시지 설정이 안전하게 되어있지 않는 경우"													>> $RESULT_FILE 2>&1
echo ""																						>> $RESULT_FILE 2>&1
echo "[참고사항]" 																				>> $RESULT_FILE 2>&1
echo " 설정 값이 없거나 추가적인 내용 확인이 필요한 경우 설정 파일에서 다시한번 확인 필요!!"							>> $RESULT_FILE 2>&1
echo "※ server.xml 파일 내에서 사용중인 connector port 절의 server 설정 유무 확인" 						>> $RESULT_FILE 2>&1
echo "ex) <Connector connectionTimeout=”20000” port=”8090” protocol=”HTTP/1.1” redirectPort=”8443” server=”server” />" >> $RESULT_FILE 2>&1
echo "※ server="" 또는 server 설정이 없는 경우 취약"													>> $RESULT_FILE 2>&1
echo "============================================="										>> $RESULT_FILE 2>&1
echo "============================================="										>> $RESULT_FILE 2>&1


echo ""																						>> $RESULT_FILE 2>&1
echo ""																						>> $RESULT_FILE 2>&1
echo ""																						>> $RESULT_FILE 2>&1



echo "[WAS-12] 세션 타임아웃 설정"
echo "[WAS-12] 세션 타임아웃 설정"																>> $RESULT_FILE 2>&1
echo "[START]"																				>> $RESULT_FILE 2>&1
echo "============================================"											>> $RESULT_FILE 2>&1
echo "[+] Tomcat 점검현황"  																	>> $RESULT_FILE 2>&1
if [ `cat $Tomcat_CONF/web.xml |grep -i "session-timeout" | wc -l` -eq 0 ]
        then
                echo "session-timeout 설정 값이 없습니다" 										>> $RESULT_FILE 2>&1
        else
                cat $Tomcat_CONF/web.xml | awk -f ctx.awk PAT='session-timeout' B=4 A=4 |grep -v "#" 				>> $RESULT_FILE 2>&1

fi
echo "============================================="										>> $RESULT_FILE 2>&1
echo "[END]"																				>> $RESULT_FILE 2>&1
echo ""																						>> $RESULT_FILE 2>&1
echo ""																						>> $RESULT_FILE 2>&1
echo "[진단기준]"																				>> $RESULT_FILE 2>&1
echo "양호 : Session Timeout 설정이 30 이내인 경우" 													>> $RESULT_FILE 2>&1
echo "취약 : Session Timeout 설정이 30 이상인 경우"													>> $RESULT_FILE 2>&1
echo ""																						>> $RESULT_FILE 2>&1
echo "[참고사항]"																				>> $RESULT_FILE 2>&1
echo "※ 설정 값이 없거나 추가적인 내용 확인이 필요한 경우 설정 파일에서 다시한번 확인 필요!!"							>> $RESULT_FILE 2>&1
echo "※ web.xml 파일 내에서 session-timeout 확인"												>> $RESULT_FILE 2>&1
echo "============================================="										>> $RESULT_FILE 2>&1
echo "============================================="										>> $RESULT_FILE 2>&1


echo ""																						>> $RESULT_FILE 2>&1
echo ""																						>> $RESULT_FILE 2>&1
echo ""																						>> $RESULT_FILE 2>&1


echo "[WAS-13] sample 디렉터리 삭제"
echo "[WAS-13] sample 디렉터리 삭제"																>> $RESULT_FILE 2>&1
echo "[START]"																				>> $RESULT_FILE 2>&1
echo "============================================"											>> $RESULT_FILE 2>&1
echo "[+] Tomcat 점검현황"  																	>> $RESULT_FILE 2>&1
if [ `ls -al $Tomcat_ROOT | wc -l` -eq 0 ]
        then
                echo "루트 경로가 존재하지 않음" 													>> $RESULT_FILE 2>&1					
        else
                ls -dl $Tomcat_ROOT															>> $RESULT_FILE 2>&1						
                ls -al $Tomcat_ROOT															>> $RESULT_FILE 2>&1						
fi
echo "============================================="										>> $RESULT_FILE 2>&1
echo "[END]"																				>> $RESULT_FILE 2>&1
echo ""																						>> $RESULT_FILE 2>&1
echo ""																						>> $RESULT_FILE 2>&1
echo "[진단기준]"																				>> $RESULT_FILE 2>&1
echo "양호 : Sample 설치 경로가 삭제된 경우" 															>> $RESULT_FILE 2>&1
echo "취약 : Sample 설치 경로가 존재하는 경우"															>> $RESULT_FILE 2>&1
echo ""																						>> $RESULT_FILE 2>&1
echo "[참고사항]"																				>> $RESULT_FILE 2>&1
echo "※ 불필요한 디렉터리 : examples , sample , webdav , docs 등"									>> $RESULT_FILE 2>&1
echo "============================================="										>> $RESULT_FILE 2>&1
echo "============================================="										>> $RESULT_FILE 2>&1


echo ""																						>> $RESULT_FILE 2>&1
echo ""																						>> $RESULT_FILE 2>&1
echo ""																						>> $RESULT_FILE 2>&1


echo "[WAS-14] 프로세스 관리 기능 삭제"
echo "[WAS-14] 프로세스 관리 기능 삭제"																>> $RESULT_FILE 2>&1
echo "[START]"																				>> $RESULT_FILE 2>&1
echo "============================================"											>> $RESULT_FILE 2>&1
echo "[+] Tomcat 점검현황"  																	>> $RESULT_FILE 2>&1
if [ `ls -al $Tomcat_ROOT/manager/WEB-INF/ | wc -l` -eq 0 ]
        then
                echo "manager 디렉터리가 존재하지 않음" 												>> $RESULT_FILE 2>&1					
        else
                ls -dl $Tomcat_ROOT/manager/WEB-INF											>> $RESULT_FILE 2>&1						
                ls -al $Tomcat_ROOT/manager/WEB-INF											>> $RESULT_FILE 2>&1						
fi
if [ `ls -al $Tomcat_ROOT/manager/WEB-INF/lib | wc -l` -eq 0 ]   
        then
                echo "manager 하위 디렉터리가 존재하지 않음" 											>> $RESULT_FILE 2>&1					
        else
                ls -dl $Tomcat_ROOT/manager/WEB-INF/lib										>> $RESULT_FILE 2>&1						
                ls -al $Tomcat_ROOT/manager/WEB-INF/lib										>> $RESULT_FILE 2>&1						
fi
echo "============================================="										>> $RESULT_FILE 2>&1
echo "[END]"																				>> $RESULT_FILE 2>&1
echo ""																						>> $RESULT_FILE 2>&1
echo ""																						>> $RESULT_FILE 2>&1
echo "[진단기준]"																				>> $RESULT_FILE 2>&1
echo "양호 : 프로세스 관리 디렉터리가 삭제되어 있는 경우" 													>> $RESULT_FILE 2>&1
echo "취약 : 프로세스 관리 디렉터리가 존재하는 경우"															>> $RESULT_FILE 2>&1
echo ""																						>> $RESULT_FILE 2>&1
echo "[참고사항]"																				>> $RESULT_FILE 2>&1
echo "※ manager 디렉터리 하위에 catalina-manager.jar 파일를 통해 취약 유무 판단"							>> $RESULT_FILE 2>&1
echo "※ manager 디렉터리가 없다면 양호"																>> $RESULT_FILE 2>&1
echo "============================================="										>> $RESULT_FILE 2>&1
echo "============================================="										>> $RESULT_FILE 2>&1


echo ""																						>> $RESULT_FILE 2>&1
echo ""																						>> $RESULT_FILE 2>&1
echo ""																						>> $RESULT_FILE 2>&1


echo "[WAS-15] 보안 패치"
echo "[WAS-15] 보안 패치"																		>> $RESULT_FILE 2>&1
echo "[START]"																				>> $RESULT_FILE 2>&1
echo "============================================"											>> $RESULT_FILE 2>&1
echo "[+] Tomcat 점검현황"  						 											>> $RESULT_FILE 2>&1
if [ `ls -al $Tomcat_HOME/bin/version.sh | wc -l` -eq 0 ]
        then
                echo "결과 출력이 없는 경우 수동 진단 필요" 											>> $RESULT_FILE 2>&1					
        else
                $Tomcat_HOME/bin/version.sh													>> $RESULT_FILE 2>&1						
fi
echo "============================================="										>> $RESULT_FILE 2>&1
echo "[END]"																				>> $RESULT_FILE 2>&1
echo ""																						>> $RESULT_FILE 2>&1
echo ""																						>> $RESULT_FILE 2>&1
echo "[진단기준]"																				>> $RESULT_FILE 2>&1
echo "양호 : Tomcat에 대한 최신 버전과 패치가 업그레이드 되어 있는 경우" 										>> $RESULT_FILE 2>&1
echo "취약 : Tomcat에 대한 버전 및 패치 업그레이드를 하지 않는 경우"										>> $RESULT_FILE 2>&1
echo "============================================="										>> $RESULT_FILE 2>&1
echo "============================================="										>> $RESULT_FILE 2>&1


echo ""																						>> $RESULT_FILE 2>&1
echo ""																						>> $RESULT_FILE 2>&1
echo ""																						>> $RESULT_FILE 2>&1


echo "============================================="										>> $RESULT_FILE 2>&1
echo "server.xml 출력"																		>> $RESULT_FILE 2>&1
echo ""																						>> $RESULT_FILE 2>&1
cat $Tomcat_CONF/server.xml 																>> $RESULT_FILE 2>&1
echo "============================================="										>> $RESULT_FILE 2>&1
echo ""																						>> $RESULT_FILE 2>&1
echo "============================================="										>> $RESULT_FILE 2>&1
echo "web.xml 출력"																			>> $RESULT_FILE 2>&1
echo ""																						>> $RESULT_FILE 2>&1
cat $Tomcat_CONF/web.xml 																	>> $RESULT_FILE 2>&1
echo "============================================="										>> $RESULT_FILE 2>&1
echo ""																						>> $RESULT_FILE 2>&1
echo "============================================="										>> $RESULT_FILE 2>&1
echo "tomcat-users.xml 출력"																	>> $RESULT_FILE 2>&1
echo ""																						>> $RESULT_FILE 2>&1
cat $Tomcat_CONF/tomcat-users.xml 															>> $RESULT_FILE 2>&1
echo "============================================="										>> $RESULT_FILE 2>&1




unset Tomcat_HOME
unset Tomcat_CONF
unset Tomcat_LOG
unset Tomcat_ROOT
unset tomcat
unset WAS_NAME



#================================================================================
# Tomcat 스크립트 종료
#================================================================================






#================================================================================
# 결과 파일 정리
#================================================================================

tar cvf $TAR_FILE $RESULT_FILE
rm -rf *_*.txt


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