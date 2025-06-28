#!/bin/bash

LANG=C
export LANG

CREATE_FILE=[Lyn_secure]`hostname`"_"$OS"_"$IP"_"`date +%m%d`.txt
############################
# 안전 함수
############################

grep_file() {
    local file="$1"
    local string="$2"
    if [ -e "$file" ]; then
		grep -- "$string" "$file" 2>/dev/null
    else
        echo "파일이 존재하지 않습니다."
    fi
}

safe_cat() {
	local file="$1"
    if [ -e "$file" ]; then
		cat "$file" 2>/dev/null
    else
        echo "파일이 존재하지 않습니다. $file"
    fi	

}

# 파일 존재여부 체크 함수 (표준 방식)
file_check() {
    local file="$1"
    if [ -e "$file" ]; then
        return 0  # 존재하면 0 (성공)
    else
        return 1  # 존재하지 않으면 1 (실패)
    fi
}

############################
# 항목별 함수
############################


U-18(){
echo "[U-18] 접속 IP 및 포트 제한"
echo "[U-18] 접속 IP 및 포트 제한"
echo "[U-18_START]"
echo "============================================="
hosts_file(){
	if file_check "$file"; then
		echo "[*] 파일 존재여부 체크"
		ls -la "$file"
		
		echo "[*] 파일 내 적절한 설정 체크"
		cat "$file"
	else
		echo "$file 파일이 존재하지 않습니다."
	fi
	echo ""
}
echo "[+] /etc/hosts.allow"
hosts_file "/etc/hosts.allow"

echo "[+] /etc/hosts.deny"
hosts_file "/etc/hosts.deny"

echo ""
echo "[U-18_END]"
echo "============================================="
echo "[참고 - 진단기준, 결과 값 출력]"
echo " * 양호 조건 : 시스템 서비스로의 접근통제가 적절하게 수행되고 있을 경우 (방화벽, tcp-wrapper, 3rd-party 제품 등을 활용) 또는 예시( /etc/hosts.allow - sshd : IP주소 (접근을 허용할 호스트) && /etc/hosts.deny - ALL:ALL (ALL Deny 설정))"
echo " * 취약 조건 : 시스템 서비스로의 접근통제가 적절하게 수행되고 있지 않을 경우 또는 관련설정 없을 시 "
echo "============================================="
echo ""
echo ""
echo ""
echo ""
}

U-18