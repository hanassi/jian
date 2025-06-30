#!/bin/bash
Systemfile_list="/etc/inetd.conf /etc/xinetd.conf"
for Check_SystemFile in $Systemfile_list
	do
		if [ -f $Check_SystemFile ]; then
			echo ""
			echo "[+]" $Check_SystemFile
			ls -laR $Check_SystemFile
		else
			echo "파일이 존재하지 않습니다. $Check_SystemFile"
		fi
	done