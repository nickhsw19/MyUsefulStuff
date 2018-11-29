#!/bin/ksh
#
#

if [ "$1" = '-d' ]
then
	debug=true
fi

_logit() {
	#
	#
	#
	echo $*
	return
}
_check_user() {
	if [ "$debug" ]
	then
		set -x 
	fi
	#
	#       Many of these commands wont run correctly
	#       unless run by root
	#
	
	UID=$(id | sed -n 's/uid=\([0-9]*\).*$/\1/p')
	
	if [ $UID != '0' ]
	then
		print "$0: You have to be root to run this"
		exit 1
	fi
}

_check_svcs() {
	if [ "$debug" ]
	then
		set -x 
	fi

	TEST="2.2.1 Disable Local CDE ToolTalk Database Server"
	svcs -H -o STATE svc:/network/rpc/cde-ttdbserver:tcp 2>/dev/null | grep online 2>/dev/null
	if [ $? -eq 0 ]
	then
		_logit $TEST failed
	fi

	TEST="2.2.2 Disable Local CDE Calendar Manager"
	svcs -H -o STATE svc:/network/rpc/cde-calendar-manager 2>/dev/null | grep online >/dev/null
	if [ $? -eq 0 ]
	then
		_logit $TEST failed
	fi


	TEST="2.2.3 Disable Local CDE"
	svcs -H -o STATE svc:/application/graphical-login/cde-login 2>/dev/null| grep online>/dev/null
	if [ $? -eq 0 ]
	then
		_logit $TEST failed
	fi

	TEST="2.2.4 Disable Local sendmail "
	svcs -H -o STATE svc:/network/smtp:sendmail 2>/dev/null | grep online>/dev/null
	if [ $? -eq 0 ]
	then
		_logit $TEST failed
	fi


	TEST="2.2.5 Disable Local Web Console"
	svcs -H -o STATE svc:/system/webconsole:console 2>/dev/null | grep online>/dev/null
	if [ $? -eq 0 ]
	then
		_logit $TEST failed
	fi
	TEST="2.2.6 Disable Local WBEM"
	svcs -H -o STATE svc:/application/management/wbem 2>/dev/null | grep online >/dev/null
	if [ $? -eq 0 ]
	then
		_logit $TEST failed
	fi

	TEST="2.2.7 Disable Local BSD Print Protocol Adapter"
	svcs -H -o STATE svc:/application/print/rfc1179:default 2>/dev/null | grep online>/dev/null
	if [ $? -eq 0 ]
	then
		_logit $TEST failed
	fi


	TEST="2.3.1 Disable RPC Encryption Key"
	svcs -H -o STATE svc:/network/rpc/keyserv:default 2>/dev/null | grep online>/dev/null
	if [ $? -eq 0 ]
	then
		_logit $TEST failed
	fi

	TEST="2.3.2 Disable NIS Server Daemons"
	for i in svc:/network/nis/server:default \
		svc:/network/nis/passwd:default \
		svc:/network/nis/update:default \
		svc:/network/nis/xfr:default
	do
		svcs -H -o STATE $i 2>/dev/null | grep online>/dev/null

		if [ $? -eq 0 ]
		then
			_logit $TEST failed
		fi
	done

	TEST="2.3.3 Disable NIS Client Daemons"
	svcs -H -o STATE svc:/network/nis/client:default 2>/dev/null | grep online >/dev/null
	if [ $? -eq 0 ]
	then
		_logit $TEST failed
	fi

	TEST="2.3.4 Disable NIS+ daemons"
	svcs -H -o STATE svc:/network/rpc/nisplus:default 2>/dev/null | grep online >/dev/null
	if [ $? -eq 0 ]
	then
		_logit $TEST failed
	fi

	TEST="2.3.5 Disable LDAP Cache Manager"
	svcs -H -o STATE svc:/network/ldap/client:default 2>/dev/null| grep online>/dev/null
	if [ $? -eq 0 ]
	then
		_logit $TEST failed
	fi

	TEST="2.3.6 Disable Kerberos TGT Expiration Warning"
	svcs -H -o STATE svc:/network/security/ktkt_warn:default 2>/dev/null | grep online >/dev/null
	if [ $? -eq 0 ]
	then
		_logit $TEST failed
	fi

	TEST="2.3.7 Disable Generic Security Services (GSS) daemons"
	svcs -H -o STATE svc:/network/rpc/gss:default 2>/dev/null | grep online >/dev/null
	if [ $? -eq 0 ]
	then
		_logit $TEST failed
	fi

	TEST="2.3.8 Disable Volume Manager"
	ZONENAME=$(zonename)

	if [[ $ZONENAME == 'global' ]]
	then
		for i in svc:/system/filesystem/volfs:default \
			 svc:/network/rpc/smserver:default
		do
			svcs -H -o STATE $i 2>/dev/null   | grep online >/dev/null
			if [ $? -eq 0 ]
			then
				_logit $TEST failed
			fi
		done
	else
		_logit $TEST for global zone only
	fi

	TEST="2.3.9 Disable Samba Support"
	svcs -H -o STATE svc:/network/samba:default 2>/dev/null | grep online >/dev/null
	if [ $? -eq 0 ]
	then
		_logit $TEST failed
	fi

	TEST="2.3.10  Disable automount daemon"
	svcs -H -o STATE svc:/system/filesystem/autofs:default 2>/dev/null | grep online >/dev/null
	if [ $? -eq 0 ]
	then
		_logit $TEST failed
	fi

	TEST="2.3.11        Disable Apache services"
	svcs -H -o STATE svc:/network/http:apache2 2>/dev/null  | grep online >/dev/null
	if [ $? -eq 0 ]
	then
		_logit $TEST failed
	fi
	
	TEST="2.3.12        Disable Solaris Volume Manager Services"
	ZONENAME=$(zonename)

	if [[ $ZONENAME == 'global' ]]
	then
		for i in svc:/system/metainit:default \
		 	 svc:/platform/sun4u/mpxio-upgrade:default \
		 	 svc:/system/mdmonitor:default
		do
			svcs -H -o STATE $i  2>/dev/null | grep online >/dev/null
			if [ $? -eq 0 ]
			then
				_logit $TEST failed
			fi
		done
	else
		_logit $TEST for global zone only
	fi

	TEST="2.3.13        Disable Solaris Volume Manager GUI"
	ZONENAME=$(zonename)

	if [[ $ZONENAME == 'global' ]]
	then
		for i in svc:/network/rpc/mdcomm:default \
			 svc:/network/rpc/meta:default \
			 svc:/network/rpc/metamed:default \
			 svc:/network/rpc/metamh:default
		do
			svcs -H -o STATE $i  2>/dev/null | grep online  >/dev/null
			if [ $? -eq 0 ]
			then
				_logit $TEST failed
			fi
		done
	else
		_logit $TEST for global zone only
	fi

	TEST="2.3.14        Disable Local RPC Port Mapping Service"
	svcs -H -o STATE  svc:/network/rpc/bind:default 2>/dev/null| grep online >/dev/null
	if [ $? -eq 0 ]
	then
		_logit $TEST    failed
	fi

	TEST="2.4.1 Kerberos server daemons"
	for i in svc:/network/security/kadmin:default \
		 svc:/network/security/krb5kdc:default \
		 svc:/network/security/krb5_prop:default
	do
		svcs -H -o STATE  $i 2>/dev/null| grep online >/dev/null
		if [ $? -eq 0 ]
		then
			_logit $TEST $i offline   failed 
		fi
	done

	TEST="2.4.2 NFS server processes" 
	ZONENAME=$(zonename)

	if [[ $ZONENAME == 'global' ]]
	then
		svcs -H -o STATE svcs svc:/network/nfs/server:default  2>/dev/null| grep online >/dev/null
		if [ $? -eq 0 ]
		then
			_logit $TEST    failed
		fi
	else
		_logit $TEST for global zone only
	fi

	TEST="2.4.3 NFS client processes"
	svcs -H -o STATE svcs svc:/network/nfs/client:default  2>/dev/null| grep online >/dev/null
	if [ $? -eq 0 ]
	then
		_logit $TEST    failed
	fi

	TEST="2.4.4 telnet access"
	svcs -H -o STATE svcs svc:/network/telnet:default  2>/dev/null| grep online >/dev/null
	if [ $? -eq 0 ]
	then
		_logit $TEST    failed
	fi

	TEST="2.4.5 ftp access"
	svcs -H -o STATE svcs svc:/network/ftp:default  2>/dev/null| grep online >/dev/null
	if [ $? -eq 0 ]
	then
		_logit $TEST    failed
	fi

	TEST="2.4.6 boot Services"

	ZONENAME=$(zonename)

	if [[ $ZONENAME == 'global' ]]
	then
		svcs -H -o STATE svcs svc:/network/rpc/bootparams:default  2>/dev/null| grep online >/dev/null
		if [ $? -eq 0 ]
		then
			_logit $TEST    failed
		fi
	else 
		_logit $TEST for global zone only
	fi

	TEST="2.4.7 rarp Services"

	ZONENAME=$(zonename)

	if [[ $ZONENAME == 'global' ]]
	then
		svcs -H -o STATE svcs svc:/network/rarp:default  2>/dev/null| grep online >/dev/null
		if [ $? -eq 0 ]
		then
			_logit $TEST    failed
		fi
	else 
		_logit $TEST for global zone only
	fi
	
	TEST="2.4.8 DHCP Services"

	ZONENAME=$(zonename)

	if [[ $ZONENAME == 'global' ]]
	then
		svcs -H -o STATE svcs svc:/network/dhcp-server:default 2>/dev/null| grep online >/dev/null
		if [ $? -eq 0 ]
		then
			_logit $TEST    failed
		fi
	else 
		_logit $TEST for global zone only
	fi
	TEST="2.4.9 DNS Services"


	svcs -H -o STATE svcs svc:/network/dns/server:default  2>/dev/null| grep online >/dev/null
	if [ $? -eq 0 ]
	then
		_logit $TEST    failed
	fi

	TEST="2.4.10 TFTP Services"


	svcs -H -o STATE svcs svc:/network/tftp:default  2>/dev/null| grep online >/dev/null
	if [ $? -eq 0 ]
	then
		_logit $TEST    failed
	fi
}
			
_check_kernel() {
	if [ "$debug" ]
	then
		set -vx
	fi

	TEST="3.1 Core Dumps"
	if [ ! -d /var/core ]
	then
		_logit $TEST ' ' /var/core not found
	fi
	
	if [ ! -O /var/core ]
	then
		_logit $TEST /var/core wrong user ownership
	fi

	if [ ! -G /var/core ]
	then
		_logit $TEST /var/core wrong group ownership
	fi

	#
	#	Now check the settings for coreadm
	#

	coreadm | grep 'global core file pattern: /var/core/core_%n_%f_%u_%g_%t_%p' >/dev/null
	if [ $? -ne 0 ]
	then
		
		_logit $TEST ' ' global core file pattern incorrect
	fi

	coreadm  | grep 'global core dump logging: enabled' >/dev/null
	if [ $? -ne 0 ]
	then
		
		_logit $TEST ' ' global core dump logging not enabled
	fi

	TEST="3.2 Enable Stack Protection"
	egrep "^set noexec_user_stack[ 	]*=[ 	]*1" /etc/system >/dev/null
	if [ $? -ne 0 ]
	then
		_logit $TEST ' ' stack protection not set
	fi

	egrep "^set noexec_user_stack_log[ 	]*=[ 	]*1" /etc/system >/dev/null
	if [ $? -ne 0 ]
	then
		_logit $TEST ' ' stack protection not set
	fi

	TEST='3.3 Enable Strong TCP Sequence Number Generation'
	grep '^TCP_STRONG_ISS=2' /etc/default/inetinit >/dev/null
	if [ $? -ne 0 ]
	then
		_logit $TEST ' ' Strong sequence numbering not set
	fi

	TEST="3.4 Modify Network Parameters"
	#
	#       Check incoming connection queue protection
	#
	VAL=$(ndd /dev/tcp tcp_conn_req_max_q)

	if [ $VAL -ne 1024 ]
	then
		_logit   "$TEST failed ndd /dev/tcp tcp_conn_req_max_q returning $VAL"
	fi
	#
	VAL=$(ndd /dev/tcp tcp_conn_req_max_q0)
	if [ $VAL -ne 4096 ]
	then
		_logit   "$TEST failed ndd /dev/tcp tcp_conn_req_max_q0 returning $VAL"
	fi

	VAL=$(ndd /dev/tcp tcp_rev_src_routes)
	if [ $VAL -ne 0 ]
	then
		_logit   "$TEST failed ndd /dev/tcp tcp_rev_src_routes returning $VAL"
	fi

	VAL=$(ndd /dev/ip ip_forward_src_routed)
	if [ $VAL -ne 0 ]
	then
		_logit   "$TEST failed ndd /dev/ip ip_forward_src_routed returning $VAL"
	fi

	VAL=$(ndd /dev/ip ip6_forward_src_routed)
	if [ $VAL -ne 0 ]
	then
		_logit   "$TEST failed ndd /dev/ip ip6_forward_src_routed returning $VAL"
	fi

	VAL=$(ndd /dev/ip ip_forward_directed_broadcasts)
	if [ $VAL -ne 0 ]
	then
		_logit   "$TEST failed ndd /dev/ip ip_forward_directed_broadcasts returning $VAL"
	fi

	VAL=$(ndd /dev/ip ip_respond_to_timestamp)
	if [ $VAL -ne 0 ]
	then
		_logit   "$TEST failed ndd /dev/ip ip_respond_to_timestamp returning $VAL"
	fi
	VAL=$(ndd /dev/ip ip_respond_to_timestamp_broadcast)
	if [ $VAL -ne 0 ]
	then
		_logit   "$TEST failed ndd /dev/ip ip_respond_to_timestamp_broadcast returning $VAL"
	fi

	VAL=$(ndd /dev/ip ip_respond_to_address_mask_broadcast)
	if [ $VAL -ne 0 ]
	then
		_logit   "$TEST failed ndd /dev/ip ip_respond_to_address_mask_broadcast returning $VAL"
	fi

	VAL=$(ndd /dev/ip ip_respond_to_echo_broadcast)
	if [ $VAL -ne 0 ]
	then
		_logit   "$TEST failed ndd /dev/ip ip_respond_to_echo_broadcast returning $VAL"
	fi

	VAL=$(ndd /dev/arp arp_cleanup_interval)
	if [ $VAL -ne 60000 ]
	then
		_logit   "$TEST failed ndd /dev/arp arp_cleanup_interval returning $VAL"
	fi

	VAL=$(ndd /dev/ip ip_ire_arp_interval)
	if [ $VAL -ne 60000 ]
	then
		_logit   "$TEST failed ndd /dev/ip ip_ire_arp_interval returning $VAL"
	fi

	VAL=$(ndd /dev/ip ip_ignore_redirect)
	if [ $VAL -ne 1 ]
	then
		_logit   "$TEST failed ndd /dev/ip ip_ignore_redirect returning $VAL"
	fi

	VAL=$(ndd /dev/ip ip6_ignore_redirect)
	if [ $VAL -ne 1 ]
	then
		_logit   "$TEST failed ndd /dev/ip ip6_ignore_redirect returning $VAL"
	fi

	VAL=$(ndd /dev/tcp tcp_extra_priv_ports_add )
	if [ $VAL -ne 6112 ]
	then
		_logit   "$TEST failed ndd /dev/tcp tcp_extra_priv_ports_addr returning $VAL"
	fi

	VAL=$(ndd /dev/ip ip_strict_dst_multihoming)
	if [ $VAL -ne 1 ]
	then
		_logit   "$TEST failed ndd /dev/ip ip_strict_dst_multihoming returning $VAL"
	fi

	VAL=$(ndd /dev/ip ip6_strict_dst_multihoming)
	if [ $VAL -ne 1 ]
	then
		_logit   "$TEST failed ndd /dev/ipip6_strict_dst_multihoming  returning $VAL"
	fi

	VAL=$(ndd /dev/ip ip_send_redirects)
	if [ $VAL -ne 0 ]
	then
		_logit   "$TEST failed ndd /dev/ip ip_send_redirects returning $VAL"
	fi

	VAL=$(ndd /dev/ip ip6_send_redirects)
	if [ $VAL -ne 0 ]
	then
		_logit   "$TEST failed ndd /dev/ip ip6_send_redirects returning $VAL"
	fi

#FIXME	TEST="3.5 Disable Network Routing"
#FIXME	set `routeadm | grep 'IPv4 forwarding'`
#FIXME	if [ $3 != 'disabled' || $4 != 'disabled' ]
#FIXME	then
#FIXME		_logit $TEST failed $1 $2 $3 $4
#FIXME	fi
#FIXME
#FIXME	set `routeadm | grep 'IPv6 forwarding'`
#FIXME	if [ $3 != 'disabled' || $4 != 'disabled' ]
#FIXME	then
#FIXME		_logit $TEST failed $1 $2 $3 $4
#FIXME	fi
#FIXME
#FIXME	set `routeadm | grep 'IPv4 routing'`
#FIXME	if [ $3 != 'disabled' || $4 != 'disabled' ]
#FIXME	then
#FIXME		_logit $TEST failed $1 $2 $3 $4
#FIXME	fi
#FIXME	set `routeadm | grep 'IPv6 routing'`
#FIXME	if [ $3 != 'disabled' || $4 != 'disabled' ]
#FIXME	then
#FIXME		_logit $TEST failed $1 $2 $3 $4
#FIXME	fi

	TEST="4.1 Enable inetd Connection Logging"
	inetadm -p | grep -i 'tcp_trace=true' >/dev/null
	if [ $? -ne 0 ]
	then
		_logit $TEST tcp_trace not true
	fi

	#
	#	Test 4.2 is for ftp logging 
	#	as we dont run in.ftpd, not set up	
	#
	
	TEST='4.3 Enable Debug Level Daemon Logging'
	VAL=$(grep '^daemon.debug' /etc/syslog.conf | nawk '{print $2;}')
	if [[ -z $VAL || ! -f $VAL ]]
	then
		_logit $TEST daemon logging not set
	fi

	TEST='4.4 Capture syslog AUTH Messages'	
	VAL=$(grep '^auth.info' /etc/syslog.conf | nawk '{print $2;}')
	if [[ -z $VAL || ! -f $VAL ]]
	then
		_logit $TEST daemon logging not set
	fi

	TEST="4.5 Enable Login Records"
	if [ ! -f /var/adm/loginlog ]
	then
		_logit $TEST /var/adm/loginlog not found 
	fi

	TEST="4.6 Capture All Failed Login Attempts"
	grep '^SYSLOG_FAILED_LOGINS=0' /etc/default/login >/dev/null
	if [[ $? -ne 0 ]]
	then
		_logit $TEST failed
	fi

	TEST='4.7 Enable cron Logging'
	grep '^CRONLOG=YES' /etc/default/cron
	if [ $? -ne 0 ]
	then
		_logit $TEST failed
	fi

	TEST='4.8 Enable System Accounting'
	STATE=$(svcs -H -o STATE svc:/system/sar:default 2>/dev/null)
	if [[ $STATE != online ]]
	then
		_logit $TEST not enabled - $STATE
	else
		#
		#	Check enabled in sys crontab
		#
		crontab -l sys | grep -v '^#' | grep sa1
		if [ $? -ne 0 ]
		then
			_logit $TEST  check sys crontab 	
		fi
	fi

	TEST='4.9 Enable Kernel Level Auditing'
	grep '^set c2audit:audit_load = 1' /etc/system >/dev/null
	if [ $? -ne 0 ]
	then
		_logit $TEST check auditting not enabled
	fi

	TEST="5.1 Set daemon umask"
	grep '^CMASK=022' /etc/default/init >/dev/null
	if [ $? -ne 0 ]
	then
		_logit $TEST CMASK not set
	fi

	TEST='5.2 Restrict Set-UID on User Mounted Devices'
	grep '^mount.*-o nosuid' /etc/rmmount.conf >/dev/null
	if [ $? -ne 0 ]
	then
		_logit $TEST failed
	fi

	#
	#	5.3 check package integrity...
	#

	#
	#	5.4. look for world writable directories 
	#	that dont have the sticky bit set
	#
	TEST='5.4 Set Sticky Bit on World Writable Directories'
	

#find / \( -fstype nfs -o -fstype cachefs -o -fstype ctfs \
#	-o -fstype mntfs -o -fstype objfs -o -fstype proc \) -prune -o \
#	-type d \( -perm -0002 -a ! -perm -1000 \) -print 
#
#	TEST='5.5 World Writable Files"
#find / \( -fstype nfs -o -fstype cachefs -o -fstype ctfs 
#	-o -fstype mntfs -o -fstype objfs -o fstype proc \) -prune -o \
#	-type f -perm -0002 -print
#
#	TEST='5.6 Find SUID/SGID System Executables'
#find / \( -fstype nfs -o -fstype cachefs -o -fstype ctfs
#	-o -fstype mntfs -o -fstype objfs -o fstype proc \) -prune -o \
#	-type f  \( -perm -04000 -o -perm -02000 \) -print
#
#	TEST="5.7 Find Un-owned Files and Directories"
#find / \( -fstype nfs -o -fstype cachefs -o -fstype ctfs
#	-o -fstype mntfs -o -fstype objfs -o -fstype proc \) -prune -o \
#	\( -nouser -o -nogroup \) -print
#
#	TEST="5.8 Find Files and Directories with Extended Attributes
#find / \( -fstype nfs -o -fstype cachefs -o -fstype ctfs
#	-o -fstype mntfs -o -fstype objfs -o -fstype proc \) -prune -o \
#	-xattr -print
#
	TEST='6.1 Disable login: Prompts on Serial Ports'
	for t in ttya ttyb 
	do
		FLAG=$(pmadm -L -p zsmon -s $t | cut -f 4 -d':')
		if [ "$FLAG" = "u" ]
		then
			_logit $TEST port monitor enabled on $t
		fi
	done

	TEST='6.2 Disable "nobody" Access for RPC Encryption Key Storage'
	grep '^ENABLE_NOBODY_KEYS=NO' /etc/default/keyserv >/dev/null
	if [ $? -ne 0 ]
	then
		_logit $TEST failed
	fi

	TEST='6.3 Configure SSH'

	SSHDCONFIG[0]="^Protocol[ 	]*2"
	SSHDCONFIG[1]="^X11Forwarding[ 	]*yes"
	SSHDCONFIG[2]="^MaxAuthTries[ 	]*5"
	SSHDCONFIG[3]="^MaxAuthTriesLog[ 	]*0"
	SSHDCONFIG[4]="^IgnoreRhosts yes"
	SSHDCONFIG[5]="^RhostsAuthentication no"
	SSHDCONFIG[6]="^RhostsRSAAuthentication no"
	SSHDCONFIG[7]="^PermitRootLogin no"
	SSHDCONFIG[8]="^PermitEmptyPasswords no"
	SSHDCONFIG[9]="^AllowUsers.*[ 	]cts[ 	]"
	SSHDCONFIG[10]="^AllowTcpForwarding No"
	SSHDCONFIG[11]="^Banner[ 	]*/etc/issue.net"
	SSHDCONFIG[12]="^LoginGraceTime 60"

	#
	#       This is OS dependant
	#

	VER=$(uname -r)

	case $VER
	in
		5.9|5.10)    CONFIGPATH=/etc/ssh/sshd_config
			SSHDCONFIG[13]="^Subsystem sftp /usr/lib/ssh/sftp-server"
			;;
	
		5.8)    CONFIGPATH=/usr/local/etc/sshd_config
			SSHDCONFIG[13]="^Subsystem sftp /usr/local/libexec/sftp-server";;
		*)      print "Test 38 unknown OS version $VER";;
	esac

	for i in "${SSHDCONFIG[@]}"
	do
		grep "$i" $CONFIGPATH >/dev/null
		if [ $? -ne 0 ]
		then
			_logit "$TEST failed $i not set in $CONFIGPATH"
		fi
	done

	TEST="6.4 Disable .rhosts Support in /etc/pam.conf"
	grep -v '^#' /etc/pam.conf |  grep pam_rhosts_auth >/dev/null

	if [ $? -eq 0 ]
	then
		_logit $TEST failed
	fi

	TEST="6.5 Restrict FTP Use"
	for user in root daemon bin sys adm lp uucp nuucp \
		       smmsp listen gdm webservd nobody \
				      noaccess nobody4
	do
		grep $user /etc/ftpd/ftpusers >/dev/null
		if [ $? -ne 0 ]
		then
			_logit $TEST $user not in /etc/ftpd/ftpusers
		fi
	done
	TEST='6.6 Verify Delay between Failed Login Attempts Set to 4'

	grep 'SLEEPTIME=4' /etc/default/login >/dev/null
	if [ $? -ne 0 ]
	then
		_logit $TEST SLEEPTIME not set in /etc/default/login
	fi

	#
	#	this next one - we shouldnt be running 
	#
	TEST="6.7 Set Default Screen Lock for CDE Users"	
	for i in /usr/dt/config/*/sys.resources
	do
		FILE=$(echo $i | sed 's/usr/etc/')
		if [ -f $FILE ]
		then
			grep '^dtsession\*saverTimeout: 10' $FILE >/dev/null
			if [ $? -ne 0 ]
			then
				_logit $TEST dtsession saverTimeout not set
			fi
			grep '^dtsession\*lockTimeout: 10' $FILE >/dev/null
			if [ $? -ne 0 ]
			then
				_logit $TEST dtsession lockTimeout not set
			fi
		else 
			_logit $TEST $FILE not found
		fi
	done
#
	TEST='6.8 Set Default Screen Lock for GNOME Users'

	XSCRSAVER[0]='timeout: 0:10:00'	
	XSCRSAVER[1]='lockTimeout: 0:00:00'	
	XSCRSAVER[2]='lock: True'	

	for i in "${XSCRSAVER[@]}"
	do
		grep "$i" /usr/openwin/lib/app-defaults/XScreenSaver >/dev/null
		if [ $? -ne 0 ]
		then
			_logit $TEST $i not found
		fi
	done

	TEST='6.9 Restrict at/cron to Authorized Users'
	grep -v root /etc/cron.d/*.allow >/dev/null
	if [ $? -ne 0 ]
	then
		_logit $TEST failed - other users have cron access
	fi

	TEST='6.10 Restrict root Login to System Console'

 	grep '^CONSOLE=/dev/console' /etc/default/login >/dev/null
	if [ $? -ne 0 ]
	then	
		_logit $TEST failed 
	fi
	TEST='6.11 Set Retry Limit for Account Lockout'
	grep 'RETRIES=3' /etc/default/login >/dev/null
	if [ $? -ne 0 ]
	then	
		_logit $TEST failed 
	fi
	TEST='6.12 Set EEPROM Security Mode and Log Failed Access'
	if [ -x /usr/platform/`uname -i`/sbin/eeprom ]
	then
		VAL=$(/usr/platform/`uname -i`/sbin/eeprom security-mode | sed 's/.*=\(command\)/\1/p')
		if [ $VAL != 'command' ]
		then
			_logit $TEST EEPROM security mode $VAL
		fi
	fi

	#
	#	This next test x86 only...
	#
	TEST='6.12 Set EEPROM Security Mode and Log Failed Access'
	PROC=$(uname -p)
	if [ $PROC = 'sparc' ]
	then
		_logit $TEST skipped on $PROC
	fi

	TEST='7.1 Disable System Accounts'
	for u in bin nuucp smmsp listen gdm webservd nobody noaccess nobody4
	do
		VAL=$(passwd -s $u |  nawk '{print $2;}')
		if [[ $VAL != 'LK' && $VAL != 'NL' ]]
		then
			_logit $TEST password not locked for $u
		fi
	done

	for u in adm lp uucp
	do
		VAL=$(passwd -s $u |  nawk '{print $2;}')
		if [[ $VAL != 'NL' && $VAL != 'NL' ]]
		then
			_logit $TEST password no login  for $u
		fi
	done

	TEST='7.2 Ensure Password Fields are Not Empty'

	BADUSERS=$(logins -p)
	if [[ ! -z $BADUSERS ]]
	then
		for  u in $BADUSERS
		do
			_logit $TEST $BADUSERS
		done
	fi

#FIXME	TEST='7.3 Set Password Expiration Parameters on Active Accounts'
#FIXME	PWD[0]='^MAXWEEKS=13'
#FIXME	PWD[1]='^MINWEEKS=1'
#FIXME	PWD[2]='^WARNWEEKS=4'
#FIXME
#FIXME	for p in "${PWD[@]}"
#FIXME	do
#FIXME		grep $p /etc/default/passwd  > /dev/null
#FIXME		if [ $? -ne 0 ]
#FIXME		then
#FIXME			_logit $TEST password values not for $p
#FIXME		fi
#FIXME	done
#FIXME
#FIXME	#
#FIXME	#	Also test whether parameters are set on current users
#FIXME	#
#FIXME	logins -ox |&
#FIXME	while :
#FIXME	do
#FIXME		read -p LINE
#FIXME		if [ $? -ne 0 ]
#FIXME		then
#FIXME			break
#FIXME		fi
#FIXME		set `echo $LINE | sed 's/:/ /g'`
#FIXME		if [[ $8 == "LK" ]]
#FIXME		then
#FIXME			continue
#FIXME		fi
#FIXME		if [[ $11 -le 0 || $11 -gt 91 ]]
#FIXME		then
#FIXME			_logit $TEST $1 max wrong $11
#FIXME		fi
#FIXME
#FIXME		if [[ $10 -lt 7 ]]
#FIXME		then
#FIXME			_logit $TEST $1 min wrong $10
#FIXME		fi
#FIXME
#FIXME		if [[ $10 -lt 28 ]]
#FIXME		then
#FIXME			_logit $TEST $1 min wrong $10
#FIXME		fi
#FIXME	done

	TEST='7.4 Set Strong Password Creation Policies'

	PASSSTR[0]='^PASSLENGTH=8'
	PASSSTR[1]='^NAMECHECK=YES'
	PASSSTR[2]='^HISTORY=10'
	PASSSTR[3]='^MINDIFF=3'
	PASSSTR[4]='^MINALPHA=2'
	PASSSTR[5]='^MINUPPER=1'
	PASSSTR[6]='^MINLOWER=1'
	PASSSTR[7]='^MINNONALPHA=1'
	PASSSTR[8]='^MAXREPEATS=8'
	PASSSTR[9]='^WHITESPACE=YES'
	PASSSTR[10]='^DICTIONDBDIR=/var/passwd'
	PASSSTR[11]='^DICTIONLIST=/usr/share/lib/dict/words'

	for i in "${PASSSTR[@]}"
	do
		grep $i /etc/default/passwd >/dev/null
		if [ $? -ne 0 ]
		then
			_logit $TEST $i not set in /etc/default/passwd
		fi
	done

	TEST='7.5 Verify No Legacy Entries Exist in passwd, shadow, and group Files'

	for f in /etc/passwd /etc/shadow /etc/group
	do
		grep '^+:' $f
		if [ $? -eq 0 ]
		then
			_logit $TEST Legacy entry in $f
		fi
	done

	TEST='7.6 Verify No UID 0 Accounts Exist Other than root'
	
	(logins -o | awk -F: '($2 == 0) { print $1 }') |&
	while :
	do
		read -p LINE
		if [ $? -ne 0 ]
		then
			break
		fi
		if [[ $LINE != 'root' ]]
		then
			_logit $TEST $LINE has uid 0
		fi
	done

	TEST='7.7 Set Default Group for root Account'

	VAL=$(logins -o -l root | cut -f 3 -d':')
	if [ $VAL != 'root' ]
	then
		_logit $TEST wrong group for root $VAL
	fi
			
	TEST='7.8 Change Home Directory for root Account'

	RD=$(grep '^root:' /etc/passwd | cut -f 6 -d':')
	if [[ $RD != '/root' ]]
	then
		_logit $TEST root home directory set to $RD
	fi

	TEST='7.9 Ensure root PATH Integrity'
	
	if [ "`echo $PATH | grep "::" `" != "" ]
	then
		echo "Empty Directory in PATH \(::\)"
	fi
	if [ "`echo $PATH | grep ":$"`" != "" ]
	then
		echo "Trailing : in PATH."
	fi
	p=`echo $PATH | sed -e 's/::/:/' -e 's/:$//' -e 's/:/ /g'`
	set -- $p
	while [ "$1" != "" ]
	do
		if [ "$1" = "." ]
		then
			echo "PATH contains ."
			shift
			continue
		fi
		if [ -d $1 ]
		then
			dirperm=`ls -ld $1 | cut -f1 -d" "`
			if [ `echo $dirperm | cut -c6 ` != "-" ]
			then
				echo "Group Write permission set on directory $1"
			fi
			if [ `echo $dirperm | cut -c9 ` != "-" ]
			then
				echo "Other Write permission set on directory $1"
			fi
		fi
		shift
	done

	TEST='7.10 Check Permissions on User Home Directories'

	for dir in `logins -ox | \
		awk -F: '($8 == "PS" && $1 != "root") { print $6 }'`
	do
		dirperm=`ls -ld $dir | cut -f1 -d" "`
		if [ `echo $dirperm | cut -c6 ` != "-" ]
		then
			echo "Group Write permission set on directory $dir"
		fi
		if [ `echo $dirperm | cut -c8 ` != "-" ]
		then
			echo "Other Read permission set on directory $dir"
		fi
		if [ `echo $dirperm | cut -c9 ` != "-" ]
		then
			echo "Other Write permission set on directory $dir"
		fi
		if [ `echo $dirperm | cut -c10 ` != "-" ]
		then
			echo "Other Execute permission set on directory $dir"
		fi
	done

	TEST='7.11 Check User Dot File Permissions'

	for dir in `logins -ox | \
		awk -F: '($8 == "PS") { print $6 }'`
	do
		for file in $dir/.[A-Za-z0-9]*; do
			if [ ! -h "$file" -a -f "$file" ]
			then
				fileperm=`ls -ld $file | cut -f1 -d" "`
				if [ `echo $fileperm | cut -c6 ` != "-" ]
				then
					echo "Group Write permission set on file $file"
				fi
				if [ `echo $fileperm | cut -c9 ` != "-" ]
				then
					echo "Other Write permission set on file $file"
				fi
			fi
		done
	done

	TEST='7.12 Check Permissions on User .netrc Files'

	for dir in `logins -ox | \
		awk -F: '($8 == "PS") { print $6 }'`
	do
		for file in $dir/.netrc
		do
			if [ ! -h "$file" -a -f "$file" ]
			then
				fileperm=`ls -ld $file | cut -f1 -d" "`
				if [ `echo $fileperm | cut -c5 ` != "-" ]
				then
					echo "Group Read permission set on directory $file"
				fi
				if [ `echo $fileperm | cut -c6 ` != "-" ]
				then
					echo "Group Write permission set on directory $file"
				fi
				if [ `echo $fileperm | cut -c7 ` != "-" ]
				then
					echo "Group Execute permission set on directory $file"
				fi
				if [ `echo $fileperm | cut -c8 ` != "-" ]
				then
					echo "Other Read permission set on directory $file"
				fi
				if [ `echo $fileperm | cut -c9 ` != "-" ]
				then
					echo "Other Write permission set on directory $file"
				fi
				if [ `echo $fileperm | cut -c10 ` != "-" ]
				then
					echo "Other Execute permission set on directory $file"
				fi
			fi
		done
	done

	TEST="7.13 Check for Presence of User .rhosts Files"
	for dir in `logins -ox | \
      		awk -F: '($8 == "PS") { print $6 }'`
	do
		for file in $dir/.rhosts 
		do
			if [ ! -h "$file" -a -f "$file" ]
			then
				echo .rhosts file in $dir
			fi
		done
	done

	TEST="7.14 Set Default umask for Users"

	grep '^UMASK=077' /etc/default/login >/dev/null

	if [ $? -ne 0 ]
	then
		_logit $TEST UMASK not set in /etc/default/login
	fi


	for f in  /etc/profile /etc/.login
	do
		grep -i "umask 077" $f >/dev/null
		if [ $? -ne 0 ]
		then
			_logit $TEST UMASK not set in $f
		fi
	done

	TEST='7.15 Set Default umask for ftp Users'
	VAL=$(grep '^defumask' /etc/ftpd/ftpaccess | cut -f 2)

	if [[ -z $VAL || $VAL != '077' ]]
	then
		_logit $TEST failed 
	fi

	TEST='7.16 Set "mesg n" as Default for All Users'
	for i in /etc/profile /etc/.login 
	do
		YORN=$(grep '^mesg'  $f | cut -f 2)
		if [[ -z $YORN || $YORN != 'y' ]]
		then
			_logit $TEST message setting $YORN
		fi
	done

	TEST='8.1 Create Warnings for Standard Login Services'

	for f in /etc/motd /etc/issue
	do
		grep 'Authorized' $f >/dev/null
		if [ $? -ne 0 ]
		then
			_logit $TEST files on $f
		fi
	done

	TEST='8.2 Create Warning Banner for CDE Users'
	for file in /usr/dt/config/*/Xresources
	do
		dir=`dirname $file | sed s/usr/etc/`
		if [ ! -f $dir/Xresources  ]
		then
			_logit $TEST failed
			continue
		fi
		grep 'Authorized'  $dir/Xresources >/dev/null
		if [ $? -ne 0 ]
		then
			_logit $TEST no banner found for $file
		fi
	  done

	TEST='8.3 Create Warning Banner for GNOME Users'
	STR=$(cat /etc/X11/gdm/gdm.conf | sed -n 's/^Welcome=\(.*\)/\1/p')
	if [[ -z $STR  || $STR != *Authorized* ]]
	then
		_logit $TEST Welcome string not set $STR
	fi
	
	TEST='8.4 Create Warning Banner for FTP daemon'
	grep 'Authorized' /etc/ftpd/banner.msg >/dev/null
	if [ $? -ne 0 ]
	then
		_logit $TEST  Warning banner not set
	fi


	#
	#	8.5 is for telnet which we dont run
	#
	TEST='8.6 Create Power On Warning'
	if [ -x /usr/platform/`uname -i`/sbin/eeprom ]
	then
		STR1=$(/usr/platform/`uname -i`/sbin/eeprom oem-banner | sed -n 's/.*=.*\(You may only logon for LBHF purposes\).*$/\1/p')
		STR2=$(/usr/platform/`uname -i`/sbin/eeprom oem-banner\? | sed -n 's/.*=\(true\)/\1/p')

		if [[ -z $STR1 || -z $STR2 ]]
		then
			_logit $TEST failed
		fi
	fi
		
#	#
#	#	8.7 is a test for sendmail which we dont use
#	#	should probably change smptd_banner in postfix
#	#
#

}
PATH=$PATH:/usr/sbin
export PATH
#
#	The numbering on these tests is crap...
#
_check_user;
#_check_os;
#_check_patches;
#_check_encryption_kit;
_check_svcs;
_check_kernel;

