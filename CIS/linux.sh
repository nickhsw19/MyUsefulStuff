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
#        exit 1
    fi
}

_check_svcs() {
    if [ "$debug" ]
    then
        set -x 
    fi
    TEST='1.3 Configure SSH'

    SSHDCONFIG[0]="^Protocol[     ]*2"
    SSHDCONFIG[1]="^X11Forwarding[     ]*yes"
    SSHDCONFIG[2]="^IgnoreRhosts yes"
    SSHDCONFIG[3]="^RhostsAuthentication no"
    SSHDCONFIG[4]="^RhostsRSAAuthentication no"
    SSHDCONFIG[5]="HostbasedAuthentication no"
    SSHDCONFIG[6]="^PermitRootLogin no"
    SSHDCONFIG[7]="^PermitEmptyPasswords no"
    SSHDCONFIG[8]="^Banner[     ]*/etc/issue.net"
    SSHDCONFIG[9]="^MaxAuthTries[     ]*5"
    SSHDCONFIG[10]="^MaxAuthTriesLog[     ]*0"
    SSHDCONFIG[11]="^AllowUsers.*[     ]cts[     ]"
    SSHDCONFIG[12]="^AllowTcpForwarding No"
    SSHDCONFIG[13]="^LoginGraceTime 60"

    #
    #       This is OS dependant
    #

    VER=$(uname -r)

    case $VER
    in
        2.6.3)    CONFIGPATH=/etc/ssh/sshd_config;
            SSHDCONFIG[14]="^Subsystem sftp /usr/lib/ssh/sftp-server";;
        2.6.9-*)    CONFIGPATH=/etc/ssh/sshd_config;
            SSHDCONFIG[14]="^Subsystem sftp /usr/lib/ssh/sftp-server";;
        2.6.18-*)    CONFIGPATH=/etc/ssh/sshd_config;
            SSHDCONFIG[14]="^Subsystem sftp /usr/lib/ssh/sftp-server";;
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

    TEST='1.4 Enable System Accounting'
    rpm -q sysstat > /dev/null

    if [[ $? -ne 0 ]]
    then
        _logit "$TEST sysstat not installed "
    else
        #
        #    check whether set in chkconfig 2>/dev/null
        #
        RL=$(who -r |  gawk '{print $2;}')
        /sbin/chkconfig --list sysstat |  grep "${RL}:on" >/dev/null 2>/dev/null
        if [[ $? -ne 0 ]]
        then
            _logit "$TEST  failed check chkconfig "
        fi 

    fi

    TEST="2.1 Disable standard services"
    cd /etc/xinetd.d
    for FILE in chargen chargen-udp cups-lpd cups daytime \
    daytime-udp echo echo-udp eklogin ekrb5-telnet finger \
    gssftp imap imaps ipop2 ipop3 krb5-telnet klogin kshell \
    ktalk ntalk pop3s rexec rlogin rsh rsync servers services \
    sgi_fam talk telnet tftp time time-udp vsftpd wu-ftpd
    do
        if [ -f $FILE ]
        then
            _logit "$TEST failed $FILE enabled"
        fi
    done



    TEST="2.3 Check telnet"
    RL=$(who -r | gawk '{print $2;}')
    /sbin/chkconfig --list |  grep telnet |  grep "on" > /dev/null 2>/dev/null
    if [ $? -eq 0 ]
    then
        _logit "$TEST failed  - telnet enabled"
    fi

    TEST="2.4 Check ftp  "
    /sbin/chkconfig --list |  grep ftp |  grep "on" > /dev/null 2>/dev/null
    if [ $? -eq 0 ]
    then
        _logit "$TEST failed - ftp enabled"
    fi


    TEST="2.5 Check whether r commands enabled"
    for i in login shell 
    do
        /sbin/chkconfig --list |  grep $i |  grep "on" > /dev/null         2>/dev/null
        if [ $? -eq 0 ]
        then
            _logit "$TEST failed $i enabled"
        fi
    done
    TEST="2.6 Check tftp "
    /sbin/chkconfig --list  |  grep tftp | grep on > /dev/null     2>/dev/null
    if [ $? -eq 0 ]
    then
        _logit "$TEST failed  - tftp enabled"
    fi

    TEST="2.7 Check imap"
    /sbin/chkconfig --list |  grep imap |  grep on > /dev/null 2>/dev/null
    if [ $? -eq 0 ]
    then
        _logit "$TEST failed imap enabled"
    fi


    TEST="2.8 Check pop3"
    /sbin/chkconfig --list  | grep pop |  grep on > /dev/null 2>/dev/null
    if [ $? -eq 0 ]
    then
        _logit "$TEST failed - pop enabled"
    fi

#}

#_check_boot() {
#    if [ "$debug" ]
#    then
#        set -vx
#    fi

    TEST="3.1 daemon mask"

    let MASK=$(grep '^umask ' /etc/init.d/functions |gawk '{print $2;}')


    if (( $MASK < 27 )) 
    then
        _logit $TEST /etc/init.d/functions umask too low $MASK
    fi


    TEST="3.2  Check xinetd " 
    RL=$(who -r | gawk  '{print $2;}')

    /sbin/chkconfig --list xinetd 2>/dev/null | grep "${RL}:on" >/dev/null 2>/dev/null
    if [ $? -eq 0 ]
    then
        _logit $TEST ' ' failed xinetd enabled
    fi



    TEST='3.3 check sendmail runninsg'
    RL=$(who -r | gawk  '{print $2;}')

    /sbin/chkconfig --list  |  grep sendmail | grep "${RL}:on" >/dev/null 2>/dev/null
    if [ $? -eq 0 ]
    then
        _logit "$TEST   sendmail enabled"
    fi
    #
    #    Also check to see if port 25 is open
    #
    #    netstat -an | gawk '{print $4;}' |   egrep ':25[\t ]*' > /dev/null
    type nc >/dev/null
    if [ $? -ne 0 ]
    then
        _logit "$TEST no netcat/nc in path"
    else
        nc -uvz localhost 25
        if [ $? -eq 0 ]
        then
            _logit "$TEST there is a process using port 25"
        fi
    fi


    TEST="3.4 Check GUI Login"

    DEFRL=$(grep -v '^#' /etc/inittab | grep initdefault |   gawk -F':' '{print $2;}')
    if [[ $DEFRL = '5' ]]
    then
        _logit   "$TEST failed - default runlevel $DEFRL"
    fi

    TEST="3.5 Disable XFont Server"
    RL=$(who -r | gawk  '{print $2;}')
    /sbin/chkconfig --list xfs |  grep "${RL}:off" > /dev/null 2>/dev/null
    if [[ $? -ne 0 ]]
    then
        _logit "$TEST failed -xfs enabled"
    fi

    TEST="3.6 Disable Standard boot services"
    RL=$(who -r | gawk  '{print $2;}')


    for FILE in apmd avahi-daemon canna cups-config-daemon \
         FreeWnn gpm hidd hpoj hplip innd irda isdn kdcrotate \
              lvs mars-nwe messagebus oki4daemon privoxy rstatd \
               rusersd rwalld rwhod spamassassin wine
    do

        /sbin/chkconfig --list $FILE 2>/dev/null | grep "${RL}:on" >/dev/null 
        if [[ $? -eq 0 ]]
        then
            _logit "$TEST failed $FILE enabled"
        fi
    done

    for FILE in nfs nfslock autofs ypbind ypserv yppasswdd \
         portmap smb netfs lpd apache httpd tux snmpd \
              named postgresql mysqld webmin kudzu squid cups \
               ip6tables iptables pcmcia bluetooth mDNSResponder
    do
        /sbin/chkconfig --list $FILE 2>/dev/null  | grep "${RL}:on" >/dev/null 2>/dev/null
        if [[ $? -eq 0 ]]
        then
            _logit "$TEST failed $FILE enabled"
        fi
    done

    TEST="3.7 Check SAMBA"
    RL=$(who -r | gawk  '{print $2;}')

    /sbin/chkconfig --list smb |  grep "${RL}:on" >/dev/null 2>/dev/null
    if [ $? -eq 0 ]
    then
        _logit "$TEST failed - smb enabled"
    fi

    TEST="3.8 Check NFS server"
    RL=$(who -r | gawk  '{print $2;}')
    /sbin/chkconfig --list nfs  | grep "${RL}:on" >/dev/null 2>/dev/null
    if [ $? -eq 0 ]
    then
        _logit "$TEST failed - nfs server enabled"
    fi

    TEST="3.9 Check NFS client"
    RL=$(who -r | gawk  '{print $2;}')
    for i in nfslock autolock
    do
        /sbin/chkconfig --list $i 2>/dev/null | grep "${RL}:on" >/dev/null 2>/dev/null
        if [ $? -eq 0 ]
        then
            _logit "$TEST failed - $i enabled"
        fi
    done

    TEST="3.10 Check NIS client"
    RL=$(who -r | gawk  '{print $2;}')
    for i in ypbind
    do
        /sbin/chkconfig --list $i  | grep "${RL}:on" >/dev/null 2>/dev/null
        if [ $? -eq 0 ]
        then
            _logit "$TEST failed - $i enabled"
        fi
    done
    TEST="3.11 Check NIS server"
    RL=$(who -r | gawk  '{print $2;}')
    for i in ypserv yppasswdd
    do
        /sbin/chkconfig --list $i 2>/dev/null | grep "${RL}:on" >/dev/null 2>/dev/null
        if [ $? -eq 0 ]
        then
            _logit "$TEST failed - $i enabled"
        fi
    done

    TEST="3.12 Check RPC portmap"
    RL=$(who -r | gawk  '{print $2;}')
    for i in portmap
    do
        /sbin/chkconfig --list $i  | grep "${RL}:on" >/dev/null 2>/dev/null
        if [ $? -eq 0 ]
        then
            _logit "$TEST failed - $i enabled"
        fi
    done

    TEST="3.13 Check netfs"
    RL=$(who -r | gawk  '{print $2;}')
    for i in newfs
    do
        /sbin/chkconfig --list $i 2>/dev/null  | grep "${RL}:on" >/dev/null 2>/dev/null
        if [ $? -eq 0 ]
        then
            _logit "$TEST failed - $i enabled"
        fi
    done

    TEST="3.14 Check printing"
    RL=$(who -r | gawk  '{print $2;}')
    for i in cups hpoj lpd
    do
        /sbin/chkconfig --list $i  2>/dev/null | grep "${RL}:on" >/dev/null 2>/dev/null
        if [ $? -eq 0 ]
        then
            _logit "$TEST failed - $i enabled"
        fi
    done

    TEST="3.15 Check http"
    RL=$(who -r | gawk  '{print $2;}')
    for i in apache httpd tux
    do
        /sbin/chkconfig --list $i 2>/dev/null | grep "${RL}:on" >/dev/null 2>/dev/null
        if [ $? -eq 0 ]
        then
            _logit "$TEST failed - $i enabled"
        fi
    done

    TEST="3.16 Check SNMP"
    RL=$(who -r | gawk  '{print $2;}')
    for i in snmpd
    do
        /sbin/chkconfig --list $i 2>/dev/null | grep "${RL}:on" >/dev/null 2>/dev/null
        if [ $? -eq 0 ]
        then
            _logit "$TEST failed - $i enabled"
        fi
    done

    TEST="3.17 Check named"
    RL=$(who -r | gawk  '{print $2;}')
    for i in named
    do
        /sbin/chkconfig --list $i  2>/dev/null | grep "${RL}:on" >/dev/null 2>/dev/null
        if [ $? -eq 0 ]
        then
            _logit "$TEST failed - $i enabled"
        fi
    done


    TEST="3.18 Check database servers"
    RL=$(who -r | gawk  '{print $2;}')

    for i in postgresql mysqld
    do
        /sbin/chkconfig --list $i 2>/dev/null | grep "${RL}:on" >/dev/null 2>/dev/null
        if [ $? -eq 0 ]
        then
            _logit "$TEST failed - $i enabled"
        fi
    done

    TEST="3.19 Check NIS client"
    RL=$(who -r | gawk  '{print $2;}')
    for i in webmin
    do
        /sbin/chkconfig --list $i  2>/dev/null | grep "${RL}:on" >/dev/null 2>/dev/null
        if [ $? -eq 0 ]
        then
            _logit "$TEST failed - $i enabled"
        fi
    done

    TEST="3.20 Check Squid"
    RL=$(who -r | gawk  '{print $2;}')
    for i in squid
    do
        /sbin/chkconfig --list $i  2>/dev/null | grep "${RL}:on" >/dev/null 2>/dev/null
        if [ $? -eq 0 ]
        then
            _logit "$TEST failed - $i enabled"
        fi
    done

    TEST="3.21 check kudzu"
    RL=$(who -r | gawk  '{print $2;}')
    for i in kudzu
    do
        /sbin/chkconfig --list $i  | grep "${RL}:on" >/dev/null 2>/dev/null
        if [ $? -eq 0 ]
        then
            _logit "$TEST failed - $i enabled"
        fi
    done

    TEST="4.1 network hardening"
    NETHARD[0]='net.ipv4.tcp_max_syn_backlog = 4096'
    NETHARD[1]='net.ipv4.tcp_syncookies = 1'
    NETHARD[2]='net.ipv4.conf.all.rp_filter = 1'
    NETHARD[3]='net.ipv4.conf.all.accept_source_route = 0'
    NETHARD[4]='net.ipv4.conf.all.accept_redirects = 0'
    NETHARD[5]='net.ipv4.conf.all.secure_redirects = 0'
    NETHARD[6]='net.ipv4.conf.default.rp_filter = 1'
    NETHARD[7]='net.ipv4.conf.default.accept_source_route = 0'
    NETHARD[8]='net.ipv4.conf.default.accept_redirects = 0'
    NETHARD[9]='net.ipv4.conf.default.secure_redirects = 0'
    NETHARD[10]='net.ipv4.icmp_echo_ignore_broadcasts = 1'


    for i in "${NETHARD[@]}"
    do
        grep "$i" /etc/sysctl.conf >/dev/null
        if [ $? -ne 0 ]
        then
            _logit "$TEST failed $i not set in /etc/sysctl.conf"
        fi
    done

    if [ ! -O /etc/sysctl.conf ]
    then
        $logit "$TEST not owned by root"
    fi
    if [ ! -G /etc/sysctl.conf ]
    then
        $logit "$TEST not group owned by root"
    fi

    PERM=$(stat -c %a /etc/sysctl.conf)
    if [[ $PERM != '600' ]]
    then
        _logit "$TEST failed - wrong permissions $PERM on /etc/sysctlconf"
    fi
    #
    #
    TEST="4.2 network hardening"
    NETHARD[0]='net.ipv4.ip_forward = 0'
    NETHARD[1]='net.ipv4.conf.all.send_redirects = 0'
    NETHARD[2]='net.ipv4.conf.default.send_redirects = 0'

    for i in "${NETHARD[@]}"
    do
        grep "$i" /etc/sysctl.conf >/dev/null
        if [ $? -ne 0 ]
        then
            _logit "$TEST failed $i not set in /etc/sysctl.conf"
        fi
    done


    TEST='5.1 Capture syslog AUTH Messages'
    VAL=$(grep '^auth.info' /etc/syslog.conf | gawk '{print $2;}')
    if [[ -z $VAL || ! -f $VAL ]]
    then
        _logit $TEST daemon logging not set
    else
        if [[ $VAL != '/var/log/secure' ]]
        then
            _logit "$TEST failed logging being sent to $VAL"
        else 
            if [ ! -O /var/log/secure ]
            then
                _logit "$TEST failed /var/log/secure not owned by root"
            fi
            if [ ! -G /var/log/secure ]
            then
                _logit "$TEST failed /var/log/secure not group owned by root"
            fi
            PERM=$(stat -c %a /var/log/secure)
            if [[ $PERM != '600' ]]
            then
                _logit "$TEST failed wrong permissions $PERM"
            fi
        fi
    fi


    #
    #    ftp logging
    #
    TEST="5.2 ftp logging"
    if [ -f /etc/ftpaccess ]
    then
        if [ -f /etc/xinetd.d/wu-ftpd ]
        then
            grep 'server_args = -l -a -d' /etc/xinetd.d/wu-ftpd >/dev/null
            if [ $? -ne 0 ]
            then
                _logit "$TEST failed - logging not configured"
            fi
        fi
    fi

    if [ -f /etc/vsftpd.conf ]
    then
        FILE="/etc/vsftpd.conf"
    else 
        FILE="/etc/vsftpd/vsftpd.conf"
    fi

    if [ -f $FILE ]
    then
        LOGSTR[0]="^xferlog_std_format=NO"
        LOGSTR[1]="^log_ftp_protocol=YES"
        for i in "${LOGSTR[@]}"
        do
            egrep "$i" $FILE >/dev/null
            if [ $? -ne 0 ]
            then
                _logit "$TEST failed $i not found in $FILE"
            fi
        done
        if [ ! -O $FILE ]
        then
            _logit "$TEST failed - $FILE not owned by root"
        fi
        if [ ! -G $FILE ]
        then
            _logit "$TEST failed - $FILE not group owned by root"
        fi
        PERM=$(stat -c %a $FILE)
        if [[ $PERM != '600' ]]
        then
            _logit "$TEST failed $FILE wrong perms $PERM"
        fi
    fi

    TEST="5.3 check log permissions"
    cd /var/log
    #
    #    First group o-rwx
    #
    for i in boot.log* cron* dmesg ksyms* httpd/* \
    maillog* messages* news/* pgsql rpmpkgs* samba/* sa/* \
    scrollkeeper.log secure* spooler* squid/* vbox/* wtmp
    do
        if [ ! -e $i ]
        then
            continue
        fi

        PERM1=$(stat -c %a $i)
        #
        #    Convert to decimal
        #
        let PERM=$(echo 8 i $PERM1 n | dc)
        if (( (PERM & 7) != 0 ))
        then
            _logit "$TEST failed first group $i wrong permission"
        fi
    done

    #
    #    Second group o-rx
    #
    for i in  boot.log* cron* maillog* messages* pgsql \
    secure* spooler* squid/* sa/*
    do
        if [ ! -e $i ]
        then
            continue
        fi

        PERM1=$(stat -c %a $i)
        let PERM=$(echo 8 i $PERM1 n | dc)
        if (( (PERM & 5) != 0 ))
        then
            _logit "$TEST failed second group $i wrong permission"
        fi
    done

    #
    #    Thris group g-w
    #
    for i in boot.log* cron* dmesg httpd/* ksyms* \
    maillog* messages* pgsql rpmpkgs* samba/* sa/* \
    scrollkeeper.log secure* spooler*
    do
        if [ ! -e $i ]
        then
            continue
        fi

        PERM1=$(stat -c %a $i)
        let PERM=$(echo 8 i $PERM1 n | dc)
        if (( (PERM & 16) == 1 ))
        then
            _logit "$TEST failed third group $i wrong permission"
        fi
    done

    #
    #    g-rx
    #
    for i in  boot.log* cron* maillog* messages* pgsql \
    secure* spooler*
    do
        if [ ! -e $i ]
        then
            continue
        fi

        PERM1=$(stat -c %a $i)

        let PERM=$(echo 8 i $PERM1 n | dc)

        if (( (PERM & 40)  != 0 ))
        then
            _logit "$TEST failed fourth group $i wrong permissions"
        fi
    done

    #
    #    o-w
    #
    for i in gdm/ httpd/ news/ samba/ squid/ sa/ vbox/
    do
        if [ ! -e $i ]
        then
            continue
        fi

        PERM1=$(stat -c %a $i)
        let PERM=$(echo 8 i $PERM1 n | dc )
        if (( (PERM & 2) == 1 ))
        then
            _logit "$TEST failed fifth group $i wrong permission"
        fi
    done

    #
    #    g-rx
    #
    for i in httpd/ samba/ squid/ sa/
    do
        if [ ! -e $i ]
        then
            continue
        fi

        PERM1=$(stat -c %a $i)
        let PERM=$(echo 8 i $PERM1 n | dc )
        if (( (PERM & 40)  != 0 ))
        then
            _logit "$TEST failed sixth group $i wrong permission"
        fi
    done

    #
    #    g-w
    #
    for i in gdm/ httpd/ news/ samba/ squid/ sa/ vbox/
    do
        if [ ! -e $i ]
        then
            continue
        fi

        PERM1=$(stat -c %a $i)
        let PERM=$(echo 8 i $PERM1 n | dc)
        if (( (PERM & 16) == 1 ))
        then
            _logit "$TEST failed seventh group $i wrong permission"
        fi
    done


    #
    #    g-rx
    #
    for i in httpd/ samba/ sa/
    do
        if [ ! -e $i ]
        then
            continue
        fi

        PERM1=$(stat -c %a $i)
        PERM=$(echo 8 i $PERM1 n | dc)
        if (( (PERM & 40) != 0 ))
        then
            _logit "$TEST failed eighth group $i wrong permission"
        fi
    done

    #
    #    u-x
    #
    for i in kernel syslog loginlog
    do
        if [ ! -e $i ]
        then
            continue
        fi

        PERM1=$(stat -c %a $i)
        PERM=$(echo 8 i $PERM1 n | dc)
        if (( (PERM & 64) == 1 ))
        then
            _logit "$TEST failed ninth group $i wrong permission"
        fi
    done

    if [ ! -O /var/log ]
    then
        _logit "$TEST failed - /var/log not owned by root"
    fi

    if [ ! -G /var/log ]
    then
        _logit "$TEST failed - /var/log not group owned by root"
    fi
    #
    #
    #
    TEST="6.1 Check for nodev in /etc/fstab"
    #FS=$(cat /etc/fstab | gawk '{if ($3 ~ /^ext[23]$/ && $2 != "/" && $4 !~ /nodev/) print $2;}')
    if [[ ! -z $FS ]] 
    then
        _logit "$TEST failed $FS need nodev set"
    fi

    TEST="6.2 check removable media"
    FS=$(cat /etc/fstab | gawk '{if (($2 ~ /^\/m.*\/(floppy|cdrom)$/) && ($4 !~ /,nodev,nosuid/)) print $2;}')

    if [[ ! -z $FS ]] 
    then
        _logit "$TEST failed $FS need nodev,nosuid set"
    fi
#FIX
#FIX    TEST='6.3 check user mounted removable file systems"
#FIX    cd /etc/security
#FIX
#FIX
#FIX
    TEST='6.4 check password, shadow, group'
    for i in /etc/passwd /etc/group
    do
        if [ ! -O $i ]
        then
            _logit "$TEST failed wrong owner on $i
        fi
        if [ ! -G $i ]
        then
            _logit "$TEST failed wrong group owner on $i
        fi
        PERM=$(stat -c %a $i)

        if [[ $PERM -ne '644' ]]
        then
            _logit "$TEST wrong perm on $i $PERM"
        fi
    done

    if [ ! -O /etc/shadow ]
    then
        _logit "$TEST failed wrong owner on /etc/shadow"
    fi

    if [ ! -G /etc/shadow ]
    then
        _logit "$TEST failed wrong group owner on /etc/shadow"
    fi

    PERM=$(stat -c %a /etc/shadow)
    if [[ $PERM -ne '400' ]]
    then
        _logit "$TEST failed wrong perm $PERM on /etc/shadow"
    fi


    #
    #    look for world writable directories
    #
#    TEST="6.5 check world writable directories"
#    _logit "$TEST starting..."
#    for PART in `awk '($3 == "ext2" || $3 == "ext3") \
#        { print $2 }' /etc/fstab`
#    do
#        find $PART -xdev -type d \( -perm -0002 -a ! -perm -1000 \) -print
#    done
#    _logit "$TEST starting..."
#    TEST="6.6 Check world Writable files"
#    for PART in $(grep -v '^#' /etc/fstab | awk '($6 != "0") { print $2 }' )
#    do
#           find $PART -xdev -type f  \( -perm -0002 -a ! -perm -1000 \) -print
#    done
#
#    TEST="6.7 SetUID/SetGID files"
#    _logit "$TEST starting..."
#    for PART in $(grep -v '^#' /etc/fstab | awk '($6 != "0") { print $2 }' )
#    do
#         find $PART -xdev \( -perm -04000 -o -perm -02000 \)  -type f -print
#    done
#
#    TEST="6.8 Find all unowned files"
#    _logit "$TEST starting..."
#    for PART in $(grep -v '^#' /etc/fstab | awk '($6 != "0") { print $2 }')
#    do
#        find $PART -xdev -nouser -o -nogroup -print
#    done
#
#FIX    #
#FIX    #    6.9 Disable USB devices ... tbd
#FIX    #
#FIX
    TEST="7.1 Disable .rhosts Support in /etc/pam.conf"
    for i in /etc/pam.d/* 
    do
        grep -v '^#' $i |  grep pam_rhosts_auth >/dev/null

        if [ $? -eq 0 ]
        then
            _logit $TEST failed - rhost_auth in $i
        fi
    done

    TEST="7.2 Restrict FTP Use"
    if [ ! -e /etc/ftpusers ]
    then
        _logit "$TEST failed - /etc/ftpusers not find"
    else
        if [ ! -O /etc/ftpusers ]
        then
            _logit "$TEST failed - /etc/ftpusers wrong owner"
        fi

        if [ ! -G /etc/ftpusers ]
        then
            _logit "$TEST failed - /etc/ftpusers wrong group"
        fi

        PERM=$(stat -c %a /etc/ftpusers)
        if [[ $PERM -ne '600' ]]
        then
            _logit "$TEST failed - /etc/ftpusers wrong perm $PERM"
        fi

        if [ -f /etc/vsftpd/vsftpd.conf ]
        then
            #
            #    Look for userlist_deny
            #
            grep -i '^userlist_deny=yes' /etc/vsftpd/vsftpd.conf > /dev/null
            if [ $? -eq 0 ]
            then
                #
                #    Ok - its enabled
                #    check that every userid under
                #    500 is listed in the userlist
                #
                USERS=$(cat /etc/passwd | gawk -F':' '{if ($3 < 500) print $1;}')
                for u in $USERS
                do
                    grep "^$u" /etc/vsftpd/user_list >/dev/null
                    if [ $? -ne 0 ]
                    then
                        _logit "$TEST failed - $u not in /etc/vsftpd/user_list"
                    fi
                done
            fi
        fi
    fi

    TEST="7.3 Check Xserver on port 6000"
    if [ -e /etc/X11/xdm/Xservers ]
    then
        cat /etc/X11/xdm/Xservers | grep -v '^#' |grep '/usr/X11R6/bin/X' | grep '-nolisten tcp' >/dev/null
        if [ $? -eq 0 ]
        then
            _logit "$TEST failed - fix /etc/X11/xdm/Xservers"
        fi
    fi

    if [ -e /etc/X11/gdm/gdm.conf ]
    then
        #
        #    Look for lines that finish /X
        #
        egrep '/X$' /etc/X11/gdm/gdm.conf >/dev/null
        if [ $? -eq 0 ]
        then
            _logit "$TEST failed - check /etc/X11/gdm/gdm.conf"
        fi
    fi
    if [ -e /etc/X11/xinit/xserverrc ]
    then
        cat /etc/X11/xinit/xserverrc | grep -v '^#' |grep '/X' | grep '-nolisten tcp' >/dev/null
        if [ $? -eq 0 ]
        then
            _logit "$TEST failed - check /etc/X11/xinit/xserverrc"
        fi
    fi


    TEST='7.4 Restrict use of at/cron'

    if [[ ! -e /etc/cron.allow || ! -e /etc/cron.deny ]]
    then
        _logit "$TEST - cron open"
    fi
    if [[ ! -e /etc/at.allow || ! -e /etc/at.deny ]]
    then
        _logit "$TEST - at open"
    fi

    TEST='7.5 check crontab permissions'

    if [ ! -O /etc/crontab ]
    then
        _logit "$TEST failed - wrong ownership of /etc/crontab
    fi

    if [ ! -G /etc/crontab ]
    then
        _logit "$TEST failed - wrong group ownership of /etc/crontab
    fi

    PERM=$(stat -c %a /etc/crontab)
    if [[ $PERM -ne '400' ]]
    then
        _logit "$TEST failed - wrong permissino on /etc/crontab $PERM"
    fi

    for i in /var/spool/cron /var/spool/cron/*
    do
        if [[ ! -e $i ]]
        then
            continue
        fi

        if [[ ! -O $i ]]
        then
            _logit "$TEST failed - wrong owner of $i"
        fi

        if [[ ! -G $i ]]
        then
            _logit "$TEST failed - wrong group owner of $i"
        fi


        PERM1=$(stat -c %a $i)
        let PERM=$(echo 8 i $PERM1 n | dc)

        if (( $PERM&63 )) 
        then
            _logit "$TEST wrong permissions on $i $PERM1"
        fi
    done

    TEST='7.6 check xinetd access control'
    grep only_from /etc/xinetd.conf > /dev/null
    if [[ $? -ne 0 ]]
    then
        _logit "$TEST failed"
    fi

    TEST='7.7 check root login'

    grep console /etc/securetty
    if [ $? -ne 0 ]
    then
        _logit "$TEST console not found in /etc/securetty"
    fi

    for i in $(seq 1 11)
    do
        grep  vc/$i /etc/securetty >/dev/null
        if [ $? -ne 0 ]
        then
            _logit "$TEST failed vc/$i not in /etc/securetty"
        fi
    done

    for i in $(seq 1 6)
    do
        grep  tty$i /etc/securetty >/dev/null
        if [ $? -ne 0 ]
        then
            _logit "$TEST failed tty/$i not in /etc/securetty"
        fi
    done

    if [ ! -O /etc/securetty ]
    then
        _logit "$TEST failed - wrong ownership"
    fi
    if [ ! -G /etc/securetty ]
    then
        _logit "$TEST failed - wrong group ownership"
    fi

    PERM=$(stat -c %a /etc/securetty)
    if [[ $PERM -ne '400' ]]
    then
        _logit "$TEST failed - wrong permissions $PERM"
    fi


    TEST="7.8 check lilo/grub password"
    if [[ -e /etc/lilo.conf ]]
    then
        grep '^password=' /etc/lilo.conf >/dev/null
        if [[ $? -ne 0 ]]
        then 
            _logit "$TEST password not set in /etc/lilo.conf"
        fi
        if [[ ! -O /etc/lilo.conf ]]
        then
            _logit "$TEST failed wrong owner /etc/lilo.conf"
        fi
        if [[ ! -G /etc/lilo.conf ]]
        then
            _logit "$TEST failed wrong group owner /etc/lilo.conf"
        fi
        PERM=$(stat -Lc %a /etc/lilo.conf)
        if [[ $PERM -ne '600' ]]
        then
            _logit "$TEST failed wrong permissions on /etc/lilo.conf $PERM"
        fi

    fi

    if [[ -e /etc/grub.conf ]]
    then
        grep '^password=' /etc/grub.conf >/dev/null
        if [[ $? -ne 0 ]]
        then 
            _logit "$TEST password not set in /etc/grub.conf"
        fi
        if [[ ! -O /etc/grub.conf ]]
        then
            _logit "$TEST failed wrong owner /etc/grub.conf"
        fi
        if [[ ! -G /etc/grub.conf ]]
        then
            _logit "$TEST failed wrong group owner /etc/grub.conf"
        fi
        PERM=$(stat -Lc %a /etc/grub.conf)
        if [[ $PERM -ne '600' ]]
        then
            _logit "$TEST failed wrong permissions on /etc/grub.conf $PERM"
        fi
    fi

    TEST='7.9 check fo rlogin in single user mode'
    cat /etc/inittab | egrep '.*:?S:.*/sbin/sulogin$'>/dev/null
    if [[ $? -ne 0 ]]
    then
        _logit "$TEST failed"
    fi

#FIX    #
#FIX    #    syslog - tbd
#FIX    #
#FIX
#FIX    #
#FIX    #
#FIX    #
    TEST='8.1 check for locked user accounts'
    USERS=$(cat /etc/passwd | gawk -F':' '{if ($3 < 500) print $1;}')
    for i in $USERS
    do
        if [[ $i == 'root' ]]
        then
            continue;
        fi

        passwd -S $i |  egrep -i '(LK|locked|alternate)' > /dev/null
        if [[ $? -ne 0 ]]
        then
            _logit "$TEST failed - password not locked for $i"
        fi
    done

    TEST='8.2 check for empty passwords'
    BADU=$(gawk -F: '($2 == "") { print $1 }' /etc/shadow)
    for i in $BADU
    do
        _logit "$TEST failed - null password for $i"
    done

    TEST='8.3 check password parameters'

    PWPARM[0]='^PASS_MAX_DAYS *90$'
    PWPARM[1]='^PASS_MIN_DAYS *7$'
    PWPARM[2]='^PASS_WARN_AGE *28$'
    PWPARM[3]='^PASS_MIN_LEN *6$'

    for p in "${PWPARM[@]}"
    do
        egrep "$p" /etc/login.defs   > /dev/null
        if [ $? -ne 0 ]
        then
            _logit "$TEST password values not for $p"
        fi
    done

    if [ ! -O  /etc/login.defs ]
    then
        _logit "$TEST  failed - wrong owner on /etc/login.defs"
    fi

    if [ ! -G  /etc/login.defs ]
    then
        _logit "$TEST  failed - wrong group owner on /etc/login.defs"
    fi

    PERM=$(stat -c %a /etc/login.defs)

    if [[ $PERM != '640' ]]
    then
        _logit "$TEST failed - wrong perm on file /etc/logins.defs $PERM"
    fi

    #
    #    Now check the aging information for the users
    #

#FIXME    for i in $USERS
#FIXME    do
#FIXME        set `grep "${i}:" /etc/passwd |  gawk '{print $4, $5, $6, $7;}'`
#FIXME        MIN=$4
#FIXME        MAX=$5
#FIXME        WARN=$6
#FIXME        INACT=$7
#FIXME
#FIXME        if [[ $MIN != '7' ]]
#FIXME        then
#FIXME            _logit "$TEST failed $i min aging $MIN "
#FIXME        fi
#FIXME
#FIXME        if [[ $MAX != '90' ]]
#FIXME        then
#FIXME            _logit "$TEST failed $i max aging $MAX "
#FIXME        fi
#FIXME        if [[ $MAX != '90' ]]
#FIXME        then
#FIXME            _logit "$TEST failed $i max aging $MAX "
#FIXME        fi
#FIXME        if [[ $WARN != '28' ]]
#FIXME        then
#FIXME            _logit "$TEST failed $i warn aging $WARN "
#FIXME        fi
#FIXME        if [[ $INACT != '7' ]]
#FIXME        then
#FIXME            _logit "$TEST failed $i inact aging $INACT "
#FIXME        fi
#FIXME    done

    TEST='8.4 Verify No Legacy Entries Exist in passwd, shadow, and group Files'

    for f in /etc/passwd /etc/shadow /etc/group
    do
        grep '^+:' $f
        if [ $? -eq 0 ]
        then
            _logit "$TEST Legacy entry in $f"
        fi
    done


    TEST='8.5 Ensure root PATH Integrity'

    LINE=$( echo $PATH | egrep '(^|:)(\.|:|$)')
    if [[ ! -z $LINE ]]
    then
        _logit "$TEST failed - PATH contains . $PATH"
    fi

    COUNT=$(find `echo $PATH | tr ':' ' '` -type d  \( -perm -002 -o -perm -020 \) -ls 2>&1 | wc -l)
    if [[ $COUNT != '0' ]]
    then
        _logit "$TEST check permissions in root directories"
    fi

    TEST="8.6 User Home Directories Should Be Mode 750 or More Restrictive"
    for DIR in $(gawk -F: '($3 >= 500) { print $6 }' /etc/passwd)
    do
        PERM1=$(stat -c %a $DIR)
        let PERM=$(echo 8 i $PERM1 n |  dc)
        if (( PERM > 488 )) 
        then
            _logit "$TEST - check permissions on $DIR"
        fi
    done

    TEST="8.7 No User Dot-Files Should Be World-Writable"

    for DIR in $(gawk -F: '($3 >= 500) { print $6 }' /etc/passwd); 
    do
        for FILE in $DIR/.[A-Za-z0-9]* 
        do
            if [ ! -h "$FILE" -a -f "$FILE" ] 
            then
                #
                #    stat is nice
                #    but I cant get ksh arithmetic
                #    to handle the out properly
                #
                PERM1=$(stat -c %a $FILE)
                let PERM=$(echo 8 i $PERM1 n | dc)
                if (( (PERM & 2) == 2 ))
                then
                    _logit "$TEST - check $FILE"
                fi
            fi
        done
    done

    TEST="8.8 - check for .netrc"
    FILES=$(find / -name '.netrc' )
    if [[ ! -z $FILES ]]
    then
        _logit "TEST - found .netrc files \n$FILES"
    fi

    TEST="8.9 check default umask For Users"
    cd /etc
    for FILE in profile csh.login csh.cshrc bashrc; 
    do
        egrep -q 'umask.*77' $FILE > /dev/null
        if [[ $? -eq 1 ]]
        then
            _logit "$TEST - umask not set in $FILE"                  
        fi
        if [ ! -O $FILE ]
        then
            _logit "$TEST - wrong owner on $FILE"
        fi

        if [ ! -G $FILE ]
        then
            _logit "$TEST - wrong group owner on $FILE"
        fi

        PERM=$(stat -c %a $FILE)
        if [[ $PERM != '444' ]]
        then
            _logit "$TEST wrong permissions $PERM on $FILE"
        fi
    done

    cd /root
    for FILE in .bash_profile .bashrc .cshrc .tcshrc
    do
        egrep -q 'umask.*77' $FILE >/dev/null
        if [ $? -eq 1 ]
        then
            _logit "$TEST umask not set in /root/${FILE}"
        fi
    done

    TEST="8.10 Check whether core dumps enabled"
    CORELINE[0]="^\* soft core 0"
    CORELINE[1]="^\* hard core 0"
    for i in "${CORELINE[@]}"
    do
        egrep "$i" /etc/security/limits.conf >/dev/null
        if [ $? -eq 1 ]
        then
            _logit "$TEST $i not set in /etc/security/limits.conf"
        fi
    done

    TEST='8.11 check wheel group'
    LINE="^[     ]*auth[     ]*required[     ]*.*pam_wheel.so[     ]*use_uid"

    egrep "$LINE" /etc/pam.d/su >/dev/null
    if [ $? -eq 1 ]
    then
        _logit "$TEST - wheel group not enabled in /etc/pam.d/su"
    fi

    TEST='9.1 Warnings for access'
    for f in /etc/issue /etc/issue.net /etc/motd
    do
        if [  -e $f ]
        then
            grep 'authorised use' $f >/dev/null
            if [ $? -eq 1 ]
            then
                _logit "$TEST authorised banner not set in $f"
            fi

            if [ ! -O ]
            then
                _logit "$TEST wrong owner for $f"
            fi

            if [ ! -G ]
            then
                _logit "$TEST wrong group owner for $f"
            fi
            PERM=$(stat -c %a $f)
            if [[ $PERM != '644' ]]
            then
                _logit "$TEST wrong permission on $f $PERM"
            fi
        else 
            _logit "$TEST $f not found"
        fi

    done
    TEST='9.2 Check for GUI based login'
    if [ -e /etc/X11/xdm/Xresources ]
    then
        egrep -i "xlogin.*greeting: authorised" /etc/X11/xdm/Xresources >/dev/null
        if [ $? -eq 1 ]
        then
            _logit "$TEST check /etc/X11/xdm/Xresources for banner"
        fi

        if [ ! -O /etc/X11/xdm/Xresources ]
        then
            _logit "$TEST /etc/X11/xdm/Xresources wrong owner"
        fi

        if [ ! -G /etc/X11/xdm/Xresources ]
        then
            _logit "$TEST /etc/X11/xdm/Xresources wrong owner"
        fi
        PERM=$(stat -c %a  /etc/X11/xdm/Xresources)
        if [[ $PERM != '644' ]]
        then
            _logit "$TEST wrong permissions on /etc/X11/xdm/Xresources"
        fi
    fi

    if [ -e /etc/X11/xdm/kdmrc ]
    then
        grep 'GreetString=Authorised uses only' /etc/X11/xdm/kdmrc >/dev/null
        if [ $? -eq 1 ]
        then
            _logit "$TEST no authorisation string in /etc/X11/xdm/kdmrc"
        fi
        if [ ! -O /etc/X11/xdm/kdmrc ]
        then
            _logit "$TEST /etc/X11/xdm/kdmrc wrong owner"
        fi

        if [ ! -G /etc/X11/xdm/kdmrc ]
        then
            _logit "$TEST /etc/X11/xdm/kdmrc wrong owner"
        fi
        PERM=$(stat -c %a  /etc/X11/xdm/kdmrc)
        if [[ $PERM != '644' ]]
        then
            _logit "$TEST wrong permissions on /etc/X11/xdm/kdmrc"
        fi
    fi

    TEST='9.3 ftp banners'

    if [ -d /etc/vsftpd ]
    then
        if [ -e /etc/vsftpd/vsftpd.conf ]
        then
            grep -i '^ftpd_banner=authorised' /etc/vsftpd/vsftpd.conf
            if [ $? -eq 1 ]
            then
                _logit "$TEST failed on /etc/vsftpd/vsftpd.conf"
            fi
        fi
    fi

    if [ -e /etc/proftpd.conf ]
    then
        grep "DisplayConnect\t\t/etc/issue.net" /etc/proftpd.conf
        if [ $? -eq 1 ]
        then
            _logit "$TEST failed displayconnect not set in  /etc/proftpd.conf"
        fi
        grep "DisplayLogin\t\t/etc/motd" /etc/proftpd.conf
        if [ $? -eq 1 ]
        then
            _logit "$TEST failed displaylogin not set in  /etc/proftpd.conf"
        fi
    fi
}
PATH=$PATH:/usr/sbin
export PATH
#
#    The numbering on these tests is crap...
#
_check_user;
#_check_os;
#_check_patches;
#_check_encryption_kit;
_check_svcs;
#_check_kernel;

