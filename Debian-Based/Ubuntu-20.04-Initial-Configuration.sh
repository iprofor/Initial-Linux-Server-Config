#!/bin/bash

# Start counting the time since the execution of this script
start=`date +%s`

# ATTENTION: run the script as root

# Ubuntu 20.04 - INITIAL SERVER CONFIGURATION

# +------------------+----------------+---------------------------------------------------+
# | IMPLEMENTED BY   | DATE           | VERSION                                           |
# +------------------+----------------+---------------------------------------------------+
# | Profor Ivan      | 2022-03-12     | Based on the 9th version for Oracle Linux 8       |
# | Profor Ivan      | 2022-03-29     | 1st version for Ubuntu 20.04                      |
# +------------------+----------------+---------------------------------------------------+


# SYNOPSIS
# ----
# - Configure history command to show the dates
# - Auditctl configuration
# - Change of timezone
# - Update/upgrade the system
# - Configuration of SELinux
# - Disable of IPv6 interface
# - Configuration of Firewalld
# - Installation of system administrator needed packages
# - Change SSH default port and miscellaneous related to the sshd_config file:
    # BELOW ITEMS ARE OPTIONAL, HAS TO BE UNCOMMENTED
    # --------------------------------------
    # - Changing default SSH port to $sshp
    # - Disabling SSH root log in
    # - Disabling SSH password authentication
    # - Enabling SSH key authentication
    # - Changing LoginGraceTime to $sshlgt
    # - Limiting SSH:
        # - Disabling X11Forwarding
        # - GSSAPI authentication method
        # - Defininig MaxStartups - the maximum number of concurrent unauthenticated connections to the SSH daemon
        # - Setting maximum number of concurrent authenticated SSH connections to the SSH daemon
    # - Replacing the distribution title and version to a specific banner
    # --------------------------------------
# - Installation of EPEL repository
# BELOW ITEMS ARE OPTIONAL, HAS TO BE UNCOMMENTED
# --------------------------------------
# - Installation of additional packages from EPEL
# - Installation of Fish Shell
# - NOT OPTIONAL: Addition of a secondary sudo user
    # NOT OPTIONAL: - Insertion of the public SSH key
# - Installation of the fail2ban
# - Configuration of the fail2ban
# - Installation of the ClamAV
# - Configuration of the ClamAV
    # - Configure periodic scan using clamdscan on a specfic directory
    # - Enable On-Access mode
# - Installation of the rkhunter
# - Configuration of the rkhunter
# - Allowance of only one TTY
# - Installation of Google Authenticator (with PAM) module
# - Configuration of Google Authenticator (with PAM) module
# --------------------------------------

# The output of all the below commands is resumed in the /root/installation.log file 

# ----


# GLOBAL VARIABLES
# ----

# Installation log
il="/root/installation.log"

# Destination email
dstml="INSERT@EMAIL.HERE";

# Secondary user public SSH key
pk="INSERT THE SSH KEY PUBLIC PAIR HERE";

# ----


# THE SCRIPT
# ----

# Configure history command to show the dates
grep -w 'HISTTIMEFORMAT="%F %T "' /etc/profile

if [ $? == 0 ]; then
    echo "+ $(date +%H:%M:%S) - The timestamps are already present in the history command." > $il
else 
    # backing up the configuration file
    cp /etc/profile /etc/profile.orig
    # Append following HISTTIMEFORMAT variable to /etc/profile file to make it permanent to all users.
    echo 'HISTTIMEFORMAT="%F %T "' >> /etc/profile
    # Run the following command to effect the changes made to the file.
    source /etc/profile
    echo "+ $(date +%H:%M:%S) - Timestamps in history log - configured now." >> $il
fi



# Auditctl configuration

# verify if the packages are installed (audit audit-libs)
apt list --installed |grep -w auditd > /dev/null 2>&1

if [ $? == 1 ]; then
    # Installing
    apt-get -y install auditd > /dev/null 2>&1
    # backing up the configuration file
    cp /etc/audit/rules.d/audit.rules /etc/audit/rules.d/audit.rules.orig
    # Add the following rules:
    auditctl -w /etc/passwd -p w -k unusual_passwd
    auditctl -w /etc/group -p w -k unusual_group
    auditctl -w /etc/sudoers -p w -k unusual_sudoer
    auditctl -w /etc/shadow -p w -k unusual_shadow
    auditctl -w /etc/gshadow -p w -k unusual_gshadow
    auditctl -w /etc/rsyslog.conf -p w -k unusual_syslog
    auditctl -w /etc/rc.local -p w -k unusual_rclocal
    auditctl -w /etc/rc.sysinit -p w -k unusual_rcsysinit
    auditctl -w /etc/audit/auditd.conf -p w -k unusual_auditd
    auditctl -w /etc/audit/audit.rules -p w -k unusual_auditrules
    auditctl -w /etc/ssh/sshd_config -p w -k unusual_sshd
    # auditctl -w /etc/sysconfig/iptables -p w -k unusual_iptables
    # Make them permanent:
    auditctl -l >> /etc/audit/rules.d/audit.rules
    echo "+ $(date +%H:%M:%S) - Auditctl - installed and configured now." >> $il
fi



# Miscellaneous
# mkdir -m 700 /root/.ssh

# Insertion of the public SSH key into the root's directory
echo $pk > /root/.ssh/authorized_keys




# Change of timezone
# Variables
td="INSERT THE TIMEZONE HERE"
timedatectl set-timezone $td

# Verify the result
timedatectl|grep $td > /dev/null 2>&1

if [ $? == 0 ]; then
    echo "+ $(date +%H:%M:%S) - Timezone - reconfigured now to: $td." >> $il
else 
    echo "- $(date +%H:%M:%S) - Time reconfiguration to $td failed." >> $il
fi



# Update/upgrade the system
echo "+ $(date +%H:%M:%S) - Updating and upgrading the system ..." >> $il
apt-get -y update && apt-get -y upgrade && apt-get -y dist-upgrade && apt-get -y full-upgrade && apt-get -y autoremove


# Configuration of SELinux

# Verify the rule
getenforce|grep -w "Enforcing"

if [ $? == 0 ]; then
    echo "+ $(date +%H:%M:%S) - The SELinux Enforcing rule is in place.  $(date +%H:%M:%S)" >> $il
else 
    # backing up the configuration file
    cp /etc/selinux/config /etc/selinux/config.orig
    sed -i s/^SELINUX=.*$/SELINUX=enforcing/ /etc/selinux/config
    echo "+ $(date +%H:%M:%S) - SELinux - configured now." >> $il
fi



# Disable of IPv6 interface

# check whether IPv6 is enabled 
ip a | grep -w inet6

if [ $? == 0 ]; then
    # Disable IPv6 Using sysctl command, by adding the following lines and then save the file:
    echo "net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1" > /etc/sysctl.d/70-ipv6.conf

    # Now, to disable IPv6 use the following command.
    sysctl --load /etc/sysctl.d/70-ipv6.conf
    # When using this method, some of your network interfaces may still use IPv6 once you reboot your system. This happens because CentOS 8 uses Network Manager by default.
    echo "+ $(date +%H:%M:%S) - IPv6 interface was disabled now." >> $il
else 
    echo "+ $(date +%H:%M:%S) - There are no IPv6 interfaces on the machine." >> $il
fi

# To completely stop using IPv6, use the following nmcli command.
# nmcli connection modify <INTERFACE> ipv6.method ignore

# To apply the changes the machine should be rebooted.



# Configuration of Firewalld
# Delete unneeded allowed incoming services

if [[ $(firewall-cmd --state|grep -w "running") ]]; then
    echo "+ $(date +%H:%M:%S) - Firewalld is running." >> $il
    if [[ $(firewall-cmd --get-default-zone|grep -w "public") ]]; then
        echo "+ $(date +%H:%M:%S) - The default zone is: Public." >> $il
        if [[ $(firewall-cmd --zone=public --list-all|grep -w "dhcpv6-client") ]]; then
            firewall-cmd --zone=public --remove-service=dhcpv6-client --permanent;
            firewall-cmd --reload;
            echo "+ $(date +%H:%M:%S) - The 'dhcpv6-client' firewalld rule - deleted now." >> $il
            if [[ $(firewall-cmd --zone=public --list-all|grep -w "cockpit") ]]; then
                firewall-cmd --zone=public --remove-service=cockpit --permanent;
                firewall-cmd --reload;
                echo "+ $(date +%H:%M:%S) - The 'cockpit' firewalld rule - deleted now." >> $il
            else
                echo "- $(date +%H:%M:%S) - There is no 'cockpit' firewalld rule." >> $il
            fi
        else
            echo "- $(date +%H:%M:%S) - There is no 'dhcpv6-client' firewalld rule." >> $il
        fi
    else
        echo "- $(date +%H:%M:%S) - The default active zone is not 'Public'." >> $il
    fi
else
    echo "- $(date +%H:%M:%S) - Firewalld is not running." >> $il
fi



# Installation of system administrator needed packages:
# policycoreutils-python-utils is for installing the semanage app

# Variables
pckg="bc bind-utils git iptraf mc mtr nc net-tools nmap open-vm-tools pigz policycoreutils-python-utils tcpdump telnet tmux vim wget yum-utils"

# The main multi-loop for installing packages
for a in $pckg; do
    yum -y install $a;
    if [ $? == 0 ]; then
        echo "+ $(date +%H:%M:%S) - $a - installed now." >> $il;
    else
        echo "- $(date +%H:%M:%S) - $a - was not found, therefore was not installed." >> $il;
    fi
done



# OPTIONAL - Change SSH default port and miscellaneous related to the sshd_config file

# Verify the sshd_config file existence
ls /etc/ssh/sshd_config > /dev/null 2>&1

if [ $? == 0 ]; then
    # Variables
    # SSH port
    sshp=INSERT THE PORT HERE
    # LoginGraceTime
    sshlgt=1440m
    # MaxStartups
    mxst="5:50:10"
    # MaxSessions
    mxse="4"


    # backing up the configuration file
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.orig


    # Changing default SSH port to $sshp
    sed -i -re 's/^(\#)(Port)([[:space:]]+)22/\2 '$sshp'/' /etc/ssh/sshd_config
    echo "+ $(date +%H:%M:%S) - Default SSH port was changed to $sshp now." >> $il;
    
    # On a SELinux system, you have to tell SELinux about port change.
    semanage port -a -t ssh_port_t -p tcp $sshp


    # Disabling SSH root log in
    sed -i -re "s/^PermitRootLogin yes/PermitRootLogin no/" /etc/ssh/sshd_config
    echo "+ $(date +%H:%M:%S) - SSH root log in - disabled now." >> $il;


    # Disabling SSH password authentication
    sed -i -re "s/^PasswordAuthentication yes/PasswordAuthentication no/" /etc/ssh/sshd_config
    echo "+ $(date +%H:%M:%S) - SSH password authentication - disabled now." >> $il;


    # Enabling SSH key authentication
    sed -i -re "s/^(\#)PubkeyAuthentication yes/PubkeyAuthentication yes/" /etc/ssh/sshd_config
    echo "+ $(date +%H:%M:%S) - SSH key authentication - enabled now." >> $il;


    # Changing LoginGraceTime to $sshlgt
    sed -i -re 's/^(\#)(LoginGraceTime)([[:space:]]+)2m/\2 '$sshlgt'/' /etc/ssh/sshd_config
    echo "+ $(date +%H:%M:%S) - SSH LoginGraceTime was changed to $sshlgt now." >> $il;


    # Disabling X11Forwarding
    sed -i -re "s/^X11Forwarding yes/X11Forwarding no/" /etc/ssh/sshd_config
    echo "+ $(date +%H:%M:%S) - SSH X11Forwarding - disabled now." >> $il;
    

    # Disable GSSAPI authentication method
    sed -i -re "s/^GSSAPIAuthentication yes/GSSAPIAuthentication no/" /etc/ssh/sshd_config
    echo "+ $(date +%H:%M:%S) - SSH GSSAPI authentication method - disabled now." >> $il;


    # Defininig MaxStartups - the maximum number of concurrent unauthenticated connections to the SSH daemon
    # Additional connections will be dropped until authentication succeeds or the LoginGraceTime expires for a connection.
    # Colon-separated value gives you more refined control. The following example will block 50% connection once it reaches 5, and will block 100% connection once the total is 10 concurrent connection.
    sed -i -re "s/^(\#)MaxStartups 10:30:100/MaxStartups $mxst/" /etc/ssh/sshd_config
    echo "+ $(date +%H:%M:%S) - Maximum number of concurrent unauthenticated SSH connections to $mxst - configured now." >> $il;
    

    # Setting maximum number of concurrent authenticated SSH connections to the SSH daemon
    sed -i -re "s/^(\#)MaxSessions 10/MaxSessions $mxse/" /etc/ssh/sshd_config
    echo "+ $(date +%H:%M:%S) - Maximum number of concurrent authenticated SSH connections to $mxse - configured now." >> $il;
    
    systemctl restart sshd;

    # Adding the incoming firewall rule for the $sshp port
    firewall-cmd --zone=public --permanent --add-port=$sshp/tcp;
    firewall-cmd --reload;

else
    echo "- $(date +%H:%M:%S) - There is no /etc/ssh/sshd_config file. The SSHD was not reconfigured now." >> $il
fi



# OPTIONAL - Replacing the distribution title and version to a specific banner

# Verify the sshd_config file existence
ls /etc/ssh/sshd_config > /dev/null 2>&1

if [ $? == 0 ]; then
    # Activating the banner
    sed -i -re "s/^(\#)Banner none/Banner \/etc\/issue.net/" /etc/ssh/sshd_config

    # Inserting the message
echo 'Pre-authentication banner message from server:
| PRIVATE COMPUTER SYSTEM - RESTRICTED ACCESS
| This computer system is provided only for authorised use. Do not attempt to
| access this system unless you are an authorised user. Unauthorised access
| will result in prosecution to the fullest extent permitted by applicable law.
| As an authorised user you are required to comply with Information Security
| Policies applicable to your business unit. These policies are updated on a
| regular basis and you will be notified of changes to these policies.
| Accessing this system indicates your agreement that you have read and
| understood the applicable Information Security Policies.

End of banner message from server
Keyboard-interactive authentication prompts from server:' > /etc/issue.net

    systemctl restart sshd;
else
    echo "- $(date +%H:%M:%S) - There is no /etc/ssh/sshd_config file. The issue.net file was not inserted." >> $il
fi



# Installation of EPEL repository

# Verifiyng the existence of the EPEL repo on the OS
if [[ $(yum search epel|grep -w "oracle-epel-release-el8.x86_64") ]]; then
    yum -y install oracle-epel-release-el8;
    echo "+ $(date +%H:%M:%S) - EPEL repository - installed now." >> $il;
else
    echo "- $(date +%H:%M:%S) - There is no packages for the EPEL repository found in the BaseOS repository." >> $il
fi

# or
# yum -y install https://dl.fedoraproject.org/pub/epel/epel-release-latest-8.noarch.rpm &&
# yum -y update && yum -y upgrade && yum -y check-update &&


# Update/upgrade the system
echo "+ $(date +%H:%M:%S) - Updating and upgrading the system ..." >> $il
apt-get -y update && apt-get -y upgrade && apt-get -y dist-upgrade && apt-get -y full-upgrade && apt-get -y autoremove



# OPTIONAL - Installation of additional packages from EPEL

# Verify if the EPEL repository is already installed in the OS
yum list installed oracle-epel-release-el8 > /dev/null 2>&1

if [ $? == 0 ]; then

    # Variables
    pckg2="htop glances sysbench"

    # The main multi-loop for installing packages
    for a in $pckg2; do
        yum -y install $a;
        if [ $? == 0 ]; then
            echo "+ $(date +%H:%M:%S) - $a - installed now." >> $il;
        else
            echo "- $(date +%H:%M:%S) - $a - was not found, therefore was not installed." >> $il;
        fi
    done

else
    echo "- $(date +%H:%M:%S) - The EPEL repository is not installed yet. Aborting the htop installation." >> $il
fi



# OPTIONAL - Installation of Fish Shell
cd /etc/yum.repos.d/
curl -LO https://download.opensuse.org/repositories/shells:/fish:/release:/3/CentOS_8/shells:fish:release:3.repo

# Verifiyng the fish repo file
ls /etc/yum.repos.d/*fish* > /dev/null 2>&1

if [ $? == 0 ]; then
    yum -y install fish
    echo "+ $(date +%H:%M:%S) - Fish Shell - installed now." >> $il
else
    echo "- $(date +%H:%M:%S) - The Fish Shell repository file was not downloaded to the machine." >> $il
fi



# Addition of a secondary sudo user

# Verify the presence of the opnessl package in the system
yum list installed openssl > /dev/null 2>&1

if [ $? == 1 ]; then
    yum -y install openssl
    echo "+ $(date +%H:%M:%S) - openssl package - installed now." >> $il
else
    echo "+ $(date +%H:%M:%S) - The openssl package is already installed." >> $il
fi

# user creation

# Variables
usr="INSERT THE USERNAME HERE"
# useradd $usr -p $(openssl passwd -1 $psw) -m -s /bin/bash
useradd $usr -m -s /bin/bash

# enforce $usr to change its password on the ext logon
# passwd -e $usr > /dev/null 2>&1

# Adding user to the sudo/root/wheel group
# "wheel" is the sudo group in CentOS
usermod -aG wheel $usr

# backing up the working file
cp /etc/sudoers /etc/sudoers.orig

# Allow the user to run root commands without password, only by invoking "sudo" command before the actual command, by uncommeting the following line
sed -i 's/^#\s*\(%wheel\s*ALL=(ALL)\s*NOPASSWD:\s*ALL\)/\1/' /etc/sudoers

mkdir -m 700 /home/$usr/.ssh

echo "+ $(date +%H:%M:%S) - User $usr - created now." >> $il



# Insertion of the public SSH key
echo $pk > /home/$usr/.ssh/authorized_keys

# Assigning the right permissions and ownerships
chmod 600 /home/$usr/.ssh/authorized_keys
chown -R $usr:$usr /home/$usr/.ssh



# OPTIONAL - Installation of the fail2ban

# Verify if the EPEL repository is already installed in the OS
yum list installed oracle-epel-release-el8 > /dev/null 2>&1

if [ $? == 0 ]; then
    yum -y install fail2ban
    echo "+ $(date +%H:%M:%S) - fail2ban - installed now." >> $il
else
    echo "- $(date +%H:%M:%S) - The EPEL repository is not installed yet. Aborting the fail2ban installation." >> $il
fi


# OPTIONAL - Configuration of the fail2ban
yum list installed fail2ban > /dev/null 2>&1

if [ $? == 0 ]; then
    systemctl enable fail2ban;

    # Variables
    # Original file
    f2bc=(/etc/fail2ban/jail.conf)
    # Active file
    f2bl=(/etc/fail2ban/jail.local)
    # Bantime
    bntm="1800";
    # Maxretries
    mxrt="3";
    # Sender email
    sndr="INSERT@EMAIL.HERE";
    # Action: to ban & send an e-mail with whois report to the destemail with relevant log lines
    actn="%(action_mwl)s";

    # creating the working file based on the old one
    cp $f2bc $f2bl

    # Replacing the values in $f2bl
    sed -i "s/^bantime  = 10m/bantime  = $bntm/" $f2bl
    sed -i ':a;N;$!ba;s/banned.\nmaxretry = 5/banned.\nmaxretry = '$mxrt'/g' $f2bl
    sed -i "s/^destemail = root@localhost/destemail = $dstml/" $f2bl
    sed -i "s/^sender = root@<fq-hostname>/sender = $sndr/" $f2bl
    sed -i "s/^action = %(action_)s/action = $actn/" $f2bl
    sed -i "s/^port    = ssh/port    = $sshp/" $f2bl

    # Starting the daemon
    systemctl start fail2ban;
    
    echo "+ $(date +%H:%M:%S) - fail2ban - configured now." >> $il
else
    echo "- $(date +%H:%M:%S) - The fail2ban is not installed. Aborting it's configuration." >> $il
fi



# OPTIONAL - Installation of the clamav

# Verify if the EPEL repository is already installed in the OS
yum list installed oracle-epel-release-el8 > /dev/null 2>&1

if [ $? == 0 ]; then
    # yum -y install clamav clamd clamav-update
    yum -y install clamd clamav-data clamav-update clamav-filesystem clamav clamav-devel clamav-lib
    echo "+ $(date +%H:%M:%S) - clamav clamd clamav-update - installed now." >> $il

    # Adjust ClamAv with SELinux and give it access to all your files with the following command
    setsebool -P antivirus_can_scan_system 1
else
    echo "- $(date +%H:%M:%S) - The EPEL repository is not installed yet. Aborting the clamav installation." >> $il
fi


# OPTIONAL - Configuration of the clamav
# source: https://www.golinuxcloud.com/steps-install-configure-clamav-antivirus-centos-linux/#Conclusion

yum list installed clamav > /dev/null 2>&1

if [ $? == 0 ]; then
    # get the latest signatures in quiet mode
    freshclam --quiet;
    echo "+ $(date +%H:%M:%S) - clamav: freshclam latest signatures - done." >> $il

    # Configure auto-update of freshclam database
    
    # Create the freshclam systemd timer unit file
    echo "[Unit]
Description=ClamAV virus database updater
After=network-online.target

[Timer]
OnCalendar=daily
Persistent=true

[Install]
WantedBy=timers.target" > /etc/systemd/system/clamav-freshclam.timer

    # creating the clamav system unit with the "ExecStart=/usr/bin/freshclam" run without the " -d --foreground=true" option. Apparently that 
    echo "[Unit]
Description=ClamAV virus database updater
Documentation=man:freshclam(1) man:freshclam.conf(5) https://www.clamav.net/documents
# If user wants it run from cron, don't start the daemon.
ConditionPathExists=!/etc/cron.d/clamav-freshclam
Wants=network-online.target
After=network-online.target

[Service]
ExecStart=/usr/bin/freshclam
StandardOutput=syslog

[Install]
WantedBy=multi-user.target" > /etc/systemd/system/clamav-freshclam.service

    # Enable and start the clamav-freshclam.timer. We don't need to start and enable the service as timer will take care of that.

    systemctl enable clamav-freshclam.timer --now
    echo "+ $(date +%H:%M:%S) - clamav: freshclam timer - enabled and started." >> $il

    # Verify
    # systemctl status clamav-freshclam.timer

    # Verify the timer schedule
    # systemctl list-timers

    # Backing up the configuration file
    cp /etc/clamd.d/scan.conf /etc/clamd.d/scan.conf.orig

    # Changing clamav user to root
    sed -i "s/^User clamscan/User root/" /etc/clamd.d/scan.conf

    # Enable LocalSocket
    sed -i 's/#LocalSocket \/run/LocalSocket \/run/g' /etc/clamd.d/scan.conf
    sed -i -re 's/^(\#)FixStaleSocket yes/FixStaleSocket yes/g' /etc/clamd.d/scan.conf

   
    # Configure and start clamd.service
    
    # copy this file to /etc/systemd/system/clamd.service. I hope you are familiar with the different systemd service file locations so you can understand why I preferred this location instead of /usr/lib/systemd/system
    cp -ap /usr/lib/systemd/system/clamd@.service /etc/systemd/system/clamd.service

    # replace %i with scan.conf from both the Description and ExecStart options in
    sed -i 's/scanner (%i) daemon/scanner (scan.conf) daemon/g' /etc/systemd/system/clamd.service
    sed -i 's/\/etc\/clamd.d\/%i.conf/\/etc\/clamd.d\/scan.conf/g' /etc/systemd/system/clamd.service

    # Enable and start the clamd service
    systemctl enable clamd.service --now
    echo "+ $(date +%H:%M:%S) - clamav: clamd.service - enabled and started." >> $il

    # Verify
    # systemctl status clamd.service

    
    # Scanning the whole system and placing all the infected files in a list
    # clamscan --recursive --no-summary --infected / 2>/dev/null | grep FOUND >> /root/clamav-first-full-scan.log;

    
    # OPTIONAL - Configure periodic scan using clamdscan on a specfic directory

    # Variables
    dir1="/home";
    cld="18:40:00";

    # create a new systemd service unit file
    echo "[Unit]
Description=ClamAV virus scan
Requires=clamd.service
After=clamd.service

[Service]
ExecStart=/usr/bin/clamdscan $dir1
StandardOutput=syslog

[Instal]
WantedBy=multi-user.target" > /etc/systemd/system/clamdscan-dir1.service

    # mapping timer unit file. Here I have added time value of 18:40 to start the scan:

    echo "[Unit]
Description=Scan $dir1 directory using ClamAV

[Timer]
OnCalendar=$cld
Persistent=true

[Install]
WantedBy=timers.target" > /etc/systemd/system/clamdscan-dir1.timer

    # enable and start the timer
    systemctl enable clamdscan-dir1.timer --now
    echo "+ $(date +%H:%M:%S) - clamav: periodic scan at $cld of the $dir1 - enabled and started." >> $il

    # Verify
    # systemctl status clamdscan-dir1.timer

    # Verify the timer schedule
    # systemctl list-timers


    # OPTIONAL - Enable On-Access mode
    # source: https://www.adminbyaccident.com/security/how-to-install-the-clamav-antivirus-on-centos-8/

    # stop the clamav service
    systemctl stop clamd.service

    # enable the on-access module.
    sed -i 's/#OnAccessPrevention yes/OnAccessPrevention yes/g' /etc/clamd.d/scan.conf

    # Set the scanning of the "/home" directory
    sed -i 's/#OnAccessIncludePath \/home/OnAccessIncludePath \/home/g' /etc/clamd.d/scan.conf

    # exclude the clamav user to be scanned and looked after so it’s not blocked. In our case it is the root user
    sed -i 's/#OnAccessExcludeUname clamav/OnAccessExcludeUname root/g' /etc/clamd.d/scan.conf

    # add a systemd entry so it starts up automatically after reboots.
    cp /usr/lib/systemd/system/clamonacc.service /etc/systemd/system/clamonacc.service

    # After this block has been placed the log file and the quarantine directory must be created.
    touch /var/log/clamonacc
    mkdir /tmp/clamav-quarantine

    # Before enabling this recently created entry on systemd let’s reload the tool.
    systemctl daemon-reload

    systemctl enable clamonacc.service

    # Because clamonacc depends on clamd and I stopped it before making these changes I need to start it up again.
    systemctl start clamd.service

    # Verify
    # systemctl status clamd.service

    # Time to start the clamonacc.service service.
    systemctl start clamonacc.service

    # Verify
    # systemctl status clamonacc.service

    echo "+ $(date +%H:%M:%S) - clamav: On-Access mode - enabled and started." >> $il

else
    echo "- $(date +%H:%M:%S) - The clamav packages are not installed. Aborting it's configuration." >> $il
fi



# OPTIONAL - Installation of the rkhunter

# Verify if the EPEL repository is already installed in the OS
yum list installed oracle-epel-release-el8 > /dev/null 2>&1

if [ $? == 0 ]; then
    yum -y install rkhunter
    echo "+ $(date +%H:%M:%S) - rkhunter - installed now." >> $il
else
    echo "- $(date +%H:%M:%S) - The EPEL repository is not installed yet. Aborting the rkhunter installation." >> $il
fi


# OPTIONAL - Configuration of the rkhunter
# source: https://www.digitalocean.com/community/tutorials/how-to-use-rkhunter-to-guard-against-rootkits-on-an-ubuntu-vps

yum list installed rkhunter > /dev/null 2>&1

if [ $? == 0 ]; then
    
    rkl="/root/rkhunter-first-scan.log";

    # Update Rootkit Signatures
    rkhunter --update --quiet --report-warnings-only > $rkl
    echo "+ $(date +%H:%M:%S) - rkhunter - updated signatures now. Logs are here: $rkl." >> $il

    # With our database files refreshed, we can set our baseline file properties so that rkhunter can alert us if any of the essential configuration files it tracks are altered. We need to tell rkhunter to check the current values and store them as known-good values:
    rkhunter --propupd --quiet
    
    # Rootkit Malware Scan with Rkhunter
    rkhunter -c --quiet --report-warnings-only >> $rkl
    echo "+ $(date +%H:%M:%S) - rkhunter - scanned the system now. Logs are here: $rkl." >> $il
    # all the rkhunter logs are here /var/log/rkhunter/rkhunter.log
    # Ignore the following first warnings:
    # Warning: Unable to check for passwd file differences: no copy of the passwd file exists.
    # Warning: Unable to check for group file differences: no copy of the group file exists

    # Backup the configuration file
    cp /etc/rkhunter.conf /etc/rkhunter.conf.orig
    
    # Set Up Mail Notifications
    echo "MAIL-ON-WARNING=$dstml" >> /etc/rkhunter.conf
    sed -i -re 's/^(\#)MAIL_CMD=mail/MAIL_CMD=mail/' /etc/rkhunter.conf

    # Allow Root SSH Login - Enable in case it is commented in the file
    # If you need root login over SSH, you should change this parameter to “yes” so that rkhunter can check this and will mark this setting as valid:
    # sed -i -re 's/^(\#)ALLOW_SSH_ROOT_USER=no/ALLOW_SSH_ROOT_USER=yes/' /etc/rkhunter.conf

    # Set Up a Cron Job to Automate Checks
    # The –cronjob option tells rkhunter to not output in a colored format and to not require interactive key presses. The update option ensures that our definitions are up-to-date. The quiet option suppresses all output
    crontab -l > /dev/null 2>&1 > mycron
    echo "15 04 * * * /usr/bin/rkhunter --cronjob --update --quiet" >> mycron
    crontab mycron
    rm -f mycron


    # It is also helpful to remember that when you make software changes on your computer, rkhunter may report differences in its next run. It is recommended that after you make changes, at least run sudo rkhunter --propupd to update rkhunter to the new file properties.
else
    echo "- $(date +%H:%M:%S) - The rkhunter is not installed. Aborting it's configuration." >> $il
fi



# OPTIONAL - Allowance of only one TTY
# For security reasons
# Source: https://www.golinuxcloud.com/disable-tty-enable-tty-virtual-console-linux/

# # Verify the logind.conf file existence
ls /etc/systemd/logind.conf > /dev/null 2>&1

if [ $? == 0 ]; then
    # Backup the configuration file
    cp /etc/systemd/logind.conf /etc/systemd/logind.conf.orig
    
    sed -i -re "s/^(\#)NAutoVTs=6/NAutoVTs=0/" /etc/systemd/logind.conf
    sed -i -re "s/^(\#)ReserveVT=6/ReserveVT=N/" /etc/systemd/logind.conf
    echo "+ $(date +%H:%M:%S) - Allow single TTY - configured now." >> $il
    # reboot the instance for the changes to take effect
else
    echo "- $(date +%H:%M:%S) - /etc/systemd/logind.conf file is not present. Aborting it's configuration." >> $il
fi



# OPTIONAL - Installation of the Google Authenticator (with PAM) module
# source: https://www.digitalocean.com/community/tutorials/how-to-set-up-multi-factor-authentication-for-ssh-on-centos-8

# Verify if the EPEL repository is already installed in the OS
yum list installed oracle-epel-release-el8 > /dev/null 2>&1

if [ $? == 0 ]; then
    yum -y install google-authenticator qrencode-libs
    echo "+ $(date +%H:%M:%S) - google-authenticator - installed now." >> $il
else
    echo "- $(date +%H:%M:%S) - The EPEL repository is not installed yet. Aborting the google-authenticator installation." >> $il
fi


# OPTIONAL - Configuration of the Google Authenticator (with PAM) module

# Verify if google-authenticator package is installed
yum list installed google-authenticator > /dev/null 2>&1

if [ $? == 0 ]; then

    # Configure offline two factor authentication in Linux

    # Normally, all you need to do is run the google-authenticator command with no arguments, but SELinux doesn’t allow the ssh daemon to write to files outside of the .ssh directory in your home folder. This prevents authentication.
    google-authenticator -t -d -f -r 3 -R 30 -w 3 -C -q -s /home/$usr/.ssh/google-authenticator
    chown $usr:$usr /home/$usr/.ssh/google-authenticator

    # Backup the google-authenticator file to a trusted location.
    cp /home/$usr/.ssh/google-authenticator /home/$usr
    chown $usr:$usr /home/$usr/google-authenticator

    # Since we stored the config file in a non-standard location, we need to restore the SELinux context based on its new location.
    restorecon -Rv /home/$usr/.ssh/

    # Configuring OpenSSH to Use MFA/2FA
    # backing up the working file
    cp /etc/pam.d/sshd /etc/pam.d/sshd.orig

    # Add the following lines to the end of the file:
    echo "auth       required     pam_google_authenticator.so secret=/home/$usr/.ssh/google-authenticator nullok
auth       required     pam_permit.so" >> /etc/pam.d/sshd
    # for any other user: /home/${USER}/.ssh/google-authenticator nullok
    # nullok - tells the PAM that this authentication method is optional. This allows users without a OATH-TOTP token to still log in just using their SSH key.

    # Configure /etc/ssh/sshd_config
    sed -i -re "s/^ChallengeResponseAuthentication no/ChallengeResponseAuthentication yes/" /etc/ssh/sshd_config

    # Restart the sshd service  the changes
    # systemctl restart sshd.service


    # Making SSH Aware of MFA
    # This line tells SSH we need a SSH key and either a password or a verification code (or all three):
    echo "AuthenticationMethods publickey,password publickey,keyboard-interactive" >> /etc/ssh/sshd_config

    # Comment the following line. This tells PAM not to prompt for a password:
    sed -i -re "s/^auth       substack     password-auth/#auth       substack     password-auth/" /etc/pam.d/sshd

    # Restart the sshd service to activate the changes
    systemctl restart sshd.service

    echo "+ $(date +%H:%M:%S) - google-authenticator - configured now." >> $il
    
    # Outputing google-authneticator's credentials
    echo "+ $(date +%H:%M:%S) - google-authenticator credentials:" >> $il
    cat /home/$usr/.ssh/google-authenticator >> $il
    echo "+ $(date +%H:%M:%S) - Open Microsoft or Google authenticator on the mobile device, add a new item by manually typing the above Secret Key (the first and the longest one)." >> $il

else
    echo "- $(date +%H:%M:%S) - The google-authenticator is not installed. Aborting it's configuration." >> $il
fi



# # reboot the instance for the changes to take effect
# echo "+ $(date +%H:%M:%S) - Rebooting." >> $il
# reboot
echo "Do not forget to:" >> $il
echo "- Create a password for the user $usr" >> $il
echo "- Reboot the system in order for several changes to be applied!" >> $il



# Stop counting the time since the execution of this script
end=`date +%s`

# The actual equation
runtime=$(echo "scale=2;($end - $start)/60" | bc -l )

# Echoing the time into the installation.log file
echo -e "\nThe script was executed in $runtime minutes"|sed 's/\./,/1' >> $il



# ----
# THE END OF THE SCRIPT



# TO DO
# Verify systemctl status clamonacc.service for several days