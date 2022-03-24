#!/bin/bash

# Start counting the time since the execution of this script
start=`date +%s`

# ATTENTION: run the script as root

# RHEL 8 - INITIAL SERVER CONFIGURATION

# +------------------+----------------+--------------------------------------+
# | IMPLEMENTED BY   | DATE           | VERSION                              |
# +------------------+----------------+--------------------------------------+
# | Profor Ivan      | 2021-01-10     | Initial version for CentOS 7         |
# | Profor Ivan      | 2022-01-02     | 2nd version for Oracle Linux 8       |
# | Profor Ivan      | 2022-01-14     | 3rd version for Oracle Linux 8       |
# | Profor Ivan      | 2022-01-18     | 4th version for Oracle Linux 8       |
# | Profor Ivan      | 2022-01-20     | 5th version for Oracle Linux 8       |
# | Profor Ivan      | 2022-01-22     | 6th version for Oracle Linux 8       |
# | Profor Ivan      | 2022-01-24     | 7th version for Oracle Linux 8       |
# | Profor Ivan      | 2022-01-26     | 8th version for Oracle Linux 8       |
# | Profor Ivan      | 2022-02-13     | 9th version for CentOS 8 Lightsail   |
# | Profor Ivan      | 2022-02-19     | 10th version for CentOS 8 Lightsail  |
# | Profor Ivan      | 2022-03-12     | 11th version for CentOS 8 Lightsail  |
# | Profor Ivan      | 2022-03-22     | 12th version for RHEL 8 AWS EC2      |
# | Profor Ivan      | 2022-03-23     | 13rd version for RHEL 8 AWS EC2 app1 |
# +------------------+----------------+--------------------------------------+


# SYNOPSIS
# ----
# - Configure history command to show the dates
# - Removal of the subscription-manager and its dependencies
# - Auditctl configuration
# - Change of timezone
# - Update/upgrade the system
# - Configuration of SELinux
# - Disable of IPv6 interface
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
    # - NOT OPTIONAL: Insertion of the public SSH key
# - Allowance of only one TTY
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
pk="INSERT THE SSH PUBLIC PAIR HERE";

# The default CentOS user on AWS Lightsail is "centos"
awsusr="ec2-user";

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



# Removal of the subscription-manager and its dependencies
yum -y remove subscription-manager



# Auditctl configuration

# verify if the packages are installed (audit audit-libs)
yum list installed audit* > /dev/null 2>&1

if [ $? == 0 ]; then
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
    auditctl -w /etc/sysconfig/iptables -p w -k unusual_iptables
    # Make them permanent:
    auditctl -l >> /etc/audit/rules.d/audit.rules
    echo "+ $(date +%H:%M:%S) - Auditctl - configured now." >> $il
else 
    echo "- $(date +%H:%M:%S) - Audit rules were not applied porbably because audit packages were not prior installed." >> $il
fi



# Miscellaneous
# Changing the hostname
# Variables
hstnm="INSERT THE HOSTNAME HERE";

hostnamectl set-hostname $hstnm
echo "+ $(date +%H:%M:%S) - The hostname was set to $hstnm" >> $il



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
yum -y update && yum -y upgrade && yum -y check-update && yum -y clean all && yum -y autoremove;



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
    # # SSH port
    # sshp=INSERT THE PORT HERE
    # LoginGraceTime
    sshlgt=1440m
    # MaxStartups
    mxst="5:50:10"
    # MaxSessions
    mxse="4"


    # backing up the configuration file
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.orig


    # # Changing default SSH port to $sshp
    # sed -i -re 's/^(\#)(Port)([[:space:]]+)22/\2 '$sshp'/' /etc/ssh/sshd_config
    # echo "+ $(date +%H:%M:%S) - Default SSH port was changed to $sshp now." >> $il;
    
    # # On a SELinux system, you have to tell SELinux about port change.
    # semanage port -a -t ssh_port_t -p tcp $sshp


    # # Disabling SSH root log in
    sed -i -re "s/^PermitRootLogin yes/PermitRootLogin no/" /etc/ssh/sshd_config
    echo "+ $(date +%H:%M:%S) - SSH root log in - disabled now." >> $il;


    # Verify the authorized_keys file existence. The existence of the file is true only if the creation of the server was chosen with the insertion of a specific SSH key (in Lightsail web ui or cli)
    ls /root/.ssh/authorized_keys > /dev/null 2>&1

    if [ $? == 0 ]; then
        # deleting the already inserted key by the Lightsail
        echo > /root/.ssh/authorized_keys
        echo "+ $(date +%H:%M:%S) - Deleting the already inserted root SSH key by the Lightsail." >> $il;
    else
        echo "- $(date +%H:%M:%S) - There is no /root/.ssh/authorized_keys file. The deletion of the SSH public key from the root folder is aborted." >> $il
    fi


    # ALREADY DISABLED - if the ssh key was used when creating the instance
    # Disabling SSH password authentication
    # sed -i -re "s/^PasswordAuthentication yes/PasswordAuthentication no/" /etc/ssh/sshd_config
    # echo "+ $(date +%H:%M:%S) - SSH password authentication - disabled now." >> $il;


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
rpm -qa| grep epel > /dev/null 2>&1

if [ $? == 1 ]; then
    yum -y install https://dl.fedoraproject.org/pub/epel/epel-release-latest-8.noarch.rpm;
    yum -y update && yum -y upgrade && yum -y check-update;
    echo "+ $(date +%H:%M:%S) - EPEL repository - installed now." >> $il;
else
    echo "+ $(date +%H:%M:%S) - The EPEL repository is already installed." >> $il
fi


# Update/upgrade the system
echo "+ $(date +%H:%M:%S) - Updating and upgrading the system ..." >> $il
yum -y update && yum -y upgrade && yum -y check-update && yum -y clean all && yum -y autoremove;



# OPTIONAL - Installation of additional packages from EPEL

# Verify if the EPEL repository is already installed in the OS
rpm -qa| grep epel > /dev/null 2>&1

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



# OPTIONAL - Allowance of only one TTY
# For security reasons
# Source: https://www.golinuxcloud.com/disable-tty-enable-tty-virtual-console-linux/

# # Verify the logind.conf file existence
ls /etc/systemd/logind.conf > /dev/null 2>&1

if [ $? == 0 ]; then
    # Backup the configuration file
    cp /etc/systemd/logind.conf /etc/systemd/logind.conf.orig
    
    # sed -i -re "s/^(\#)NAutoVTs=6/NAutoVTs=0/" /etc/systemd/logind.conf
    sed -i -re "s/^(\#)ReserveVT=6/ReserveVT=N/" /etc/systemd/logind.conf
    echo "+ $(date +%H:%M:%S) - Allow single TTY - configured now." >> $il
    # reboot the instance for the changes to take effect
else
    echo "- $(date +%H:%M:%S) - /etc/systemd/logind.conf file is not present. Aborting it's configuration." >> $il
fi



# Delete the default Lightsail user 'centos'
# -r with the homoe folder, -f force even if logged 
userdel -rf $awsusr



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