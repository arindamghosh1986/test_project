#!/bin/bash
# --------------------------------------------------------------
# Create Build Environment for NetTest and NetEPC in CentOS 7.6
# --------------------------------------------------------------

# sudoers permission is required for yum commands
if [ -z $SUDO_UID ]; then
    tput setaf 1; echo "Run the script using sudo."; tput sgr0
    exit 1
fi

SCRIPT=$(readlink -f "$0")
ROOT_DIR=$(dirname $(dirname "$SCRIPT"))
NMS_PATH=$ROOT_DIR/NMS
CONSOLE_PATH=$NMS_PATH/WebConsole/
LICENSE_SERVER_PATH=$ROOT_DIR/Licensing/LicenseServer
RPM_PATH=$ROOT_DIR/ThirdParty/rpms
NETEPC_PACKAGING_PATH=$ROOT_DIR/Packaging/netepc
CGIROOT="/var/www"
WEBROOT="/var/www/html"
TEMP=$ROOT_DIR/tmp
repo="repo-lte.polarisnetworks.net"

/bin/cat /proc/version | grep  -i -e "red hat" -e centos >/dev/null
if [ $? -ne 0 ]; then
    tput setaf 1; echo "Only Red Hat Enterprise Linux (RHEL) and CentOS systems are supported."; tput sgr0
    exit
fi

# Check if connected to Internet or not
if ping -q -c 1 -W 1 google.com >/dev/null; then
   echo "Internet is connected"
else
   echo "Internet is disconnected"
   exit
fi

# Check availability of Polaris YUM Repository (192.168.0.16)
ping -q -c 2 -W 1 $repo > /dev/null
if [ $? -ne 0 ]; then
    tput setaf 1; echo "Polaris 4G package repository is not reachable @$repo. Please ensure the connectivity to proceed"; tput sgr0
    exit 1
fi

# Check Architecture
architecture=$(uname -m)
echo -e '\E[32m'"System Architecture :" $tecreset $architecture

declare -a fun_list=( 
                        "DisableUnwantedServices"       \
                        "InstallKernelPackages"         \
                        "InstallCentOSPkgs"             \
                        "InstallPkgsFromPolarisRepo"    \
                        "InstallAndAddVlcUser"          \
                        "InstallTclCompiler"            \
                        "CreateSoftLinks"               \
                        "ConfigureTimeZone"             \
                        "ConfigureHttps"                \
                        "SetCronTabParameters"          \
                        "InstallRpcapd"                 \
                        "ConfigureSudoersFile"          \
                        "IPConfiguration"               \
                        "StopSnmp"                      \
                        "ConfigureVim"                  \
                        "ConfigureLogRotate"            \
                        "ConfigureNetCli"               \
                        "ConfigureHippe"                \
                        "ConfigureLicense"              \
                        "ConfigureEPCServices"          \
                        "CreateDirForSPRReplication"    \
                        "InstallAndConfigureKamailio"   \
)
declare -a vim_properties=( "set expandtab"     \
                            "set tabstop=4"     \
                            "set shiftwidth=4"  \
                            "retab"             \
                            "set autoindent"    \
                            "syntax enable"     )
							

trap "exit" INT

DisableUnwantedServices()
{
    #Turn off selinux
    sed -i -e "/^SELINUX=/c \SELINUX=disabled" /etc/selinux/config  # turn off permanently but will be read from next system bootup
    /usr/sbin/setenforce 0 > /dev/null 2>&1                         # turn off for current session
    
    #Turn off firewall
	systemctl stop firewalld.service
    systemctl disable firewalld.service    
	
    # Automatically identifying network resources such as printers or web servers not required
    systemctl disable avahi-daemon.service
}

InstallKernelPackages()
{
    KERNEL_VERSION_FULL=`cut -f 3 -d ' ' /proc/version | cut -f 1 -d '-'`
    KERNEL_VERSION_MAJOR=`echo $KERNEL_VERSION_FULL | cut -f 1 -d '.'`
    KERNEL_VERSION_MINOR=`echo $KERNEL_VERSION_FULL | cut -f 2 -d '.'`
    KERNEL_VERSION_PATCH=`echo $KERNEL_VERSION_FULL | cut -f 3 -d '.'`

    if [ $KERNEL_VERSION_MAJOR != "4" ] && [ $KERNEL_VERSION_MINOR != "4" ] && [ $KERNEL_VERSION_PATCH != "179" ]; then
        OSRel=$(cat /etc/redhat-release)
        tput setaf 1; echo "Your system's OS version is $OSRel"; tput sgr0
        tput setaf 1; echo "Your system's kernel version is $KERNEL_VERSION_FULL."; tput sgr0
        tput setaf 1; echo "Your kernel needs to be upgraded to 4.4.179 to build NetEPC SGW/PGW user plane modules"; tput sgr0
        #return
    fi

    tput setaf 4; echo "Updating CentOS Kernel related packages for NetEPC..."; tput sgr0
    if [ -z "`rpm -qa | grep kernel-lt-devel-4.4.179-1.el7.elrepo.x86_64`" ]; then
        rpm -ivh --nodeps --force $RPM_PATH/kernel-lt-devel-4.4.179-1.el7.elrepo.x86_64.rpm
    else
        echo "Package kernel-lt-devel-4.4.179-1.el7.elrepo.x86_64 is already installed"
    fi

    if [ -z "`rpm -qa | grep kernel-lt-headers-4.4.179-1.el7.elrepo.x86_64`" ]; then
        rpm -ivh --nodeps --force $RPM_PATH/kernel-lt-headers-4.4.179-1.el7.elrepo.x86_64.rpm
    else
        echo "Package kernel-lt-headers-4.4.179-1.el7.elrepo.x86_64 is already installed"
    fi

    if [ -z "`rpm -qa | grep kernel-lt-tools-4.4.179-1.el7.elrepo.x86_64`" ]; then
        rpm -ivh --nodeps --force $RPM_PATH/kernel-lt-tools-4.4.179-1.el7.elrepo.x86_64.rpm
    else
        echo "Package kernel-lt-tools-4.4.179-1.el7.elrepo.x86_64 is already installed"
    fi

    if [ -z "`rpm -qa | grep kernel-lt-tools-libs-4.4.179-1.el7.elrepo.x86_64`" ]; then
        rpm -ivh --nodeps --force $RPM_PATH/kernel-lt-tools-libs-4.4.179-1.el7.elrepo.x86_64.rpm
    else
        echo "Package kernel-lt-tools-libs-4.4.179-1.el7.elrepo.x86_64 is already installed"
    fi
}

InstallCentOSPkgs()
{
    appInstallCmd="/usr/bin/yum -y install"
    appRemoveCmd="/usr/bin/yum -y remove"
    appDowngradeCmd="/usr/bin/yum -y downgrade"
    rpmUpdateCmd="rpm -Uvh"

    declare -a third_party_packages=("epel-release" "jemalloc" "jemalloc-devel" "httpd" "mod_ssl" "dhcp" "apr" "apr-util" "lsof" \
                                     "php" "php-pdo" "php-xml" "php-common" "php-pgsql" "php-soap" "php-mcrypt" "php-ldap" \
                                     "xmlsec1-devel" "xmlsec1-openssl-devel" "openssl-devel" "libxslt-devel" "net-snmp-devel" \
                                     "net-snmp-libs" "net-snmp" "net-snmp-utils" "glib2-devel" "iptables-devel" "lksctp-tools-devel" \
                                     "lksctp-tools" "libxml2-devel" "gcc-c++" "rpm-build" "libnetfilter_queue-devel" \
                                     "libnetfilter_queue" "libnfnetlink-devel" "libnfnetlink" "dmidecode" "ethtool" "flex" \
                                     "flex-devel" "bison" "patch" "ctags" "ntp" "ncftp" "xmltoman" "nmap-ncat" "numactl" "numactl-devel" \
                                     "c-ares" "glibc.i686" "libtar" "libtar-devel" "libssh" "libssh-devel" "sshpass" "nodejs" "npm" \
                                     "libcurl-devel" "createrepo" "expat" "expat-devel" "dos2unix" "tclx" "strongswan" "wget" "libreoffice" \
                                     "texlive" "texlive-supertabular" "texlive-lastpage")

    #Update OpenSSL to latest and greatest
    tput setaf 4; echo "Updating OpenSSL ..."; tput sgr0
    /usr/bin/yum update -y openssl

    #Installing necessary packages
    for pkg in "${third_party_packages[@]}" ; do
        if yum list installed "$pkg" >/dev/null 2>&1; then
            tput setaf 4; echo "$pkg is already installed"; tput sgr0
        else
            tput setaf 5; echo "Installing $pkg ..."; tput sgr0
            $appInstallCmd $pkg >> /dev/null
        fi
    done

    echo "Installing jemalloc packages."
    if [ -z "`rpm -qa | grep jemalloc-3.6.0-1.el7.x86_64`" ]; then
        rpm -ivh --force $RPM_PATH/jemalloc-3.6.0-1.el7.x86_64.rpm
    else
        echo "Package jemalloc-3.6.0-1.el7.x86_64 is already installed"
    fi

    if [ -z "`rpm -qa | grep jemalloc-devel-3.6.0-1.el7.x86_64`" ]; then
        rpm -ivh --force $RPM_PATH/jemalloc-devel-3.6.0-1.el7.x86_64.rpm
    else
        echo "Package jemalloc-devel-3.6.0-1.el7.x86_64 is already installed"
    fi

    echo "Installing ncftp package."
    if [ -z "`rpm -qa | grep ncftp-3.2.5-7.el7.x86_64`" ]; then
        rpm -ivh --force $RPM_PATH/ncftp-3.2.5-7.el7.x86_64.rpm
    else
        echo "Package ncftp-3.2.5-7.el7.x86_64 is already installed"
    fi

    #Remove All tcl8.6 packages
    if [ -z "`rpm -qa | grep tcl-8.5.13-8.el7.x86_64`" ]; then
        while [ "`rpm -qa | grep tcl-devel`" ] ; do
            $appRemoveCmd tcl-devel
        done
        while [ "`rpm -qa | grep sqlite-tcl`" ] ; do
            $appRemoveCmd sqlite-tcl
        done
        while [ "`rpm -qa | grep tk-8.`" ] ; do
            $appRemoveCmd tk
        done
        $appRemoveCmd tcl
    fi

    if [ -z "`rpm -qa | grep sqlite-3.7.17-8.el7.x86_64`" ]; then
        while [ "`rpm -qa | grep sqlite-devel`" ] ; do
            $appRemoveCmd sqlite-devel
        done
        while [ "`rpm -qa | grep sqlite-tcl`" ] ; do
            $appRemoveCmd sqlite-tcl
        done
    fi

    if [ -z "`rpm -qa | grep wireshark-3.3.0_rpcap-1.x86_64`" ]; then
        while [ "`rpm -qa | grep wireshark-gnome`" ] ; do
            $appRemoveCmd wireshark-gnome
        done
        $appRemoveCmd wireshark
    fi

    if [ -z "`rpm -qa | grep libpcap-1.9.1-rpcap.el7.x86_64`" ]; then
        $appRemoveCmd libpcap-devel
    fi

    # Install packages from local third-party rpm
    PACKAGES='tcl-8.5.13-8.el7.x86_64 tk-8.5.13-6.el7.x86_64 tcl-devel-8.5.13-8.el7.x86_64 sqlite-3.7.17-8.el7.x86_64 sqlite-devel-3.7.17-8.el7.x86_64 sqlite-tcl-3.7.17-8.el7.x86_64'

    for package in $PACKAGES; do
        if [ -z "`rpm -qa | grep $package`" ]; then
            if [ $package == "sqlite-3.7.17-8.el7.x86_64" ]; then
                $rpmUpdateCmd $RPM_PATH/$package.rpm --oldpackage
            else
                $rpmUpdateCmd $RPM_PATH/$package.rpm
            fi
        else
            echo "$package is already installed"
        fi
    done

    tput setaf 4; echo "Installing uglifyjs ..."; tput sgr0
    npm install uglify-js -g
}
# Installs the third-party RPMS from Polaris YUM Repo
InstallPkgsFromPolarisRepo()
{
  repo_url="http://$repo/CentOSPkgs"
  tput setaf 4; echo "Installing/updating packages from $repo ..."; tput sgr0

  # Install third-party packages from Polaris Repo
  PACKAGES='asn1c-libs-0.9.28-1.x86_64 asn1c-headers-0.9.28-1.x86_64 libsmi-0.4.8-13.el7.x86_64 libpcap-1.9.1-rpcap.el7.x86_64 libpcap-devel-1.9.1-rpcap.el7.x86_64 wireshark-3.3.0_rpcap-1.x86_64 wireshark-qt-3.3.0_rpcap-1.x86_64 libwbxml-0.11.2-3.el7.centos.x86_64 libwbxml-devel-0.11.2-3.el7.centos.x86_64 nux-dextop-release-0-1.el7.nux.noarch'

  for package in $PACKAGES; do
    if [ -z "`rpm -qa | grep $package`" ]; then
        yum -y install "$repo_url/$package.rpm"
    else
        echo "$package is already installed"
    fi
  done

  #Add the current user to the wireshark group
  gpasswd -a `whoami` wireshark
  setcap 'CAP_NET_RAW+eip CAP_NET_ADMIN+eip' /usr/local/bin/dumpcap

}
InstallAndAddVlcUser()
{
    #Installing vlc
    /usr/bin/yum -y install vlc

    #create vlc user for MBMSGW
    user_vlc=$(getent passwd vlc)
    if [ ! "$user_vlc" ]
    then
       useradd vlc
    fi
}
InstallTclCompiler()
{
    #Check if tclcompiler is not installed, then install it
    TCLDEVKIT_TAR_FILE=TclDevKit5.2.0.291975-license.tar.gz
    TCLDEVKIT_SRC_DIR=TclDevKit5.2.0.291975-license
    TCLDEVKIT_LICENSE_FILE=Tcl-Dev-Kit-5-Linux-x86_64-SAA6AC96AAB5.executable
    TCLDEVKIT_DOWN_DIR="/tmp/TclDevKit/"

    which /opt/TclDevKit-5.2/bin/tclcompiler > /dev/null
    if [ $? -eq 1 ]; then
        tput setaf 5; echo "Installing TclDevKit..."; tput sgr0
        mkdir -p $TCLDEVKIT_DOWN_DIR
        cd $TCLDEVKIT_DOWN_DIR
        wget "http://$repo/CentOSPkgs"/$TCLDEVKIT_TAR_FILE
        tar -zxf $TCLDEVKIT_TAR_FILE > /dev/null 2>&1

        #Modify install script and run it
        sed -i 's/install.tk/install.tcl/g' $TCLDEVKIT_SRC_DIR/install.sh
        printf '\nA' | $TCLDEVKIT_SRC_DIR/install.sh > /dev/null 2>&1

        #Install ActiveState license
        chmod +x $TCLDEVKIT_SRC_DIR/$TCLDEVKIT_LICENSE_FILE
        $TCLDEVKIT_SRC_DIR/$TCLDEVKIT_LICENSE_FILE

        cd -
        rm -rf $TCLDEVKIT_DOWN_DIR
    else
        tput setaf 4; echo "TcldevKit compiler is already installed"; tput sgr0
    fi
}
InstallCMSPackages()
{
    #Install pkgs for NetEPC on Cloud environment
    echo "Installing packages required for CMS."
    cloud_packages="python-pip python-devel python-six sshpass"

    /usr/bin/yum -y install $cloud_packages
    if [ $? -ne 0 ]; then
        echo "Installation of necessary packages for Cloud environment failed"
    fi
    pip install twisted==16.4.0 service_identity pyaml pycrypto requests==2.11.1 subprocess32
    pip install --upgrade --force pip
    pip install python-keystoneclient==3.8.0 python-neutronclient==6.0.0 python-glanceclient==2.5.0 python-novaclient==6.0.0 python-ceilometerclient==2.7.0 python-heatclient==1.7.0
}
CreateSoftLinks()
{
    #Make softlink to /usr/include/opnessl for openssl 1.0.2
    if [ ! -d $TEMP ]; then
        tput setaf 5; echo "Directory $TEMP doesn't exist. Creating directory ..."; tput sgr0
        mkdir -p $TEMP
    fi
    unlink $TEMP/openssl > /dev/null 2>&1 
    ln -s /usr/include/openssl $TEMP/openssl
    tput setaf 5; echo "Creating softlink '../tmp/openssl-> /usr/include/openssl'"; tput sgr0
    chown polaris:polaris -R $TEMP

    #Check if tclsh is not installed, then make softlink to tclsh8.5
    if [ `which tclsh | grep tclsh` ]; then
        echo "Removing tclsh softlink..."
        tclshpath="$(which tclsh)"
        rm $tclshpath
    fi
    if [ `which tclsh8.5 | grep tclsh8.5` ]; then
        echo "Creating tclsh softlink to tclsh8.5..."
        ln -s tclsh8.5 /usr/bin/tclsh
    else
        echo "tclsh8.5 not installled..."
    fi
    if [ `which wish | grep wish` ]; then
        echo "Removing wish softlink..."
        wishpath="$(which wish)"
        rm $wishpath
    fi
    if [ `which wish8.5 | grep wish8.5` ]; then
        echo "Creating wish softlink to wish8.5..."
        ln -s wish8.5 /usr/bin/wish
    else
        echo "wish8.5 not installled..."
    fi
    pushd `pwd` > /dev/null 2>&1
    cd $NMS_PATH > /dev/null 2>&1
	
    #Create soft links to cgi-bin and NMS
    if [ ! -d $CGIROOT ]; then
        tput setaf 5; echo "Directory $CGIROOT doesn't exist. Creating directory ..."; tput sgr0
        mkdir -p $CGIROOT
    fi
    
    if [ ! -d $WEBROOT ]; then
        tput setaf 5; echo "Directory $WEBROOT doesn't exist. Creating directory ..."; tput sgr0
        mkdir -p $WEBROOT
    fi 
    
    rm -rf $CGIROOT/cgi-bin
    ln -sf $NMS_PATH/cgi-bin $CGIROOT 
    rm -rf $WEBROOT/NMS
    ln -sf $CONSOLE_PATH $WEBROOT/NMS

    tput setaf 5; echo "Creating softlink for tclcompiler..'"; tput sgr0
    rm -f /usr/bin/tclcompiler
    ln -s /opt/TclDevKit-5.2/bin/tclcompiler /usr/bin/
}
ConfigureTimeZone()
{
    #update timezone in /etc/php.ini
    timezone=""
    
    # On systems such as CentOS, "/etc/localtime" is a symlink to the file with the timezone info
    # On systems such as Ubuntu, "/etc/localtime" contains the time zone identifier
    
    if [[ -L /etc/localtime ]]; then
        IFS=/ read -a timezonepath <<< `readlink -f /etc/localtime`
        zoneinfostart=0
    elif [[ -f /etc/localtime ]]; then
        IFS=/ read -a timezonepath < /etc/localtime
        zoneinfostart=1
    fi
    
    for i in ${timezonepath[@]}; do
        if [[ $zoneinfostart == 1 ]]; then
            timezone=$i
            zoneinfostart=2
        elif [[ $zoneinfostart == 2 ]]; then
            #Insert \ before / in $timezone so that it can be used as a sed expression
            timezone="$timezone\\/$i"
        elif [[ $i == "zoneinfo" ]]; then
            zoneinfostart=1
        fi
    done
    
    sudo sed -i "s/.*date.timezone[ \t]*=.*/date.timezone = $timezone/" /etc/php.ini
    
    grep -q "date.timezone =" /etc/php.ini
    if [ $? -ne 0 ]; then
        sudo sed -i "\$adate.timezone = $timezone" /etc/php.ini
    fi
}
ConfigureHttps()
{
    # Configuration related to HTTPS
    #copy and update CA Certificate
    sudo cp $ROOT_DIR/security/polaris-cacert.pem /etc/pki/ca-trust/source/anchors
    sudo update-ca-trust extract

    #Generating dyna-configs.php
    touch $CONSOLE_PATH/configs/dyna-configs.php
    priv_key="/etc/pki/tls/certs/ca-bundle.crt"
    touch $ROOT_DIR/security/soap-client-ssl-cert.conf
    echo $priv_key > $ROOT_DIR/security/soap-client-ssl-cert.conf
    echo "<?php" > $CONSOLE_PATH/configs/dyna-configs.php
    echo "      define ('PROTOCOL_SCHEME', \"https\");" >> $CONSOLE_PATH/configs/dyna-configs.php
    echo "      define ('PROTOCOL', \"https://\");" >> $CONSOLE_PATH/configs/dyna-configs.php
    echo "      define ('CAFILE', \"$priv_key\");" >> $CONSOLE_PATH/configs/dyna-configs.php
    echo "      define ('HARDWARE_TYPE', \"NULL\");" >> $CONSOLE_PATH/configs/dyna-configs.php
    echo "?>" >> $CONSOLE_PATH/configs/dyna-configs.php
    
    #Generating dyna-configs.php in cgi-bin for SPR Synchronization
    touch $NMS_PATH/cgi-bin/configs/dyna-configs.php
    priv_key="/etc/pki/tls/certs/ca-bundle.crt"
    echo "<?php" > $NMS_PATH/cgi-bin/configs/dyna-configs.php
    echo "      define ('PROTOCOL_SCHEME', \"https\");" >> $NMS_PATH/cgi-bin/configs/dyna-configs.php
    echo "      define ('PROTOCOL', \"https://\");" >> $NMS_PATH/cgi-bin/configs/dyna-configs.php
    echo "      define ('CAFILE', \"$priv_key\");" >> $NMS_PATH/cgi-bin/configs/dyna-configs.php
    echo "      define ('HARDWARE_TYPE', \"NULL\");" >> $NMS_PATH/cgi-bin/configs/dyna-configs.php
    echo "      putenv ('EPC_INSTALL_PATH=$CONSOLE_PATH../..');" >> $NMS_PATH/cgi-bin/configs/dyna-configs.php
    echo "?>" >> $NMS_PATH/cgi-bin/configs/dyna-configs.php
	
	#Setting 320M as default file upload size in php configuration
    postSize=`grep post_max_size /etc/php.ini | awk '{print $3}'`
    uploadSize=`grep upload_max_filesize /etc/php.ini | awk '{print $3}'` 
    if [ $postSize != "320M" ] || [ $uploadSize != "320M" ];then
        sed -i \
            -e "/upload_max_filesize\s*=/c \upload_max_filesize = 320M" \
            -e "/post_max_size\s*=/c \post_max_size = 320M" \
            /etc/php.ini

        echo "Restarting httpd..."
        /bin/systemctl restart httpd.service > /dev/null
    fi
	#Adding netepc.conf
    echo "SetEnv EPC_INSTALL_PATH $ROOT_DIR" > /etc/httpd/conf.d/netepc.conf
    echo "SetEnv NMS_INSTALL_PATH $ROOT_DIR" > /etc/httpd/conf.d/nms.conf
    echo "SetEnv EPC_PRODUCT_ID 'netepc'"  > /etc/httpd/conf.d/product-info.conf
    echo "SetEnv EPC_COMPANY_ID 'polaris'"  >> /etc/httpd/conf.d/product-info.conf
    echo "SetEnv EPC_PRODUCT_NAME 'NetEPC'" >> /etc/httpd/conf.d/product-info.conf
    echo "SetEnv EPC_COMPANY_NAME 'Polaris Networks'" >> /etc/httpd/conf.d/product-info.conf
    echo "SetEnv EPC_CONSOLE_NAME 'NetConsole'" >> /etc/httpd/conf.d/product-info.conf
    echo "SetEnv EPC_SUPPORT_URL 'www.polarisnetworks.net/lte-netepc.html'" >> /etc/httpd/conf.d/product-info.conf
    echo "SetEnv EPC_HEADER_COLOR 008FD3" >> /etc/httpd/conf.d/product-info.conf
    cp -f pagespeed.conf /etc/httpd/conf.d/
    cp -f polaris_logo.jpg WebConsole/images/polaris_logo.jpg
    cp -f polaris_favicon.ico WebConsole/favicon.ico
    
    # Configuration related to HTTPS
    systemctl unset-environment EPC_SSL_DISABLED
    cert_conf=$ROOT_DIR/security/soap-server-ssl-cert.conf
    touch $cert_conf
    cert=$ROOT_DIR/security/polaris-netepc.pem
    echo $cert > $cert_conf
    # Update ssl.conf for ssl certificate
    sslConfFile="/etc/httpd/conf.d/ssl.conf"
    matchString="SSLCertificateFile \/"
    relaceString="SSLCertificateFile $cert"
    sed -i -e "/$matchString/c \\$relaceString" $sslConfFile
    sed -i -e "/SSLCertificateKeyFile/c \#SSLCertificateKeyFile \/etc\/pki\/tls\/private\/localhost.key" $sslConfFile
	
    systemctl enable httpd.service
    systemctl restart httpd.service
    
    sh $CONSOLE_PATH/dbScript/update_db.sh $NMS_PATH >/dev/null 2>&1
}
SetCronTabParameters()
{
    #Setting /etc/crontab parameters for calling the FTP script
    sed -i '/MMEFTPUpload.sh/d' /etc/crontab
    echo '*/30 * * * * root export EPC_INSTALL_PATH='$ROOT_DIR'; '$ROOT_DIR'/EPC/MME/MMEFTPUpload.sh' >>/etc/crontab
    sed -i '/SGWFTPUpload.sh/d' /etc/crontab
    echo '*/30 * * * * root export EPC_INSTALL_PATH='$ROOT_DIR'; '$ROOT_DIR'/EPC/SGW/SGWFTPUpload.sh' >>/etc/crontab
    sed -i '/PGWFTPUpload.sh/d' /etc/crontab
    echo '*/30 * * * * root export EPC_INSTALL_PATH='$ROOT_DIR'; '$ROOT_DIR'/EPC/PGW/PGWFTPUpload.sh' >>/etc/crontab
    sed -i '/OFCSFTPUpload.sh/d' /etc/crontab
    echo '*/30 * * * * root export EPC_INSTALL_PATH='$ROOT_DIR'; '$ROOT_DIR'/EPC/OFCS/OFCSFTPUpload.sh' >>/etc/crontab
    sed -i '/OCSFTPUpload.sh/d' /etc/crontab
    echo '*/30 * * * * root export EPC_INSTALL_PATH='$ROOT_DIR'; '$ROOT_DIR'/EPC/OCS/OCSFTPUpload.sh' >>/etc/crontab

    #Setting /etc/crontab parameters for resetting used_data field of subscribers after each billing cycle
    sed -i '/nms_reset_used_data.sh/d' /etc/crontab
    echo '0 0 * * * root export NMS_INSTALL_PATH='$NMS_PATH'; '$CONSOLE_PATH'nms_reset_used_data.sh' >>/etc/crontab
    sed -i '/epc-collect-graph-data.php/d' /etc/crontab
    echo '* * * * * root export NMS_INSTALL_PATH='$NMS_PATH'; php '$CONSOLE_PATH'epc-collect-graph-data.php' >>/etc/crontab
	
    #Giving permissions to home folder
    chmod -R 777 $ROOT_DIR
    tput setaf 4; echo "Giving read and execute permission to all directories in path $NMS_PATH ..."; tput sgr0
    dir=$NMS_PATH
    until [ $dir == "/" ]; do
        chmod a+rx $dir
    	dir=`dirname $dir`
    done
}
InstallRpcapd()
{    
    if [ ! -f ../Bin/nettest/rpcapd ]; then
        tput setaf 4; echo "Installing rpcapd ..."; tput sgr0
        mkdir -p ../Bin/nettest
        chmod 777 ../Bin/nettest
        cp ../ThirdParty/rpcapd/rpcapd64 ../Bin/nettest/rpcapd
    fi

    if [ ! -f ../Bin/netepc/rpcapd ]; then
        tput setaf 4; echo "Installing rpcapd ..."; tput sgr0
        mkdir -p ../Bin/netepc
        chmod 777 ../Bin/netepc
        cp ../ThirdParty/rpcapd/rpcapd64 ../Bin/netepc/rpcapd
    fi

    chmod 777 ../Bin/nettest/rpcapd
    chmod 777 ../Bin/netepc/rpcapd
}
ConfigureSudoersFile()
{
    #Adding changes to /etc/sudoers
    sed -i 's/^[ ]*Defaults[ ]*requiretty/#&/' /etc/sudoers
    
    if test -z "`grep -w "apache    ALL=(ALL)    NOPASSWD: ALL" /etc/sudoers`"; then
        echo "apache    ALL=(ALL)    NOPASSWD: ALL" >> /etc/sudoers
    fi
    
    if test -z "`grep -w "Defaults   !env_reset" /etc/sudoers`"; then
        echo "Defaults   !env_reset" >> /etc/sudoers
    fi
    
    if test -z "`grep secure_path /etc/sudoers | grep \"/usr/local/bin\"`"; then
       sed -i "/secure_path/s/$/:\/usr\/local\/bin/g" /etc/sudoers 
    fi
    
    if test -z "`grep -w "polaris    ALL=(ALL)    NOPASSWD: ALL" /etc/sudoers`"; then
        sed -i '/polaris/d' /etc/sudoers
        echo 'polaris    ALL=(ALL)    NOPASSWD: ALL' >> /etc/sudoers
    fi

    #Create user for SPR Replication
    useradd epcuser -p `openssl passwd -1 password` > /dev/null 2>&1
    grep "^ *epcuser .*" /etc/sudoers > /dev/null && sed -i '/^ *epcuser .*/c\epcuser  ALL=(ALL) NOPASSWD: /usr/bin/systemctl start epc-spr.service, /usr/bin/systemctl stop epc-spr.service, /usr/bin/systemctl restart epc-spr.service' /etc/sudoers ||  echo 'epcuser  ALL=(ALL) NOPASSWD: /usr/bin/systemctl start epc-spr.service, /usr/bin/systemctl stop epc-spr.service, /usr/bin/systemctl restart epc-spr.service' >> /etc/sudoers
}
IPConfiguration()
{
    # IP forwarding configuration
    /sbin/sysctl -e net.ipv4.conf.all.forwarding=1 > /dev/null
    /sbin/sysctl -w net.ipv6.conf.all.forwarding=1 > /dev/null
    /sbin/sysctl -e net.ipv4.ip_forward=1 > /dev/null
    /sbin/sysctl -e net.ipv4.conf.default.forwarding=1 > /dev/null
    /sbin/sysctl -e net.ipv4.conf.all.send_redirects=0 > /dev/null
    /sbin/sysctl -e net.ipv4.conf.default.send_redirects=0 > /dev/null
    /sbin/sysctl -e net.ipv4.conf.all.secure_redirects=0 > /dev/null
    /sbin/sysctl -e net.ipv4.conf.default.secure_redirects=0 > /dev/null
    
    echo "Flushing iptables"
    iptables -F
    ip6tables -F
}
StopSnmp()
{
    #SNMP Configuration
    status=`service snmpd status 2>/dev/null`
    if test -n "'echo $status | grep -i -e running'" ; then
        /usr/bin/pkill snmpd
    fi
}
ConfigureVim()
{
  for cmd in "${vim_properties[@]}" ; do
    if [ `grep -w "$cmd" /etc/vimrc | wc -l` -eq 0 ]; then
        echo "$cmd" >> /etc/vimrc
    fi
  done
}
ConfigureLogRotate()
{
    echo "Modifying logrotate...."
    LOGROTATE_CONFIG_FILE=/etc/logrotate.d/httpd

    #To run the Logrotate hourly
    cp /etc/cron.daily/logrotate /etc/cron.hourly/

    #Flushing the contents of the file
    :>$LOGROTATE_CONFIG_FILE

    Content="/var/log/httpd/*log {
    missingok
    notifempty
    sharedscripts
    hourly
    copytruncate
    dateext
    dateformat -%Y-%m-%d_%H_%s
    rotate 10
    minsize 100M
    delaycompress
    compress
    postrotate
        /bin/systemctl reload httpd.service > /dev/null 2>/dev/null || true
    endscript
    }"

    #Adding the content of the file
    echo "$Content" > "$LOGROTATE_CONFIG_FILE"
}
ConfigureNetCli()
{
    # Set NetCLI environment variables
    ex +g/CLI_INSTALL_PATH/d -cwq /etc/environment
    echo 'export CLI_INSTALL_PATH='$ROOT_DIR >> /etc/environment
    ex +g/CLI_SSL_DISABLED/d -cwq /etc/environment
    echo 'export CLI_SSL_DISABLED=0' >> /etc/environment  
    source /etc/environment
}
ConfigureHippe()
{
    #Creating location for HiPPE user modules.
    mkdir -p /usr/lib64/hippe/
    chmod -R 777 /usr/lib64/hippe/

    tput setaf 4; echo "Creating build environment for HiPPE ..."; tput sgr0
    $ROOT_DIR/HiPPE/Packaging/make-hippe-env.sh -o all
}
ConfigureLicense()
{
    # Build Environment for License Server.
    cd $LICENSE_SERVER_PATH
    chmod +x make_license_server_env_script.sh
    ./make_license_server_env_script.sh LOCAL
    cd -
}
ConfigureEPCServices()
{
    # Clear Start up and Kill Script
    systemctl stop netepc_env.service > /dev/null 2>&1
    /sbin/chkconfig --del netepc_env > /dev/null 2>&1
    
    # Establish Start up and Kill Script
    cp -f $NETEPC_PACKAGING_PATH/netepc_env /etc/init.d/
    chmod 755 /etc/init.d/netepc_env
    /sbin/chkconfig --add netepc_env > /dev/null 2>&1
	
    tput setaf 4; echo "Configuring EPC services ..."; tput sgr0
    for nodeType in mme sgw pgw ocs ofcs pcrf hss mmelb mbmsgw epdg spr
    do
     #remove old polaris-netpc-*.service files (if present)
        if [[ -f /lib/systemd/system/polaris-netepc-$nodeType.service ]]; then
            systemctl stop polaris-netepc-$nodeType.service
            rm -f /lib/systemd/system/polaris-netepc-$nodeType.service
        fi
    
        systemctl stop epc-$nodeType.service > /dev/null 2>&1
        if ! test -L /lib/systemd/system/epc-$nodeType.service ; then
            rm -f /lib/systemd/system/epc-$nodeType.service
        fi
    
        chmod 755 $ROOT_DIR/services/epc-$nodeType.service
    done
    systemctl --system daemon-reload
    service ntpd restart > /dev/null  2>&1 &
}
CreateDirForSPRReplication()
{
    #Create directory for SPR replication
    mkdir -p /var/patchset
    mkdir -p /var/patchset/GeneratedPatchset
    mkdir -p /var/patchset/ReceivedPatchset
    mkdir -p /var/patchset/ReceivedPatchset/Compressed
    chmod -R 777 /var/patchset/
    chown -R epcuser:epcuser /var/patchset/
}
InstallAndConfigureKamailio()
{
	echo "Installing kamailio ..."
    #Add Kamailio RPM Repository
	KAMAILIO_REPO=/etc/yum.repos.d/home:kamailio:v5.3.x-rpms.repo
	if [ -f "$KAMAILIO_REPO" ]
	then
		echo "Kamailio Repository already downloaded"
	else
		cd /etc/yum.repos.d/
		wget http://download.opensuse.org/repositories/home:/kamailio:/v5.3.x-rpms/CentOS_7/home:kamailio:v5.3.x-rpms.repo
	fi
	
	#Install kamailio
	KAMAILIO_PACKAGES='kamailio-5.3.5-11.1.x86_64 kamailio-ims-5.3.5-11.1.x86_64 kamailio-presence-5.3.5-11.1.x86_64 kamailio-tls-5.3.5-11.1.x86_64 kamailio-sctp-5.3.5-11.1.x86_64 kamailio-xmlrpc-5.3.5-11.1.x86_64 kamailio-xmpp-5.3.5-11.1.x86_64 kamailio-xmlops-5.3.5-11.1.x86_64 bind-9.11.4-16.P2.el7_8.6.x86_64 ipsec-tools mariadb-server'
	
	for package in $KAMAILIO_PACKAGES; do
		if [ -z "`rpm -qa | grep $package`" ]; then
			yum -y install "$package"
		else
			echo "$package is already installed"
		fi
	done
	
	if [ -z "`rpm -qa | grep kamailio-mysql-5.3.5-11.1.x86_64`" ]; then
		yum -y install kamailio-mysql.x86_64
		#Starting mariadb
		systemctl start mariadb
		systemctl enable mariadb

        #Setting mysql password as polaris
        mysqladmin -u root password polaris
	else
		echo "kamailio-mysql-5.3.5-11.1.x86_64 is already installed"
	fi
	
    #Edit kamailio Configuration
	if test -z "`grep -w "#!define WITH_ACCDB" /etc/kamailio/kamailio.cfg`"; then
		sed -i 's/#!KAMAILIO/&\n#!define WITH_ACCDB/' /etc/kamailio/kamailio.cfg
	fi
	if test -z "`grep -w "#!define WITH_PRESENCE" /etc/kamailio/kamailio.cfg`"; then
		sed -i 's/#!KAMAILIO/&\n#!define WITH_PRESENCE/' /etc/kamailio/kamailio.cfg
	fi
	if test -z "`grep -w "#!define WITH_NAT" /etc/kamailio/kamailio.cfg`"; then
		sed -i 's/#!KAMAILIO/&\n#!define WITH_NAT/' /etc/kamailio/kamailio.cfg
	fi
	if test -z "`grep -w "#!define WITH_USRLOCDB" /etc/kamailio/kamailio.cfg`"; then
		sed -i 's/#!KAMAILIO/&\n#!define WITH_USRLOCDB/' /etc/kamailio/kamailio.cfg
	fi
	if test -z "`grep -w "#!define WITH_AUTH" /etc/kamailio/kamailio.cfg`"; then
		sed -i 's/#!KAMAILIO/&\n#!define WITH_AUTH/' /etc/kamailio/kamailio.cfg
	fi
	if test -z "`grep -w "#!define WITH_MYSQL" /etc/kamailio/kamailio.cfg`"; then
		sed -i 's/#!KAMAILIO/&\n#!define WITH_MYSQL/' /etc/kamailio/kamailio.cfg
	fi
		
	#Kamailio is configured. It can be started by firing "systemctl start kamailio" when required.
	systemctl enable kamailio
	
	#Configure /opt/kamailio/
	tar -xvf $ROOT_DIR/Packaging/nettest/kamailio.tar -C /opt/
	
	echo "Configured /opt/kamailio ..." 
	
}

# Kill process causing yum/apt-get lock
yumpid=$(ps -aef | grep yum | grep -v grep | awk {'print $2'})
if [ "$yumpid" != "" ]; then
    kill -9 $yumpid
fi

for fun in "${fun_list[@]}" ; do
  $fun
done

# Set core pattern
echo "kernel.core_pattern=core.%e.%t.%E%%" > /etc/sysctl.conf
echo "core.%e.%t.%E%%" > /proc/sys/kernel/core_pattern
popd > /dev/null 2>&1

# Upgrade sprdb
$ROOT_DIR/Packaging/netepc/scripts/upgrade_sprdb.sh $ROOT_DIR/db

# It should not exceed than 65535. NFQueue count can not be assigned greater that 65535 used in NetTest"
sysctl -w kernel.pid_max=65535

tput setaf 2; echo "4G software development environment is ready."; tput sgr0

tput setaf 2; echo "4G software development environment is ready."; tput sgr0
