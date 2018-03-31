#! /bin/bash
# Script to automate creating new OpenVPN clients
# The client cert and key, along with the CA cert is
# zipped up and placed somewhere to download securely
#
# H Cooper - 05/02/11
#
# Usage: new-openvpn-client.sh <common-name>

# Set where we're working from
## These will be installation specific
DB_CONFIG=/opt/sdp/scripts/config.sh
OPENVPN_GATEWAY_BASE=$OPENVPN_CLIENT_FOLDER/sdp-gateway-base

. $DB_CONFIG

SDP_MANAGE_HOME=/home/sdpmanagement
FWKNOP_DIR=/etc/fwknop
FWKNOP_KEYS=$FWKNOP_DIR/fwknop_keys.conf
#FWKNOP_KEYS=$SDP_MANAGE_HOME/${CN}_fwknop_keys.conf

function showGateways {
  title="List Gateways"
  whiptail --textbox --title "$title" --scrolltext /dev/stdin 25 78 <<<"$(
        echo 'Configured Gateways:\n\n'
        mysql -h$HOST -P$PORT -u$USER -p$PASS $DB -e '
            SELECT CONCAT(
                  gateway_name,";",
                  gateway_ip,";",
                  gateway_online,";",
                  gateway_enable
            ) "<GW NAME>;<IP>;<ONLINE>;<ENABLED>"
            FROM gateway
            ORDER BY gateway_name
        ' | column -t -s ';')"
  optionsMenu

}

function selectGwIP {
  GATEWAY_IP=$(whiptail --inputbox "\nChoose an IP address for your gateway from the $GATEWAY_NET network." \
    8 78 --title "$title" 3>&1 1>&2 2>&3
  )
  exitstatus=$?

  if [ $exitstatus = 0 ]; then
    if [ `mysql -h$HOST -P$PORT -u$USER -p$PASS $DB -sNe "select count(*) from gateway where gateway_ip = '$GATEWAY_IP'"` -gt 0 ]; then
      whiptail --textbox --title "$title" --scrolltext /dev/stdin \
          8 78 <<<$(echo "IP Already in use. You must select a different IP")
      selectGwIP
    fi
    echo "ifconfig-push $GATEWAY_IP $GATEWAY_GATEWAY" > $OPENVPN_CLIENT_FOLDER/$CN
  fi 
}

function createSshKey {
    ssh-keygen -b 2048 -t rsa -f $SDP_MANAGE_HOME/${CN}_rsa -q -N ""
    cat $SDP_MANAGE_HOME/${CN}_rsa.pub >> $SDP_MANAGE_HOME/.ssh/authorized_keys
    chown sdpmanagement:sdpmanagement -R $SDP_MANAGE_HOME
}

function deleteSshKey {
    RSA_PUB=`cat $SDP_MANAGE_HOME/${CN}_rsa.pub | awk '{print $2}'`
    sed -i "\@$RSA_PUB@d" $SDP_MANAGE_HOME/.ssh/authorized_keys
    rm -f $SDP_MANAGE_HOME/${CN}_rsa.pub
    rm -f $SDP_MANAGE_HOME/${CN}_rsa
    rm -f $SDP_MANAGE_HOME/${CN}_gw_config.sh
}

function createFwknopKeys {
    fwknop --key-gen --key-gen-file $FWKNOP_KEYS
}

function deleteFwknopKeys {
    rm -f $FWKNOP_KEYS
}

function createCert {
	# Enter the easy-rsa directory and establish the default variables
	cd $OPENVPN_RSA_DIR
	source ./vars > /dev/null
	# Copied from build-key script (to ensure it works!)
	export EASY_RSA="${EASY_RSA:-.}"
	"$EASY_RSA/pkitool" --batch $CN
}

function createOvpn {
	#sudo cp $OPENVPN_GATEWAY_BASE $OPENVPN_CLIENT_FOLDER/$CN
	cat ${GATEWAY_BASE_CONFIG} \
	    <(echo -e '<ca>') \
	    ${OPENVPN_KEYS}/ca.crt \
	    <(echo -e '</ca>\n<cert>') \
	    ${OPENVPN_KEYS}/$CN.crt \
	    <(echo -e '</cert>\n<key>') \
	    ${OPENVPN_KEYS}/$CN.key \
	    <(echo -e '</key>\n<tls-auth>') \
	    ${OPENVPN_KEYS}/ta.key \
	    <(echo -e '</tls-auth>') \
	    > ${GATEWAY_OUTPUT_DIR}/$CN.ovpn
	
	# Celebrate!
	echo "Config created at ${GATEWAY_OUTPUT_DIR}/$CN.ovpn"
}

function writeGatewayConfig {
  FWKNOP_HMAC=`grep HMAC_KEY_BASE64 $FWKNOP_KEYS | awk '{print $2}'`
  FWKNOP_RIJNDAEL=`grep KEY_BASE64 $FWKNOP_KEYS | grep -v HMAC | awk '{print $2}'`
  GW_CONFIG=${GATEWAY_OUTPUT_DIR}/${CN}_gw_config.sh
  echo "Writing gateway config file"
  echo "#!/bin/bash" > $GW_CONFIG
  echo "" >> $GW_CONFIG
  echo "####Directories" >> $GW_CONFIG
  echo "OPENVPN_DIR=/etc/openvpn" >> $GW_CONFIG
  echo "" >> $GW_CONFIG
  echo "####Easy-RSA variables" >> $GW_CONFIG
  echo "KEY_EMAIL=$KEY_EMAIL" >> $GW_CONFIG
  echo "KEY_NAME=$KEY_NAME" >> $GW_CONFIG
  echo "KEY_COUNTRY=$KEY_COUNTRY" >> $GW_CONFIG
  echo "KEY_PROVINCE=$KEY_PROVINCE" >> $GW_CONFIG
  echo "KEY_CITY=$KEY_CITY" >> $GW_CONFIG
  echo "KEY_ORG=$KEY_ORG" >> $GW_CONFIG
  echo "KEY_OU=$KEY_OU" >> $GW_CONFIG
  echo "" >> $GW_CONFIG
  echo "####Database Setting" >> $GW_CONFIG
  echo "HOST=$GATEWAY_GATEWAY" >> $GW_CONFIG
  echo "PORT=$PORT" >> $GW_CONFIG
  echo "USER=$USER" >> $GW_CONFIG
  echo "PASS=$PASS" >> $GW_CONFIG
  echo "DB=$DB" >> $GW_CONFIG
  echo "" >> $GW_CONFIG
  echo "####Network Setting" >> $GW_CONFIG
  echo "BROKER_HOSTNAME=$BROKER_HOSTNAME" >> $GW_CONFIG
  echo "PRIMARY_IP=$PRIMARY_IP" >> $GW_CONFIG
  echo "CLIENT_NET=$CLIENT_NET" >> $GW_CONFIG
  echo "CLIENT_NETWORK=$CLIENT_NETWORK" >> $GW_CONFIG
  echo "CLIENT_NETMASK=$CLIENT_NETMASK" >> $GW_CONFIG
  echo "GATEWAY_IP=$GATEWAY_IP" >> $GW_CONFIG
  echo "GATEWAY_NET=$GATEWAY_NET" >> $GW_CONFIG
  echo "GATEWAY_GATEWAY=$GATEWAY_GATEWAY" >> $GW_CONFIG
  echo "GATEWAY_BROADCAST=$GATEWAY_BROADCAST" >> $GW_CONFIG
  echo "GATEWAY_NETWORK=$GATEWAY_NETWORK" >> $GW_CONFIG
  echo "GATEWAY_NETMASK=$GATEWAY_NETMASK" >> $GW_CONFIG
  echo "CLIENT_VPN_PORT=$CLIENT_VPN_PORT" >> $GW_CONFIG
  echo "GATEWAY_VPN_PORT=$GATEWAY_VPN_PORT" >> $GW_CONFIG
  echo "SQUID_PORT=$SQUID_PORT" >> $GW_CONFIG
  echo "REDSOCKS_PORT=$REDSOCKS_PORT" >> $GW_CONFIG
  echo "NGINX_PORT=$NGINX_PORT" >> $GW_CONFIG
  echo "" >> $GW_CONFIG
  echo "####FWKNOP Keys" >> $GW_CONFIG
  echo "FWKNOP_HMAC=\"$FWKNOP_HMAC\"" >> $GW_CONFIG
  echo "FWKNOP_RIJNDAEL=\"$FWKNOP_RIJNDAEL\"" >> $GW_CONFIG
}

function revokeCert {
    if [ -e ${OPENVPN_KEYS}/$CN.crt ]; then
      echo "Revoking previous Cert"
      
      # Enter the easy-rsa directory and establish the default variables
      cd $OPENVPN_RSA_DIR
      source ./vars > /dev/null
      
      # Copied from revoke-full script (to ensure it works!)
      CRL="crl.pem"
      RT="revoke-test.pem"

      if [ "$KEY_DIR" ]; then
        cd "$KEY_DIR"
        rm -f "$RT"
    
        # set defaults
        export KEY_CN=""
        export KEY_OU=""
        export KEY_NAME=""
    
        # required due to hack in openssl.cnf that supports Subject Alternative Names
        export KEY_ALTNAMES=""
    
        # revoke key and generate a new CRL
        $OPENSSL ca -revoke "$CN.crt" -config "$KEY_CONFIG"
    
        # generate a new CRL -- try to be compatible with
        # intermediate PKIs
        $OPENSSL ca -gencrl -out "$CRL" -config "$KEY_CONFIG"
        if [ -e export-ca.crt ]; then
            cat export-ca.crt "$CRL" >"$RT"
        else
            cat ca.crt "$CRL" >"$RT"
        fi
    
        # verify the revocation
        $OPENSSL verify -CAfile "$RT" -crl_check "$CN.crt"
      else
        echo 'Please source the vars script first (i.e. "source ./vars")'
        echo 'Make sure you have edited it to reflect your configuration.'
      fi
      rm ${OPENVPN_KEYS}/$CN.crt
      rm ${OPENVPN_KEYS}/$CN.key
      rm ${OPENVPN_KEYS}/$CN.csr
      sudo rm $OPENVPN_CLIENT_FOLDER/$CN
      sudo rm $GATEWAY_OUTPUT_DIR/$CN.ovpn
      echo "Previous Certificate has been revoked"
      echo ""
    fi
}

function showSetupInfo {
  clear
  echo "The remaining configuration must be completed on your Gateway."
  echo ""
  echo "The SSH Port will be open while setting up the gateway. After finishing, the SSH port will be closed again automatically."
  ufw allow 22/tcp
  echo
  echo
  echo
  echo "As root, Enter the following command on your Gateway to create the private key:"
  echo ""
  echo "mkdir -p /home/sdpmanagement"
  echo "echo \"`cat /home/sdpmanagement/${CN}_rsa`\" > /home/sdpmanagement/id_rsa"
  echo ""
  echo
  echo 
  read -p "Press 'Enter' when completed and proceed to next step..."
  clear
  echo "On the gateway, you must execute the 'gatewayInstall.sh' setup script as root"
  echo
  echo
  echo
  echo "apt-get install -y git"
  echo "git clone https://github.com/foxxyben/SD-Perimeter.git"
  echo "bash SD-Perimeter/gateway/gatewayInstall.sh"
  echo
  echo
  echo "Enter this Broker IP Address when prompted:"
  echo $PRIMARY_IP
  echo ""
  echo "Enter this Gateway Hostname when prompted:"
  echo "$CN"
  echo 
  echo
  echo
  echo "Press 'Enter' when gateway setup is completed..."
  read -p "SSH port will be closed."
  clear
  #ufw delete allow 22/tcp
}


function disableDbEntries {
    mysql -h$HOST -P$PORT -u$USER -p$PASS $DB -e "
        UPDATE gateway
        SET gateway_enable='no'
        WHERE gateway_name='$CN'
    "
}

function deleteDbEntries {
    mysql -h$HOST -P$PORT -u$USER -p$PASS $DB -e "delete from gateway where gateway_name='$CN'"
}
function enableDbEntries {
    mysql -h$HOST -P$PORT -u$USER -p$PASS $DB -e "update gateway set gateway_enable='yes' where gateway_name='$CN'"
}

function createDbEntries {
    mysql -h$HOST -P$PORT -u$USER -p$PASS $DB -e "insert into gateway (gateway_name,gateway_ip,gateway_proxy_port,gateway_start_date,gateway_end_date) values ('$CN', '$GATEWAY_IP','$SQUID_PORT',now(), now() + INTERVAL 50 year)"
    enableDbEntries
}

function createSquidPeer {
    SQUID_CONF="/etc/squid/squid.conf.d"
    if [ `grep -c $GATEWAY_IP $SQUID_CONF/cache_peers.conf` -lt 1 ]; then
      echo "cache_peer $GATEWAY_IP parent $SQUID_PORT 0 no-netdb-exchange proxy-only" >> $SQUID_CONF/cache_peers.conf
      echo "cache_peer_access $GATEWAY_IP deny all" >> $SQUID_CONF/cache_peer_deny.conf
      service squid reload
    fi
}

function removeSquidPeer {
   SQUID_CONF="/etc/squid/squid.conf.d"
   sed -i '/$GATEWAY_IP/d' $SQUID_CONF/cache_peers.conf
   sed -i '/$GATEWAY_IP/d' $SQUID_CONF/cache_peer_deny.conf
   service squid reload
}

function getCommonName {
  CN=$(
    whiptail --inputbox "\nEnter the gateway name:" 8 78 \
    --title "$title" 3>&1 1>&2 2>&3
  )
  exitstatus=$?
}

function getCurrentGwIP {
  GATEWAY_IP=`grep GATEWAY_IP $GATEWAY_OUTPUT_DIR/$CN_gw_config.sh | sed 's/GATEWAY_IP=//'`
}

function createGateway {
  title="Create a New Gateway"
  getCommonName
  if [ $exitstatus = 0 ]; then
    selectGwIP
    if [ $exitstatus = 0 ]; then
      createSshKey
      createCert
      createOvpn
      writeGatewayConfig
      createDbEntries
      createSquidPeer
      showSetupInfo
    fi
  fi
  optionsMenu
}

function refreshConfig {
  title="Refresh a Gatway Configuration"
  getCommonName
  if [ $exitstatus = 0 ]; then
    getCurrentGwIP
    revokeCert
    createCert
    createOvpn
    writeGatewayConfig
    enableDbEntries
    createSquidPeer
  fi
  optionsMenu
}

function disableGateway {
  title="Disable an existing Gateway"
  getCommonName
  if [ $exitstatus = 0 ]; then
    revokeCert
    disableDbEntries
    removeSquidPeer
  fi
  optionsMenu
}

function deleteGateway {
  title="Delete an existing Gateway"
  getCommonName
  if [ $exitstatus = 0 ]; then
    revokeCert
    deleteSshKey
    deleteDbEntries
    removeSquidPeer
  fi
  optionsMenu
}

function optionsMenu {
  opt=$(
    whiptail --title "GATEWAY MANAGEMENT OPTIONS" --menu "\nChoose an item to continue:" \
    25 78 16 \
    "List Gateways" "Show a list of all current gateways." \
    "Add Gateway" "Create a new gateway." \
    "Refresh a Configuration" "Rebuild a gateway's configuration." \
    "Disable Gateway" "Disable an existing gateway." \
    "Delete Gateway" "Delete an existing gateway." 3>&2 2>&1 1>&3
  )
  exitstatus=$?

  if [ $exitstatus = 0 ]; then
    case $opt in
      "List Gateways")
        showGateways
        ;;
      "Add Gateway")
        createGateway
        ;;
      "Refresh a Configuration")
        refreshConfig
        ;;
      "Disable Gateway")
        disableGateway
        ;;
      "Delete Gateway")
        deleteGateway
        ;;
    esac
  fi
}

if [ -z "$1" ]; then
  optionsMenu
else
  CN=$1
  if [ -e $OPENVPN_KEYS/$CN.crt ]; then
    optionsMenu
  else
    selectGwIP
    if [ $exitstatus = 0 ]; then
      createSshKey
      createCert
      createOvpn
      writeGatewayConfig
      createDbEntries
      createSquidPeer
      showSetupInfo
    fi
  fi
fi
