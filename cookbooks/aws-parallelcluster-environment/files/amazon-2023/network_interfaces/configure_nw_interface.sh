#!/bin/sh

set -ex

if
  [ -z "${DEVICE_NAME}" ] ||          # name of the device
  [ -z "${DEVICE_NUMBER}" ] ||       # index of the device
  [ -z "${NETWORK_CARD_INDEX}" ] ||   # index of the network card
  [ -z "${DEVICE_IP_ADDRESS}" ] ||       # ip of the device
  [ -z "${MAC}" ] ||                 # mac address of the device
  [ -z "${CIDR_BLOCK}" ]                 # CIDR block of the subnet
then
  echo 'One or more environment variables missing'
  exit 1
fi
echo "Configuring NIC, Device name: ${DEVICE_NAME}, Device number: ${DEVICE_NUMBER}, Network card index:${NETWORK_CARD_INDEX}"

configuration_directory="/etc/systemd/network"
file_name="70-${DEVICE_NAME}.network"
sub_directory="${configuration_directory}/${file_name}.d"
if [ ! -d "$sub_directory" ]; then
  mkdir -p "$sub_directory";
fi

cd "$configuration_directory"

SUFFIX=$NETWORK_CARD_INDEX$(printf "%02d" $DEVICE_NUMBER)
ROUTE_TABLE="$(( $SUFFIX + 1000 ))"

ln -s /usr/lib/systemd/network/80-ec2.network ${file_name} # Use default EC2 configuration. This include MTU, etc.

/bin/cat <<EOF > ${sub_directory}/eni.conf
# Configuration for network card: ${NETWORK_CARD_INDEX}, device number: ${DEVICE_NUMBER} generated by ParallelCluster
# This is inspired by https://github.com/amazonlinux/amazon-ec2-net-utils/blob/v2.4.1/lib/lib.sh
[Match]
MACAddress=${MAC}
[Network]
DHCP=yes

[DHCPv4]
RouteMetric=$ROUTE_TABLE
UseRoutes=true
UseGateway=true

[IPv6AcceptRA]
RouteMetric=$ROUTE_TABLE
UseGateway=true

[Route]
Table=$ROUTE_TABLE
Gateway=_ipv6ra

[Route]
Gateway=_dhcp4
Table=$ROUTE_TABLE
[Route]
Table=$ROUTE_TABLE
Destination=$CIDR_BLOCK
[RoutingPolicyRule]
From=${DEVICE_IP_ADDRESS}
Priority=$ROUTE_TABLE
Table=$ROUTE_TABLE
EOF