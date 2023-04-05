import pytest
from src.helpers import xmlBuilder
from src.models import SessionLogin


def test_serializeObject():
    sessionLogin = SessionLogin.SessionLogin("1", "blabla@bla.com", "blapass")

    serializedSession = xmlBuilder.serializeObject(sessionLogin)

    assert serializedSession == "<SessionLogin><sessionID>1</sessionID><password>blapass</password><userName>blabla@bla.com</userName><sessionIDVersion>2.1</sessionIDVersion></SessionLogin>"

def test_get_mac_address_of_interface():
    xmlData = """<NetworkInterfaceList version="2.0" xmlns="http://www.hikvision.com/ver20/XMLSchema">
                    <NetworkInterface version="2.0" xmlns="http://www.hikvision.com/ver20/XMLSchema">
                    <id>1</id>
                    <IPAddress version="2.0" xmlns="http://www.hikvision.com/ver20/XMLSchema">
                    <ipVersion>dual</ipVersion>
                    <addressingType>dynamic</addressingType>
                    <ipAddress>192.168.72.226</ipAddress>
                    <subnetMask>255.255.255.0</subnetMask>
                    <ipv6Address>fe80::2ea5:9cff:fecd:200a</ipv6Address>
                    <bitMask>ffff:ffff:ffff:ffff::</bitMask>
                    <ipV6AddressingType>dhcp</ipV6AddressingType>
                    <DefaultGateway>
                    <ipAddress>192.168.72.1</ipAddress>
                    </DefaultGateway>
                    <PrimaryDNS>
                    <ipAddress>192.168.72.1</ipAddress>
                    </PrimaryDNS>
                    <SecondaryDNS>
                    <ipAddress>0.0.0.0</ipAddress>
                    </SecondaryDNS>
                    </IPAddress>
                    <Discovery version="2.0" xmlns="http://www.hikvision.com/ver20/XMLSchema">
                    <UPnP>
                    <enabled>false</enabled>
                    </UPnP>
                    <Zeroconf>
                    <enabled>false</enabled>
                    </Zeroconf>
                    </Discovery>
                    <Link version="2.0" xmlns="http://www.hikvision.com/ver20/XMLSchema">
                    <MACAddress>2c:a5:9c:cd:20:0a</MACAddress>
                    <autoNegotiation>true</autoNegotiation>
                    <speed>0</speed>
                    <duplex>half</duplex>
                    <MTU min="500" max="9676">1500</MTU>
                    </Link>
                    </NetworkInterface>
                    <NetworkInterface version="2.0" xmlns="http://www.hikvision.com/ver20/XMLSchema">
                    <id>2</id>
                    <IPAddress version="2.0" xmlns="http://www.hikvision.com/ver20/XMLSchema">
                    <ipVersion>v4</ipVersion>
                    <addressingType>dynamic</addressingType>
                    <ipAddress>192.168.8.1</ipAddress>
                    <subnetMask>255.255.255.0</subnetMask>
                    <DefaultGateway>
                    <ipAddress>255.255.255.255</ipAddress>
                    </DefaultGateway>
                    <PrimaryDNS>
                    <ipAddress>0.0.0.0</ipAddress>
                    </PrimaryDNS>
                    <SecondaryDNS>
                    <ipAddress>0.0.0.0</ipAddress>
                    </SecondaryDNS>
                    </IPAddress>
                    <Link version="2.0" xmlns="http://www.hikvision.com/ver20/XMLSchema">
                    <MACAddress>60:1d:9d:b0:0f:fb</MACAddress>
                    <MTU min="500" max="9676">1500</MTU>
                    </Link>
                    </NetworkInterface>
                    </NetworkInterfaceList>"""

    mac_address = xmlBuilder.get_mac_address_of_interface(xmlData, 1)

    assert mac_address == '2c:a5:9c:cd:20:0a'