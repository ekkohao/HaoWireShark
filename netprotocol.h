#ifndef NETPROTOCOL_H
#define NETPROTOCOL_H

#include <QString>
#include <QStringList>

#include "tcpipcommon.h"

#include <QDebug>

/** eg:"FF" => "11111111" */
inline QString hex2binary(QString qstr);
/** eg:"11121314" => "17.18.19.20" */
inline QString hexIP2NormalIP(QString hexStr);
inline QString hexIPV62NormalIPV6(QString hexStr);
inline QString hexMac2NormalMac(QString hexStr);

QString hex2binary(QString qstr) {
    QString bi;
    for (int i = 0, len = qstr.length(); i < len; ++i) {
        switch (qstr.at(i).toLatin1()) {
        case '0': bi += "0000"; break;
        case '1': bi += "0001"; break;
        case '2': bi += "0010"; break;
        case '3': bi += "0011"; break;
        case '4': bi += "0100"; break;
        case '5': bi += "0101"; break;
        case '6': bi += "0110"; break;
        case '7': bi += "0111"; break;
        case '8': bi += "1000"; break;
        case '9': bi += "1001"; break;
        case 'A': bi += "1010"; break;
        case 'B': bi += "1011"; break;
        case 'C': bi += "1100"; break;
        case 'D': bi += "1101"; break;
        case 'E': bi += "1110"; break;
        case 'F': bi += "1111"; break;
        default: break;
        }
    }
    return bi;
}

QString hexIP2NormalIP(QString hexStr) {
    QStringList ipAddr;
    int t;
    for(int i = 0; i < 4; ++i) {
        t = hex2binary(hexStr.mid(2*i,2)).toInt(nullptr,2);
        ipAddr.append(QString::number(t));
    }
    return QString(ipAddr.join('.'));
}

QString hexIPV62NormalIPV6(QString hexStr){
    QStringList ipAddr;
    for(int i = 0; i < 8; ++i) {
        ipAddr.append(hexStr.mid(4 * i,4));
    }

    QString addr(ipAddr.join(':'));
    return addr;
}

QString hexMac2NormalMac(QString hexStr) {
    for (int i = 0; i < 5; ++i)
        hexStr.insert(10-2*i,QChar('-'));
    return hexStr;
}
/*********************************************************
 * Ethernet
 *********************************************************/

#define ETHERNET_HEAD_LENGTH    14
#define ETHERNET_TYPE_ARP       0x0806      //以太头类型：ARP类型,地址解析协议
#define ETHERNET_TYPE_IP        0x0800      //以太头类型：IPV4类型,	网际协议版本4
#define ETHERNET_TYPE_IPV6      0x86DD      //以太头类型，IPV6类型,网际协议版本6
#define ETHERNET_TYPE_RARP      0x8035      //以太头类型，RARP

class EthernetHead {
public:
    EthernetHead();
    EthernetHead(QString data);
    void setData(QString data);
    QString getSourceMacAddr();
    QString getDestinationMacAddr();
    QString getEthernetType();
    QString getDescription();
private:
    QString mData;
};

#define IPV4_HEAD_LENGTH    20
#define IPV4_TYPE_TCP       0x06
#define IPV4_TYPE_UDP       0x11
#define IPV4_TYPE_ICMP      0x01
#define IPV4_TYPE_IGMP      0x02

/*********************************************************
 * IPv4
 *********************************************************/

class IPv4Head {
public:
    IPv4Head();
    IPv4Head(QString data);
    void setData(QString data);
    int getIPv4HeadLength();
    QString getServiceType();
    int getIPv4HeadAndBodyLength();
    int getIdentification();
    QString getFragmentationFlag();
    int getFragmentationOffset();
    int getTTL();
    QString getIpv4Type();
    QString getCRC();
    QString getSourceIP();
    QString getDestinationIP();
    QString getDescription();
    QString getUnknownDescription();
private:
    QString mData;
};

/*********************************************************
 * IPv6
 *********************************************************/

#define IPV6_HEAD_LENGTH 40
#define IPV6_EXTEND_HEAD_HBH 0x00
#define IPV6_EXTEND_HEAD_TCP 0x06
#define IPV6_EXTEND_HEAD_UDP 0x11
#define IPV6_EXTEND_HEAD_ICMPV6 58
#define IPV6_EXTEND_HEAD_END 59

class IPv6Head {
public:
    IPv6Head();
    IPv6Head(QString data);
    void setData(QString data);
    void setExtend(QString data);
    QString getTrfficClass();
    QString getFlowLabel();
    int getExtendHeadAndBodyLength();
    QString getFirstNextHead();
    QString getIPv6Type();
    QString getBody();
    int getHotLimit();
    QString getSourceIP();
    QString getDestinationIP();
    QString getDescription();
private:
    QString mData;
    QString mExtend;
};

/*********************************************************
 * TCP
 *********************************************************/

#define TCP_HEAD_LENGTH 40

class TCPBag {
public:
    TCPBag();
    TCPBag(QString data);
    void setData(QString data);
    QString getSourcePortNum();
    QString getDestinationPortNum();
    QString getSeqNum();
    QString getACKNum();
    int getHeadLength();
    QString getFlag(); //URG,ACK,PSH,PST,SYN,FIN
    int getPoolSize();
    int getCheckedSum();
    QString getEmegencyPoint();
    QString getBodyData();
    QString getBodyDataPrint();
    QString getDescription();
private:
    QString mData;
};

/*********************************************************
 * UDP
 *********************************************************/

#define UDP_HEAD_LENGTH 8

class UDPBag {
public:
    UDPBag();
    UDPBag(QString data);
    void setData(QString data);
    QString getSourcePortNum();
    QString getDestinationPortNum();
    int getHeadAndBodyLength();
    QString getCheckedNum();
    QString getBodyData();
    QString getBodyDataPrint();
    QString getDescription();
    bool isBOOTPBag();
private:
    QString mData;
};

/*********************************************************
 * ICMP
 *********************************************************/

#define ICMP_HEAD_LENGTH 4

class ICMPBag {
public:
    ICMPBag();
    ICMPBag(QString data);
    void setData(QString data);
    QString getInfoType();
    QString getBagType();
    QString getCheckedNum();

    QString getDescription();
private:
    QString mData;
};

/*********************************************************
 * IGMP
 *********************************************************/

#define IGMP_HEAD_LENGTH 8

class IGMPBag {
public:
    IGMPBag();
    IGMPBag(QString data);
    void setData(QString data);
    QString getVersion();
    QString getType();
    QString getCheckedNum();
    QString getIPAddr();
    QString getDescription();
private:
    QString mData;
};

/*********************************************************
 * ARP
 *********************************************************/

#define ARP_HEAD_LENGTH 28

class ARPHead {
public:
    ARPHead();
    ARPHead(QString data);
    void setData(QString data);
    QString getHardType();
    QString getProtocolType();
    int getHardAddrLen();
    int getProtocolAddrLen();
    QString getOperateType();
    QString getSendMacAddr();
    QString getSendIPAddr();
    QString getDestinationMacAddr();
    QString getDestinationIPAddr();
    QString getDescription();
private:
    QString mData;
};

/*********************************************************
 * BOOTP
 *********************************************************/

#define BOOTP_HEAD_LENGTH 300

class BOOTPBag {
public:
    BOOTPBag();
    BOOTPBag(QString data);
    void setData(QString data);
    QString getOperateType();
    QString getHardType();
    int getHardMacAddrLen();
    int getJmpNum();
    QString getIdentfierNum();
    int getTime();
    QString getFlag();
    QString getClientIP();
    QString getYourIP();
    QString getServerIP();
    QString getNetMasterIP();
    QString getClientMacAddr();
    QString getServerName();
    QString getGuideFileName();
    QString getOptionCode();
    QString getDescription();
private:
    QString mData;
};

/*********************************************************
 * ICMPV6
 *********************************************************/

class ICMPV6Bag {
public:
    ICMPV6Bag();
    ICMPV6Bag(QString data);
    void setData(QString data);
    QString getBagType();
    QString getInfoType();
    QString getCode();
    QString getCheckedNum();
    QString getDescription();
private:
    QString mData;
};

#endif // NETPROTOCOL_H
