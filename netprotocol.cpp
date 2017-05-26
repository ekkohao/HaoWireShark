#include "netprotocol.h"


EthernetHead::EthernetHead()
{

}

EthernetHead::EthernetHead(QString data)
{
    this->mData = data.toUpper();
}

void EthernetHead::setData(QString data)
{
    this->mData = data.toUpper();
}

QString EthernetHead::getSourceMacAddr()
{
    QString macAddr;
    int i;
    for( i = 0; i < 5; ++i) {
        macAddr += (mData.mid(12 + 2 * i,2) + "-");
    }
    macAddr += mData.mid(12 + 2 * i,2);
    return macAddr;
}

QString EthernetHead::getDestinationMacAddr()
{
    QString macAddr;
    int i;
    for(i = 0; i < 5; ++i) {
        macAddr += (mData.mid(2 * i,2) + "-");
    }
    macAddr += mData.mid(12 + 2 * i,2);
    return macAddr;
}

QString EthernetHead::getEthernetType()
{
    QString flag = mData.mid(24,4);
    QString type;

    switch (flag.toInt(nullptr,16)) {
    case ETHERNET_TYPE_IP: type = "IPv4"; break;
    case ETHERNET_TYPE_IPV6: type = "IPv6"; break;
    case ETHERNET_TYPE_ARP: type = "ARP"; break;
    case ETHERNET_TYPE_RARP: type = "RARP"; break;
    default: type = "Unknown";
    }

    return type;
}

QString EthernetHead::getDescription()
{
    QString des;
    des = "源MAC地址：" + getSourceMacAddr() + "\n";
    des += ("目的MAC地址：" + getDestinationMacAddr() + "\n");
    des += ("因特网协议：" + getEthernetType() + "\n");
    return des;
}



IPv4Head::IPv4Head()
{

}

IPv4Head::IPv4Head(QString data)
{
    this->mData = data.toUpper();
}

void IPv4Head::setData(QString data)
{
    this->mData = data.toUpper();
}

int IPv4Head::getIPv4HeadLength()
{
    QString str = mData.mid(1,1);
    return hex2binary(str).toInt(nullptr,2) * 4;
}

QString IPv4Head::getServiceType()
{
    QString str = mData.mid(2,2);
    str = hex2binary(str).right(5);
    QString type;
    switch (str.toInt(nullptr,2)) {
    case 0: type = "Normal Service"; break;
    case 2: type = "Minimize Monetary Cost"; break;
    case 4: type = "Maximize Reliability"; break;
    case 8: type = "Maximize Throughput"; break;
    case 16: type = "Minimize Delay"; break;
    default: type = "Get Error"; break;
    }
    return type;
}

int IPv4Head::getIPv4HeadAndBodyLength()
{
    QString str = mData.mid(4,4);
    return hex2binary(str).toInt(nullptr,2);
}

int IPv4Head::getIdentification()
{
    return mData.mid(8,4).toInt(nullptr,16);
}

QString IPv4Head::getFragmentationFlag()
{
    QString str = mData.mid(12,1);
    QString flag;
    str = hex2binary(str);
    if(str.at(1).toLatin1() == '1')
        flag = "1 | Do Not Fragment";
    else if (str.at(2).toLatin1() == '1')
        flag = "1 | More Fragment Behind";
    else
        flag = "0 | No More Fragment";
    return flag;
}

int IPv4Head::getFragmentationOffset()
{
    QString str = mData.mid(12,4);
    str = hex2binary(str).mid(3);
    return str.toInt(nullptr,2);
}

int IPv4Head::getTTL()
{
    QString str = mData.mid(16,2);
    return str.toInt(nullptr,16);
}

QString IPv4Head::getIpv4Type()
{
    QString str = mData.mid(18,2);
    QString type;
    switch (str.toInt(nullptr,16)) {
    case IPV4_TYPE_ICMP: type = "ICMP"; break;
    case IPV4_TYPE_IGMP: type = "IGMP"; break;
    case IPV4_TYPE_TCP: type = "TCP"; break;
    case IPV4_TYPE_UDP: type = "UDP"; break;
    default: type = "Unknow"; break;
    }
    return type;
}

QString IPv4Head::getSourceIP()
{
    QString str = mData.mid(24,8);
    return hexIP2NormalIP(str);
}

QString IPv4Head::getDestinationIP()
{
    QString str = mData.mid(32,8);
    return hexIP2NormalIP(str);
}

QString IPv4Head::getDescription()
{
    QString des;
    des = "源IP地址：" + getSourceIP() + "\n";
    des += ("目的IP地址：" + getDestinationIP() + "\n");
    des += ("IP上层协议：" + getIpv4Type() + "\n");
    des += ("IP分组标识：" + QString::number(getIdentification()) + "\n");
    des += ("IP分片标志：" + getFragmentationFlag() + "\n");
    des += ("IP分片偏移：" + QString::number(getFragmentationOffset()) + "\n");
    des += ("IP服务类型：" + getServiceType() + "\n");
    des += ("IP包TTL：" + QString::number(getTTL()) + "\n");

    return des;
}

QString IPv4Head::getUnknownDescription()
{
    QString des;
    QString str = mData.mid(18,2);

    des = getDescription();
    des += ("未知IP包类型：" + QString::number(str.toInt(nullptr,16)) + "\n");
    return des;
}

IPv6Head::IPv6Head()
{

}

IPv6Head::IPv6Head(QString data)
{
    this->mData = data.toUpper();
}

void IPv6Head::setData(QString data)
{
    this->mData = data.toUpper();
}

void IPv6Head::setExtend(QString data)
{
    this->mExtend = data;
}

QString IPv6Head::getTrfficClass()
{
    QString str = mData.mid(1,2);
    return "0x" + str.toLower();
}

QString IPv6Head::getFlowLabel()
{
    QString str = mData.mid(3,5);
    return "0x" + str.toLower();
}

int IPv6Head::getExtendHeadAndBodyLength()
{
    QString str = mData.mid(8,4);
    return str.toInt(nullptr,16);
}

QString IPv6Head::getFirstNextHead()
{
    QString str = mData.mid(12,2);
    return "0x" + str.toLower();
}

QString IPv6Head::getIPv6Type()
{
    QString str = mData.mid(12,2);
    QString ext(mExtend);
    int next = str.toInt(nullptr,16);
    int len;
    while(next != IPV6_EXTEND_HEAD_TCP && next != IPV6_EXTEND_HEAD_UDP && next != IPV6_EXTEND_HEAD_ICMPV6 && next != IPV6_EXTEND_HEAD_END && ext.length() > 0) {
        len = ext.mid(2,2).toInt(nullptr,15);
        next = ext.mid(0,2).toInt(nullptr,16);
        ext = ext.mid(4 + 2 * len);
    }
    QString r;
    switch (next) {
    case IPV6_EXTEND_HEAD_TCP: r = "TCP"; break;
    case IPV6_EXTEND_HEAD_UDP: r = "UDP"; break;
    case IPV6_EXTEND_HEAD_ICMPV6: r = "ICMPv6"; break;
    default:
        r = "Unknown";
        break;
    }
    return r;
}

QString IPv6Head::getBody()
{
    QString str = mData.mid(12,2);
    QString ext(mExtend);
    int next = str.toInt(nullptr,16);
    int len;
    while(next != IPV6_EXTEND_HEAD_TCP && next != IPV6_EXTEND_HEAD_UDP && next != IPV6_EXTEND_HEAD_ICMPV6 && next != IPV6_EXTEND_HEAD_END && ext.length() > 0) {
        len = ext.mid(2,2).toInt(nullptr,15);
        next = ext.mid(0,2).toInt(nullptr,16);
        ext = ext.mid(4 + 2 * len);
    }
    return ext;
}

int IPv6Head::getHotLimit()
{
    QString str = mData.mid(14,2);
    return str.toInt(nullptr,16);
}

QString IPv6Head::getSourceIP()
{
    QString str = mData.mid(16,32);
    return hexIPV62NormalIPV6(str);
}

QString IPv6Head::getDestinationIP()
{
    QString str = mData.mid(48,32);
    return hexIPV62NormalIPV6(str);
}

QString IPv6Head::getDescription()
{
    QString des;
    des = "通信等级：" + getTrfficClass() + "\n";
    des += ("流标签：" + getFlowLabel() + "\n");
    des += ("数据包体长度：" + QString::number(getExtendHeadAndBodyLength()) + "\n");
    des += ("跳限制：" + QString::number(getHotLimit()) + "\n");
    des += ("源IPv6地址：" + getSourceIP() + "\n");
    des += ("目标IPv6地址：" + getDestinationIP() + "\n");
    return des;
}





TCPBag::TCPBag()
{

}

TCPBag::TCPBag(QString data)
{
    this->mData = data;
}

void TCPBag::setData(QString data)
{
    this->mData = data;
}

QString TCPBag::getSourcePortNum()
{
    QString str = mData.mid(0,4);
    return QString::number(str.toInt(nullptr,16));
}

QString TCPBag::getDestinationPortNum()
{
    QString str = mData.mid(4,4);
    return QString::number(str.toInt(nullptr,16));
}

QString TCPBag::getSeqNum()
{
    QString str = mData.mid(8,8);
    return "0x" + str.toLower();
}

QString TCPBag::getACKNum()
{
    QString str = mData.mid(16,8);
    return "0x" + str.toLower();
}

int TCPBag::getHeadLength()
{
    QString str = mData.mid(24,1);
    return str.toInt(nullptr,16) * 4;
}

QString TCPBag::getFlag()
{
    QString str = mData.mid(26,2);
    str = hex2binary(str).mid(2);
    return str;
}

int TCPBag::getPoolSize()
{
    QString str = mData.mid(28,4);
    return str.toInt(nullptr,16);
}

int TCPBag::getCheckedSum()
{
    QString str = mData.mid(32,4);
    return str.toInt(nullptr,16);
}

QString TCPBag::getEmegencyPoint()
{
    QString str = mData.mid(36,4);
    return "0x" + str.toLower();
}

QString TCPBag::getBodyData()
{
    int headLen = getHeadLength();
    return mData.mid(headLen * 2);
}

QString TCPBag::getBodyDataPrint()
{
    QString str = getBodyData();
    QString rstr("\n\t");
    QString printStr;
    QString qsT;
    int i;
    int len = str.length();
    if(len < 1)
        return "None";

    for (i = 0; i < len / 2; ++i) {
        qsT = str.mid(2*i,2);

        rstr += ( qsT + " ");
        printStr += QString(tcpip::hexStr2char(qsT));

        if(i % 8 == 7){
            rstr += " ";
            printStr += " ";
        }
        if(i % 16 == 15){
            rstr += ("  " + printStr + "\n\t");
            printStr.clear();
        }
    }
    i = (len / 2) % 16;

    if( i != 15) {
        if(i < 7)
            rstr +=" ";
        rstr += QString(3*(17-i), ' ');
        rstr += (printStr + "\n");
    }
    else
        rstr.remove(rstr.length() - 1,1);

    return rstr;

}

QString TCPBag::getDescription()
{
    QString des;
    des = "源TCP端口：" + getSourcePortNum() + "\n";
    des += ("目的TCP端口：" + getDestinationPortNum() + "\n");
    des += ("TCP序列码：" + getSeqNum() + "\n");
    des += ("TCP确认码：" + getACKNum() + "\n");
    des += ("TCP标志：" + getFlag() + "\n");
    des += ("TCP头长度：" + QString::number(getHeadLength()) + "\n");
    des += ("TCP接收窗口大小：" + QString::number(getPoolSize()) + "\n");
    des += ("TCP应急指针：" + getEmegencyPoint() + "\n");
    des += ("发送数据：" + getBodyDataPrint() + "\n");
    return des;
}



UDPBag::UDPBag()
{

}

UDPBag::UDPBag(QString data)
{
    this->mData = data;
}

void UDPBag::setData(QString data)
{
    this->mData = data;
}

QString UDPBag::getSourcePortNum()
{
    QString str = mData.mid(0,4);
    return QString::number(str.toInt(nullptr,16));
}

QString UDPBag::getDestinationPortNum()
{
    QString str = mData.mid(4,4);
    return QString::number(str.toInt(nullptr,16));
}

int UDPBag::getHeadAndBodyLength()
{
    QString str = mData.mid(8,4);
    return str.toInt(nullptr,16);
}

QString UDPBag::getCheckedNum()
{
    QString str = mData.mid(12,4);
    return hex2binary(str);
}

QString UDPBag::getDescription()
{
    QString des;
    des = "源UDP端口：" + getSourcePortNum() + "\n";
    des += ("目的UDP端口：" + getDestinationPortNum() + "\n");
    des += ("UDP数据包总长度：" + QString::number(getHeadAndBodyLength())+ "\n");
    des += ("UDP校验码：" + getCheckedNum() + "\n");
    des += ("UDP数据：" + getBodyDataPrint() + "\n");
    return des;
}

bool UDPBag::isBOOTPBag()
{
    QString sendPort = getSourcePortNum();
    QString receivePort = getDestinationPortNum();
    return (sendPort == "67" || sendPort == "68") && (receivePort == "67" || receivePort == "68") && getHeadAndBodyLength() >= 308;
}

QString UDPBag::getBodyData()
{
    return mData.mid(16);
}

QString UDPBag::getBodyDataPrint()
{
    QString str = getBodyData();
    QString rstr("\n\t");
    QString printStr;
    QString qsT;
    int i;
    int len = str.length();
    if(len < 1)
        return "None";

    for (i = 0; i < len / 2; ++i) {
        qsT = str.mid(2*i,2);

        rstr += ( qsT + " ");
        printStr += QString(tcpip::hexStr2char(qsT));

        if(i % 8 == 7){
            rstr += " ";
            printStr += " ";
        }
        if(i % 16 == 15){
            rstr += ("  " + printStr + "\n\t");
            printStr.clear();
        }
    }
    i = (len / 2) % 16;

    if( i != 15) {
        if(i < 7)
            rstr +=" ";
        rstr += QString(3*(17-i), ' ');
        rstr += (printStr + "\n");
    }
    else
        rstr.remove(rstr.length() - 1,1);

    return rstr;

}

ICMPBag::ICMPBag()
{

}

ICMPBag::ICMPBag(QString data)
{
    this->mData = data;
}

void ICMPBag::setData(QString data)
{
    this->mData = data;
}

QString ICMPBag::getInfoType()
{
    QString type = mData.mid(0,2);
    QString code = mData.mid(2,2);
    int t = type.toInt(nullptr,16);
    int c = code.toInt(nullptr,16);
    QString r;
    switch (t) {
    case 0:
        if(c == 0)
            r = "回显应答";
        else
            r = "unknown";
        break;
    case 3:
        switch (c) {
        case 0: r = "网络不可达"; break;
        case 1: r = "主机不可达"; break;
        case 2: r = "协议不可达"; break;
        case 3: r = "端口不可达"; break;
        case 4: r = "需要分片但设置的不分片比特"; break;
        case 5: r = "源站选路失败"; break;
        case 6: r = "目的网络不认识"; break;
        case 7: r = "目的主机不认识"; break;
        case 8: r = "源主机被隔离"; break;
        case 9: r = "目的网路被强制禁止"; break;
        case 10: r = "目的主机被强制禁止"; break;
        case 11: r = "由于服务类型TOS，目的网络不可达"; break;
        case 12: r = "由于服务类型TOS，目的主机不可达"; break;
        case 13: r = "由于过滤，通信被强制禁止"; break;
        case 14: r = "主机越权"; break;
        case 15: r = "优先权终止生效"; break;
        default:r = "目的不可达--具体原因未知";break;
        }
        break;
    case 4:
        if(c == 0)
            r = "源端被关闭";
        else
            r = "unknown";
        break;
    case 5:
        switch (c) {
        case 0: r = "网络重定向"; break;
        case 1: r = "主机重定向"; break;
        case 2: r = "服务类型和网络重定向"; break;
        case 3: r = "服务类型和主机重定向"; break;
        case 5: r = "源站选路失败"; break;
        default:r = "重定向--具体原因未知";break;
        }
        break;
    case 8:
        if(c == 0)
            r = "请求回显";
        else
            r = "unknown";
        break;
    case 9:
        if(c == 0)
            r = "路由器通告";
        else
            r = "unknown";
        break;
    case 10:
        if(c == 0)
            r = "路由器请求";
        else
            r = "unknown";
        break;
    case 11:
        if(c == 0)
            r = "传输期间生存时间为0";
        else
            r = "在数据包组装期间生存时间为0";
        break;
    case 12:
        if(c == 0)
            r = "坏的ip首部";
        else
            r = "缺少必要选项";
        break;
    case 13:
        if(c == 0)
            r = "时间戳请求";
        else
            r = "unknown";
        break;
    case 14:
        if(c == 0)
            r = "时间戳应答";
        else
            r = "unknown";
        break;
    case 15:
        if(c == 0)
            r = "信息请求";
        else
            r = "unknown";
        break;
    case 16:
        if(c == 0)
            r = "信息应答";
        else
            r = "unknown";
        break;
    case 17:
        if(c == 0)
            r = "地址掩码请求";
        else
            r = "unknown";
        break;
    case 18:
        if(c == 0)
            r = "地址掩码应答";
        else
            r = "unknown";
        break;
    default:r = "unknown";break;
    }
    return r;
}

QString ICMPBag::getBagType()
{
    QString type = mData.mid(0,2);
    int t = type.toInt(nullptr,16);
    QString r;
    switch (t) {
    case 0:
    case 8:
    case 9:
    case 10:
    case 13:
    case 14:
    case 15:
    case 16:
    case 17:
    case 18:
        r = "查询报文";
        break;
    case 3:
    case 4:
    case 5:
    case 11:
    case 12:
        r = "差错报文";
        break;
    default:
        r = "获取失败，报文有误";
        break;
    }
    return r;
}


QString ICMPBag::getCheckedNum()
{
    QString str = mData.mid(4,4);
    return hex2binary(str);
}

QString ICMPBag::getDescription()
{
    QString des;
    des = "ICMP数据包类型：" + getBagType() + "\n";
    des += ("ICMP报文类型：" + getInfoType() + "\n");
    des += ("ICMP校验码：" + getCheckedNum() + "\n");
    return des;
}

IGMPBag::IGMPBag()
{

}

IGMPBag::IGMPBag(QString data)
{
    this->mData = data;
}

void IGMPBag::setData(QString data)
{
    this->mData = data;
}

QString IGMPBag::getVersion()
{
    QString str = mData.mid(0,1);
    return "IGMPv" + QString::number(str.toInt(nullptr,16) + 1);
}

QString IGMPBag::getType()
{
    QString str = mData.mid(1,1);
    return QString::number(str.toInt(nullptr,16));
}

QString IGMPBag::getCheckedNum()
{
    QString str = mData.mid(4,4);
    return hex2binary(str);
}

QString IGMPBag::getIPAddr()
{
    QString str = mData.mid(8,8);
    return hexIP2NormalIP(str);
}

QString IGMPBag::getDescription()
{
    QString des;
    des = "IGMP版本：" + getVersion() + "\n";
    des += ("IGMP类型：" + getType() + "\n");
    des += ("IGMP校验码：" + getCheckedNum() + "\n");
    des += ("IGMP组地址：" + getIPAddr() + "\n");
    return des;
}

ARPHead::ARPHead()
{

}

ARPHead::ARPHead(QString data)
{
    this->mData = data;
}

void ARPHead::setData(QString data)
{
    this->mData = data;
}

QString ARPHead::getHardType()
{
    QString str = mData.mid(0,4);
    if (str == "0001")
        return "以太网(0001)";
    return "其他硬件(" + str + ")";
}

QString ARPHead::getProtocolType()
{
    QString str = mData.mid(4,4);
    if (str == "0800")
        return "IP地址协议(0800)";
    return "其他协议(" + str + ")";
}

int ARPHead::getHardAddrLen()
{
    QString str = mData.mid(8,2);
    return str.toInt(nullptr,16);
}

int ARPHead::getProtocolAddrLen()
{
    QString str = mData.mid(10,2);
    return str.toInt(nullptr,16);
}

QString ARPHead::getOperateType()
{
    QString str = mData.mid(12,4);
    QString r;
    switch (str.toInt(nullptr,16)) {
    case 1: r = "ARP请求"; break;
    case 2: r = "ARP应答"; break;
    case 3: r = "RARP请求"; break;
    case 4: r = "RARP应答"; break;
    default: r = "未知"; break;
    }
    return r;
}

QString ARPHead::getSendMacAddr()
{
    QString str = mData.mid(16,12);
    if (getHardAddrLen() != 6) {
        return str;
    }

    return hexMac2NormalMac(str);
}

QString ARPHead::getSendIPAddr()
{
    QString str = mData.mid(28,8);
    if (getProtocolAddrLen() != 4) {
        return str;
    }

    return hexIP2NormalIP(str);
}

QString ARPHead::getDestinationMacAddr()
{
    QString str = mData.mid(36,12);
    if (getHardAddrLen() != 6) {
        return str;
    }

    return hexMac2NormalMac(str);
}

QString ARPHead::getDestinationIPAddr()
{
    QString str = mData.mid(48,8);
    if (getProtocolAddrLen() != 4) {
        return str;
    }

    return hexIP2NormalIP(str);
}

QString ARPHead::getDescription()
{
    QString des;
    des = "ARP硬件类型：" + getHardType() + "\n";
    des += ("ARP协议类型：" + getProtocolType() + "\n");
    des += ("ARP硬件地址长度：" + QString::number(getHardAddrLen()) + "\n");
    des += ("ARP协议地址长度：" + QString::number(getProtocolAddrLen()) + "\n");
    des += ("ARP包类型：" + getOperateType() + "\n");
    des += ("ARP发送端硬件地址：" + getSendMacAddr() + "\n");
    des += ("ARP发送端协议地址：" + getSendIPAddr() + "\n");
    des += ("ARP接收端硬件地址：" + getDestinationMacAddr() + "\n");
    des += ("ARP接收端协议地址：" + getDestinationIPAddr() + "\n");
    return des;
}

BOOTPBag::BOOTPBag()
{

}

BOOTPBag::BOOTPBag(QString data)
{
    this->mData = data;
}

void BOOTPBag::setData(QString data)
{
    this->mData = data;
}

QString BOOTPBag::getOperateType()
{
    QString str = mData.mid(0,2);
    if(str.toInt(nullptr,16) == 1)
        return "客户端到服务端数据包";
    else
        return "服务端到客户端数据包";
}

QString BOOTPBag::getHardType()
{
    QString str =mData.mid(2,2);
    if(str== "01")
        return "以太网(01)";
    else
        return "未知("+ str +")";
}

int BOOTPBag::getHardMacAddrLen()
{
    QString str = mData.mid(4,2);
    return str.toInt(nullptr,16);
}

int BOOTPBag::getJmpNum()
{
    QString str = mData.mid(6,2);
    return str.toInt(nullptr,16);
}

QString BOOTPBag::getIdentfierNum()
{
    QString str = mData.mid(8,8);
    return hex2binary(str);
}

int BOOTPBag::getTime()
{
    QString str = mData.mid(16,4);
    return str.toInt(nullptr,16);
}

QString BOOTPBag::getFlag()
{
    QString str = mData.mid(20,4);
    QString r;
    str = hex2binary(str);
    if(str.at(0) == QChar('1'))
        r = "广播发送(" + str + ")";
    else
        r = str;
    return r;
}

QString BOOTPBag::getClientIP()
{
    QString str = mData.mid(24,8);
    return hexIP2NormalIP(str);
}

QString BOOTPBag::getYourIP()
{
    QString str = mData.mid(32,8);
    return hexIP2NormalIP(str);
}

QString BOOTPBag::getServerIP()
{
    QString str = mData.mid(40,8);
    return hexIP2NormalIP(str);
}

QString BOOTPBag::getNetMasterIP()
{
    QString str = mData.mid(48,8);
    return hexIP2NormalIP(str);
}

QString BOOTPBag::getClientMacAddr()
{
    QString str = mData.mid(56,32);
    if(getHardMacAddrLen() == 6)
        return hexMac2NormalMac(str.left(12));
    return str;
}

QString BOOTPBag::getServerName()
{
    QString str = mData.mid(88,128);
    QString t,r;
    for(int i = 0; i < 56; ++i) {
        t = str.mid(2*i,2);
        if(str == "00")
            break;
        r += tcpip::hexStr2char(t);
    }
    return r;
}

QString BOOTPBag::getGuideFileName()
{
    QString str = mData.mid(216,256);
    QString t,r;
    for(int i = 0; i < 128; ++i) {
        t = str.mid(2*i,2);
        if(str == "00")
            break;
        r += tcpip::hexStr2char(t);
    }
    return r;
}

QString BOOTPBag::getOptionCode()
{
    QString str = mData.mid(472,128);
    return str;
}

QString BOOTPBag::getDescription()
{
    QString des;
    des = "BOOTP操作：" + getOperateType() + "\n";
    des += ("BOOTP硬件类型：" + getHardType() + "\n");
    des += ("BOOTP硬件地址长度：" + QString::number(getHardMacAddrLen()) + "\n");
    des += ("BOOTP跳数：" + QString::number(getJmpNum()) + "\n");
    des += ("BOOTP数据包时间：" + QString::number(getTime()) + "\n");
    des += ("BOOTP标志：" + getFlag() + "\n");
    des += ("BOOTP客户端IP地址：" + getClientIP() + "\n");
    des += ("本地IP地址：：" + getYourIP() + "\n");
    des += ("BOOTP服务器IP地址：" + getServerIP() + "\n");
    des += ("BOOTP网关IP地址：" + getNetMasterIP() + "\n");
    des += ("BOOTP客户端硬件地址：" + getClientMacAddr() + "\n");
    des += ("BOOTP服务器名字：" + getServerName() + "\n");
    des += ("BOOTP引导文件名：" + getGuideFileName() + "\n");
    des += ("BOOTP选项：" + getOptionCode() + "\n");
    return des;
}

ICMPV6Bag::ICMPV6Bag()
{

}

ICMPV6Bag::ICMPV6Bag(QString data)
{
    this->mData = data;
}

ICMPV6Bag::setData(QString data)
{
    this->mData = data;
}

QString ICMPV6Bag::getBagType()
{
    QString str = mData.mid(0,2);
    if(str.toInt(nullptr,16) < 128)
        return "差错报文";
    else
        return "信息报文";
}

QString ICMPV6Bag::getInfoType()
{
    QString str = mData.mid(0,2);
    QString r;
    switch (str.toInt(nullptr,16)) {
    case 1: r = "目的不可达"; break;
    case 2: r = "数据报文过答"; break;
    case 3: r = "超时"; break;
    case 4: r = "参数错误"; break;
    case 128: r = "回声请求"; break;
    case 129: r = "回声应答"; break;
    case 130: r = "组成员查询"; break;
    case 131: r = "组成员报告"; break;
    case 132: r = "组成员退出"; break;
    case 133: r = "路由器请求"; break;
    case 134: r = "路由器通告"; break;
    case 135: r = "邻居请求"; break;
    case 136: r = "邻居通告"; break;
    case 137: r = "重定向"; break;
    case 138: r = "路由器重编号"; break;
    case 139: r = "节点信息查询"; break;
    case 140: r = "节点信息应答"; break;
    default: r = "未知"; break;
    }
    return r;
}

QString ICMPV6Bag::getCode()
{
    QString str = mData.mid(2,2);
    return "0x" + str;
}

QString ICMPV6Bag::getCheckedNum()
{
    QString str = mData.mid(4,4);
    return hex2binary(str);
}

QString ICMPV6Bag::getDescription()
{
    QString des;
    des = "ICMPv6数据报文类型：" + getBagType() + "\n";
    des += ("ICMPv6报文内容类型：" + getInfoType() + "\n");
    des += ("ICMPv6报文代码：" + getCode() + "\n");
    des += ("ICMPv6校验和：" + getCheckedNum() + "\n");
    return des;
}
