#include "sharkqthread.h"

#include <QDebug>

using namespace tcpip;

SharkQThread::SharkQThread()
{

}

SharkQThread::SharkQThread(const HostInfo &host,pcap_t *handle, QString filter)
{
    preStartThread(host,handle,filter);

    mEthernetHead = new EthernetHead();
    mIPv4Head = new IPv4Head();
    mIPv6Head = new IPv6Head();
    mARPHead = new ARPHead();
}

void SharkQThread::quitThread()
{
    //qDebug()<< "Quit filter Thread";
    emit sharkStatusSig(1,QString(tr("停止过滤抓包")));
    delete mEthernetHead;
    delete mIPv4Head;
    delete mIPv6Head;
    mIsRuning = false;
    pcap_close(this->mHandle);
    this->quit();

}

void SharkQThread::preStartThread(const HostInfo &host, pcap_t *handle, QString filter)
{
    mIsRuning = true;
    this->mFilter = filter;
    //混杂模式
    this->mHandle = handle;

    mHost.address = host.address;
    tcpip::strcpy(mHost.charName,host.charName);
    mHost.gateway = host.gateway;
    mHost.mac = host.mac;
    mHost.netmask = host.netmask;
}

bool SharkQThread::init()
{
    bpf_program fcode;
    // 不用关心掩码，在这个过滤器中，它不会被使用
    QByteArray bytearray = this->mFilter.toUtf8();
    char * filterCS = bytearray.data();
    // 编译过滤器
    if(pcap_compile(mHandle, &fcode, filterCS, 1, host2netl(ipnormal2net(mHost.netmask.toLocal8Bit().data()))) < 0){
        emit sendErrorMsgSig("Unable to compile the packet filter. Check the syntax.");
        emit sharkStatusSig(-1,QString(tr("过滤语法错误！")));
        quitThread();
        // 释放设备列表
        return false;
    }
    // 设置过滤器
    if(pcap_setfilter(mHandle, &fcode) < 0){
        emit sendErrorMsgSig("Error setting the filter.");
        emit sharkStatusSig(-2,QString(tr("设置过滤器出错！")));
        quitThread();
        // 释放设备列表
        return false;
    }

    return true;
}

void SharkQThread::filterStart()
{
    pcap_t *adhandle = this->mHandle;
    int res;
    struct pcap_pkthdr * pktHeader;
    const u_char * pktData;
    QString strData;
    char timestr[16] = {0};
    time_t local_tv_sec;
    struct tm *ltime;

    while (mIsRuning) {
        if ((res = pcap_next_ex(adhandle, &pktHeader, &pktData)) >= 0) {
            //qDebug() << "has bag!!!";
            strData.clear();

            char tt[4];
            for(u_int i = 0; i < pktHeader->len; ++i) {
                sprintf(tt,"%02X",pktData[i]);
                strData += QString(tt);
            }

            mEthernetHead->setData(strData.left(ETHERNET_HEAD_LENGTH * 2));

            local_tv_sec = pktHeader->ts.tv_sec;
            ltime=localtime(&local_tv_sec);
            strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);

            // 先通过以太网头判断是IP包还是ARP包
            if(mEthernetHead->getEthernetType() == "ARP"){
                mARPHead->setData(strData.mid(2 * ETHERNET_HEAD_LENGTH ,2 * ARP_HEAD_LENGTH));
                QString msg = QString("%1,,,%2,,,%3,,,%4,,,%5|||%6")
                              .arg(QString(timestr),
                                   mARPHead->getOperateType(),
                                   mARPHead->getSendMacAddr(),
                                   mARPHead->getDestinationMacAddr(),
                                   QString::number(pktHeader->len),
                                   strData
                                   );

                emit sharkUpdateDataSig(msg);

            }
            else if(mEthernetHead->getEthernetType() == "IPv4"){
                mIPv4Head->setData(strData.mid(2 * ETHERNET_HEAD_LENGTH ,2 * IPV4_HEAD_LENGTH));
                QString msg;

                msg = QString("%1,,,IPV4-%2,,,%3,,,%4,,,%5|||%6")
                              .arg(QString(timestr),
                                   mIPv4Head->getIpv4Type(),
                                   mIPv4Head->getSourceIP(),
                                   mIPv4Head->getDestinationIP(),
                                   QString::number(pktHeader->len),
                                   strData
                                   );

                if (mIPv4Head->getIpv4Type() == "UDP") {
                    UDPBag udpBag(strData.mid(2 * ETHERNET_HEAD_LENGTH + 2 * mIPv4Head->getIPv4HeadLength()));
                    if(udpBag.isBOOTPBag()) {
                        msg = QString("%1,,,BOOTP/DHCP,,,%2,,,%3,,,%4|||%5")
                              .arg(QString(timestr),
                                   mIPv4Head->getSourceIP(),
                                   mIPv4Head->getDestinationIP(),
                                   QString::number(pktHeader->len),
                                   strData
                                   );
                    }
                }

                //qDebug()<< msg;
                emit sharkUpdateDataSig(msg);
            }
            else if(mEthernetHead->getEthernetType() == "IPv6"){
                mIPv6Head->setData(strData.mid(2 * ETHERNET_HEAD_LENGTH ,2 * IPV6_HEAD_LENGTH));
                mIPv6Head->setExtend(strData.mid(2 * ETHERNET_HEAD_LENGTH + 2 * IPV6_HEAD_LENGTH));
                QString msg = QString("%1,,,IPV6-%2,,,%3,,,%4,,,%5|||%6")
                              .arg(QString(timestr),
                                   mIPv6Head->getIPv6Type(),
                                   mIPv6Head->getSourceIP(),
                                   mIPv6Head->getDestinationIP(),
                                   QString::number(pktHeader->len),
                                   strData
                                   );
                //qDebug()<< msg;
                emit sharkUpdateDataSig(msg);
            }
            else {
                qDebug() << "OTHER";
            }
        }
        // 接收缓冲下，会间歇性丢包
        usleep(100000);
    }
}

void SharkQThread::run()
{
    if(init()){
        //qDebug()<< "Filter thread init finished!";
        emit sharkStatusSig(0,QString(tr("开始过滤抓包")));
        filterStart();
    }
}
