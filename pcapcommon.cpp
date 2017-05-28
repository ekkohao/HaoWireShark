#include "pcapcommon.h"
#include <QDebug>

PcapCommon::PcapCommon()
{
    mHandle = nullptr;
    mSharkQThread = nullptr;

}

PcapCommon::~PcapCommon()
{
    delete mSharkQThread;
    pcap_close(mHandle);
}

QVector<DEVInfo> PcapCommon::findAllDev()
{
    QVector<DEVInfo> allDev;
    DEVInfo tempDevInfo;
    //PIP_ADAPTER_INFO结构体指针存储本机网卡信息
    PIP_ADAPTER_INFO pIpAdapterInfo = new IP_ADAPTER_INFO();
    //得到结构体大小,用于GetAdaptersInfo参数
    unsigned long stSize = sizeof(IP_ADAPTER_INFO);
    //调用GetAdaptersInfo函数,填充pIpAdapterInfo指针变量;其中stSize参数既是一个输入量也是一个输出量
    int nRel = GetAdaptersInfo(pIpAdapterInfo,&stSize);
    //记录网卡数量
    //int netCardNum = 0;
    //记录每张网卡上的IP地址数量
    //int IPnumPerNetCard = 0;
    if (ERROR_BUFFER_OVERFLOW == nRel)
    {
        //如果函数返回的是ERROR_BUFFER_OVERFLOW
        //则说明GetAdaptersInfo参数传递的内存空间不够,同时其传出stSize,表示需要的空间大小
        //这也是说明为什么stSize既是一个输入量也是一个输出量
        //释放原来的内存空间
        delete pIpAdapterInfo;
        //重新申请内存空间用来存储所有网卡信息
        pIpAdapterInfo = (PIP_ADAPTER_INFO)new BYTE[stSize];
        //再次调用GetAdaptersInfo函数,填充pIpAdapterInfo指针变量
        nRel=GetAdaptersInfo(pIpAdapterInfo,&stSize);
     }
    if (ERROR_SUCCESS == nRel)
    {
        //输出网卡信息
        //可能有多网卡,因此通过循环去判断
        while (pIpAdapterInfo)
        {
            tempDevInfo.name = pIpAdapterInfo->AdapterName;
            tempDevInfo.description = QString::fromLocal8Bit(pIpAdapterInfo->Description);

            switch(pIpAdapterInfo->Type)
            {
            case MIB_IF_TYPE_OTHER:
               tempDevInfo.type = "OTHER";
               break;
            case MIB_IF_TYPE_ETHERNET:
               tempDevInfo.type = "ETHERNET";
               break;
            case MIB_IF_TYPE_TOKENRING:
               tempDevInfo.type = "TOKENRING";
               break;
            case MIB_IF_TYPE_FDDI:
               tempDevInfo.type = "FDDI";
               break;
            case MIB_IF_TYPE_PPP:
               tempDevInfo.type = "PPP";
               break;
            case MIB_IF_TYPE_LOOPBACK:
               tempDevInfo.type = "LOOPBACK";
               break;
            case MIB_IF_TYPE_SLIP:
               tempDevInfo.type = "SLIP";
               break;
            default:
                tempDevInfo.type = "unknown";
               break;
            }

            //"网卡MAC地址：";
            QString macAddr("");
            char ctempAddr[3];

            for (DWORD i = 0; i < pIpAdapterInfo->AddressLength; i++) {
                sprintf(ctempAddr,"%02X", pIpAdapterInfo->Address[i]);
                //ctempAddr[2]=0x00;
                macAddr += (QString(ctempAddr) + "-");
                //ctempAddr[0] = 0x00;
            }
            int len = macAddr.length();
            if ( len > 2)
            tempDevInfo.mac = macAddr.left(len - 1);
           //cout<<"网卡IP地址如下："<<endl;
           //可能网卡有多IP,因此通过循环去判断
           IP_ADDR_STRING *pIpAddrString =&(pIpAdapterInfo->IpAddressList);
           //do
           //{
           //cout<<"该网卡上的IP数量："<<++IPnumPerNetCard<<endl;
           tempDevInfo.address = pIpAddrString->IpAddress.String;
           tempDevInfo.netmask = pIpAddrString->IpMask.String;
           tempDevInfo.gateway = pIpAdapterInfo->GatewayList.IpAddress.String;
           //pIpAddrString=pIpAddrString->Next;
           //} while (pIpAddrString);
           allDev.append(tempDevInfo);
           pIpAdapterInfo = pIpAdapterInfo->Next;
           //cout<<"--------------------------------------------------------------------"<<endl;
        }//end while

    }
    //释放内存空间
    if (pIpAdapterInfo)
    {
       delete pIpAdapterInfo;
       pIpAdapterInfo = nullptr;
    }
    return allDev;
}

void PcapCommon::closeLiveDev()
{
    pcap_close(mHandle);

    mHost.address = "";
    mHost.charName[0] = 0x00;
    mHost.gateway = "";
    mHost.mac = "";
    mHost.netmask ="";
}

//打开一个适配器
bool PcapCommon::openLiveDev(const char *dev)
{
    char errBuf[PCAP_ERRBUF_SIZE] = {0};

    //混杂模式
    if(isLiveDevOpen()) {
        //qDebug() << "open live sucess \n" << mHost.charName << " -- " <<mHost.mac;
        mHandle = pcap_open_live(dev,65535,1,0,errBuf);
        //qDebug() << "error:" << QString(dev) << " : "<< QString::fromLocal8Bit(errBuf);
        if (mHandle == nullptr) {
            emit sendErrorMsgSig(QString::fromLocal8Bit(errBuf) + "\n请检查NPF服务是否打开");
            return false;
        }
        else
            return true;
            ;
    }
    else {
        //qDebug() << "open live false";
        mHost.address = "";
        mHost.charName[0] = 0x00;
        mHost.gateway = "";
        mHost.mac = "";
        mHost.netmask ="";
        emit sendErrorMsgSig("本机信息获取失败");
    }

    return false;
}

/** 设置本机信息：ip 、 掩码 、 Mac */
bool PcapCommon::setHostInfoAndOpenDev(QString devDescription)
{
    QVector<DEVInfo> allDev(this->findAllDev());

    int len = allDev.length();
    for(int i = 0; i < len; ++i) {
        if(allDev.at(i).description == devDescription) {
            QString devName = PCAP_DEVPREFIX + allDev.at(i).name;
            QByteArray tempBA = devName.toLatin1();
            tcpip::strcpy(mHost.charName, tempBA.data());
            mHost.address = allDev.at(i).address;
            mHost.mac = allDev.at(i).mac;
            mHost.netmask = allDev.at(i).netmask;
            mHost.gateway = allDev.at(i).gateway;
            return openLiveDev(mHost.charName);
        }
    }
    return false;

}

bool PcapCommon::startShark(QString filter)
{
    char errBuf[PCAP_ERRBUF_SIZE] = {0};
    pcap_t * handle = pcap_open_live(mHost.charName,65535,1,0,errBuf);
    if(handle == nullptr || !this->isLiveDevOpen()) {
        qDebug() << "start shark failed" << this->isLiveDevOpen();
        return false;
    }

    mSharkQThread = new SharkQThread(mHost,handle,filter);

    connect(mSharkQThread,SIGNAL(sharkUpdateDataSig(QString)),this,SLOT(sharkUpdateDataSlot(QString)));
    connect(mSharkQThread,SIGNAL(sharkStatusSig(int,QString)),this,SLOT(sharkStatusSlot(int,QString)));
    connect(mSharkQThread,SIGNAL(finished()),this,SLOT(sharkQThreadAlreadyStopedSlot()));
    connect(mSharkQThread,SIGNAL(sendErrorMsgSig(QString)),this,SLOT(on_receivedErrorMsgSlot(QString)));

    mSharkQThread->start();
    return mSharkQThread->isRunning();

}

void PcapCommon::stopShark()
{
    if(mSharkQThread != nullptr) {
        mSharkQThread->quitThread();
        mSharkQThread->wait();
        delete mSharkQThread;
        mSharkQThread = nullptr;
    }
}

SharkQThread *PcapCommon::getSharkQThread()
{
    return mSharkQThread;
}

bool PcapCommon::isLiveDevOpen()
{
    //qDebug() << "devName1:" << mHost.charName;
    QString devName = QString(mHost.charName);
    //qDebug() << "devName2:" << devName;
    return !devName.isEmpty();
}

HostInfo PcapCommon::getHostInfo()
{
    return mHost;
}

void PcapCommon::sharkUpdateDataSlot(QString data)
{
    emit sharkUpdateDataSig(data);
}

void PcapCommon::sharkStatusSlot(int num, QString msg)
{
    emit sharkStatusSig(num,msg);
}

void PcapCommon::sharkQThreadAlreadyStopedSlot()
{
    delete mSharkQThread;
    mSharkQThread = nullptr;
    emit sharkQThreadAlreadyStopedSig();
}

void PcapCommon::on_receivedErrorMsgSlot(QString msg)
{
    emit sendErrorMsgSig(msg);
}
