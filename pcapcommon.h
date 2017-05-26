#ifndef PCAPCOMMON_H
#define PCAPCOMMON_H

#include <WinSock2.h>
#include <QVector>
#include <QObject>

#include <Iphlpapi.h>
#include "pcap.h"
#include "sharkqthread.h"
#include "tcpipcommon.h"



#define PCAP_DEVPREFIX "/Device/NPF_"

class PcapCommon : public QObject
{
    Q_OBJECT

    public:
        PcapCommon();
        ~PcapCommon();
        // 扫描本机所有的适配器，并获取每个适配器的信息
        QVector<DEVInfo> findAllDev();

        // 设置本机信息：ip 、 掩码 、 Mac
        void closeLiveDev();
        bool setHostInfoAndOpenDev(QString devDescription);
        /** 开始捕获数据包 */
        bool startShark(QString filter);
        void stopShark();
        SharkQThread *getSharkQThread();
        bool isLiveDevOpen();
        HostInfo getHostInfo();

    public slots:
        void sharkUpdateDataSlot(QString data);
        void sharkStatusSlot(int num,QString msg);
        void sharkQThreadAlreadyStopedSlot();
        void on_receivedErrorMsgSlot(QString msg);

    signals:
        void sharkUpdateDataSig(QString data);
        void sharkStatusSig(int num,QString msg);
        void sharkQThreadAlreadyStopedSig();
        void sendErrorMsgSig(QString msg);

    private:
        pcap_t *mHandle;
        HostInfo mHost;
        SharkQThread *mSharkQThread;
        // 打开一个适配器
        bool openLiveDev(const char *dev);
};

#endif // PCAPCOMMON_H
