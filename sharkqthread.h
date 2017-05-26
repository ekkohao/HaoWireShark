#ifndef SHARKQTHREAD_H
#define SHARKQTHREAD_H

#include <QThread>
#include <cstdio>
#include "tcpipcommon.h"
#include "netprotocol.h"
#include "pcap.h"


class SharkQThread : public QThread

{
    Q_OBJECT

    public:
        SharkQThread();
        SharkQThread(const HostInfo &host, pcap_t *handle, QString filter);
        void quitThread();
        void preStartThread(const HostInfo &host, pcap_t *handle, QString filter);
        bool mIsRuning;
      private:
          bool init();
          void filterStart();
          void run();

          pcap_t * mHandle;
          HostInfo mHost;
          QString mFilter;
          EthernetHead * mEthernetHead;
          //A *mArppacket;
          IPv4Head * mIPv4Head;
          IPv6Head * mIPv6Head;
          ARPHead * mARPHead;
      signals:
          void sharkUpdateDataSig(QString data);
          void sharkStatusSig(int num,QString msg);
          void sendErrorMsgSig(QString msg);
};

#endif // SHARKQTHREAD_H
