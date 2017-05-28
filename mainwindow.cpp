#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <QDebug>
#include <iostream>
using namespace std;

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    this->comboboxAdapterInit();

    mAboutBox = new AboutBox(this);

    pcap = new PcapCommon();

    ui->pushButtonStartShark->setEnabled(false);
    //ui->pushButtonCls->setEnabled(false);

    ui->tableWidgetBags->setColumnCount(6);
    QStringList tableHeader ;
    tableHeader<<"TIME"<<"PROTOCOL"<<"SOURCE"<<"DESTINATION"<<"SIZE"<<"";
    ui->tableWidgetBags->setHorizontalHeaderLabels(tableHeader);
    ui->tableWidgetBags->horizontalHeader()->setStretchLastSection(true);
    ui->tableWidgetBags->setSelectionBehavior(QAbstractItemView::SelectRows);
    ui->tableWidgetBags->setSelectionMode(QAbstractItemView::SingleSelection);
    ui->tableWidgetBags->setEditTriggers(QAbstractItemView::NoEditTriggers);
    ui->stackedWidget->setCurrentIndex(0);
    ui->tableWidgetBags->setContextMenuPolicy(Qt::CustomContextMenu);
    popTableMenu = new QMenu(ui->tableWidgetBags);
    popTableAction = new QAction("分析此数据包",this);

    ui->lineEditPageCur->setText("1");

    this->connect(pcap,SIGNAL(sharkUpdateDataSig(QString)),this,SLOT(sharkUpdateDataSlot(QString)));
    this->connect(pcap,SIGNAL(sharkStatusSig(int,QString)),this,SLOT(sharkStatusSlot(int,QString)));
    this->connect(pcap,SIGNAL(sharkQThreadAlreadyStopedSig()),this,SLOT(sharkQThreadAlreadyStopedSlot()));
    this->connect(ui->tableWidgetBags,SIGNAL(cellClicked(int,int)),this,SLOT(on_tableItemClicked(int,int)));
    this->connect(popTableAction, SIGNAL(triggered()), this, SLOT(itemRightClickedOperationSlot()));
    this->connect(pcap,SIGNAL(sendErrorMsgSig(QString)),this,SLOT(on_receivedErrorMsg(QString)));
    updateTableWidgetWidth();
}

MainWindow::~MainWindow()
{
    //if(ui->pushButtonStartShark->text() == "停止捕获")
     //   pcap->stopShark();
    delete popTableMenu;

    delete popTableAction;
    delete ui;
    delete mAboutBox;
    pcap->stopShark();
    //while(pcap->getSharkQThread()->isRunning()){}
    pcap->deleteLater();//QObject 如果在父程序析构中delete需要这样做

}

// combobox adapter 初始化
void MainWindow::comboboxAdapterInit()
{
    QVector<DEVInfo> devInfo(pcap->findAllDev());
    while(ui->ComboBoxAdapter->count() > 0){
        ui->ComboBoxAdapter->removeItem(0);
    }

    for(int i = 0; i < devInfo.length(); ++i){
        QPixmap icon  = style()->standardPixmap(QStyle::SP_DriveNetIcon);
        ui->ComboBoxAdapter->addItem(icon,devInfo.at(i).description + "{mac address:" + devInfo.at(i).mac + "}");
    }
}

void MainWindow::updatePageNumTag(int sum)
{
    int showSum = ui->labelPageTotal->text().toInt();
    if( sum > showSum)
        ui->labelPageTotal->setText(QString::number(sum));
}

void MainWindow::updateTableWidget(bool flag)
{
    if(mBagsList.isEmpty())
        return;
    int len = mBagsList.length();
    int index = (ui->lineEditPageCur->text().toInt() - 1) * SHOWNUMPPAGE;
    int index_max = index + SHOWNUMPPAGE;

    if(!flag) {
        index += ui->tableWidgetBags->rowCount();
    }
    else {
        ui->tableWidgetBags->setRowCount(0);
    }

    while (index < len && index < index_max) {
        QString bag = mBagsList.at(index);
        int i = bag.indexOf("|||");
        QString data = bag.left(i);
        //QString info = bag.mid(i+3);

        int row = ui->tableWidgetBags->rowCount();
        ui->tableWidgetBags->insertRow(row);
        QStringList dataList = data.split(",,,");
        for(int i=0; i < 5; ++i)
            ui->tableWidgetBags->setItem(row,i,new QTableWidgetItem(dataList.at(i)));
        if(ui->checkBoxLiveShark->isChecked() && ui->pushButtonStartShark->text() == "停止捕获")
            ui->tableWidgetBags->scrollToBottom();
        //else if(index % 3 == 0)
        //    repaint();
        ++index;
    }
}

bool MainWindow::setCurPageNum(int num)
{
    if (num < 1 || num > ui->labelPageTotal->text().toInt())
        return false;

    int curSum = ui->lineEditPageCur->text().toInt();
    if( num != curSum) {
        ui->lineEditPageCur->setText(QString::number(num));
        return true;
    }
    return false;
}

void MainWindow::updateTableWidgetWidth()
{
    ui->tableWidgetBags->setColumnWidth(0,100);
    ui->tableWidgetBags->setColumnWidth(1,110);
    ui->tableWidgetBags->setColumnWidth(2,350);
    ui->tableWidgetBags->setColumnWidth(3,350);
    ui->tableWidgetBags->setColumnWidth(4,90);
}

void MainWindow::on_pushButtonOpenAdapter_clicked()
{
    if (ui->pushButtonOpenAdapter->text() == "打开适配器") {
        QString devDescription = ui->ComboBoxAdapter->currentText();
        int k = devDescription.lastIndexOf("{");
        devDescription = devDescription.left(k);

        /** 获取并打开选择网卡name,mac,ip和netmask */
        if (pcap->setHostInfoAndOpenDev(devDescription)) {
            HostInfo host = pcap->getHostInfo();
            QStringList hostInfoList;
            hostInfoList << " IP: " + host.address + " "
                         << " MAC: " + host.mac+ " "
                         << " 网关: " + host.gateway+ " "
                         << " 子网掩码: " + host.netmask+ " ";
            ui->ComboBoxAdapter->setEnabled(false);
            ui->pushButtonStartShark->setEnabled(true);
            //ui->pushButtonCls->setEnabled(true);
            ui->pushButtonOpenAdapter->setText("关闭适配器");
            ui->labelTips->setText("<p style=\"color:green\">适配器已打开 |"+ QString(hostInfoList.join('|')) +"</p>");
        }
    }
    else {
        if(ui->pushButtonStartShark->text() == "停止捕获"){
            ui->pushButtonStartShark->setEnabled(false);
            mClsAllFlag = true;
            pcap->stopShark();

        }
        pcap->closeLiveDev();
        ui->ComboBoxAdapter->setEnabled(true);
        ui->pushButtonStartShark->setEnabled(false);
        //ui->pushButtonCls->setEnabled(false);
        ui->pushButtonOpenAdapter->setText("打开适配器");
        ui->labelTips->setText("<p style=\"color:red\">适配器已关闭</p>");
    }

    // 3线程获取本机MAC
    //pcap->getSelfMac();
    // 开启流量监控线程
    //pcap->trafficStatistic(devName);

}

void MainWindow::on_pushButtonStartShark_clicked()
{
    QString filter = ui->lineEditFilter->text().trimmed();
    if(ui->pushButtonStartShark->text() == "开始捕获") {
        ui->pushButtonStartShark->setEnabled(false);
        if(!pcap->startShark(filter)) {
            ui->pushButtonStartShark->setEnabled(true);
        }
    }
    else {
        mClsAllFlag = false;
        ui->pushButtonStartShark->setEnabled(false);
        pcap->stopShark();
    }
}

void MainWindow::sharkUpdateDataSlot(QString data)
{
    mBagsList.append(data);
    int pageSum = mBagsList.length() / SHOWNUMPPAGE + 1;
    updatePageNumTag(pageSum);

    if(ui->checkBoxLiveShark->isChecked()) {
        updateTableWidget(setCurPageNum(pageSum));
    }
}

void MainWindow::sharkStatusSlot(int num, QString msg)
{
    if(num == 0) {
        ui->pushButtonStartShark->setEnabled(true);
        ui->pushButtonStartShark->setText("停止捕获");
    }
    else if(num < 0)
        on_receivedErrorMsg(msg);
}

void MainWindow::sharkQThreadAlreadyStopedSlot()
{
    if(!mClsAllFlag)
        ui->pushButtonStartShark->setEnabled(true);
    ui->pushButtonStartShark->setText("开始捕获");
}

void MainWindow::on_pushButtonNextPage_clicked()
{
    int curNum = ui->lineEditPageCur->text().toInt();
    updateTableWidget(setCurPageNum(curNum + 1));
}

void MainWindow::on_pushButtonBackPage_clicked()
{
    int curNum = ui->lineEditPageCur->text().toInt();
    updateTableWidget(setCurPageNum(curNum - 1));
}

void MainWindow::on_tableItemClicked(int row, int colomn)
{
    int curNum = ui->lineEditPageCur->text().toInt();
    int index = (curNum - 1) * SHOWNUMPPAGE + row;
    int i;
    int len;
    colomn = 0;

    if(index > mBagsList.length() - 1)
        return;
    QString bag = mBagsList.at(index);
    i = bag.indexOf("|||");
    QString info = bag.mid(i + 3);
    QString rgx_info;
    QString printStr;
    QString qsT;

    len = info.length();
    for (i = 0; i < len / 2; ++i) {
        qsT = info.mid(2*i,2);

        rgx_info += ( qsT + " ");
        printStr += QString(tcpip::hexStr2char(qsT));

        if(i % 8 == 7){
            rgx_info += " ";
            printStr += " ";
        }
        if(i % 16 == 15){
            rgx_info += ("  " + printStr + "\n");
            printStr.clear();
        }
    }

    i = (len / 2) % 16;
    if( i != 15) {
        if(i < 7)
            rgx_info +=" ";
        rgx_info += QString(3*(17-i), ' ');
        rgx_info += printStr;
    }


    ui->textBrowserCode->setText(rgx_info);
}

void MainWindow::on_tableWidgetBags_customContextMenuRequested(const QPoint &pos)
{
    QTableWidgetItem *item;
    item = ui->tableWidgetBags->itemAt(pos);
    if( item== NULL)
        return;
    mRightClickedRow = ui->tableWidgetBags->row(item);
    popTableMenu->addAction(popTableAction);
    popTableMenu->exec(QCursor::pos());

}

void MainWindow::itemRightClickedOperationSlot()
{
    int curNum = ui->lineEditPageCur->text().toInt();
    int index = (curNum - 1) * SHOWNUMPPAGE + mRightClickedRow;
    int i;
    int len;

    if(index > mBagsList.length() - 1)
        return;
    QString bag = mBagsList.at(index);
    i = bag.indexOf("|||");
    QString info = bag.mid(i + 3);
    QString rgx_info;
    QString qsT;

    len = info.length();
    for (i = 0; i < len / 2; ++i) {
        qsT = info.mid(2*i,2);

        rgx_info += ( qsT + " ");

        if(i % 8 == 7){
            rgx_info += " ";
        }
        if(i % 16 == 15){
            rgx_info += ("\n");
        }
    }

    ui->textEditSrc->setText(rgx_info);
    on_pushButtonStartAna_clicked();
    ui->stackedWidget->setCurrentIndex(1);
}

void MainWindow::on_pushButton_clicked()
{
    if(ui->stackedWidget->currentIndex() != 0)
        ui->stackedWidget->setCurrentIndex(0);
}

void MainWindow::on_pushButton_3_clicked()
{
    if(ui->stackedWidget->currentIndex() != 1)
        ui->stackedWidget->setCurrentIndex(1);
}

void MainWindow::on_pushButtonCls_clicked()
{
    mBagsList.clear();
    ui->tableWidgetBags->setRowCount(0);
    ui->labelPageTotal->setText(QString::number(1));
    ui->lineEditPageCur->setText(QString::number(1));
}

void MainWindow::on_pushButtonStartAna_clicked()
{
    QString data = ui->textEditSrc->toPlainText();
    QRegExp re("[ \n]");
    data.remove(re);
    EthernetHead ethernetHead(data.left(ETHERNET_HEAD_LENGTH * 2));
    if(ethernetHead.getEthernetType() == "IPv4"){
        IPv4Head ipv4Head(data.mid(ETHERNET_HEAD_LENGTH * 2,IPV4_HEAD_LENGTH * 2));
        if(ipv4Head.getIpv4Type() == "TCP") {
            TCPBag tcpBag(data.mid((ETHERNET_HEAD_LENGTH + ipv4Head.getIPv4HeadLength()) * 2));
            ui->textEditResults->setText(ethernetHead.getDescription() + ipv4Head.getDescription() + tcpBag.getDescription());
        }
        else if (ipv4Head.getIpv4Type() == "UDP") {
            UDPBag udpBag(data.mid((ETHERNET_HEAD_LENGTH + ipv4Head.getIPv4HeadLength()) * 2));
            if(udpBag.isBOOTPBag()) {
                BOOTPBag bootpBag(data.mid((ETHERNET_HEAD_LENGTH + ipv4Head.getIPv4HeadLength() + UDP_HEAD_LENGTH) * 2));
                ui->textEditResults->setText(ethernetHead.getDescription() + ipv4Head.getDescription() + bootpBag.getDescription());
            }
            else
                ui->textEditResults->setText(ethernetHead.getDescription() + ipv4Head.getDescription() + udpBag.getDescription());
        }
        else if (ipv4Head.getIpv4Type() == "ICMP") {
            ICMPBag icmpbag(data.mid((ETHERNET_HEAD_LENGTH + ipv4Head.getIPv4HeadLength()) * 2));
            ui->textEditResults->setText(ethernetHead.getDescription() + ipv4Head.getDescription() + icmpbag.getDescription());
        }
        else if (ipv4Head.getIpv4Type() == "IGMP") {
            IGMPBag igmpBag(data.mid((ETHERNET_HEAD_LENGTH + ipv4Head.getIPv4HeadLength()) * 2));
            ui->textEditResults->setText(ethernetHead.getDescription() + ipv4Head.getDescription() + igmpBag.getDescription());
        }
        else {
            ui->textEditResults->setText(ethernetHead.getDescription() + ipv4Head.getUnknownDescription());
        }
    }
    else if (ethernetHead.getEthernetType() == "IPv6") {
        IPv6Head ipv6Head(data.mid(ETHERNET_HEAD_LENGTH * 2,IPV6_HEAD_LENGTH * 2));
        ipv6Head.setExtend(data.mid(ETHERNET_HEAD_LENGTH * 2 + IPV6_HEAD_LENGTH * 2));
        if(ipv6Head.getIPv6Type() == "TCP") {
            TCPBag tcpBag(ipv6Head.getBody());
            ui->textEditResults->setText(ethernetHead.getDescription() + ipv6Head.getDescription() + tcpBag.getDescription());
        }
        else if (ipv6Head.getIPv6Type() == "UDP") {
            UDPBag udpBag(ipv6Head.getBody());
            if(udpBag.isBOOTPBag()) {
                BOOTPBag bootpBag(ipv6Head.getBody().mid(UDP_HEAD_LENGTH * 2));
                ui->textEditResults->setText(ethernetHead.getDescription() + ipv6Head.getDescription() + bootpBag.getDescription());
            }
            else
                ui->textEditResults->setText(ethernetHead.getDescription() + ipv6Head.getDescription() + udpBag.getDescription());
        }
        else if (ipv6Head.getIPv6Type() == "ICMPv6") {
            ICMPV6Bag icmpv6Bag(ipv6Head.getBody());
            ui->textEditResults->setText(ethernetHead.getDescription() + ipv6Head.getDescription() + icmpv6Bag.getDescription());
        }
        else {
            ui->textEditResults->setText(ethernetHead.getDescription() + ipv6Head.getDescription());
        }
    }
    else if (ethernetHead.getEthernetType() == "ARP") {
        ARPHead arpHead(data.mid(ETHERNET_HEAD_LENGTH * 2,ARP_HEAD_LENGTH * 2));
        ui->textEditResults->setText(ethernetHead.getDescription() + arpHead.getDescription());
    }
    else if (ethernetHead.getEthernetType() == "RARP") {

    }
    else {
        ui->textEditResults->setText("报文分析失败，请检查报文结构是否完整。");
    }
    //qDebug() << data;
}

void MainWindow::on_receivedErrorMsg(QString msg)
{
    QMessageBox::warning(this,"错误",msg,QMessageBox::Yes);
}

void MainWindow::on_pushButton_4_clicked()
{
   mAboutBox->show();
}
