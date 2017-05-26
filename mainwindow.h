#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QVector>
#include <QRegExp>
#include <QMessageBox>

#include "pcapcommon.h"
#include "netprotocol.h"
#include "aboutbox.h"

#define SHOWNUMPPAGE 100

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = 0);
    ~MainWindow();

private slots:
    void on_pushButtonOpenAdapter_clicked();

    void on_pushButtonStartShark_clicked();

    void sharkUpdateDataSlot(QString data);

    void sharkStatusSlot(int num,QString msg);

    void sharkQThreadAlreadyStopedSlot();

    void on_pushButtonNextPage_clicked();

    void on_pushButtonBackPage_clicked();

    void on_tableItemClicked(int row,int colomn);

    void on_tableWidgetBags_customContextMenuRequested(const QPoint &pos);

    void itemRightClickedOperationSlot();

    void on_pushButton_clicked();

    void on_pushButton_3_clicked();

    void on_pushButtonCls_clicked();

    void on_pushButtonStartAna_clicked();

    void on_receivedErrorMsg(QString msg);
    void on_pushButton_4_clicked();

private:
    Ui::MainWindow *ui;
    QMenu *popTableMenu;
    QAction *popTableAction;
    AboutBox *mAboutBox;
    //Pcap
    PcapCommon *pcap;
    bool mClsAllFlag;

    int mRightClickedRow;

    /** 接收数据包列表 */
    QStringList mBagsList;

    /** 当前显示 */

    //初始化Adapter
    void comboboxAdapterInit();

    void updatePageNumTag(int sum);

    void updateTableWidget(bool flag);
    /** 更改页码，若更改成功（即与原来当前页码不同），返回true */
    bool setCurPageNum(int num);

};

#endif // MAINWINDOW_H
