// MainWindow.h
// Константы для типов блоков pcapng
#define SECTION_HEADER_BLOCK 0x0A0D0D0A
#define INTERFACE_DESCRIPTION_BLOCK 0x00000001
#define ENHANCED_PACKET_BLOCK 0x00000006
#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QListWidgetItem>
#include "infopacet.h"


QT_BEGIN_NAMESPACE//открывает пространство имен
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private slots:
    void on_action_triggered();
    void readPcapngFile(const QString &fileName);
    void on_listWidget_currentItemChanged(QListWidgetItem *current, QListWidgetItem *previous);
    void on_pushButton_clicked();
    void on_lineEdit_textChanged(const QString &text);
    void on_listWidget_itemDoubleClicked(QListWidgetItem *item);

private:
    Ui::MainWindow *ui;
    void filterPackets(const QString &text);
    void processSectionHeaderBlock(const quint8 *data, quint32 blockLength);
    void processInterfaceDescriptionBlock(const quint8 *data, quint32 blockLength);
    void processEnhancedPacketBlock(const quint8 *data, quint32 blockLength);
};


#endif // MAINWINDOW_H
