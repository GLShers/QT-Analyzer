#include "dialog.h"
#include "ui_dialog.h"
#include <QModelIndexList>
#include <QDebug>



Dialog::Dialog(QWidget *parent)
    : QDialog(parent)
    , ui(new Ui::Dialog)
{
    ui->setupUi(this);
}

Dialog::~Dialog()
{
    delete ui;
}





