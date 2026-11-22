#pragma once

#include <QList>
#include <QMainWindow>
#include <QPoint>
#include <QTreeWidgetItem>

#include "GxtParser.h"
#include "RpfReader.h"

class QAbstractTableModel;
class QAction;
class QComboBox;
class QLabel;
class QLineEdit;
class QPlainTextEdit;
class QSplitter;
class QStackedWidget;
class QTableView;
class QTextBrowser;
class QTreeWidget;
class QTableWidget;

class MainWindow : public QMainWindow {
    Q_OBJECT
public:
    explicit MainWindow(QWidget* parent = nullptr);

    bool loadFile(const QString& path);
    bool selectResourceBySeq(int seq);   // 界面启动后直达指定资源

private slots:
    void onOpen();
    void onExportSelected();
    void onExportAll();
    void onExportText();
    void onExportCorpus();
    void onExportGxt();
    void onExportEmbedded();
    void onItemSelected();
    void onItemDoubleClicked(QTreeWidgetItem* item, int column);
    void onTreeContextMenu(const QPoint& pos);

private:
    void buildTree();
    void showHeaderField(const HeaderField& f);
    void showResource(const Resource& r);
    void showNested(const NestedArchive& a);
    void showCoverage();
    void clearDetail(const QString& title);
    void showGxtPanel(const GxtInfo& info);
    void hideGxtPanel();
    void showResourceProperties(int index);
    void showDashboard();
    void applyTreeFilter();

    RpfReader m_reader;

    QTreeWidget*   m_tree = nullptr;
    QLineEdit*     m_treeFilter = nullptr;
    QComboBox*     m_treeType = nullptr;
    QComboBox*     m_treeMode = nullptr;
    QTableWidget*  m_props = nullptr;
    QPlainTextEdit* m_preview = nullptr;
    QStackedWidget* m_previewStack = nullptr;
    QTextBrowser*  m_dashboard = nullptr;
    QLabel*        m_status = nullptr;

    QWidget*       m_gxtPanel = nullptr;
    QLabel*        m_gxtInfo = nullptr;
    QLineEdit*     m_gxtFilter = nullptr;
    QTableView*    m_gxtView = nullptr;
    QAbstractTableModel* m_gxtModel = nullptr;
    QAction*       m_actExportGxt = nullptr;

    QList<GxtEntry> m_gxtEntries;
    bool            m_gxtValid = false;
};
