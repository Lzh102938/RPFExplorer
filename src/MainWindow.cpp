#include "MainWindow.h"

#include "EmbeddedScan.h"
#include "DrpFile.h"
#include "GxtParser.h"

#include <functional>
#include <QComboBox>
#include <QElapsedTimer>
#include <QIcon>
#include <QPainter>
#include <QStackedWidget>
#include <QTextBrowser>
#include <QAbstractTableModel>
#include <QAction>
#include <QApplication>
#include <QCoreApplication>
#include <QDialog>
#include <QDir>
#include <QFile>
#include <QFileDialog>
#include <QFileInfo>
#include <QFormLayout>
#include <QFont>
#include <QHBoxLayout>
#include <QHash>
#include <QHeaderView>
#include <QImage>
#include <QLabel>
#include <QLineEdit>
#include <QMenu>
#include <QMenuBar>
#include <QMessageBox>
#include <QPixmap>
#include <QPlainTextEdit>
#include <QProgressDialog>
#include <QPushButton>
#include <QRegularExpression>
#include <QSet>
#include <QSignalBlocker>
#include <QSplitter>
#include <QStatusBar>
#include <QStringConverter>
#include <QTabWidget>
#include <QTableWidget>
#include <QTableView>
#include <QToolBar>
#include <QTreeWidget>
#include <QUrl>
#include <QVBoxLayout>
#include <QVector>

#include <algorithm>
#include <cstring>

namespace {
// 十六进制 + 可打印 ASCII 预览（类似 hexdump）
QString hexDump(const QByteArray& d, int maxBytes = 4096) {
    QString out;
    const int n = qMin(d.size(), maxBytes);
    for (int r = 0; r < n; r += 16) {
        out += QStringLiteral("%1  ").arg(r, 8, 16, QChar('0'));
        QString asc;
        for (int i = 0; i < 16; ++i) {
            if (r + i < n) {
                const uint8_t c = static_cast<uint8_t>(d[r + i]);
                out += QStringLiteral("%1 ").arg(c, 2, 16, QChar('0'));
                asc += (c >= 0x20 && c < 0x7F) ? QChar(c) : QChar('.');
            } else {
                out += QStringLiteral("   ");
                asc += QChar(' ');
            }
        }
        out += QStringLiteral(" |%1|\n").arg(asc);
    }
    if (d.size() > maxBytes)
        out += QStringLiteral("\n…（共 %1 字节，仅显示前 %2）").arg(d.size()).arg(maxBytes);
    return out;
}

QString textPreview(const QByteArray& d, int maxChars = 4000) {
    QString s = QString::fromUtf8(d.constData(), qMin(d.size(), maxChars));
    s.replace(QChar('\0'), QChar(0x00B7));
    return s;
}

// 从二进制里提取可打印字符串：严格 UTF-8、以 NUL 结尾、长度 >= minLen。
// 只用于「帮助人眼找线索」，不代表任何结构解析。
QList<QPair<int, QString>> printableStrings(const QByteArray& d, int minLen, int maxItems) {
    QList<QPair<int, QString>> out;
    int i = 0;
    while (i < d.size() && out.size() < maxItems) {
        const uint8_t c = static_cast<uint8_t>(d[i]);
        if (c < 0x20 || c == 0x7F) { ++i; continue; }
        const int start = i;
        while (i < d.size()) {
            const uint8_t b = static_cast<uint8_t>(d[i]);
            if (b == 0 || b < 0x20 || b == 0x7F) break;
            ++i;
        }
        const QByteArray candidate = d.mid(start, i - start);
        if (candidate.size() >= minLen) {
            QStringDecoder dec(QStringDecoder::Utf8);
            const QString s = dec.decode(candidate);
            if (!dec.hasError()) {
                bool printable = true;
                for (const QChar ch : s) {
                    if (!ch.isPrint()) { printable = false; break; }
                }
                if (printable) out.append({start, s});
            }
        }
        ++i;
    }
    return out;
}

// 小端读取
inline quint32 le32(const QByteArray& b, int o) {
    return quint32(quint8(b[o])) | (quint32(quint8(b[o + 1])) << 8)
         | (quint32(quint8(b[o + 2])) << 16) | (quint32(quint8(b[o + 3])) << 24);
}
inline quint64 le64(const QByteArray& b, int o) {
    return quint64(le32(b, o)) | (quint64(le32(b, o + 4)) << 32);
}

// PSIN 块表：{u32 标签, u32 大小, u64 0xAAAAAAAAAAAAAAAA} × N（97.5% 资源符合）
struct PsinBlocks {
    int count = 0;
    QList<QPair<quint32, quint32>> first;
};

PsinBlocks parsePsinBlocks(const QByteArray& d) {
    PsinBlocks r;
    int o = 0x08;
    while (o + 16 <= d.size() && r.count < 100000) {
        const quint32 tag = le32(d, o);
        const quint32 size = le32(d, o + 4);
        if (le64(d, o + 8) != 0xAAAAAAAAAAAAAAAAull) break;
        if (size == 0 || quint64(size) > quint64(d.size())) break;
        if (r.first.size() < 6) r.first.append({tag, size});
        ++r.count;
        o += 16;
    }
    return r;
}

// 按类型选择解析方式，产出可读文本
struct TextExportResult {
    QString kind;
    QString content;
};

TextExportResult textForExport(const Resource& r) {
    TextExportResult out;
    if (GxtParser::looksLikeGxt(r.data)) {
        const GxtInfo g = GxtParser::parse(r.data);
        if (g.ok) {
            out.kind = QStringLiteral("GXT 文本表（%1 条，非空 %2）")
                           .arg(g.recordCount).arg(g.decoded);
            QString s;
            s.reserve(g.entries.size() * 48);
            for (const GxtEntry& e : g.entries) {
                if (e.text.isEmpty()) continue;
                s += QStringLiteral("%1").arg(e.hash, 8, 16, QChar('0')).toUpper();
                s += QLatin1Char('\t');
                s += e.text;
                s += QLatin1Char('\n');
            }
            out.content = s;
            return out;
        }
    }
    if (r.type == QLatin1String("0drp")) {
        const QVector<DrpItem> items = drpItems(r.data);
        const QByteArray pool = drpTextPool(r.data, items);
        if (!pool.isEmpty()) {
            const QStringList ss = drpPoolStrings(pool, 0);
            out.kind = QStringLiteral("0DRP 字符串池（%1 条，%2）")
                           .arg(ss.size()).arg(drpTextLanguage(ss));
            out.content = ss.join(QLatin1Char('\n'));
            return out;
        }
    }
    if (r.type == QLatin1String("xml")) {
        QString s = QString::fromUtf8(r.data);
        s.replace(QChar('\0'), QChar(0x00B7));
        out.kind = QStringLiteral("XML / 纯文本（完整 UTF-8）");
        out.content = s;
        return out;
    }
    if (r.type == QLatin1String("rbf")) {
        const QStringList ss = rbfStrings(r.data, 100000);
        if (!ss.isEmpty()) {
            out.kind = QStringLiteral("RBF0 字符串（%1 个）").arg(ss.size());
            out.content = ss.join(QLatin1Char('\n'));
            return out;
        }
    }
    if (r.type == QLatin1String("psin")) {
        out.kind = QStringLiteral("PSIN 结构化报告");
        out.content = psinReport(r.data);
        return out;
    }
    const auto strings = printableStrings(r.data, 8, 200000);
    out.kind = QStringLiteral("可打印字符串（%1 个）").arg(strings.size());
    QString s;
    for (const auto& p : strings)
        s += QStringLiteral("0x%1  %2\n").arg(p.first, 8, 16, QChar('0')).arg(p.second);
    if (s.isEmpty()) s = QStringLiteral("（未找到 ≥8 字符的合法 UTF-8 字符串）\n");
    out.content = s;
    return out;
}

QString safeRelPath(const QString& rel, const QString& fallback) {
    QString p = rel;
    p.replace(QRegularExpression(QStringLiteral("[\\\\:*?\"<>|]")), QStringLiteral("_"));
    QStringList clean;
    const QStringList parts = p.split(QLatin1Char('/'), Qt::SkipEmptyParts);
    for (const QString& s : parts) {
        if (s == QLatin1String(".") || s == QLatin1String("..")) continue;
        clean << s;
    }
    p = clean.join(QLatin1Char('/'));
    if (p.isEmpty()) p = fallback;
    return p;
}

} // namespace

namespace gxtmodel {
// GXT 条目表模型：只保存被筛中的行号，3.6 万条也能秒开
class GxtTableModel : public QAbstractTableModel {
public:
    explicit GxtTableModel(QObject* parent = nullptr) : QAbstractTableModel(parent) {}

    void setEntries(const QList<GxtEntry>& entries) {
        beginResetModel();
        m_entries = entries;
        m_filter.clear();
        rebuild();
        endResetModel();
    }

    void setFilter(const QString& filter) {
        beginResetModel();
        m_filter = filter.trimmed();
        rebuild();
        endResetModel();
    }

    int rowCount(const QModelIndex& = QModelIndex()) const override {
        return m_rows.size();
    }
    int columnCount(const QModelIndex& = QModelIndex()) const override { return 4; }

    QVariant data(const QModelIndex& idx, int role) const override {
        if (!idx.isValid() || idx.row() < 0 || idx.row() >= m_rows.size()) return {};
        const int i = m_rows[idx.row()];
        const GxtEntry& e = m_entries.at(i);
        if (role == Qt::DisplayRole) {
            switch (idx.column()) {
                case 0: return i + 1;
                case 1: return QStringLiteral("%1").arg(e.hash, 8, 16, QChar('0')).toUpper();
                case 2: return e.cls;
                case 3: return e.text;
            }
        }
        if (role == Qt::ToolTipRole && idx.column() == 3) return e.text;
        return {};
    }

    QVariant headerData(int section, Qt::Orientation o, int role) const override {
        if (role != Qt::DisplayRole || o != Qt::Horizontal) return {};
        switch (section) {
            case 0: return QStringLiteral("序号");
            case 1: return QStringLiteral("哈希");
            case 2: return QStringLiteral("池");
            case 3: return QStringLiteral("文本");
        }
        return {};
    }

private:
    void rebuild() {
        m_rows.clear();
        m_rows.reserve(m_entries.size());
        for (int i = 0; i < m_entries.size(); ++i) {
            if (m_filter.isEmpty()) {
                m_rows.append(i);
                continue;
            }
            const GxtEntry& e = m_entries.at(i);
            const QString hash = QStringLiteral("%1").arg(e.hash, 8, 16, QChar('0'));
            if (e.text.contains(m_filter, Qt::CaseInsensitive) ||
                hash.contains(m_filter, Qt::CaseInsensitive))
                m_rows.append(i);
        }
    }

    QList<GxtEntry> m_entries;
    QVector<int> m_rows;
    QString m_filter;
};
} // namespace

namespace hexmodel {
// 虚拟化十六进制模型：按需生成单元格文本，大资源也不卡
class HexTableModel : public QAbstractTableModel {
public:
    explicit HexTableModel(QByteArray data, QObject* parent = nullptr)
        : QAbstractTableModel(parent), m_data(std::move(data)) {}

    int rowCount(const QModelIndex& = QModelIndex()) const override {
        return (m_data.size() + 15) / 16;
    }
    int columnCount(const QModelIndex& = QModelIndex()) const override { return 18; }

    QVariant data(const QModelIndex& idx, int role) const override {
        if (!idx.isValid() || role != Qt::DisplayRole) return {};
        const int row = idx.row();
        const int col = idx.column();
        if (col == 0)
            return QStringLiteral("%1").arg(quint64(row) * 16, 8, 16, QChar('0'));
        if (col >= 1 && col <= 16) {
            const int i = row * 16 + col - 1;
            if (i >= m_data.size()) return QString();
            return QStringLiteral("%1").arg(quint8(m_data.at(i)), 2, 16, QChar('0'));
        }
        QString asc;
        const int base = row * 16;
        for (int k = 0; k < 16 && base + k < m_data.size(); ++k) {
            const quint8 c = quint8(m_data.at(base + k));
            asc += (c >= 0x20 && c < 0x7F) ? QChar(c) : QChar('.');
        }
        return asc;
    }

    QVariant headerData(int section, Qt::Orientation o, int role) const override {
        if (role != Qt::DisplayRole || o != Qt::Horizontal) return {};
        if (section == 0) return QStringLiteral("偏移");
        if (section == 17) return QStringLiteral("ASCII");
        return QStringLiteral("%1").arg(section - 1, 2, 16, QChar('0')).toUpper();
    }

private:
    QByteArray m_data;
};
} // namespace

// ---- 面向普通玩家的显示辅助 ----
static QString friendlyType(const QString& t) {
    if (t == QLatin1String("gxt"))  return QStringLiteral("文本表");
    if (t == QLatin1String("rbf"))  return QStringLiteral("UI 数据");
    if (t == QLatin1String("psin")) return QStringLiteral("数据容器");
    if (t == QLatin1String("gfx"))  return QStringLiteral("界面文件");
    if (t == QLatin1String("xml"))  return QStringLiteral("配置 / 清单");
    if (t == QLatin1String("0drp")) return QStringLiteral("资源容器");
    if (t == QLatin1String("chk"))  return QStringLiteral("校验文件");
    return QStringLiteral("未知二进制");
}

static QString formatBytes(quint64 n) {
    if (n >= (1ull << 30)) return QStringLiteral("%1 GB").arg(n / 1024.0 / 1024.0 / 1024.0, 0, 'f', 1);
    if (n >= (1ull << 20)) return QStringLiteral("%1 MB").arg(n / 1024.0 / 1024.0, 0, 'f', 1);
    if (n >= (1ull << 10)) return QStringLiteral("%1 KB").arg(n / 1024.0, 0, 'f', 1);
    return QStringLiteral("%1 B").arg(n);
}

static QIcon typeIcon(const QString& t) {
    QColor c(0x9E, 0x9E, 0x9E);
    if (t == QLatin1String("gxt"))  c.setRgb(0x4C, 0xAF, 0x50);
    else if (t == QLatin1String("rbf"))  c.setRgb(0xFF, 0x98, 0x00);
    else if (t == QLatin1String("psin")) c.setRgb(0x21, 0x96, 0xF3);
    else if (t == QLatin1String("gfx"))  c.setRgb(0x9C, 0x27, 0xB0);
    else if (t == QLatin1String("xml"))  c.setRgb(0x00, 0xBC, 0xD4);
    else if (t == QLatin1String("0drp")) c.setRgb(0x60, 0x7D, 0x8B);
    QPixmap pm(12, 12);
    pm.fill(Qt::transparent);
    QPainter p(&pm);
    p.setRenderHint(QPainter::Antialiasing);
    p.setBrush(c);
    p.setPen(Qt::NoPen);
    p.drawEllipse(1, 1, 10, 10);
    return QIcon(pm);
}

MainWindow::MainWindow(QWidget* parent) : QMainWindow(parent) {
    setWindowTitle(QStringLiteral("RPF 资源管理器"));
    resize(1260, 800);

    // ---- 工具栏 ----
    auto* tb = addToolBar(QStringLiteral("主工具栏"));
    tb->setMovable(false);
    auto* actOpen = tb->addAction(QStringLiteral("打开 RPF…"));
    auto* actExpSel = tb->addAction(QStringLiteral("导出选中"));
    auto* actExpText = tb->addAction(QStringLiteral("导出文本…"));
    actExpText->setShortcut(QKeySequence(QStringLiteral("Ctrl+Shift+T")));
    auto* actExpAll = tb->addAction(QStringLiteral("导出全部"));
    auto* actExpCorpus = tb->addAction(QStringLiteral("导出语料…"));
    m_actExportGxt = tb->addAction(QStringLiteral("导出 GXT 文本…"));
    m_actExportGxt->setEnabled(false);
    connect(actOpen, &QAction::triggered, this, &MainWindow::onOpen);
    connect(actExpSel, &QAction::triggered, this, &MainWindow::onExportSelected);
    connect(actExpText, &QAction::triggered, this, &MainWindow::onExportText);
    connect(actExpCorpus, &QAction::triggered, this, &MainWindow::onExportCorpus);
    connect(actExpAll, &QAction::triggered, this, &MainWindow::onExportAll);
    connect(m_actExportGxt, &QAction::triggered, this, &MainWindow::onExportGxt);

    auto* m = menuBar()->addMenu(QStringLiteral("文件"));
    auto* actOpen2 = m->addAction(QStringLiteral("打开 RPF…"));
    actOpen2->setShortcut(QKeySequence::Open);
    connect(actOpen2, &QAction::triggered, this, &MainWindow::onOpen);
    m->addSeparator();
    m->addAction(QStringLiteral("导出选中"), this, &MainWindow::onExportSelected);
    m->addAction(QStringLiteral("导出选中文本…"), this, &MainWindow::onExportText);
    m->addAction(QStringLiteral("导出多语言语料…"), this, &MainWindow::onExportCorpus);
    m->addAction(QStringLiteral("导出全部"), this, &MainWindow::onExportAll);
    m->addSeparator();
    auto* actQuit = m->addAction(QStringLiteral("退出"));
    actQuit->setShortcut(QKeySequence::Quit);
    connect(actQuit, &QAction::triggered, qApp, &QApplication::quit);

    // ---- 中央：左树 + 右详情 ----
    auto* split = new QSplitter(Qt::Horizontal, this);

    auto* left = new QWidget(split);
    auto* leftLayout = new QVBoxLayout(left);
    leftLayout->setContentsMargins(0, 0, 0, 0);
    leftLayout->setSpacing(4);
    auto* filterRow = new QHBoxLayout();
    m_treeFilter = new QLineEdit(left);
    m_treeFilter->setPlaceholderText(QStringLiteral("搜索：文件名 / 类名 / 哈希…"));
    m_treeFilter->setClearButtonEnabled(true);
    m_treeType = new QComboBox(left);
    m_treeType->addItem(QStringLiteral("全部类型"), QString());
    m_treeType->addItem(QStringLiteral("文本表"), QStringLiteral("gxt"));
    m_treeType->addItem(QStringLiteral("UI 数据"), QStringLiteral("rbf"));
    m_treeType->addItem(QStringLiteral("数据容器"), QStringLiteral("psin"));
    m_treeType->addItem(QStringLiteral("界面文件"), QStringLiteral("gfx"));
    m_treeType->addItem(QStringLiteral("配置 / 清单"), QStringLiteral("xml"));
    m_treeType->addItem(QStringLiteral("资源容器"), QStringLiteral("0drp"));
    m_treeType->addItem(QStringLiteral("未知二进制"), QStringLiteral("bin"));
    m_treeMode = new QComboBox(left);
    m_treeMode->addItem(QStringLiteral("按类型浏览"), QStringLiteral("type"));
    m_treeMode->addItem(QStringLiteral("按路径浏览"), QStringLiteral("path"));
    m_treeMode->setToolTip(QStringLiteral("按类型：先看到「文本表 / UI 数据 / 资源容器」等分类；"
                                          "按路径：看到归档内的文件夹层级"));
    filterRow->addWidget(m_treeFilter, 1);
    filterRow->addWidget(m_treeType);
    filterRow->addWidget(m_treeMode);
    leftLayout->addLayout(filterRow);

    m_tree = new QTreeWidget(left);
    leftLayout->addWidget(m_tree, 1);
    connect(m_treeFilter, &QLineEdit::textChanged, this, [this] { applyTreeFilter(); });
    connect(m_treeType, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, [this] { applyTreeFilter(); });
    connect(m_treeMode, QOverload<int>::of(&QComboBox::currentIndexChanged),
            this, [this] { buildTree(); applyTreeFilter(); });
    m_tree->setHeaderLabels({QStringLiteral("文件"), QStringLiteral("说明")});
    m_tree->setColumnWidth(0, 320);
    m_tree->setUniformRowHeights(true);
    m_tree->setSelectionMode(QAbstractItemView::ExtendedSelection);
    m_tree->setContextMenuPolicy(Qt::CustomContextMenu);
    connect(m_tree, &QTreeWidget::itemSelectionChanged,
            this, &MainWindow::onItemSelected);
    connect(m_tree, &QTreeWidget::itemDoubleClicked,
            this, &MainWindow::onItemDoubleClicked);
    connect(m_tree, &QTreeWidget::customContextMenuRequested,
            this, &MainWindow::onTreeContextMenu);

    auto* right = new QSplitter(Qt::Vertical, split);

    m_props = new QTableWidget(right);
    m_props->setColumnCount(4);
    m_props->setHorizontalHeaderLabels({
        QStringLiteral("项"), QStringLiteral("值"),
        QStringLiteral("来源"), QStringLiteral("说明")});
    m_props->horizontalHeader()->setStretchLastSection(true);
    m_props->horizontalHeader()->setSectionResizeMode(1, QHeaderView::Stretch);
    m_props->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_props->setSelectionBehavior(QAbstractItemView::SelectRows);

    // ---- GXT 文本表预览（选中 0DRP 文本表时出现）----
    m_gxtPanel = new QWidget(right);
    auto* gxtLayout = new QVBoxLayout(m_gxtPanel);
    gxtLayout->setContentsMargins(0, 0, 0, 0);
    m_gxtInfo = new QLabel(m_gxtPanel);
    m_gxtInfo->setWordWrap(true);
    m_gxtFilter = new QLineEdit(m_gxtPanel);
    m_gxtFilter->setPlaceholderText(
        QStringLiteral("筛选：文本包含… 或哈希前缀（如 BLIP_ACTIVITY / 4A2C）"));
    m_gxtView = new QTableView(m_gxtPanel);
    m_gxtModel = new gxtmodel::GxtTableModel(m_gxtView);
    m_gxtView->setModel(m_gxtModel);
    m_gxtView->setEditTriggers(QAbstractItemView::NoEditTriggers);
    m_gxtView->setSelectionBehavior(QAbstractItemView::SelectRows);
    m_gxtView->setAlternatingRowColors(true);
    m_gxtView->verticalHeader()->setVisible(false);
    m_gxtView->setColumnWidth(0, 64);
    m_gxtView->setColumnWidth(1, 88);
    m_gxtView->setColumnWidth(2, 44);
    m_gxtView->horizontalHeader()->setStretchLastSection(true);
    gxtLayout->addWidget(m_gxtInfo);
    gxtLayout->addWidget(m_gxtFilter);
    gxtLayout->addWidget(m_gxtView, 1);
    m_gxtPanel->setVisible(false);
    connect(m_gxtFilter, &QLineEdit::textChanged, this, [this](const QString& s) {
        if (m_gxtModel)
            static_cast<gxtmodel::GxtTableModel*>(m_gxtModel)->setFilter(s);
    });

    m_previewStack = new QStackedWidget(right);
    m_dashboard = new QTextBrowser(m_previewStack);
    m_dashboard->setOpenLinks(false);
    connect(m_dashboard, &QTextBrowser::anchorClicked, this, [this](const QUrl& u) {
        if (u.scheme() != QLatin1String("flt")) return;
        const QString t = u.path();
        for (int i = 0; i < m_treeType->count(); ++i) {
            if (m_treeType->itemData(i).toString() == t) {
                m_treeType->setCurrentIndex(i);
                break;
            }
        }
        applyTreeFilter();
    });
    m_dashboard->setHtml(QStringLiteral(
        "<div style='font-family:Microsoft YaHei;padding:24px'>"
        "<h2>RPF 资源管理器</h2>"
        "<p>点击工具栏「打开 RPF…」选择一个 .rpf 归档。</p>"
        "<p>打开后：左侧展开文件夹 → 单击文件查看内容 → 右键导出。</p></div>"));
    m_preview = new QPlainTextEdit(m_previewStack);
    m_preview->setReadOnly(true);
    m_preview->setPlaceholderText(QStringLiteral("选中左侧文件以查看内容"));
    QFont mono(QStringLiteral("Consolas"));
    mono.setStyleHint(QFont::Monospace);
    m_preview->setFont(mono);
    m_previewStack->addWidget(m_dashboard);
    m_previewStack->addWidget(m_preview);

    right->setSizes({200, 320, 380});
    split->setSizes({400, 860});
    setCentralWidget(split);

    m_status = new QLabel(this);
    statusBar()->addPermanentWidget(m_status, 1);
    statusBar()->showMessage(QStringLiteral("就绪 — 请打开 RPF 归档"));
}

// ---------------------------------------------------------------------------
bool MainWindow::loadFile(const QString& path) {
    QProgressDialog prog(QStringLiteral("正在扫描归档…首次打开约 10 秒"), QString(),
                         0, 0, this);
    prog.setWindowTitle(QStringLiteral("打开 RPF"));
    prog.setWindowModality(Qt::WindowModal);
    prog.setCancelButton(nullptr);
    prog.setMinimumDuration(0);
    prog.show();
    QApplication::processEvents();

    QElapsedTimer timer;
    timer.start();
    QString err;
    const bool ok = m_reader.open(path, &err);
    prog.close();
    if (!ok) {
        QMessageBox::warning(this, QStringLiteral("打开失败"), err);
        return false;
    }
    // 大归档默认按类型分组（否则两万多个文件铺成一列），小归档保留路径层级
    {
        QSignalBlocker block(m_treeMode);
        m_treeMode->setCurrentIndex(m_reader.resources().size() > 2000 ? 0 : 1);
    }
    buildTree();
    showDashboard();
    statusBar()->showMessage(
        QStringLiteral("已载入：%1（%2 个资源，用时 %3 秒）")
            .arg(path)
            .arg(m_reader.resources().size())
            .arg(timer.elapsed() / 1000.0, 0, 'f', 1));
    return true;
}

bool MainWindow::selectResourceBySeq(int seq) {
    for (int i = 0; i < m_reader.resources().size(); ++i) {
        if (m_reader.resources()[i].seq != seq) continue;

        QList<QTreeWidgetItem*> stack;
        for (int k = 0; k < m_tree->topLevelItemCount(); ++k)
            stack.append(m_tree->topLevelItem(k));
        while (!stack.isEmpty()) {
            QTreeWidgetItem* it = stack.takeLast();
            if (it->data(0, Qt::UserRole).toInt() == 200000 + i) {
                for (QTreeWidgetItem* p = it->parent(); p; p = p->parent())
                    p->setExpanded(true);
                m_tree->setCurrentItem(it);
                m_tree->scrollToItem(it);
                return true;
            }
            for (int k = 0; k < it->childCount(); ++k)
                stack.append(it->child(k));
        }
        return false;
    }
    return false;
}

void MainWindow::onOpen() {
    const QString p = QFileDialog::getOpenFileName(
        this, QStringLiteral("打开 RPF 归档"), QString(),
        QStringLiteral("RPF 归档 (*.rpf);;所有文件 (*.*)"));
    if (!p.isEmpty()) loadFile(p);
}

// ---------------------------------------------------------------------------
void MainWindow::buildTree() {
    m_tree->clear();
    if (m_reader.resources().isEmpty()) return;

    // 归档根节点
    auto* root = new QTreeWidgetItem(m_tree);
    root->setText(0, m_reader.archiveName());
    root->setText(1, QStringLiteral("%1 个文件").arg(m_reader.resources().size()));
    root->setData(0, Qt::UserRole, -1);

    const bool byType = m_treeMode &&
        m_treeMode->currentData().toString() == QLatin1String("type");

    if (byType) {
        // 三级结构：类型 → 来源归档（内嵌时才有）→ 文件
        // 先看到「文本表 / UI 数据 / 资源容器」这类能理解的分类，
        // 而不是 41 个无名的「内嵌归档 #n」。
        static const QStringList kOrder = {
            QStringLiteral("gxt"), QStringLiteral("rbf"), QStringLiteral("gfx"),
            QStringLiteral("psin"), QStringLiteral("0drp"), QStringLiteral("xml"),
            QStringLiteral("chk"), QStringLiteral("bin")};

        // 统计：type → 总数，type/scope → 数量
        QHash<QString, int> typeCount;
        QHash<QString, QHash<QString, int>> scopeCount;
        QStringList typeOrder;
        for (const Resource& r : m_reader.resources()) {
            if (!typeCount.contains(r.type)) typeOrder.append(r.type);
            ++typeCount[r.type];
            ++scopeCount[r.type][QString::number(r.nestedIdx)];
        }

        QHash<QString, QTreeWidgetItem*> nodes;   // "type" 或 "type/scope" → 节点
        auto makeTypeFolder = [&](const QString& t) {
            auto* g = new QTreeWidgetItem(root);
            g->setText(0, friendlyType(t));
            g->setText(1, QStringLiteral("%1 个文件").arg(typeCount.value(t)));
            g->setIcon(0, typeIcon(t));
            g->setData(0, Qt::UserRole, -2);
            nodes.insert(t, g);
            return g;
        };

        for (const QString& t : kOrder)
            if (typeCount.contains(t)) makeTypeFolder(t);
        for (const QString& t : typeOrder)      // 未列入固定顺序的类型兜底
            if (!kOrder.contains(t)) makeTypeFolder(t);

        // 每种类型下按来源归档分组（仅内嵌资源需要）
        for (const QString& t : typeOrder) {
            QTreeWidgetItem* typeNode = nodes.value(t);
            const QHash<QString, int> scopes = scopeCount.value(t);
            for (auto it = scopes.constBegin(); it != scopes.constEnd(); ++it) {
                if (it.key() == QLatin1String("-1")) continue;
                const int idx = it.key().toInt();
                QString name = QStringLiteral("内嵌归档 #%1").arg(idx + 1);
                if (idx >= 0 && idx < m_reader.nested().size()) {
                    const NestedArchive& a = m_reader.nested()[idx];
                    if (!a.realName.isEmpty()) name = a.realName;
                }
                auto* s = new QTreeWidgetItem(typeNode);
                s->setText(0, name);
                s->setText(1, QStringLiteral("%1 个文件").arg(it.value()));
                s->setData(0, Qt::UserRole, -2);
                s->setExpanded(true);
                nodes.insert(t + QLatin1Char('/') + it.key(), s);
            }
        }

        for (int i = 0; i < m_reader.resources().size(); ++i) {
            const Resource& r = m_reader.resources()[i];
            QTreeWidgetItem* parent = nodes.value(r.type);
            if (r.nestedIdx >= 0) {
                const QString gk = r.type + QLatin1Char('/') + QString::number(r.nestedIdx);
                if (nodes.contains(gk)) parent = nodes.value(gk);
            }

            const QString leaf = QFileInfo(r.relPath).fileName();
            auto* it = new QTreeWidgetItem(parent);
            it->setText(0, leaf.isEmpty() ? QString::number(i) : leaf);
            it->setText(1, QStringLiteral("%1  ·  %2")
                               .arg(friendlyType(r.type), formatBytes(r.size)));
            it->setIcon(0, typeIcon(r.type));
            it->setData(0, Qt::UserRole, 200000 + i);
            it->setData(0, Qt::UserRole + 1, r.type);
            it->setData(1, Qt::UserRole, 3);
        }

        root->setExpanded(true);
        return;
    }

    // ---- 按路径：文件夹树（按展示路径）----
    QHash<QString, QTreeWidgetItem*> dirs;

    for (int i = 0; i < m_reader.resources().size(); ++i) {
        const Resource& r = m_reader.resources()[i];

        // relPath 已含内嵌归档前缀，直接按它建目录树
        const QString path = r.relPath;
        const QStringList parts = path.split(QLatin1Char('/'), Qt::SkipEmptyParts);
        QTreeWidgetItem* parent = root;
        QString cur;
        for (int d = 0; d + 1 < parts.size(); ++d) {
            cur += parts[d] + QLatin1Char('/');
            if (!dirs.contains(cur)) {
                auto* node = new QTreeWidgetItem(parent);
                node->setText(0, parts[d]);
                node->setText(1, QStringLiteral("文件夹"));
                node->setData(0, Qt::UserRole, -2);
                dirs.insert(cur, node);
            }
            parent = dirs.value(cur);
        }

        auto* it = new QTreeWidgetItem(parent);
        it->setText(0, parts.isEmpty() ? QString::number(i) : parts.last());
        it->setText(1, QStringLiteral("%1  ·  %2")
                           .arg(friendlyType(r.type), formatBytes(r.size)));
        it->setIcon(0, typeIcon(r.type));
        it->setData(0, Qt::UserRole, 200000 + i);
        it->setData(0, Qt::UserRole + 1, r.type);   // 类型过滤用
        it->setData(1, Qt::UserRole, 3);
    }

    root->setExpanded(true);
}

// ---------------------------------------------------------------------------
void MainWindow::onItemDoubleClicked(QTreeWidgetItem* item, int) {
    if (!item) return;
    const int tag = item->data(0, Qt::UserRole).toInt();
    if (tag < 200000) return;                 // 文件夹：切换展开
    const int i = tag - 200000;
    if (i >= m_reader.resources().size()) return;
    const Resource& r = m_reader.resources()[i];

    const QString p = QFileDialog::getSaveFileName(
        this, QStringLiteral("导出文件"),
        QFileInfo(r.relPath).fileName(),
        QStringLiteral("所有文件 (*.*)"));
    if (p.isEmpty()) return;
    QFile f(p);
    if (!f.open(QIODevice::WriteOnly)) {
        QMessageBox::warning(this, QStringLiteral("导出失败"),
                             QStringLiteral("无法写入：%1").arg(p));
        return;
    }
    f.write(r.data);
    f.close();
    statusBar()->showMessage(QStringLiteral("已导出：%1").arg(p));
}

void MainWindow::onItemSelected() {
    const auto items = m_tree->selectedItems();
    if (items.isEmpty()) return;
    const int tag = items.first()->data(0, Qt::UserRole).toInt();

    if (tag == -1) { showDashboard(); return; }
    if (tag == -2) { clearDetail(QStringLiteral("文件夹")); return; }
    if (tag >= 200000) {
        const int i = tag - 200000;
        if (i < m_reader.resources().size()) showResource(m_reader.resources()[i]);
        return;
    }
    clearDetail(QStringLiteral("归档"));
}

void MainWindow::clearDetail(const QString& title) {
    m_props->setRowCount(0);
    m_previewStack->setCurrentWidget(m_preview);
    m_preview->setPlainText(title);
    hideGxtPanel();
}

static void addRow(QTableWidget* t, const QString& k, const QString& v,
                   Source s, const QString& note) {
    const int r = t->rowCount();
    t->insertRow(r);
    t->setItem(r, 0, new QTableWidgetItem(k));
    t->setItem(r, 1, new QTableWidgetItem(v));
    t->setItem(r, 2, new QTableWidgetItem(sourceName(s)));
    t->setItem(r, 3, new QTableWidgetItem(note));
}

void MainWindow::showHeaderField(const HeaderField& f) {
    m_props->setRowCount(0);
    addRow(m_props, QStringLiteral("偏移"), QStringLiteral("0x%1").arg(f.offset, 4, 16, QChar('0')),
           Source::FromFile, QString());
    addRow(m_props, QStringLiteral("大小/类型"), f.size, Source::FromFile, QString());
    addRow(m_props, QStringLiteral("值"), f.value, f.source, f.note);
    addRow(m_props, QStringLiteral("来源"), sourceName(f.source), f.source,
           f.source == Source::Unknown
               ? QStringLiteral("该字段含义尚未解明，显示的是原始字节")
               : QString());
    m_preview->setPlainText(QStringLiteral("这是归档头字段。\n\n%1").arg(f.note));
}

void MainWindow::showNested(const NestedArchive& a) {
    m_props->setRowCount(0);
    addRow(m_props, QStringLiteral("偏移"), QStringLiteral("0x%1").arg(a.offset, 8, 16, QChar('0')),
           Source::FromFile, QStringLiteral("4 KB 对齐，9FPR 头"));
    addRow(m_props, QStringLiteral("条目数 (+0x24)"), QString::number(a.entryCount),
           Source::Derived, QStringLiteral("由头部直读"));
    addRow(m_props, QStringLiteral("TOC 大小 (+0x04)"), QString::number(a.tocSize),
           Source::Derived, QStringLiteral("含 0x40 头；42 个归档验证，非「名字表长度」"));
    addRow(m_props, QStringLiteral("TOC 结束"), QStringLiteral("0x%1").arg(a.tocEnd, 8, 16, QChar('0')),
           Source::Derived, QStringLiteral("偏移 + 0x40 + TOC 大小"));
    addRow(m_props, QStringLiteral("数据区起点"),
           QStringLiteral("0x%1").arg(a.dataStart, 8, 16, QChar('0')),
           Source::Derived,
           QStringLiteral("4 KB 对齐(TOC 结束)；起点形态：%1").arg(a.dataKind));
    addRow(m_props, QStringLiteral("条目表"), QString::number(a.entryBytes) + QStringLiteral(" 字节"),
           Source::Derived, QStringLiteral("条目数 × 16"));
    addRow(m_props, QStringLiteral("名字/哈希区"), QString::number(a.restBytes) + QStringLiteral(" 字节"),
           Source::Derived, QStringLiteral("TOC 大小 − 0x40 − 条目表；内容加密"));
    addRow(m_props, QStringLiteral("未压缩数据块"),
           a.rawSpans ? QStringLiteral("%1 段 / %2 字节（非零 %3）")
                            .arg(a.rawSpans).arg(a.rawBytes).arg(a.rawNonZero)
                      : QStringLiteral("无"),
           Source::Derived,
           QStringLiteral("数据区里未被 zlib 流覆盖、≥4KB 且含非零字节的块（疑似未压缩数据，边界未知）"));
    addRow(m_props, QStringLiteral("内含资源"), QString::number(a.resourceCount),
           Source::Derived, QStringLiteral("本次扫描结果"));
    addRow(m_props, QStringLiteral("真实名"),
           a.realName.isEmpty() ? QStringLiteral("未知") : a.realName,
           a.realName.isEmpty() ? Source::Unknown : Source::External,
           a.realName.isEmpty()
               ? QStringLiteral("RPF9 目录表加密，无法还原")
               : QStringLiteral("来自游戏自身清单 XML"));
    m_preview->setPlainText(QStringLiteral("内嵌归档。\n真实文件名在 RPF9 目录表内加密，"
                                           "本工具不作猜测。\n\n"
                                           "数据区起点形态说明：\n"
                                           "  zlib    = 起点即压缩页（最常见）\n"
                                           "  rpf     = 起点是另一个内嵌归档头\n"
                                           "  nonzero = 非 zlib 的未识别数据（疑似未压缩页）\n"
                                           "  zero    = 起点为全零"));
}

void MainWindow::showResource(const Resource& r) {
    m_previewStack->setCurrentWidget(m_preview);
    m_props->setRowCount(0);
    const QStringList assetNames = (r.type == QLatin1String("bin"))
                                       ? embeddedAssetNames(r.data, 256)
                                       : QStringList();
    addRow(m_props, QStringLiteral("文件名"), r.relPath, Source::Derived,
           r.realName.isEmpty()
               ? QStringLiteral("按内容魔数判定的类型名")
               : r.nameSource);
    addRow(m_props, QStringLiteral("偏移"), QStringLiteral("0x%1").arg(r.offset, 8, 16, QChar('0')),
           Source::FromFile, QStringLiteral("归档内偏移"));
    addRow(m_props, QStringLiteral("压缩字节"), QString::number(r.compSize), Source::Derived, QString());
    addRow(m_props, QStringLiteral("解压字节"), QString::number(r.size), Source::Derived, QString());
    addRow(m_props, QStringLiteral("占用页数"), QString::number(r.pages), Source::Derived,
           QStringLiteral("每页 64 KB"));
    addRow(m_props, QStringLiteral("类型"), r.type, Source::Derived,
           QStringLiteral("按内容魔数判定"));
    if (!assetNames.isEmpty()) {
        addRow(m_props, QStringLiteral("内嵌资源名"),
               QStringLiteral("%1 个").arg(assetNames.size()), Source::Derived,
               assetNames.mid(0, 8).join(QStringLiteral(" | "))
                   + QStringLiteral("；名字来自文件内字符串表，可用于判断资源类型"));
    }
    addRow(m_props, QStringLiteral("SHA-1"), r.sha1, Source::Derived,
           QStringLiteral("解压内容的散列"));
    addRow(m_props, QStringLiteral("真实名"),
           r.realName.isEmpty() ? QStringLiteral("未知") : r.realName,
           r.realName.isEmpty() ? Source::Unknown : Source::External,
           r.realName.isEmpty()
               ? QStringLiteral("目录表加密，无法还原；显示名为内容判定")
               : r.nameSource);

    // ---- 0DRP 资源：文本表按 GXT 结构解析，其它如实标注 ----
    GxtInfo gxt;
    const bool is0drp = GxtParser::looksLikeGxt(r.data);
    const bool isGxt = is0drp && (gxt = GxtParser::parse(r.data)).ok;

    if (is0drp) {
        addRow(m_props, QStringLiteral("容器"),
               isGxt ? QStringLiteral("0DRP 文本表（GXT）")
                     : QStringLiteral("0DRP 二进制资源（非文本表）"),
               isGxt ? Source::Derived : Source::Unknown,
               isGxt ? QStringLiteral("槽位表 + 记录表 + 串池结构校验通过")
                     : QStringLiteral("0DRP 是通用资源容器，只有语言包文本表是 GXT 结构"));
    }

    if (is0drp && r.data.size() >= 0x60) {
        const QByteArray& d = r.data;
        addRow(m_props, QStringLiteral("0DRP 头部"),
               QStringLiteral("+0x14=0x%1  +0x20=%2  +0x48=%3  +0x4C=%4")
                   .arg(le32(d, 0x14), 0, 16).arg(le32(d, 0x20))
                   .arg(le32(d, 0x48)).arg(le32(d, 0x4C)),
               Source::Derived,
               QStringLiteral("0x14 恒为 0x7A；0x20 多为 2；0x48/0x4C 多为 4"));
        QString ptrs;
        int bad = 0;
        for (int off : {0x08, 0x28, 0x38, 0x40}) {
            const quint32 v = le32(d, off);
            if (v < 0x50000000u) continue;
            const quint32 rel = v - 0x50000000u;
            if (rel >= quint32(d.size())) ++bad;
            ptrs += QStringLiteral("+0x%1→0x%2  ").arg(off, 2, 16, QChar('0')).arg(rel, 0, 16);
        }
        if (!ptrs.isEmpty())
            addRow(m_props, QStringLiteral("指针字段"), ptrs.trimmed(),
                   Source::Derived,
                   QStringLiteral("0x50xxxxxx 减 0x50000000 即资源内偏移%1")
                       .arg(bad ? QStringLiteral("；%1 个越界").arg(bad) : QString()));
        const QVector<DrpItem> items = drpItems(r.data);
        if (!items.isEmpty()) {
            addRow(m_props, QStringLiteral("容器用途"),
                   drpContainerKind(items), Source::Derived,
                   QStringLiteral("按段 ID 组合判定；全库只有 5 类"));
            QStringList secs;
            for (const DrpItem& it : items)
                secs << QStringLiteral("%1[0x%2] %3 B @0x%4")
                            .arg(drpSectionName(it.id))
                            .arg(it.id, 8, 16, QChar('0'))
                            .arg(it.size)
                            .arg(it.offset, 0, 16);
            addRow(m_props, QStringLiteral("段结构"),
                   QStringLiteral("%1 段").arg(items.size()), Source::Derived,
                   secs.join(QStringLiteral("  "))
                       + QStringLiteral("；每项 16B {u64 段ID+size, u64 0x50 指针}"));
            const QByteArray pool = drpTextPool(r.data, items);
            if (!pool.isEmpty()) {
                const QStringList ss = drpPoolStrings(pool, 0);
                QSet<QString> uniq(ss.begin(), ss.end());
                addRow(m_props, QStringLiteral("字符串池"),
                       QStringLiteral("%1 条（唯一 %2）").arg(ss.size()).arg(uniq.size()),
                       Source::Derived,
                       QStringLiteral("0x10 段：null 分隔 UTF-8 文本"));
                const QString pathLang = languageDisplayName(languageKeyFromPath(r.relPath));
                addRow(m_props, QStringLiteral("文本语言"),
                       pathLang.isEmpty() ? drpTextLanguage(ss) : pathLang,
                       Source::Derived,
                       pathLang.isEmpty()
                           ? QStringLiteral("按文字系统统计")
                           : QStringLiteral("来自语言包路径 data/lang/<名称>_final.rpf"));
            }

            // 4 段文本包的已解明结构：索引头 {版本, N, 3, 0} + N×16B 记录 + N 个字符串
            const DrpItem* hdr = nullptr;
            const DrpItem* rec = nullptr;
            const DrpItem* blk = nullptr;
            for (const DrpItem& it : items) {
                if (it.id == 0x99331089u) hdr = &it;
                else if (it.id == 0xa8478889u) rec = &it;
                else if (it.id == 0x00000101u) blk = &it;
            }
            if (hdr && hdr->size >= 16 && int(hdr->offset) + 16 <= r.data.size()) {
                addRow(m_props, QStringLiteral("索引头"),
                       QStringLiteral("0x%1 · %2 条 · %3 · %4")
                           .arg(le32(r.data, hdr->offset), 0, 16)
                           .arg(le32(r.data, hdr->offset + 4))
                           .arg(le32(r.data, hdr->offset + 8))
                           .arg(le32(r.data, hdr->offset + 12)),
                       Source::Derived,
                       QStringLiteral("第 2 个字段 = 字符串/记录条数，"
                                      "与该段 null 数、记录表条数一致"));
            }
            if (rec)
                addRow(m_props, QStringLiteral("记录表"),
                       QStringLiteral("%1 × 16 B").arg(rec->size / 16), Source::Derived,
                       QStringLiteral("0xa8478889：每条对应一个字符串"));
            if (blk)
                addRow(m_props, QStringLiteral("数据块"),
                       QStringLiteral("%1 × 544 B（%2 × 16 B 槽）")
                           .arg(blk->size / 544).arg(blk->size / 16),
                       Source::Derived,
                       QStringLiteral("0x101：544 = 34 × 16，按 16B 槽读取"));
        }
        if (!isGxt) {
            DrpFile drp;
            if (drp.parse(r.data))
                addRow(m_props, QStringLiteral("写回校验"),
                       drp.roundTripOk() ? QStringLiteral("通过（字节一致）")
                                         : QStringLiteral("失败"),
                       Source::Derived,
                       QStringLiteral("按头部 + 子资源表重写后与原始字节比对"));
        }
    }
    if (r.type == QLatin1String("psin") && r.data.size() >= 0x18) {
        const PsinBlocks pb = parsePsinBlocks(r.data);
        if (pb.count > 0) {
            QStringList first;
            for (const auto& p : pb.first)
                first << QStringLiteral("0x%1:%2").arg(p.first, 0, 16).arg(p.second);
            addRow(m_props, QStringLiteral("PSIN 块表"),
                   QStringLiteral("%1 块").arg(pb.count), Source::Derived,
                   QStringLiteral("每块 16B {u32 标签, u32 大小, u64 0xAA 填充}；首块 %1。"
                                  "注意：PSIN 是通用容器，内容不一定是音频——"
                                  "实测有文本、哈希表和嵌套 0DRP")
                       .arg(first.join(QStringLiteral(", "))));
        }
        const QVector<PsinChunk> ch = psinChunks(r.data);
        if (!ch.isEmpty()) {
            QStringList parts;
            for (const PsinChunk& c : ch)
                parts << QStringLiteral("%1(%2)").arg(c.tag).arg(c.size);
            addRow(m_props, QStringLiteral("PSIN 块链"),
                   QStringLiteral("%1 块").arg(ch.size()), Source::Derived,
                   parts.join(QStringLiteral("  "))
                       + QStringLiteral("；LSCH=模式 LENM=枚举 LSNS=取值 LRSC=资源引用 CHKS=校验"));
            int recs = 0;
            for (const PsinChunk& c : ch)
                if (c.tag == QLatin1String("LSCH")) recs = (c.size - 8) / 32;
            if (recs > 0)
                addRow(m_props, QStringLiteral("模式记录"),
                       QStringLiteral("%1 条").arg(recs), Source::Derived,
                       QStringLiteral("LSCH 负载按 32 字节/条解析（字段名是 64 位哈希，"
                                      "「导出文本」可看完整表）"));
        }
    }

    if (r.type == QLatin1String("rbf") && r.data.size() >= 0x0C) {
        const QByteArray& d = r.data;
        const int len = quint8(d[0x0A]) | (quint8(d[0x0B]) << 8);
        if (len >= 2 && len <= 64 && 0x0C + len <= d.size()) {
            const QByteArray name = d.mid(0x0C, len);
            bool printable = true;
            for (char c : name)
                if (c < 32 || c > 126) { printable = false; break; }
            if (printable)
                addRow(m_props, QStringLiteral("RBF0 类"),
                       QString::fromLatin1(name), Source::Derived,
                       QStringLiteral("u16 长度 + 类名 @0x0A；1,260/1,263 个 RBF0 可读"
                                      "（UI Prefab / 动画图 / 字幕容器等）"));
        }
        const QStringList ss = rbfStrings(d, 64);
        if (!ss.isEmpty()) {
            addRow(m_props, QStringLiteral("RBF0 可读串"),
                   QStringLiteral("%1 个").arg(ss.size()), Source::Derived,
                   ss.mid(0, 8).join(QStringLiteral(" | ")));
        }
    }
    if (r.type == QLatin1String("gfx") && r.data.size() > 0x10) {
        const QByteArray& d = r.data;
        addRow(m_props, QStringLiteral("GFX 容器"),
               QStringLiteral("声明大小 %1 字节").arg(le32(d, 4)), Source::Derived,
               QStringLiteral("魔数 GFX*；严格校验后 87 个 GFX 里没有真 SWF"
                              "（FWS 三字节匹配是压缩数据里的偶然）"));
        int swf = d.indexOf(QByteArrayLiteral("FWS"));
        QLatin1String kind("FWS");
        if (swf < 0) {
            swf = d.indexOf(QByteArrayLiteral("CWS"));
            kind = QLatin1String("CWS");
        }
        if (swf >= 0 && swf + 8 <= d.size()) {
            addRow(m_props, QStringLiteral("内嵌 SWF"),
                   QStringLiteral("%1 @0x%2，版本 %3，声明 %4 字节")
                       .arg(kind).arg(swf, 0, 16)
                       .arg(int(quint8(d[swf + 3]))).arg(le32(d, swf + 4)),
                   Source::Derived,
                   QStringLiteral("FWS 为未压缩 SWF，可导出后用 Flash 播放器/反编译器打开"));
        }
    }

    if (r.type != QLatin1String("gxt") && r.type != QLatin1String("xml")) {
        const QVector<EmbeddedFile> emb = scanEmbedded(r.data);
        if (!emb.isEmpty()) {
            QStringList parts;
            for (int k = 0; k < emb.size() && k < 8; ++k)
                parts << QStringLiteral("%1@0x%2(%3B)")
                             .arg(emb[k].kind).arg(emb[k].offset, 0, 16).arg(emb[k].size);
            addRow(m_props, QStringLiteral("嵌入文件"),
                   QStringLiteral("%1 个").arg(emb.size()), Source::Derived,
                   parts.join(QStringLiteral("  "))
                       + QStringLiteral("；右键「导出嵌入文件…」可全部导出"));
        }
    }

    if (isGxt) {
        QStringList pools;
        for (auto it = gxt.poolBases.constBegin(); it != gxt.poolBases.constEnd(); ++it)
            pools << QStringLiteral("class%1→0x%2")
                         .arg(it.key()).arg(it.value(), 0, 16);
        addRow(m_props, QStringLiteral("GXT 条目数"), QString::number(gxt.recordCount),
               Source::Derived, QStringLiteral("槽位表筛选结果"));
        addRow(m_props, QStringLiteral("非空文本"), QString::number(gxt.decoded),
               Source::Derived, QStringLiteral("按记录地址成功解码的条数"));
        addRow(m_props, QStringLiteral("记录表偏移"),
               QStringLiteral("0x%1").arg(gxt.recordOffset, 0, 16),
               Source::Derived, QStringLiteral("锚点 + 200 条结构校验"));
        addRow(m_props, QStringLiteral("槽位/记录一致"),
               gxt.validSlots == gxt.recordCount ? QStringLiteral("是") : QStringLiteral("否"),
               Source::Derived,
               QStringLiteral("槽位 %1 / 记录 %2").arg(gxt.validSlots).arg(gxt.recordCount));
        addRow(m_props, QStringLiteral("串池基址"), pools.join(QStringLiteral("  ")),
               Source::Derived, QStringLiteral("按「偏移落在串首」投票实测"));
        addRow(m_props, QStringLiteral("解码率"),
               QStringLiteral("%1%").arg(QString::number(gxt.decodeRatio() * 100.0, 'f', 1)),
               Source::Derived, QStringLiteral("记录表末尾为 0x00：%1")
                                    .arg(gxt.tailZero ? QStringLiteral("是") : QStringLiteral("否")));

        showGxtPanel(gxt);
        m_preview->setPlainText(
            QStringLiteral("GXT 文本表已在上方表格中完整显示：%1 条。\n"
                           "可用筛选框按文本/哈希过滤，或「导出 GXT 文本…」导出 TSV。\n\n"
                           "完整字符串 / 文本 / 十六进制：右键该文件 →「文件属性…」。")
                .arg(gxt.recordCount));
        return;
    }

    hideGxtPanel();
    if (r.type == QLatin1String("xml")) {
        QString t = QString::fromUtf8(r.data);
        t.replace(QChar('\0'), QChar(0x00B7));
        m_preview->setPlainText(
            QStringLiteral("── XML / 纯文本（完整 %1 字节）──\n%2").arg(r.size).arg(t));
        return;
    }

    const auto found = printableStrings(r.data, 8, 200000);

    if (r.type == QLatin1String("psin")) {
        QString text = psinReport(r.data);
        text += QStringLiteral("\n── 可打印字符串（%1 个）──\n").arg(found.size());
        for (const auto& p : found)
            text += QStringLiteral("0x%1  %2\n").arg(p.first, 8, 16, QChar('0')).arg(p.second);
        m_preview->setPlainText(text);
        return;
    }
    if (r.type == QLatin1String("rbf")) {
        const QStringList ss = rbfStrings(r.data, 100000);
        QString text = QStringLiteral("── RBF0 结构（长度前缀字符串，完整 %1 个）──\n").arg(ss.size());
        for (int i = 0; i < ss.size(); ++i)
            text += QStringLiteral("#%1  %2\n").arg(i, 4).arg(ss.at(i));
        text += QStringLiteral("\n── 可打印字符串（%1 个）──\n").arg(found.size());
        for (const auto& p : found)
            text += QStringLiteral("0x%1  %2\n").arg(p.first, 8, 16, QChar('0')).arg(p.second);
        m_preview->setPlainText(text);
        return;
    }

    if (is0drp) {
        const QVector<DrpItem> items = drpItems(r.data);
        QString text = QStringLiteral("── 0DRP 容器 ──\n");
        text += QStringLiteral("用途: %1\n").arg(drpContainerKind(items));
        text += QStringLiteral("段结构: %1 段\n").arg(items.size());
        for (int k = 0; k < items.size(); ++k) {
            const DrpItem& it = items.at(k);
            text += QStringLiteral("  #%1  0x%2  %3 %4 B @0x%5\n")
                        .arg(k, 2)
                        .arg(it.id, 8, 16, QChar('0'))
                        .arg(drpSectionName(it.id), -10)
                        .arg(it.size)
                        .arg(it.offset, 0, 16);
        }
        const QByteArray pool = drpTextPool(r.data, items);
        if (!pool.isEmpty()) {
            const QStringList all = drpPoolStrings(pool, 0);
            const int shown = qMin(all.size(), 300);
            text += QStringLiteral("\n── 字符串池（%1 条，%2；显示前 %3 条）──\n")
                        .arg(all.size())
                        .arg(drpTextLanguage(all))
                        .arg(shown);
            for (int k = 0; k < shown; ++k)
                text += QStringLiteral("#%1  %2\n").arg(k + 1, 4).arg(all.at(k));
            if (all.size() > shown)
                text += QStringLiteral("…（其余 %1 条用「导出文本…」查看）\n")
                            .arg(all.size() - shown);
        } else {
            for (int k = 0; k < items.size() && k < 8; ++k) {
                const DrpItem& it = items.at(k);
                const auto ss = printableStrings(r.data.mid(it.offset, it.size), 6, 500);
                text += QStringLiteral("\n── 段 #%1（%2 B @0x%3）可打印字符串 ──\n")
                            .arg(k).arg(it.size).arg(it.offset, 0, 16);
                if (ss.isEmpty()) text += QStringLiteral("  （无可打印字符串）\n");
                for (const auto& p : ss)
                    text += QStringLiteral("  0x%1  %2\n")
                                .arg(p.first, 6, 16, QChar('0')).arg(p.second);
            }
        }
        m_preview->setPlainText(text);
        return;
    }

    QString text;
    if (!assetNames.isEmpty()) {
        text += QStringLiteral("── 内嵌资源名（%1 个）──\n").arg(assetNames.size());
        for (const QString& n : assetNames)
            text += n + QLatin1Char('\n');
        text += QLatin1Char('\n');
    }
    text += QStringLiteral("── 可打印字符串（%1 个）──\n").arg(found.size());
    if (found.isEmpty())
        text += QStringLiteral("（未找到 ≥8 字符的合法 UTF-8 字符串）\n");
    for (const auto& p : found)
        text += QStringLiteral("0x%1  %2\n").arg(p.first, 8, 16, QChar('0')).arg(p.second);
    text += QStringLiteral("\n完整文本 / 十六进制：右键该文件 →「文件属性…」。\n");
    m_preview->setPlainText(text);
}

void MainWindow::showGxtPanel(const GxtInfo& info) {
    m_gxtEntries = info.entries;
    m_gxtValid = true;
    static_cast<gxtmodel::GxtTableModel*>(m_gxtModel)->setEntries(m_gxtEntries);
    m_gxtFilter->clear();

    QStringList pools;
    for (auto it = info.poolBases.constBegin(); it != info.poolBases.constEnd(); ++it)
        pools << QStringLiteral("class%1→0x%2").arg(it.key()).arg(it.value(), 0, 16);
    m_gxtInfo->setText(
        QStringLiteral("GXT 文本表：%1 条（非空 %2） · 记录表 @0x%3 · 解码率 %4% · %5")
            .arg(info.recordCount)
            .arg(info.decoded)
            .arg(info.recordOffset, 0, 16)
            .arg(QString::number(info.decodeRatio() * 100.0, 'f', 1))
            .arg(pools.join(QStringLiteral("  "))));
    m_gxtPanel->setVisible(true);
    m_actExportGxt->setEnabled(true);
}

void MainWindow::hideGxtPanel() {
    if (m_gxtPanel) m_gxtPanel->setVisible(false);
    if (m_actExportGxt) m_actExportGxt->setEnabled(false);
    if (m_gxtValid && m_gxtModel) {
        m_gxtEntries.clear();
        static_cast<gxtmodel::GxtTableModel*>(m_gxtModel)->setEntries(m_gxtEntries);
    }
    m_gxtValid = false;
}

void MainWindow::onExportGxt() {
    if (!m_gxtValid || m_gxtEntries.isEmpty()) return;
    const QString suggested = m_reader.archiveName() + QStringLiteral("_gxt.tsv");
    const QString p = QFileDialog::getSaveFileName(
        this, QStringLiteral("导出 GXT 文本"), suggested,
        QStringLiteral("TSV 文本 (*.tsv);;所有文件 (*.*)"));
    if (p.isEmpty()) return;
    QFile f(p);
    if (!f.open(QIODevice::WriteOnly)) {
        QMessageBox::warning(this, QStringLiteral("导出失败"),
                             QStringLiteral("无法写入：%1").arg(p));
        return;
    }
    f.write(GxtParser::toTsv(m_gxtEntries).toUtf8());
    f.close();
    statusBar()->showMessage(QStringLiteral("已导出 GXT 文本：%1（%2 条）")
                                 .arg(p).arg(m_gxtEntries.size()));
}

void MainWindow::onExportCorpus() {
    if (m_reader.resources().isEmpty()) {
        QMessageBox::information(this, QStringLiteral("导出多语言语料"),
                                 QStringLiteral("请先打开一个 RPF 归档。"));
        return;
    }
    const QString dir = QFileDialog::getExistingDirectory(
        this, QStringLiteral("选择多语言语料导出目录"));
    if (dir.isEmpty()) return;

    QProgressDialog prog(QStringLiteral("正在导出 0DRP 字符串池…"),
                         QStringLiteral("取消"), 0, m_reader.resources().size(), this);
    prog.setWindowTitle(QStringLiteral("导出多语言语料"));
    prog.setWindowModality(Qt::WindowModal);
    prog.setMinimumDuration(0);
    prog.show();
    QApplication::processEvents();

    CorpusStats st;
    QString err;
    const bool ok = m_reader.exportTextCorpus(
        dir, &st, &err, [&prog](int i, int) {
            prog.setValue(i);
            QCoreApplication::processEvents();
            return !prog.wasCanceled();
        });
    prog.close();

    if (!ok) {
        if (err == QLatin1String("已取消"))
            statusBar()->showMessage(QStringLiteral("已取消语料导出"));
        else
            QMessageBox::warning(this, QStringLiteral("导出失败"), err);
        return;
    }

    QList<QPair<int, QString>> langs;
    for (auto it = st.perLanguage.constBegin(); it != st.perLanguage.constEnd(); ++it)
        langs.append({it.value(), it.key()});
    std::sort(langs.begin(), langs.end(),
              [](const QPair<int, QString>& a, const QPair<int, QString>& b) {
                  return a.first > b.first;
              });
    QStringList lines;
    for (const auto& l : langs)
        lines << QStringLiteral("%1：%2 条")
                     .arg(languageDisplayName(l.second)).arg(l.first);

    QMessageBox::information(
        this, QStringLiteral("导出多语言语料"),
        QStringLiteral("完成。\n\n容器：%1 个\n字符串：%2 条\n字符串池：%3\n\n%4\n\n"
                       "每种语言一个 TSV，另有 _index.csv。\n目录：%5")
            .arg(st.containers)
            .arg(st.strings)
            .arg(formatBytes(st.bytes))
            .arg(lines.join(QStringLiteral("；")))
            .arg(dir));
    statusBar()->showMessage(QStringLiteral("已导出语料：%1 条字符串 → %2")
                                 .arg(st.strings).arg(dir));
}

// ---------------------------------------------------------------------------
// 导出选中文件的文本：按类型自动选择解析方式，可选合并/分别导出
//   · GXT 文本表   → 哈希 + 文本
//   · 0DRP 文本包  → 字符串池（含语言判定）
//   · XML          → 完整 UTF-8 文本
//   · 其它二进制   → 可打印字符串
// 触发入口：工具栏「导出文本…」、文件菜单「导出选中文本…」、资源右键「导出文本…」
// ---------------------------------------------------------------------------
void MainWindow::onExportText() {
    QList<int> indices;
    for (QTreeWidgetItem* item : m_tree->selectedItems()) {
        const int tag = item->data(0, Qt::UserRole).toInt();
        if (tag < 200000) continue;
        const int i = tag - 200000;
        if (i >= 0 && i < m_reader.resources().size() && !indices.contains(i))
            indices.append(i);
    }
    if (indices.isEmpty()) {
        QMessageBox::information(this, QStringLiteral("导出选中文本"),
                                 QStringLiteral("请先在左侧选中一个或多个资源文件（文件夹不参与）。"));
        return;
    }
    std::sort(indices.begin(), indices.end());

    QMessageBox box(this);
    box.setWindowTitle(QStringLiteral("导出选中文本"));
    box.setText(QStringLiteral("已选中 %1 个资源。\n\n"
                               "按类型自动解析：\n"
                               "· GXT 文本表 → 哈希 + 文本\n"
                               "· 0DRP 文本包 → 字符串池（含语言判定）\n"
                               "· XML → 完整文本\n"
                               "· 其它二进制 → 可打印字符串")
                    .arg(indices.size()));
    QPushButton* btnSingle = box.addButton(QStringLiteral("合并到一个文本文件"),
                                           QMessageBox::AcceptRole);
    QPushButton* btnMulti = box.addButton(QStringLiteral("分别导出为多个文件"),
                                          QMessageBox::ActionRole);
    box.addButton(QStringLiteral("取消"), QMessageBox::RejectRole);
    box.exec();
    if (box.clickedButton() != btnSingle && box.clickedButton() != btnMulti) return;
    const bool singleFile = (box.clickedButton() == btnSingle);

    QString target;
    if (singleFile) {
        target = QFileDialog::getSaveFileName(
            this, QStringLiteral("合并导出文本"),
            m_reader.archiveName() + QStringLiteral("_选中文本.txt"),
            QStringLiteral("文本文件 (*.txt);;所有文件 (*.*)"));
        if (target.isEmpty()) return;
    } else {
        target = QFileDialog::getExistingDirectory(this, QStringLiteral("选择导出目录"));
        if (target.isEmpty()) return;
    }

    QProgressDialog progress(QStringLiteral("正在按类型解析并导出…"),
                             QStringLiteral("取消"), 0, indices.size(), this);
    progress.setWindowTitle(QStringLiteral("导出选中文本"));
    progress.setWindowModality(Qt::WindowModal);
    progress.setMinimumDuration(200);

    int done = 0, failed = 0;
    QByteArray merged;
    QSet<QString> used;

    for (int k = 0; k < indices.size(); ++k) {
        progress.setValue(k);
        QCoreApplication::processEvents();
        if (progress.wasCanceled()) break;

        const Resource& r = m_reader.resources().at(indices[k]);
        const TextExportResult res = textForExport(r);
        const QString realName = r.realName.isEmpty()
                                     ? QStringLiteral("未知") : r.realName;
        const QString header =
            QStringLiteral("文件: %1\n真实名: %2\n偏移: 0x%3  压缩: %4  解压: %5  类型: %6\n"
                           "解析方式: %7\n\n")
                .arg(r.relPath, realName)
                .arg(r.offset, 8, 16, QChar('0'))
                .arg(r.compSize).arg(r.size).arg(r.type).arg(res.kind);

        if (singleFile) {
            merged += "================================================================\n";
            merged += header.toUtf8();
            merged += "================================================================\n\n";
            merged += res.content.toUtf8();
            merged += "\n\n";
            ++done;
            continue;
        }

        const QString fallback = QStringLiteral("%1_%2_%3")
                                     .arg(r.seq, 4, 10, QChar('0'))
                                     .arg(r.offset, 8, 16, QChar('0'))
                                     .arg(r.size);
        const QString rel = safeRelPath(r.relPath, fallback) + QStringLiteral(".txt");
        QString unique = rel;
        int n = 1;
        while (used.contains(unique)) {
            const int dot = rel.lastIndexOf(QLatin1Char('.'));
            unique = rel.left(dot) + QStringLiteral("~%1").arg(++n) + rel.mid(dot);
        }
        used.insert(unique);

        const QString path = QDir(target).filePath(unique);
        QDir().mkpath(QFileInfo(path).absolutePath());
        QFile f(path);
        if (!f.open(QIODevice::WriteOnly)) { ++failed; continue; }
        f.write(header.toUtf8());
        f.write(res.content.toUtf8());
        f.close();
        ++done;
    }
    progress.setValue(indices.size());

    if (singleFile && done > 0) {
        QFile f(target);
        if (!f.open(QIODevice::WriteOnly)) {
            QMessageBox::warning(this, QStringLiteral("导出失败"),
                                 QStringLiteral("无法写入：%1").arg(target));
            return;
        }
        f.write(merged);
        f.close();
    }

    statusBar()->showMessage(
        QStringLiteral("导出选中文本：成功 %1 / 失败 %2").arg(done).arg(failed));
    QMessageBox::information(this, QStringLiteral("导出选中文本"),
                             QStringLiteral("完成：%1 个成功，%2 个失败。\n输出：%3")
                                 .arg(done).arg(failed).arg(target));
}

// ---------------------------------------------------------------------------
// 导出选中资源里嵌入的标准文件（SWF/BMP/JPEG/RIFF/DDS）
// ---------------------------------------------------------------------------
void MainWindow::onExportEmbedded() {
    QList<int> indices;
    for (QTreeWidgetItem* item : m_tree->selectedItems()) {
        const int tag = item->data(0, Qt::UserRole).toInt();
        if (tag < 200000) continue;
        const int i = tag - 200000;
        if (i >= 0 && i < m_reader.resources().size() && !indices.contains(i))
            indices.append(i);
    }
    if (indices.isEmpty()) {
        QMessageBox::information(this, QStringLiteral("导出嵌入文件"),
                                 QStringLiteral("请先选中一个或多个资源文件（文件夹不参与）。"));
        return;
    }
    std::sort(indices.begin(), indices.end());

    struct Found { int index; EmbeddedFile f; };
    QList<Found> found;
    for (int k = 0; k < indices.size() && k < 300; ++k) {
        const Resource& r = m_reader.resources().at(indices[k]);
        for (const EmbeddedFile& f : scanEmbedded(r.data))
            found.append({indices[k], f});
    }
    if (found.isEmpty()) {
        QMessageBox::information(this, QStringLiteral("导出嵌入文件"),
                                 QStringLiteral("选中的资源里没有识别到嵌入文件"
                                                "（SWF/BMP/JPEG/RIFF/DDS）。"));
        return;
    }
    const QString dir = QFileDialog::getExistingDirectory(
        this, QStringLiteral("选择导出目录（%1 个嵌入文件）").arg(found.size()));
    if (dir.isEmpty()) return;

    QProgressDialog prog(QStringLiteral("正在导出嵌入文件…"), QStringLiteral("取消"),
                         0, int(found.size()), this);
    prog.setWindowModality(Qt::WindowModal);
    QHash<int, int> counters;
    int done = 0, failed = 0;
    for (const Found& it : found) {
        if (prog.wasCanceled()) break;
        const Resource& r = m_reader.resources().at(it.index);
        const int n = ++counters[it.index];
        const QString name = QStringLiteral("%1_%2%3.%4")
                                 .arg(r.seq)
                                 .arg(it.f.kind)
                                 .arg(n > 1 ? QString::number(n) : QString())
                                 .arg(it.f.ext);
        QFile out(QDir(dir).filePath(name));
        if (out.open(QIODevice::WriteOnly) &&
            out.write(r.data.mid(it.f.offset, it.f.size)) == it.f.size)
            ++done;
        else
            ++failed;
        prog.setValue(prog.value() + 1);
    }
    m_status->setText(QStringLiteral("导出嵌入文件：成功 %1 / 失败 %2").arg(done).arg(failed));
    QMessageBox::information(this, QStringLiteral("导出嵌入文件"),
                             QStringLiteral("成功 %1 个，失败 %2 个。\n目录：%3")
                                 .arg(done).arg(failed).arg(dir));
}

// ---------------------------------------------------------------------------
// 右键：文件属性（完整字符串 / 文本 / 十六进制，单开窗口，不截断）
// ---------------------------------------------------------------------------
void MainWindow::onTreeContextMenu(const QPoint& pos) {
    QTreeWidgetItem* item = m_tree->itemAt(pos);
    if (!item) return;
    const int tag = item->data(0, Qt::UserRole).toInt();
    if (tag < 200000) return;                       // 只对资源提供文件属性
    const int index = tag - 200000;
    if (index < 0 || index >= m_reader.resources().size()) return;

    if (!item->isSelected()) m_tree->setCurrentItem(item);   // 保留多选

    QMenu menu(this);
    menu.addAction(QStringLiteral("文件属性…（完整字符串 / 文本 / 十六进制）"),
                   this, [this, index] { showResourceProperties(index); });
    menu.addAction(QStringLiteral("导出文本…"), this, &MainWindow::onExportText);
    menu.addAction(QStringLiteral("导出嵌入文件…（SWF/BMP/JPEG/RIFF/DDS）"),
                   this, &MainWindow::onExportEmbedded);
    if (m_gxtValid)
        menu.addAction(QStringLiteral("导出 GXT 文本…"), this, &MainWindow::onExportGxt);
    menu.exec(m_tree->viewport()->mapToGlobal(pos));
}

void MainWindow::showResourceProperties(int index) {
    if (index < 0 || index >= m_reader.resources().size()) return;
    const Resource& r = m_reader.resources().at(index);

    QDialog dlg(this);
    const QString title = r.relPath.isEmpty()
                              ? QStringLiteral("资源 #%1").arg(r.seq)
                              : r.relPath;
    dlg.setWindowTitle(QStringLiteral("文件属性 — %1").arg(title));
    dlg.resize(1020, 720);

    auto* outer = new QVBoxLayout(&dlg);
    auto* tabs = new QTabWidget(&dlg);

    // 1) 基本信息
    auto* info = new QTableWidget(tabs);
    info->setColumnCount(2);
    info->setHorizontalHeaderLabels({QStringLiteral("项"), QStringLiteral("值")});
    info->horizontalHeader()->setStretchLastSection(true);
    info->verticalHeader()->setVisible(false);
    info->setEditTriggers(QAbstractItemView::NoEditTriggers);
    auto addInfo = [info](const QString& k, const QString& v) {
        const int row = info->rowCount();
        info->insertRow(row);
        info->setItem(row, 0, new QTableWidgetItem(k));
        info->setItem(row, 1, new QTableWidgetItem(v));
    };

    const auto strings = printableStrings(r.data, 8, 200000);

    addInfo(QStringLiteral("文件名"), r.relPath);
    addInfo(QStringLiteral("真实名"),
            r.realName.isEmpty() ? QStringLiteral("未知") : r.realName);
    addInfo(QStringLiteral("序号"), QString::number(r.seq));
    addInfo(QStringLiteral("偏移"), QStringLiteral("0x%1").arg(r.offset, 8, 16, QChar('0')));
    addInfo(QStringLiteral("压缩字节"), QString::number(r.compSize));
    addInfo(QStringLiteral("解压字节"), QString::number(r.size));
    addInfo(QStringLiteral("页数"), QString::number(r.pages));
    addInfo(QStringLiteral("类型"), r.type);
    addInfo(QStringLiteral("SHA-1"), r.sha1);
    addInfo(QStringLiteral("可打印字符串"), QString::number(strings.size()));

    // 2) 字符串（完整）
    QString strText = QStringLiteral("共 %1 个（严格 UTF-8 + NUL、≥8 字符）\n\n")
                          .arg(strings.size());
    for (const auto& p : strings)
        strText += QStringLiteral("0x%1  %2\n").arg(p.first, 8, 16, QChar('0')).arg(p.second);
    auto* strEdit = new QPlainTextEdit(tabs);
    strEdit->setReadOnly(true);
    strEdit->setFont(QFont(QStringLiteral("Consolas")));
    strEdit->setPlainText(strText);

    // 3) 文本（完整 UTF-8）
    QString txt = QString::fromUtf8(r.data);
    txt.replace(QChar('\0'), QChar(0x00B7));
    auto* txtEdit = new QPlainTextEdit(tabs);
    txtEdit->setReadOnly(true);
    txtEdit->setFont(QFont(QStringLiteral("Consolas")));
    txtEdit->setPlainText(txt);

    // 4) 十六进制（完整，虚拟化，按需生成单元格）
    auto* hex = new QTableView(tabs);
    hex->setModel(new hexmodel::HexTableModel(r.data, hex));
    hex->setFont(QFont(QStringLiteral("Consolas")));
    hex->verticalHeader()->setVisible(false);
    hex->setSelectionBehavior(QAbstractItemView::SelectRows);
    hex->setEditTriggers(QAbstractItemView::NoEditTriggers);
    hex->setColumnWidth(0, 92);
    for (int c = 1; c <= 16; ++c) hex->setColumnWidth(c, 28);
    hex->setColumnWidth(17, 140);

    tabs->addTab(info, QStringLiteral("基本信息"));
    tabs->addTab(strEdit, QStringLiteral("字符串（%1）").arg(strings.size()));
    tabs->addTab(txtEdit, QStringLiteral("文本（完整）"));
    tabs->addTab(hex, QStringLiteral("十六进制（完整）"));

    // 5) 嵌入内容：类型/偏移/大小 + 第一张图预览
    const QVector<EmbeddedFile> emb = scanEmbedded(r.data);
    if (!emb.isEmpty()) {
        auto* ep = new QWidget(tabs);
        auto* epLay = new QVBoxLayout(ep);
        auto* et = new QTableWidget(emb.size(), 4, ep);
        et->setHorizontalHeaderLabels({QStringLiteral("类型"), QStringLiteral("偏移"),
                                       QStringLiteral("大小"), QStringLiteral("说明")});
        et->verticalHeader()->setVisible(false);
        et->setEditTriggers(QAbstractItemView::NoEditTriggers);
        et->horizontalHeader()->setStretchLastSection(true);
        for (int k = 0; k < emb.size(); ++k) {
            const EmbeddedFile& e = emb.at(k);
            et->setItem(k, 0, new QTableWidgetItem(e.kind));
            et->setItem(k, 1, new QTableWidgetItem(
                                  QStringLiteral("0x%1").arg(e.offset, 8, 16, QChar('0'))));
            et->setItem(k, 2, new QTableWidgetItem(QString::number(e.size)));
            et->setItem(k, 3, new QTableWidgetItem(
                                  QStringLiteral("声明 %1 字节，可用「导出嵌入文件…」导出")
                                      .arg(e.declared)));
        }
        et->resizeColumnsToContents();
        epLay->addWidget(et, 1);
        for (const EmbeddedFile& e : emb) {
            if (e.kind != QLatin1String("BMP") && e.kind != QLatin1String("JPEG")) continue;
            QImage img = QImage::fromData(r.data.mid(e.offset, e.size));
            if (img.isNull()) continue;
            auto* lab = new QLabel(ep);
            lab->setAlignment(Qt::AlignCenter);
            lab->setPixmap(QPixmap::fromImage(img).scaled(
                640, 420, Qt::KeepAspectRatio, Qt::SmoothTransformation));
            epLay->addWidget(lab);
            break;
        }
        tabs->addTab(ep, QStringLiteral("嵌入内容（%1）").arg(emb.size()));
    }

    if (r.type == QLatin1String("psin")) {
        auto* ps = new QPlainTextEdit(tabs);
        ps->setReadOnly(true);
        ps->setFont(QFont(QStringLiteral("Consolas")));
        ps->setPlainText(psinReport(r.data));
        tabs->addTab(ps, QStringLiteral("PSIN 结构"));
    }

    if (r.type == QLatin1String("0drp")) {
        const QVector<DrpItem> items = drpItems(r.data);
        if (!items.isEmpty()) {
            auto* dt = new QTableWidget(int(items.size()), 5, tabs);
            dt->setHorizontalHeaderLabels({QStringLiteral("#"), QStringLiteral("段 ID"),
                                           QStringLiteral("名称"), QStringLiteral("大小"),
                                           QStringLiteral("偏移")});
            dt->verticalHeader()->setVisible(false);
            dt->setEditTriggers(QAbstractItemView::NoEditTriggers);
            dt->horizontalHeader()->setStretchLastSection(true);
            for (int k = 0; k < items.size(); ++k) {
                dt->setItem(k, 0, new QTableWidgetItem(QString::number(k)));
                dt->setItem(k, 1, new QTableWidgetItem(
                                      QStringLiteral("0x%1").arg(items[k].id, 8, 16, QChar('0'))));
                dt->setItem(k, 2, new QTableWidgetItem(drpSectionName(items[k].id)));
                dt->setItem(k, 3, new QTableWidgetItem(QString::number(items[k].size)));
                dt->setItem(k, 4, new QTableWidgetItem(
                                      QStringLiteral("0x%1").arg(items[k].offset, 0, 16)));
            }
            dt->resizeColumnsToContents();
            tabs->addTab(dt, QStringLiteral("0DRP 分段（%1）").arg(items.size()));

            const QByteArray pool = drpTextPool(r.data, items);
            if (!pool.isEmpty()) {
                const QStringList ss = drpPoolStrings(pool, 0);
                auto* pt = new QPlainTextEdit(tabs);
                pt->setReadOnly(true);
                pt->setPlainText(QStringLiteral("语言：%1\n字符串：%2 条\n\n%3")
                                     .arg(drpTextLanguage(ss))
                                     .arg(ss.size())
                                     .arg(ss.join(QLatin1Char('\n'))));
                tabs->addTab(pt, QStringLiteral("文本池（%1）").arg(ss.size()));
            }
        }
    }

    outer->addWidget(tabs, 1);

    auto* btnRow = new QHBoxLayout();
    auto* close = new QPushButton(QStringLiteral("关闭"), &dlg);
    connect(close, &QPushButton::clicked, &dlg, &QDialog::accept);
    btnRow->addStretch(1);
    btnRow->addWidget(close);
    outer->addLayout(btnRow);

    dlg.exec();
}

// ---------------------------------------------------------------------------
void MainWindow::showCoverage() {
    const Coverage& c = m_reader.coverage();
    const double pct = c.dataArea ? (100.0 * c.resourceBytes / c.dataArea) : 0.0;
    m_status->setText(
        QStringLiteral("文件 %1 字节  |  数据区起点 0x%2  |  资源 %3 个  |  "
                       "资源字节 %4（占数据区 %5%）  |  未计入 %6 字节"
                       "（零填充 %7 / 非零未识别 %8，共 %9 段）")
            .arg(c.fileSize)
            .arg(c.dataStart, 8, 16, QChar('0'))
            .arg(c.resourceCount)
            .arg(c.resourceBytes)
            .arg(pct, 0, 'f', 1)
            .arg(c.unaccounted)
            .arg(c.gapZero)
            .arg(c.gapNonZero)
            .arg(c.gapCount));
}

// ---------------------------------------------------------------------------
// 首页仪表盘：打开归档后显示，给普通玩家看的概览
// ---------------------------------------------------------------------------
void MainWindow::showDashboard() {
    if (!m_dashboard || !m_previewStack) return;
    hideGxtPanel();
    m_props->setRowCount(0);
    m_previewStack->setCurrentWidget(m_dashboard);

    const auto& res = m_reader.resources();
    const Coverage& c = m_reader.coverage();
    QHash<QString, int> counts;
    quint64 totalBytes = 0;
    for (const Resource& r : res) {
        ++counts[r.type];
        totalBytes += r.size;
    }

    QList<QPair<int, QString>> top;
    for (auto it = counts.constBegin(); it != counts.constEnd(); ++it)
        top.append({it.value(), it.key()});
    std::sort(top.begin(), top.end(),
              [](const QPair<int, QString>& a, const QPair<int, QString>& b) {
                  return a.first > b.first;
              });
    const int maxCount = top.isEmpty() ? 1 : top.first().first;

    QString rows;
    for (int i = 0; i < top.size() && i < 8; ++i) {
        const int n = top.at(i).first;
        const QString t = top.at(i).second;
        const int w = qMax(4, int(220.0 * n / maxCount));
        rows += QStringLiteral(
                    "<tr><td style='padding:3px 12px'>"
                    "<a href='flt:%1' style='color:#1a5fb4;text-decoration:none'>%2</a></td>"
                    "<td style='padding:3px 12px;text-align:right'>%3</td>"
                    "<td style='padding:3px 12px'>"
                    "<div style='background:#4C9BE8;height:10px;width:%4px'></div></td></tr>")
                    .arg(t, friendlyType(t))
                    .arg(n)
                    .arg(w);
    }

    const double cov = c.dataArea ? (100.0 * c.resourceBytes / c.dataArea) : 0.0;
    const QString html = QStringLiteral(
        "<div style='font-family:Microsoft YaHei;padding:20px'>"
        "<h2 style='margin:0'>%1</h2>"
        "<div style='color:#666;margin:4px 0 16px 0'>归档概览</div>"
        "<table style='border-spacing:10px'><tr>"
        "<td style='background:#E8F2FD;padding:12px 18px'><div style='color:#666'>资源总数</div>"
        "<div style='font-size:24px;font-weight:bold'>%2</div></td>"
        "<td style='background:#EAF7EA;padding:12px 18px'><div style='color:#666'>解压后体积</div>"
        "<div style='font-size:24px;font-weight:bold'>%3</div></td>"
        "<td style='background:#FFF4E5;padding:12px 18px'><div style='color:#666'>内嵌归档</div>"
        "<div style='font-size:24px;font-weight:bold'>%4</div></td>"
        "<td style='background:#F3EAF9;padding:12px 18px'><div style='color:#666'>数据覆盖率</div>"
        "<div style='font-size:24px;font-weight:bold'>%5%</div></td>"
        "</tr></table>"
        "<h3>里面有什么</h3><table>%6</table>"
        "<div style='color:#888;font-size:12px;margin:4px 0 12px 0'>"
        "点击类型名可只看这一类文件</div>"
        "<h3>怎么用</h3>"
        "<ol style='line-height:1.8'>"
        "<li>左侧先看到分类文件夹（文本表 / UI 数据 / 资源容器…），展开即可；"
        "左上角可切换「按类型浏览」和「按路径浏览」</li>"
        "<li>彩色圆点表示类型"
        "（绿=文本表，橙=UI 数据，蓝=数据容器，紫=界面，灰=其他）</li>"
        "<li>单击文件：右侧显示可读内容；文本表可直接搜索</li>"
        "<li>右键文件：查看完整属性 / 导出文本 / 导出嵌入文件</li>"
        "<li>顶部搜索框和类型下拉可以快速筛选</li>"
        "</ol>"
        "<p style='color:#888'>说明：真实文件名在加密目录表里，暂时没有钥匙；"
        "当前文件名是按内容识别的。文件大小、偏移和类型都已验证。</p>"
        "</div>")
        .arg(m_reader.archiveName().toHtmlEscaped())
        .arg(res.size())
        .arg(formatBytes(totalBytes))
        .arg(m_reader.nested().size())
        .arg(QString::number(cov, 'f', 1))
        .arg(rows);
    m_dashboard->setHtml(html);
}

// ---------------------------------------------------------------------------
// 左侧搜索 / 类型过滤
// ---------------------------------------------------------------------------
void MainWindow::applyTreeFilter() {
    if (!m_tree) return;
    const QString q = m_treeFilter ? m_treeFilter->text().trimmed().toLower() : QString();
    const QString type = m_treeType ? m_treeType->currentData().toString() : QString();
    const bool active = !q.isEmpty() || !type.isEmpty();

    std::function<bool(QTreeWidgetItem*)> visit = [&](QTreeWidgetItem* it) -> bool {
        const int tag = it->data(0, Qt::UserRole).toInt();
        bool self = false;
        if (tag >= 200000) {
            const QString rtype = it->data(0, Qt::UserRole + 1).toString();
            self = (type.isEmpty() || rtype == type) &&
                   (q.isEmpty() || it->text(0).toLower().contains(q) ||
                    it->text(1).toLower().contains(q));
        }
        bool child = false;
        for (int k = 0; k < it->childCount(); ++k)
            child = visit(it->child(k)) || child;
        const bool show = self || child || tag == -1;
        it->setHidden(!show);
        if (active && show && it->childCount() > 0) it->setExpanded(true);
        return show;
    };
    for (int k = 0; k < m_tree->topLevelItemCount(); ++k)
        visit(m_tree->topLevelItem(k));
}

// ---------------------------------------------------------------------------
// 导出文件名：优先用展示路径（真实名或内容判定名），否则用序号_偏移_大小
static QString exportName(const Resource& r) {
    if (!r.relPath.isEmpty()) {
        QString leaf = QFileInfo(r.relPath).fileName();
        leaf.replace(QRegularExpression(QStringLiteral("[\\\\/:*?\"<>|]")), QStringLiteral("_"));
        if (!leaf.isEmpty()) return leaf;
    }
    return QStringLiteral("%1_%2_%3.bin")
        .arg(r.seq, 4, 10, QChar('0'))
        .arg(r.offset, 8, 16, QChar('0'))
        .arg(r.size);
}

void MainWindow::onExportSelected() {
    const auto items = m_tree->selectedItems();
    if (items.isEmpty()) return;
    const int tag = items.first()->data(0, Qt::UserRole).toInt();
    if (tag < 200000) {
        QMessageBox::information(this, QStringLiteral("导出"),
                                 QStringLiteral("请在左侧选中一个「资源」节点。"));
        return;
    }
    const int i = tag - 200000;
    if (i >= m_reader.resources().size()) return;
    const Resource& r = m_reader.resources()[i];

    const QString def = exportName(r);
    const QString p = QFileDialog::getSaveFileName(
        this, QStringLiteral("导出资源"), def,
        QStringLiteral("所有文件 (*.*)"));
    if (p.isEmpty()) return;

    QFile f(p);
    if (!f.open(QIODevice::WriteOnly)) {
        QMessageBox::warning(this, QStringLiteral("导出失败"),
                             QStringLiteral("无法写入：%1").arg(p));
        return;
    }
    f.write(r.data);
    f.close();
    statusBar()->showMessage(QStringLiteral("已导出：%1").arg(p));
}

void MainWindow::onExportAll() {
    const QString dir = QFileDialog::getExistingDirectory(
        this, QStringLiteral("选择导出目录"));
    if (dir.isEmpty()) return;

    int ok = 0;
    for (const Resource& r : m_reader.resources()) {
        // 保留目录结构，像解压软件一样
        const QString rel = r.relPath.isEmpty() ? exportName(r) : r.relPath;
        const QString outPath = QDir(dir).filePath(rel);
        QDir().mkpath(QFileInfo(outPath).absolutePath());
        QFile f(outPath);
        if (f.open(QIODevice::WriteOnly)) {
            f.write(r.data);
            f.close();
            ++ok;
        }
    }
    QMessageBox::information(
        this, QStringLiteral("导出完成"),
        QStringLiteral("已导出 %1 / %2 个文件到：\n%3\n\n"
                       "目录结构按真实文件名还原；无真实名的文件"
                       "按内容类型命名（如 文本表.gxt、PSIN资源.psin）。")
            .arg(ok).arg(m_reader.resources().size()).arg(dir));
}
