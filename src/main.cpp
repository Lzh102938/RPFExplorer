#include <QApplication>
#include <QCommandLineParser>
#include <QCryptographicHash>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QTextStream>

#include <algorithm>

#ifdef _WIN32
#include <windows.h>
#endif

#include "MainWindow.h"
#include "DrpFile.h"
#include "EmbeddedScan.h"
#include "GxtParser.h"
#include "RpfReader.h"

// 本程序是 GUI 子系统（WIN32_EXECUTABLE），默认没有控制台。
// 交互式运行时主动附到父进程控制台，便于 --dump 直接看输出；
// 但 Windows 下 GUI 子系统的标准句柄不可靠，需要可靠落地请用 -o 写文件。
static void attachParentConsole() {
#ifdef _WIN32
    if (AttachConsole(ATTACH_PARENT_PROCESS)) {
        FILE* fp = nullptr;
        freopen_s(&fp, "CONOUT$", "w", stdout);
        freopen_s(&fp, "CONOUT$", "w", stderr);
        freopen_s(&fp, "CONIN$", "r", stdin);
    }
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
#endif
}

// ---------------------------------------------------------------------------
// 结构信息输出
// ---------------------------------------------------------------------------
static void dumpArchive(QTextStream& out, RpfReader& r) {
    out << "==== RPF 归档（忠实读取） ====\n";
    out << "文件: " << r.archiveName() << "\n";
    out << "大小: " << r.coverage().fileSize << " 字节\n\n";

    out << "---- 归档头 ----\n";
    out << QString("%1  %2  %3  %4  %5\n")
               .arg("偏移", -8).arg("类型", -10).arg("值", -24)
               .arg("来源", -12).arg("说明");
    for (const HeaderField& f : r.headerFields()) {
        out << QString("0x%1  %2  %3  %4  %5\n")
                   .arg(f.offset, 4, 16, QChar('0'))
                   .arg(f.size, -10)
                   .arg(f.value, -24)
                   .arg(sourceName(f.source), -12)
                   .arg(f.note);
    }

    out << "\n---- 目录表（TOC）----\n";
    out << "TOC 总大小(+0x04): " << r.tocSize() << " 字节（含 0x40 头）\n";
    out << "条目表: " << r.tocEntryBytes() << " 字节（" << (r.tocEntryBytes() / 16) << " 条 × 16）\n";
    out << "名字/哈希区: " << r.tocNameBytes() << " 字节\n";
    QByteArray sent = r.tocSentinel();
    QString sentHex;
    for (int i = 0; i < sent.size(); ++i)
        sentHex += QStringLiteral("%1").arg(static_cast<uint8_t>(sent[i]), 2, 16, QChar('0'));
    out << "前 32 字节哨兵: " << sentHex
        << (r.tocSentinelMatches() ? "  [与 42 归档基准一致]" : "  [与基准不符]") << "\n";
    out << "正文加密: 是（每归档独立；条目/偏移/名字均不可读）\n";

    out << "\n---- 覆盖率 ----\n";
    const Coverage& c = r.coverage();
    const double pct = c.dataArea ? (100.0 * c.resourceBytes / c.dataArea) : 0.0;
    out << "数据区起点: 0x" << QString::number(c.dataStart, 16) << "\n";
    out << "数据区字节: " << c.dataArea << "\n";
    out << "资源个数:   " << c.resourceCount << "\n";
    out << "资源压缩字节: " << c.resourceBytes
        << "  (占数据区 " << QString::number(pct, 'f', 1) << "%)\n";
    out << "未计入字节: " << c.unaccounted
        << "  <- 空隙/未知结构，不是已解出的资源\n";
    out << "  其中全零填充: " << c.gapZero << " 字节\n";
    out << "  其中非零未识别: " << c.gapNonZero << " 字节（" << c.gapCount << " 段）\n";
    out << "  其中疑似未压缩数据块(>=4KB): " << c.rawSpanBytes
        << " 字节（" << c.rawSpanCount << " 段，非零 " << c.rawSpanNonZero << " 字节）\n";

    out << "\n---- 内嵌归档 (" << r.nested().size() << ") ----\n";
    out << QString("%1  %2  %3  %4  %5  %6  %7  %8\n")
               .arg("偏移", -12).arg("TOC大小", -10).arg("条目", -8)
               .arg("数据区起点", -14).arg("起点形态", -10).arg("资源", -8)
               .arg("未压缩块", -12).arg("真实名");
    for (const NestedArchive& a : r.nested()) {
        out << QString("0x%1  %2  %3  %4  %5  %6  %7  %8\n")
                   .arg(a.offset, 8, 16, QChar('0'))
                   .arg(a.tocSize, -10)
                   .arg(a.entryCount, -8)
                   .arg(QStringLiteral("0x%1").arg(a.dataStart, 8, 16, QChar('0')), -14)
                   .arg(a.dataKind, -10)
                   .arg(a.resourceCount, -8)
                   .arg(QStringLiteral("%1 段/%2 B").arg(a.rawSpans).arg(a.rawBytes), -12)
                   .arg(a.realName.isEmpty() ? QStringLiteral("未知") : a.realName);
    }

    {
        int named = 0;
        for (const Resource& s : r.resources())
            if (!s.realName.isEmpty()) ++named;
        out << "\n---- 资源 (前 20 / 共 " << r.resources().size()
            << "，其中 " << named << " 个已还原真实名) ----\n";
    }
    out << QString("%1  %2  %3  %4  %5  %6  %7  %8\n")
               .arg("序号", -6).arg("偏移", -10).arg("压缩", -10)
               .arg("解压", -10).arg("页", -4).arg("类型", -6)
               .arg("SHA-1", -42).arg("真实名");
    const int show = qMin(20, r.resources().size());
    for (int i = 0; i < show; ++i) {
        const Resource& s = r.resources()[i];
        out << QString("%1  0x%2  %3  %4  %5  %6  %7  %8\n")
                   .arg(s.seq, -6)
                   .arg(s.offset, 8, 16, QChar('0'))
                   .arg(s.compSize, -10)
                   .arg(s.size, -10)
                   .arg(s.pages, -4)
                   .arg(s.type, -6)
                   .arg(s.sha1)
                   .arg(s.realName.isEmpty() ? QStringLiteral("未知") : s.realName);
    }
}

static void dumpCsv(QTextStream& out, RpfReader& r) {
    out << "seq,offset,comp_size,size,pages,type,sha1,real_name,name_source,rel_path\n";
    for (const Resource& s : r.resources()) {
        QString nm = s.realName;
        nm.replace(QLatin1Char('"'), QStringLiteral("\"\""));
        QString src = s.nameSource;
        src.replace(QLatin1Char('"'), QStringLiteral("\"\""));
        QString rp = s.relPath;
        rp.replace(QLatin1Char('"'), QStringLiteral("\"\""));
        out << s.seq << ",0x" << QString::number(s.offset, 16)
            << "," << s.compSize << "," << s.size << "," << s.pages
            << "," << s.type << "," << s.sha1
            << ",\"" << nm << "\",\"" << src << "\",\"" << rp << "\"\n";
    }
}

int main(int argc, char** argv) {
    QApplication app(argc, argv);
    QApplication::setApplicationName(QStringLiteral("RPFExplorer"));
    QApplication::setApplicationVersion(QStringLiteral("1.0"));

    QCommandLineParser parser;
    parser.setApplicationDescription(
        QStringLiteral("RPF9 归档资源管理器 —— 忠实读取，不臆造数据。\n"
                       "每个字段都标注来源：文件直读 / 计算得出 / 外部佐证 / 含义未明。\n"
                       "真实文件名不可得时一律显示「未知」，绝不猜测。"));
    parser.addHelpOption();
    parser.addVersionOption();

    QCommandLineOption dumpOpt(QStringList() << "d" << "dump",
                               QStringLiteral("输出结构信息后退出"));
    parser.addOption(dumpOpt);
    QCommandLineOption csvOpt(QStringList() << "csv",
                              QStringLiteral("输出资源清单 CSV（seq,offset,comp,size,pages,type,sha1）"));
    parser.addOption(csvOpt);
    QCommandLineOption gxtOpt(QStringList() << "gxt",
                              QStringLiteral("把指定 seq 的资源按 GXT 文本表解析，输出 TSV"),
                              QStringLiteral("seq"));
    parser.addOption(gxtOpt);
    QCommandLineOption embOpt(QStringList() << "embedded",
                              QStringLiteral("列出指定 seq 的资源里嵌入的标准文件与 RBF0 字符串"),
                              QStringLiteral("seq"));
    parser.addOption(embOpt);
    QCommandLineOption drpOpt(QStringList() << "drp",
                              QStringLiteral("解析指定 seq 的 0DRP 结构并做写回校验"),
                              QStringLiteral("seq"));
    parser.addOption(drpOpt);
    QCommandLineOption drpVerifyOpt(QStringList() << "drp-verify",
                                    QStringLiteral("对所有 0DRP 资源做结构解析与写回校验"));
    parser.addOption(drpVerifyOpt);
    QCommandLineOption selectOpt(QStringList() << "select",
                                 QStringLiteral("打开界面后直接选中指定 seq 的资源"),
                                 QStringLiteral("seq"));
    parser.addOption(selectOpt);
    QCommandLineOption corpusOpt(QStringList() << "corpus",
                                 QStringLiteral("把所有 0DRP 字符串池按语言导出到目录"
                                                "（<语言>.tsv + _index.csv）"),
                                 QStringLiteral("目录"));
    parser.addOption(corpusOpt);
    QCommandLineOption outOpt(QStringList() << "o" << "out",
                              QStringLiteral("把 --dump/--csv 的结果写入文件（推荐，最可靠）"),
                              QStringLiteral("文件"));
    parser.addOption(outOpt);
    QCommandLineOption extOpt(QStringList() << "x" << "extract",
                              QStringLiteral("把所有资源提取到指定目录，并逐个校验 SHA-1"),
                              QStringLiteral("目录"));
    parser.addOption(extOpt);
    parser.addPositionalArgument(QStringLiteral("rpf"),
                                 QStringLiteral("要打开的 .rpf 文件"));
    parser.process(app);

    const QStringList args = parser.positionalArguments();
    if (args.isEmpty()) {
        parser.showHelp(1);
    }

    const QString path = args.first();
    if (!QFileInfo::exists(path)) {
        attachParentConsole();
        QTextStream(stderr) << "错误: 文件不存在 " << path << "\n";
        return 1;
    }

    const bool wantDump = parser.isSet(dumpOpt);
    const bool wantCsv = parser.isSet(csvOpt);
    const QString extDir = parser.value(extOpt);

    // --gxt <seq>：把指定资源按 GXT 文本表解析，输出 TSV（用于与独立 Python 提取器比对）
    if (parser.isSet(gxtOpt)) {
        bool okNum = false;
        const int seq = parser.value(gxtOpt).toInt(&okNum);
        if (!okNum || seq <= 0) {
            attachParentConsole();
            QTextStream(stderr) << "错误: --gxt 需要正整数 seq\n";
            return 1;
        }
        RpfReader r;
        QString err;
        if (!r.open(path, &err)) {
            attachParentConsole();
            QTextStream(stderr) << "错误: " << err << "\n";
            return 1;
        }
        const Resource* target = nullptr;
        for (const Resource& s : r.resources())
            if (s.seq == seq) { target = &s; break; }
        if (!target) {
            attachParentConsole();
            QTextStream(stderr) << "错误: 找不到 seq=" << seq << "\n";
            return 1;
        }
        const GxtInfo info = GxtParser::parse(target->data);
        if (!info.ok) {
            attachParentConsole();
            QTextStream(stderr) << "错误: " << info.error << "\n";
            return 1;
        }
        const QByteArray tsv = GxtParser::toTsv(info.entries).toUtf8();
        const QString outPath = parser.value(outOpt);
        if (!outPath.isEmpty()) {
            QFile f(outPath);
            if (!f.open(QIODevice::WriteOnly)) {
                attachParentConsole();
                QTextStream(stderr) << "错误: 无法写入 " << outPath << "\n";
                return 1;
            }
            f.write(tsv);
            f.close();
        } else {
            attachParentConsole();
            QTextStream ts(stdout);
            ts.setEncoding(QStringConverter::Utf8);
            ts << QString::fromUtf8(tsv);
            ts.flush();
        }
        return 0;
    }

    // --embedded <seq>：列出嵌入的标准文件 + RBF0 字符串（已在上方声明 embOpt）
    if (parser.isSet(embOpt)) {
        bool okNum = false;
        const int seq = parser.value(embOpt).toInt(&okNum);
        if (!okNum || seq <= 0) {
            attachParentConsole();
            QTextStream(stderr) << "错误: --embedded 需要正整数 seq\n";
            return 1;
        }
        RpfReader r;
        QString err;
        if (!r.open(path, &err)) {
            attachParentConsole();
            QTextStream(stderr) << "错误: " << err << "\n";
            return 1;
        }
        const Resource* target = nullptr;
        for (const Resource& s : r.resources())
            if (s.seq == seq) { target = &s; break; }
        if (!target) {
            attachParentConsole();
            QTextStream(stderr) << "错误: 找不到 seq=" << seq << "\n";
            return 1;
        }
        QString txt;
        txt += QStringLiteral("资源 seq=%1 类型=%2 大小=%3\n")
                   .arg(target->seq).arg(target->type).arg(target->size);
        const QVector<EmbeddedFile> emb = scanEmbedded(target->data);
        txt += QStringLiteral("嵌入文件: %1 个\n").arg(emb.size());
        for (const EmbeddedFile& e : emb)
            txt += QStringLiteral("  %1 @0x%2 大小=%3 声明=%4\n")
                       .arg(e.kind)
                       .arg(e.offset, 0, 16)
                       .arg(e.size)
                       .arg(e.declared);
        const QStringList assetNames = embeddedAssetNames(target->data, 64);
        if (!assetNames.isEmpty()) {
            txt += QStringLiteral("内嵌资源名: %1 个\n").arg(assetNames.size());
            for (const QString& n : assetNames) txt += QStringLiteral("  %1\n").arg(n);
        }
        const QStringList ss =
            target->type == QLatin1String("rbf") ? rbfStrings(target->data, 40) : QStringList();
        if (!ss.isEmpty()) {
            txt += QStringLiteral("RBF0 字符串: %1 个\n").arg(ss.size());
            for (const QString& s : ss) txt += QStringLiteral("  %1\n").arg(s);
        }
        if (target->type == QLatin1String("psin")) {
            txt += psinReport(target->data);
        }
        if (target->type == QLatin1String("0drp")) {
            const QVector<DrpItem> items = drpItems(target->data);
            txt += QStringLiteral("0DRP 子资源: %1 项\n").arg(items.size());
            for (int k = 0; k < items.size(); ++k)
                txt += QStringLiteral("  #%1 id=0x%2(%3) size=%4 @0x%5\n")
                           .arg(k)
                           .arg(items[k].id, 8, 16, QChar('0'))
                           .arg(drpSectionName(items[k].id))
                           .arg(items[k].size)
                           .arg(items[k].offset, 0, 16);
        }
        const QString outPath = parser.value(outOpt);
        if (!outPath.isEmpty()) {
            QFile f(outPath);
            if (!f.open(QIODevice::WriteOnly)) {
                attachParentConsole();
                QTextStream(stderr) << "错误: 无法写入 " << outPath << "\n";
                return 1;
            }
            f.write(txt.toUtf8());
            f.close();
        } else {
            attachParentConsole();
            QTextStream ts(stdout);
            ts.setEncoding(QStringConverter::Utf8);
            ts << txt;
            ts.flush();
        }
        return 0;
    }

    const QString corpusDir = parser.value(corpusOpt);
    if (!corpusDir.isEmpty()) {
        RpfReader r;
        QString err;
        if (!r.open(path, &err)) {
            attachParentConsole();
            QTextStream(stderr) << "错误: " << err << "\n";
            return 1;
        }
        CorpusStats st;
        QString cerr;
        if (!r.exportTextCorpus(corpusDir, &st, &cerr)) {
            attachParentConsole();
            QTextStream(stderr) << "错误: " << cerr << "\n";
            return 1;
        }

        QList<QPair<int, QString>> langs;
        for (auto it = st.perLanguage.constBegin(); it != st.perLanguage.constEnd(); ++it)
            langs.append({it.value(), it.key()});
        std::sort(langs.begin(), langs.end(),
                  [](const QPair<int, QString>& a, const QPair<int, QString>& b) {
                      return a.first > b.first;
                  });

        QString txt = QStringLiteral("多语言语料导出\n目录: %1\n容器: %2\n字符串: %3\n"
                                     "字符串池: %4 字节\n\n")
                          .arg(corpusDir)
                          .arg(st.containers)
                          .arg(st.strings)
                          .arg(st.bytes);
        for (const auto& l : langs)
            txt += QStringLiteral("  %1（%2）: %3 条\n")
                       .arg(languageDisplayName(l.second), l.second).arg(l.first);
        txt += QStringLiteral("\n文件: <语言>.tsv（seq\\t序号\\t文本）+ _index.csv\n");

        QFile summary(QDir(corpusDir).filePath(QStringLiteral("_SUMMARY.txt")));
        if (summary.open(QIODevice::WriteOnly)) {
            summary.write(txt.toUtf8());
            summary.close();
        }
        attachParentConsole();
        QTextStream ts(stdout);
        ts.setEncoding(QStringConverter::Utf8);
        ts << txt;
        ts.flush();
        return 0;
    }

    if (parser.isSet(drpOpt) || parser.isSet(drpVerifyOpt)) {
        RpfReader r;
        QString err;
        if (!r.open(path, &err)) {
            attachParentConsole();
            QTextStream(stderr) << "错误: " << err << "\n";
            return 1;
        }
        QString txt;
        if (parser.isSet(drpOpt)) {
            bool okNum = false;
            const int seq = parser.value(drpOpt).toInt(&okNum);
            if (!okNum || seq <= 0) {
                attachParentConsole();
                QTextStream(stderr) << "错误: --drp 需要正整数 seq\n";
                return 1;
            }
            const Resource* target = nullptr;
            for (const Resource& s : r.resources())
                if (s.seq == seq) { target = &s; break; }
            if (!target) {
                attachParentConsole();
                QTextStream(stderr) << "错误: 找不到 seq=" << seq << "\n";
                return 1;
            }
            txt += QStringLiteral("0DRP seq=%1 大小=%2\n").arg(seq).arg(target->size);
            DrpFile d;
            if (!d.parse(target->data)) {
                txt += QStringLiteral("解析: 失败（不是 0DRP 或表不合法）\n");
            } else {
                txt += QStringLiteral("头部: +0x14=0x%1 +0x20=%2 +0x48=%3 +0x4C=%4\n")
                           .arg(d.field(0x14), 0, 16).arg(d.field(0x20))
                           .arg(d.field(0x48)).arg(d.field(0x4C));
                txt += QStringLiteral("子资源表: 0x%1 .. 0x%2\n")
                           .arg(d.tableOffset(), 0, 16).arg(d.tableEnd(), 0, 16);
                for (int i = 0; i < d.items().size(); ++i)
                    txt += QStringLiteral("  #%1 id=0x%2(%3) size=%4 @0x%5\n")
                               .arg(i)
                               .arg(d.items()[i].id, 8, 16, QChar('0'))
                               .arg(drpSectionName(d.items()[i].id))
                               .arg(d.items()[i].size)
                               .arg(d.items()[i].offset, 0, 16);
                txt += QStringLiteral("写回校验: %1\n")
                           .arg(d.roundTripOk() ? QStringLiteral("通过（字节一致）")
                                                : QStringLiteral("失败"));
            }
        } else {
            int total = 0, valid = 0, ok = 0, bad = 0;
            QStringList fails;
            for (const Resource& s : r.resources()) {
                if (s.type != QLatin1String("0drp")) continue;
                ++total;
                DrpFile d;
                if (!d.parse(s.data)) {
                    ++bad;
                    if (fails.size() < 10)
                        fails << QStringLiteral("seq=%1 解析失败").arg(s.seq);
                    continue;
                }
                ++valid;
                if (d.roundTripOk()) {
                    ++ok;
                } else {
                    ++bad;
                    if (fails.size() < 10)
                        fails << QStringLiteral("seq=%1 写回不一致").arg(s.seq);
                }
            }
            txt += QStringLiteral("0DRP 总数: %1  解析成功: %2  写回一致: %3  失败: %4\n")
                       .arg(total).arg(valid).arg(ok).arg(bad);
            for (const QString& f : fails) txt += QStringLiteral("  %1\n").arg(f);
        }
        const QString outPath = parser.value(outOpt);
        if (!outPath.isEmpty()) {
            QFile f(outPath);
            if (!f.open(QIODevice::WriteOnly)) {
                attachParentConsole();
                QTextStream(stderr) << "错误: 无法写入 " << outPath << "\n";
                return 1;
            }
            f.write(txt.toUtf8());
            f.close();
        } else {
            attachParentConsole();
            QTextStream ts(stdout);
            ts.setEncoding(QStringConverter::Utf8);
            ts << txt;
            ts.flush();
        }
        return 0;
    }

    if (!extDir.isEmpty()) {
        RpfReader r;
        QString err;
        if (!r.open(path, &err)) {
            attachParentConsole();
            QTextStream(stderr) << "错误: " << err << "\n";
            return 1;
        }
        if (!QDir().mkpath(extDir)) {
            attachParentConsole();
            QTextStream(stderr) << "错误: 无法创建目录 " << extDir << "\n";
            return 1;
        }

        // 提取全部资源，保留 relPath 目录结构，逐个校验 SHA-1
        int ok = 0, bad = 0;
        for (const Resource& s : r.resources()) {
            const QString rel = s.relPath.isEmpty()
                                    ? QStringLiteral("%1_%2.bin").arg(s.offset, 8, 16, QChar('0')).arg(s.size)
                                    : s.relPath;
            const QString outPath = QDir(extDir).filePath(rel);
            QDir().mkpath(QFileInfo(outPath).absolutePath());
            QFile f(outPath);
            if (!f.open(QIODevice::WriteOnly)) { ++bad; continue; }
            f.write(s.data);
            f.close();

            // 回读校验
            QFile g(outPath);
            QByteArray back;
            if (g.open(QIODevice::ReadOnly)) { back = g.readAll(); g.close(); }
            const QString h = QString::fromLatin1(
                QCryptographicHash::hash(back, QCryptographicHash::Sha1).toHex());
            if (h == s.sha1 && back.size() == static_cast<int>(s.size)) ++ok;
            else {
                ++bad;
                attachParentConsole();
                QTextStream(stderr) << "校验失败: " << outPath << "\n";
            }
        }

        // 报告
        QFile rep(QDir(extDir).filePath(QStringLiteral("_EXTRACT_REPORT.txt")));
        if (rep.open(QIODevice::WriteOnly | QIODevice::Text)) {
            QTextStream ts(&rep);
            ts.setEncoding(QStringConverter::Utf8);
            ts << "提取报告\n来源: " << path << "\n"
               << "资源总数: " << r.resources().size() << "\n"
               << "成功(逐个 SHA-1 校验通过): " << ok << "\n"
               << "失败: " << bad << "\n";
            for (const Resource& s : r.resources())
                ts << s.sha1 << "  " << s.relPath << "\n";
            rep.close();
        }

        attachParentConsole();
        QTextStream out(stdout);
        out.setEncoding(QStringConverter::Utf8);
        out << "提取完成: 成功 " << ok << " / " << r.resources().size()
            << "，失败 " << bad << " -> " << extDir << "\n";
        return bad == 0 ? 0 : 1;
    }

    if (wantDump || wantCsv) {
        RpfReader r;
        QString err;
        if (!r.open(path, &err)) {
            attachParentConsole();
            QTextStream(stderr) << "错误: " << err << "\n";
            return 1;
        }

        // 优先写文件：GUI 子系统下控制台/管道重定向在 Windows 上不可靠
        const QString outPath = parser.value(outOpt);
        if (!outPath.isEmpty()) {
            QFile f(outPath);
            if (!f.open(QIODevice::WriteOnly | QIODevice::Text)) {
                attachParentConsole();
                QTextStream(stderr) << "错误: 无法写入 " << outPath << "\n";
                return 1;
            }
            QTextStream ts(&f);
            ts.setEncoding(QStringConverter::Utf8);
            if (wantCsv) dumpCsv(ts, r); else dumpArchive(ts, r);
            f.close();
            return 0;
        }

        // 未指定 -o：尝试写到标准输出
        attachParentConsole();
        QTextStream ts(stdout);
        ts.setEncoding(QStringConverter::Utf8);
        if (wantCsv) dumpCsv(ts, r); else dumpArchive(ts, r);
        ts.flush();
        return 0;
    }

    MainWindow w;
    w.loadFile(path);
    bool selOk = false;
    const int selSeq = parser.value(selectOpt).toInt(&selOk);
    if (selOk && selSeq > 0) w.selectResourceBySeq(selSeq);
    w.show();
    return app.exec();
}
