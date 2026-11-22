#include "RpfReader.h"
#include "EmbeddedScan.h"
#include "GxtParser.h"

#include <QCryptographicHash>
#include <QDir>
#include <QFile>
#include <QFileInfo>
#include <QHash>
#include <QRegularExpression>
#include <zlib.h>

#include <algorithm>
#include <cstring>

QHash<QString, QString> RpfReader::s_knownNames;

QString sourceName(Source s) {
    switch (s) {
        case Source::FromFile:  return QStringLiteral("文件直读");
        case Source::Derived:   return QStringLiteral("计算得出");
        case Source::External:  return QStringLiteral("外部佐证");
        case Source::Unknown:   return QStringLiteral("含义未明");
    }
    return QString();
}

// ---------------------------------------------------------------------------
// 小工具
// ---------------------------------------------------------------------------
static uint16_t rd16(const QByteArray& b, int o) {
    return static_cast<uint8_t>(b[o]) | (static_cast<uint16_t>(static_cast<uint8_t>(b[o + 1])) << 8);
}
static uint32_t rd32(const QByteArray& b, int o) {
    return static_cast<uint32_t>(static_cast<uint8_t>(b[o]))
         | (static_cast<uint32_t>(static_cast<uint8_t>(b[o + 1])) << 8)
         | (static_cast<uint32_t>(static_cast<uint8_t>(b[o + 2])) << 16)
         | (static_cast<uint32_t>(static_cast<uint8_t>(b[o + 3])) << 24);
}

static bool isZlibHdr(const QByteArray& b, int i) {
    if (i + 1 >= b.size()) return false;
    const uint8_t cmf = static_cast<uint8_t>(b[i]);
    const uint8_t flg = static_cast<uint8_t>(b[i + 1]);
    return cmf == 0x78 && (cmf & 0x0F) == 8 && ((0x7800 + flg) % 31) == 0 && !(flg & 0x20);
}

// RPF9 目录表的前 32 字节：42 个归档（common + data 内 41 个内嵌）在 +0x40 处逐字节相同。
// 它是明文哨兵，不是可解密的条目——正文在它之后整体按归档加密。
static const unsigned char kTocSentinel[32] = {
    0x5f, 0x08, 0xda, 0xab, 0xec, 0xbd, 0xd4, 0x02,
    0x58, 0xc3, 0x51, 0x68, 0x07, 0x02, 0x4c, 0x24,
    0xfb, 0x9f, 0x75, 0x67, 0x55, 0xef, 0x4b, 0xe4,
    0x58, 0x78, 0x5b, 0xfe, 0xd8, 0xaa, 0x69, 0x89
};

static inline uint64_t align4k(uint64_t x) { return (x + 0xFFF) & ~uint64_t(0xFFF); }

// 数据区起点处的字节形态（用于判断「结构自洽」）
static QString dataKindAt(const QByteArray& b, uint64_t off) {
    if (off + 4 > static_cast<uint64_t>(b.size())) return QStringLiteral("越界");
    const int o = static_cast<int>(off);
    if (isZlibHdr(b, o)) return QStringLiteral("zlib");
    if (b.mid(o, 4) == QByteArrayLiteral("9FPR")) return QStringLiteral("rpf");
    bool allZero = true;
    const int n = qMin(o + 64, b.size());
    for (int i = o; i < n; ++i)
        if (b[i] != 0) { allZero = false; break; }
    return allZero ? QStringLiteral("zero") : QStringLiteral("nonzero");
}

// 解压 buf[i:] 的第一个 zlib 流；成功返回 true 并填 out / consumed
// 分块输出，避免一次性分配超大缓冲
static bool inflateAt(const QByteArray& buf, int i, int end, QByteArray& out, int& consumed) {
    out.clear();
    consumed = 0;
    z_stream zs;
    std::memset(&zs, 0, sizeof(zs));
    if (inflateInit(&zs) != Z_OK) return false;

    const int CHUNK = 1 << 16;              // 64 KB
    const int MAX_OUT = 256 << 20;          // 单流解压上限 256 MB
    QByteArray chunk(CHUNK, Qt::Uninitialized);
    zs.next_in  = reinterpret_cast<Bytef*>(const_cast<char*>(buf.data() + i));
    zs.avail_in = static_cast<uInt>(end - i);

    int rc = Z_OK;
    int produced = 0;
    while (true) {
        zs.next_out = reinterpret_cast<Bytef*>(chunk.data());
        zs.avail_out = static_cast<uInt>(CHUNK);
        rc = inflate(&zs, Z_NO_FLUSH);
        const int got = CHUNK - static_cast<int>(zs.avail_out);
        if (got > 0) {
            out.append(chunk.constData(), got);
            produced += got;
        }
        if (rc == Z_STREAM_END) break;
        if (rc != Z_OK) { inflateEnd(&zs); return false; }
        if (zs.avail_in == 0) { inflateEnd(&zs); return false; }   // 输入耗尽仍未结束
        if (produced > MAX_OUT) { inflateEnd(&zs); return false; }
    }
    consumed = (end - i) - static_cast<int>(zs.avail_in);
    inflateEnd(&zs);

    if (produced <= 0) return false;
    if (consumed <= 0) consumed = 1;
    return true;
}

// 向后找下一个「能成功解压」的 zlib 页起点；找不到返回 -1
// maxGap <= 0 表示不限距离；firstOut/firstUsed 可复用首屏的解压结果，避免重复解压
static int findNextPage(const QByteArray& b, int start, int end, int maxGap,
                        QByteArray* firstOut = nullptr, int* firstUsed = nullptr) {
    const int limit = (maxGap <= 0) ? (end - 2) : qMin(end - 2, start + maxGap);
    int i = start;
    while (i <= limit) {
        i = b.indexOf(char(0x78), i);          // 直接跳到下一个 0x78，避免逐字节
        if (i < 0 || i > limit) return -1;
        if (isZlibHdr(b, i)) {
            QByteArray tmp;
            int used = 0;
            if (inflateAt(b, i, end, tmp, used)) {
                if (firstOut) *firstOut = tmp;
                if (firstUsed) *firstUsed = used;
                return i;
            }
        }
        ++i;
    }
    return -1;
}

static QString classify(const QByteArray& d) {
    int s = 0;
    if (d.size() >= 3 && static_cast<uint8_t>(d[0]) == 0xEF &&
        static_cast<uint8_t>(d[1]) == 0xBB && static_cast<uint8_t>(d[2]) == 0xBF)
        s = 3;                                   // 跳过 UTF-8 BOM 再判魔数
    if (d.size() > s && d.mid(s, 4) == QByteArrayLiteral("PSIN")) return QStringLiteral("psin");
    if (d.size() > s && d.mid(s, 4) == QByteArrayLiteral("RBF0")) return QStringLiteral("rbf");
    if (d.size() > s && d.mid(s, 4) == QByteArrayLiteral("GFX*")) return QStringLiteral("gfx");
    if (d.size() > s && d.mid(s, 4) == QByteArrayLiteral("<?xm")) return QStringLiteral("xml");
    if (d.size() > s && d.mid(s, 4) == QByteArrayLiteral("CHKS")) return QStringLiteral("chk");
    if (d.size() > s && d.mid(s, 4) == QByteArrayLiteral("9FPR")) return QStringLiteral("rpf");
    // 0DRP 资源容器（GTA VI 通用资源包装，+0x10 处魔数）
    if (d.size() > 0x14 && d.mid(0x10, 4) == QByteArrayLiteral("0DRP")) {
        // 只有完整结构校验通过才算 GXT 文本表（大 + 锚点 + 槽位 + 解码率）；
        // 仅凭「大」会把普通二进制 0DRP 误标成文本表
        if (d.size() > (2 << 20) && GxtParser::hasTextTableStructure(d)) {
            const GxtInfo g = GxtParser::parse(d);
            if (g.ok) return QStringLiteral("gxt");
        }
        return QStringLiteral("0drp");
    }
    return QStringLiteral("bin");
}

// ---------------------------------------------------------------------------
// 打开
// ---------------------------------------------------------------------------
bool RpfReader::open(const QString& path, QString* error) {
    m_open = false;
    m_path = path;
    m_raw.clear();
    m_header.clear();
    m_resources.clear();
    m_nested.clear();

    QFile f(path);
    if (!f.open(QIODevice::ReadOnly)) {
        if (error) *error = QStringLiteral("无法打开文件：%1").arg(path);
        return false;
    }
    m_raw = f.readAll();
    f.close();

    if (m_raw.size() < 0x40 || !m_raw.startsWith("9FPR")) {
        if (error) *error = QStringLiteral("不是 RPF9 归档（缺少 9FPR 魔数）");
        return false;
    }

    parseHeader();
    scanNested();
    scanResources();
    discoverNames();
    discoverNestedNames();
    assignRelPaths();
    computeCoverage();
    m_open = true;
    return true;
}

QString RpfReader::archiveName() const {
    return QFileInfo(m_path).fileName();
}

// ---------------------------------------------------------------------------
// 头部：每个字段标注来源，未解明的一律写「含义未明」
// ---------------------------------------------------------------------------
void RpfReader::parseHeader() {
    const QByteArray& b = m_raw;
    auto add = [this](uint32_t off, const char* size, const QString& val,
                      Source src, const QString& note) {
        HeaderField f;
        f.offset = off;
        f.size = QString::fromLatin1(size);
        f.value = val;
        f.source = src;
        f.note = note;
        m_header.append(f);
    };

    add(0x00, "char[4]", QStringLiteral("%1").arg(QString::fromLatin1(b.constData(), 4)),
        Source::FromFile, QStringLiteral("归档魔数，读作 RPF9"));

    const uint32_t v04 = rd32(b, 4), v08 = rd32(b, 8), v0c = rd32(b, 12);
    add(0x04, "u32", QStringLiteral("0x%1  (%2)").arg(v04, 8, 16, QChar('0')).arg(v04),
        Source::Derived,
        QStringLiteral("目录表（TOC）总大小，含 0x40 头。"
                       "42 个归档验证：数据区起点 = 4 KB 对齐上取整(0x40+本值)"));
    add(0x08, "u32", QStringLiteral("0x%1  (%2)").arg(v08, 8, 16, QChar('0')).arg(v08),
        Source::Unknown,
        QStringLiteral("含义未解明。13 个语言包上恒为 65,376（0xFF00），"
                       "疑似固定容量上限，而非实际长度"));
    add(0x0C, "u32", QStringLiteral("0x%1  (%2)").arg(v0c, 8, 16, QChar('0')).arg(v0c),
        Source::Unknown,
        QStringLiteral("含义未解明。13 个语言包上随内容小幅波动（0xFF50~0xFFB0），"
                       "疑似实际使用长度"));

    // 0x10 起 8 字节
    {
        QString hex;
        for (int i = 0x10; i < 0x18; ++i)
            hex += QStringLiteral("%1").arg(static_cast<uint8_t>(b[i]), 2, 16, QChar('0'));
        add(0x10, "u64", hex, Source::Unknown,
            QStringLiteral("每文件不同，疑似哈希/密钥材料"));
    }

    const uint32_t v18 = rd32(b, 0x18), v1c = rd32(b, 0x1C);
    add(0x18, "u32", QStringLiteral("0x%1  (%2)").arg(v18, 8, 16, QChar('0')).arg(v18),
        Source::FromFile, QStringLiteral("全部归档恒为 0x47A00"));
    add(0x1C, "u32", QStringLiteral("0x%1  (%2)").arg(v1c, 8, 16, QChar('0')).arg(v1c),
        Source::FromFile, QStringLiteral("全部归档恒为 0x150"));

    const uint16_t v20a = rd16(b, 0x20), v20b = rd16(b, 0x22);
    add(0x20, "u16,u16", QStringLiteral("%1 , %2").arg(v20a).arg(v20b),
        Source::Unknown, QStringLiteral("随文件变化（4..8 , 1..2），含义未解明"));

    const uint32_t v24 = rd32(b, 0x24);
    add(0x24, "u32", QStringLiteral("%1").arg(v24),
        Source::Derived, QStringLiteral("条目数；13 个语言包上与实际资源数完全吻合"));

    const uint32_t v28 = rd32(b, 0x28);
    add(0x28, "u32", QStringLiteral("0x%1").arg(v28, 8, 16, QChar('0')),
        Source::Unknown,
        QStringLiteral("全部 42 个归档只出现 5 种取值（0xDA72573E / 0xC0A92754 / "
                       "0x5A5B4C6F / 0xD98004D5 / 0xABE9B070）：与归档类别相关，"
                       "不是每文件随机的密钥材料"));

    const uint32_t v2c = rd32(b, 0x2C), v30 = rd32(b, 0x30);
    add(0x2C, "u32", QStringLiteral("0x%1  (%2)").arg(v2c, 8, 16, QChar('0')).arg(v2c),
        Source::FromFile, QStringLiteral("全部归档恒为 0x90F02"));
    add(0x30, "u32", QStringLiteral("0x%1  (%2)").arg(v30, 8, 16, QChar('0')).arg(v30),
        Source::FromFile, QStringLiteral("全部归档恒为 0x10"));

    add(0x34, "12B", QStringLiteral("全零"), Source::FromFile, QStringLiteral("填充"));

    // ---- 目录表（TOC）总览：大小 + 固定哨兵 + 加密正文 ----
    m_tocSize = v04;
    m_tocEntryBytes = v24 * 16;
    m_tocNameBytes = (m_tocSize > 0x40 + m_tocEntryBytes)
                         ? (m_tocSize - 0x40 - m_tocEntryBytes)
                         : 0;
    m_tocSentinel = b.mid(0x40, 32);
    m_tocSentinelOk = (m_tocSentinel.size() == 32) &&
                      (std::memcmp(m_tocSentinel.constData(), kTocSentinel, 32) == 0);

    QString sentHex;
    for (int i = 0; i < m_tocSentinel.size(); ++i)
        sentHex += QStringLiteral("%1").arg(static_cast<uint8_t>(m_tocSentinel[i]), 2, 16, QChar('0'));
    add(0x40, "32B", sentHex.left(16) + QStringLiteral("…"),
        Source::FromFile,
        QStringLiteral("TOC 明文哨兵：42 个归档逐字节相同（%1）。"
                       "其后为每归档加密的条目表 + 名字/哈希区")
            .arg(m_tocSentinelOk ? QStringLiteral("本文件符合") : QStringLiteral("本文件不符")));

    add(0x60, "n/a",
        QStringLiteral("条目 %1×16 = %2 B；名字/哈希区 %3 B")
            .arg(v24).arg(m_tocEntryBytes).arg(m_tocNameBytes),
        Source::Derived,
        QStringLiteral("TOC 正文整体加密，无法读出文件名/偏移/哈希；"
                       "已排除 AES-ECB/CBC/CTR、ChaCha20、RC4、周期 XOR、"
                       "明文哈希与 GTA5 已知密钥"));
}

// ---------------------------------------------------------------------------
// 内嵌归档：4 KB 对齐处的 9FPR
// ---------------------------------------------------------------------------
void RpfReader::scanNested() {
    const QByteArray& b = m_raw;
    for (int pos = 0; pos + 0x40 <= b.size(); pos += 0x1000) {
        if (!b.mid(pos, 4).startsWith("9FPR")) continue;
        if (pos == 0) continue;                 // 归档自身头
        NestedArchive a;
        a.offset = static_cast<uint64_t>(pos);
        a.entryCount = rd32(b, pos + 0x24);
        a.nameLen = rd32(b, pos + 0x04);
        a.tocSize = a.nameLen;
        a.tocEnd = a.offset + 0x40 + a.tocSize;
        a.dataStart = align4k(a.tocEnd);
        a.dataKind = dataKindAt(b, a.dataStart);
        a.entryBytes = a.entryCount * 16;
        a.restBytes = (a.tocSize > 0x40 + a.entryBytes)
                          ? (a.tocSize - 0x40 - a.entryBytes)
                          : 0;
        m_nested.append(a);
    }
}

// ---------------------------------------------------------------------------
// 资源扫描：zlib 页 + 64KB 合并规则
//   一个资源 = 连续若干 64KB 页；某页解压长度恰为 65536 的整数倍时
//   下一页仍属同一资源，否则该页是末页。
//   页与页之间最多 15 字节零填充。
// ---------------------------------------------------------------------------
void RpfReader::scanResources() {
    const QByteArray& b = m_raw;
    const int end = b.size();

    // 数据区起点：头部 +0x04 = TOC 总大小（含 0x40 头），再按 4 KB 上取整。
    // 42 个归档（含 41 个内嵌）全部满足：(tocSize-0x40) % 16 == 0 且
    // count*16 <= tocSize-0x40。起点处应是 zlib 页 / 内嵌 RPF / 未压缩数据。
    const uint32_t s04 = rd32(b, 4);
    const uint64_t tocEnd = 0x40 + static_cast<uint64_t>(s04);
    uint64_t hdrStart = align4k(tocEnd);
    if (hdrStart >= static_cast<uint64_t>(end)) hdrStart = 0;

    int pos = -1;
    if (hdrStart != 0)
        pos = findNextPage(b, static_cast<int>(hdrStart), end, 1 << 20);
    if (pos < 0)                                    // 头部不靠谱时退回全盘扫描
        pos = findNextPage(b, 0x40, end, 1 << 20);
    if (pos < 0) {
        // 全文件没有任何可解压页（如 appdata0.rpf：数据区非 zlib）
        // 仍按头部给出数据区起点，保证覆盖率如实统计，而不是报成 0 字节
        m_coverage.dataStart = (hdrStart != 0) ? hdrStart : 0x40;
        return;
    }

    m_coverage.dataStart = (hdrStart != 0) ? hdrStart : static_cast<uint64_t>(pos);

    int seq = 0;
    while (pos < end - 2) {
        // 外层不限距离：资源之间可能隔着很大的空隙（未识别结构/未知数据）
        QByteArray firstData;
        int firstUsed = 0;
        const int start = findNextPage(b, pos, end, 0, &firstData, &firstUsed);
        if (start < 0) break;

        // 保持原合并语义：首屏不做 gap 检查，但同样受「64KB 整数倍」约束；
        // 首屏复用 findNextPage 的解压结果，后续页复用 findNextPage 的解压结果（各一次）
        QVector<QByteArray> parts;
        int cur = start;
        int prevEnd = start;
        bool first = true;
        QByteArray out = firstData;
        int used = firstUsed;
        while (cur < end - 2) {
            int q = -1;
            if (first) {
                q = start;
            } else {
                q = findNextPage(b, cur, end, 32, &out, &used);
                if (q < 0) break;
                const int gap = q - prevEnd;
                if (gap < 0 || gap > 16) break;
                bool padOk = true;
                for (int z = prevEnd; z < q; ++z) {
                    if (b[z] != 0) { padOk = false; break; }
                }
                if (!padOk) break;
            }
            parts.append(out);
            cur = q + used;
            prevEnd = cur;
            first = false;
            if (out.size() % 65536 != 0) break;            // 末页
        }
        if (parts.isEmpty()) {
            pos = start + 1;
            continue;
        }

        QByteArray blob;
        for (const QByteArray& p : parts) blob += p;

        ++seq;
        Resource r;
        r.seq = seq;
        r.offset = static_cast<uint64_t>(start);
        r.compSize = static_cast<uint32_t>(cur - start);
        r.size = static_cast<uint32_t>(blob.size());
        r.pages = parts.size();
        r.type = classify(blob);
        r.sha1 = QString::fromLatin1(
            QCryptographicHash::hash(blob, QCryptographicHash::Sha1).toHex());
        r.data = blob;
        r.realName = lookupRealName(r.offset, r.seq);
        m_resources.append(r);

        pos = cur;
    }

    // 内嵌归档的资源数与归属：区间 = [本归档偏移, 下一个归档偏移)
    for (int ai = 0; ai < m_nested.size(); ++ai) {
        NestedArchive& a = m_nested[ai];
        const uint64_t lo = a.offset;
        const uint64_t hi = (ai + 1 < m_nested.size())
                                ? m_nested[ai + 1].offset
                                : static_cast<uint64_t>(b.size());
        int n = 0;
        for (int ri = 0; ri < m_resources.size(); ++ri) {
            Resource& r = m_resources[ri];
            if (r.offset >= lo && r.offset < hi) {
                r.nestedIdx = ai;
                ++n;
            }
        }
        a.resourceCount = n;
    }

    // 每个内嵌归档：数据区里未被 zlib 流覆盖、≥4KB 且含非零字节的块 → 疑似未压缩数据
    auto analyzeSpan = [&](uint64_t from, uint64_t to, NestedArchive& a) {
        if (to <= from || (to - from) < 4096) return;
        uint64_t nonZero = 0;
        for (uint64_t i = from; i < to; ++i)
            if (m_raw[static_cast<int>(i)] != 0) ++nonZero;
        if (nonZero == 0) return;
        ++a.rawSpans;
        a.rawBytes += (to - from);
        a.rawNonZero += nonZero;
    };
    for (int ai = 0; ai < m_nested.size(); ++ai) {
        NestedArchive& a = m_nested[ai];
        const uint64_t lo = a.dataStart;
        const uint64_t hi = (ai + 1 < m_nested.size())
                                ? m_nested[ai + 1].offset
                                : static_cast<uint64_t>(b.size());
        if (lo >= hi) continue;
        uint64_t cursor = lo;
        for (const Resource& r : m_resources) {
            if (r.offset < lo || r.offset >= hi) continue;
            if (r.offset > cursor) analyzeSpan(cursor, r.offset, a);
            const uint64_t e = r.offset + r.compSize;
            if (e > cursor) cursor = e;
        }
        if (cursor < hi) analyzeSpan(cursor, hi, a);
    }
}

// ---------------------------------------------------------------------------
// 真实文件名回收：只能来自归档自身的清单 XML，绝不猜测。
//   1) 自引用：清单的 <id> 形如路径（含 '/' 与 ':'）时，它就是该清单自己的真实名
//   2) 顺序映射：清单的 <fileList> 声明 N 个文件，紧跟其后的 N 个资源按序对应；
//      仅当「扩展名与内容类型吻合率 ≥ 90%」时才采信，否则放弃（宁缺毋滥）
// ---------------------------------------------------------------------------
static bool extMatchesType(const QString& path, const QString& type) {
    QString e = QFileInfo(path).suffix().toLower();
    if (type == "xml") return e == "xml" || e == "meta" || e == "txt" || e == "ini";
    if (type == "psin") return e == "psin" || e == "bin";
    if (type == "rbf")  return e == "rbf" || e == "bin";
    if (type == "gfx")  return e == "gfx" || e == "bin";
    if (type == "chk")  return e == "chk" || e == "bin";
    return e == "bin" || e == "dat" || e == "bk2" || e == "rpf" || e == "ityp"
        || e == "ydr" || e == "yft" || e == "ytd" || e == "ymt" || e == "ybn"
        || e == "ypt" || e == "ycd" || e == "awc" || e == "rel" || e.isEmpty();
}

void RpfReader::discoverNames() {
    static const QRegularExpression reId(QStringLiteral("<id>\\s*([^<]+?)\\s*</id>"));
    static const QRegularExpression reFn(QStringLiteral("<filename>\\s*([^<]+?)\\s*</filename>"));

    // 资源按「所属归档」分组：内嵌归档各自成组，组内保持物理偏移顺序。
    // 清单声明的 <fileList> 只可能映射到同一归档内的后续资源，不能跨归档。
    QHash<int, QVector<int>> groups;
    for (int i = 0; i < m_resources.size(); ++i)
        groups[m_resources[i].nestedIdx].append(i);

    struct Manifest {
        int index = -1;
        int group = -1;
        int posInGroup = -1;
        QString id;
        QStringList files;
    };
    QList<Manifest> mans;

    for (auto it = groups.cbegin(); it != groups.cend(); ++it) {
        const QVector<int>& g = it.value();
        for (int p = 0; p < g.size(); ++p) {
            const int i = g[p];
            const QByteArray& d = m_resources[i].data;
            if (!d.contains("<filename>") && !d.contains("ContentChangeSetDef"))
                continue;
            const QString txt = QString::fromUtf8(d);
            Manifest m;
            m.index = i;
            m.group = it.key();
            m.posInGroup = p;
            auto mi = reId.match(txt);
            if (mi.hasMatch()) m.id = mi.captured(1).trimmed();
            auto fn = reFn.globalMatch(txt);
            while (fn.hasNext()) m.files << fn.next().captured(1).trimmed();
            mans.append(m);
        }
    }

    // 1) 自引用：清单的 <id> 本身就是该清单自己的真实路径
    for (const Manifest& m : mans) {
        if (m.id.isEmpty()) continue;
        if (m.id.contains(QLatin1Char('/')) && m.id.contains(QLatin1Char(':'))) {
            Resource& r = m_resources[m.index];
            if (r.realName.isEmpty()) {
                r.realName = m.id;
                r.nameSource = QStringLiteral("清单 <id> 自引用");
            }
        }
    }

    // 2) 顺序映射：清单声明 N 个文件，紧跟其后的 N 个资源按序对应
    //    只允许在同一归档组内匹配；扩展名吻合率 ≥ 90% 才采信（宁缺毋滥）
    for (const Manifest& m : mans) {
        if (m.files.isEmpty()) continue;
        const QVector<int>& g = groups.value(m.group);
        const int start = m.posInGroup + 1;
        const int end = start + m.files.size();
        if (end > g.size()) continue;                 // 跨出本归档组，不采信

        int match = 0;
        for (int j = 0; j < m.files.size(); ++j)
            if (extMatchesType(m.files[j], m_resources[g[start + j]].type)) ++match;
        const double ratio = double(match) / double(m.files.size());
        if (ratio < 0.9) continue;

        QString src = QStringLiteral("清单顺序映射（%1）")
                          .arg(m.id.isEmpty() ? QStringLiteral("#%1").arg(m.index) : m.id);
        if (m.group >= 0 && m.group < m_nested.size())
            src += QStringLiteral(" @内嵌归档 0x%1")
                       .arg(m_nested[m.group].offset, 0, 16);

        for (int j = 0; j < m.files.size(); ++j) {
            Resource& r = m_resources[g[start + j]];
            if (r.realName.isEmpty()) {
                r.realName = m.files[j];
                r.nameSource = src;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// 内嵌归档真名：只采信「游戏清单 core_language 声明的 13 个 data/lang/*.rpf」，
// 且必须通过 GXT 文字内容校验（中文包含汉字、日文包含假名……），宁缺毋滥。
// ---------------------------------------------------------------------------
void RpfReader::discoverNestedNames() {
    // core_language 清单声明的 13 个语言包（字母序 == 归档偏移序，已验证）
    static const char* kLangNames[13] = {
        "data/lang/american_final.rpf",
        "data/lang/brazilian_final.rpf",
        "data/lang/chinesesimp_final.rpf",
        "data/lang/chinesetrad_final.rpf",
        "data/lang/french_final.rpf",
        "data/lang/german_final.rpf",
        "data/lang/italian_final.rpf",
        "data/lang/japanese_final.rpf",
        "data/lang/korean_final.rpf",
        "data/lang/mexican_final.rpf",
        "data/lang/polish_final.rpf",
        "data/lang/russian_final.rpf",
        "data/lang/spanish_final.rpf",
    };

    // 只取条目数 == 1115 的归档（本作语言包的实测特征），按偏移升序
    QList<int> langIdx;
    for (int i = 0; i < m_nested.size(); ++i)
        if (m_nested[i].entryCount == 1115) langIdx.append(i);
    if (langIdx.size() != 13) return;   // 数量不符就不猜

    std::sort(langIdx.begin(), langIdx.end(), [this](int a, int b) {
        return m_nested[a].offset < m_nested[b].offset;
    });

    // GXT 文字内容校验：每包最大的 0DRP 资源即 GXT 文本表，检测其文字系统
    // 0=拉丁 1=汉字 2=假名 3=谚文 4=西里尔；-1 = 未检出
    auto scriptOf = [this](int nestedIdx) -> int {
        int best = -1;
        size_t bestSize = 0;
        for (const Resource& r : m_resources) {
            if (r.nestedIdx != nestedIdx) continue;
            if (r.size > bestSize && r.size > (2u << 20) &&
                r.data.size() > 0x14 && r.data.mid(0x10, 4) == QByteArrayLiteral("0DRP")) {
                best = r.seq;
                bestSize = r.size;
            }
        }
        if (best < 0) return -1;
        const Resource* gxt = nullptr;
        for (const Resource& r : m_resources)
            if (r.seq == best) { gxt = &r; break; }
        if (!gxt) return -1;

        int cjk = 0, kana = 0, hangul = 0, cyr = 0;
        const QByteArray& d = gxt->data;
        // 只采样文本池（跳过槽位表），粗解 UTF-8 统计各文字系统
        const int from = qMin(d.size() / 4, 0x110000);
        for (int i = from; i + 3 < d.size() && i < from + 1500000; ) {
            const uint8_t c = static_cast<uint8_t>(d[i]);
            if (c < 0x80) { ++i; continue; }
            int len = 0; uint32_t cp = 0;
            if ((c & 0xE0) == 0xC0) { len = 2; cp = c & 0x1Fu; }
            else if ((c & 0xF0) == 0xE0) { len = 3; cp = c & 0x0Fu; }
            else if ((c & 0xF8) == 0xF0) { len = 4; cp = c & 0x07u; }
            else { ++i; continue; }
            if (i + len > d.size()) break;
            bool ok = true;
            for (int k = 1; k < len; ++k) {
                const uint8_t cc = static_cast<uint8_t>(d[i + k]);
                if ((cc & 0xC0) != 0x80) { ok = false; break; }
                cp = (cp << 6) | (cc & 0x3Fu);
            }
            if (!ok) { ++i; continue; }
            i += len;
            if (cp >= 0x4E00 && cp <= 0x9FFF) ++cjk;
            else if (cp >= 0x3040 && cp <= 0x30FF) ++kana;
            else if (cp >= 0xAC00 && cp <= 0xD7AF) ++hangul;
            else if (cp >= 0x0400 && cp <= 0x04FF) ++cyr;
        }
        if (kana > 200) return 2;
        if (hangul > 200) return 3;
        if (cjk > 200) return 1;
        if (cyr > 200) return 4;
        return 0;
    };

    // 期望文字系统（与 kLangNames 同序）
    static const int kExpect[13] = {
        0 /*american*/, 0 /*brazilian*/, 1 /*chinesesimp*/, 1 /*chinesetrad*/,
        0 /*french*/, 0 /*german*/, 0 /*italian*/, 2 /*japanese*/, 3 /*korean*/,
        0 /*mexican*/, 0 /*polish*/, 4 /*russian*/, 0 /*spanish*/,
    };

    for (int k = 0; k < 13; ++k) {
        const int got = scriptOf(langIdx[k]);
        if (got != kExpect[k]) continue;          // 内容校验不过 → 不采信
        NestedArchive& a = m_nested[langIdx[k]];
        a.realName = QString::fromLatin1(kLangNames[k]);
        a.nameSource = QStringLiteral("游戏清单 core_language + GXT 文字内容校验");
    }
}

// ---------------------------------------------------------------------------
// 展示/导出路径：真实名优先；否则按内容类型给出稳定的名字（不编造语义）
// ---------------------------------------------------------------------------
void RpfReader::assignRelPaths() {
    QHash<QString, int> used;
    for (int i = 0; i < m_resources.size(); ++i) {
        Resource& r = m_resources[i];

        QString p;
        if (!r.realName.isEmpty()) {
            p = r.realName;
            p.remove(QRegularExpression(QStringLiteral("^\\$\\([^)]*\\)/")));
            const int colon = p.indexOf(QLatin1Char(':'));
            if (colon >= 0) p = p.mid(colon + 1);
            while (p.startsWith(QLatin1Char('/'))) p.remove(0, 1);
        } else {
            // 无真实名：按类型命名，语义只来自内容魔数
            QString leaf;
            if (r.type == QLatin1String("gxt"))
                leaf = QStringLiteral("文本表.gxt");
            else if (r.type == QLatin1String("psin")) {
                // 视觉命名：有 6 块链的是模式对象；否则按文本占比区分文本/数据
                if (!psinChunks(r.data).isEmpty()) {
                    leaf = QStringLiteral("模式对象.psin");
                } else {
                    int printable = 0;
                    const int n = qMin(r.data.size(), 4096);
                    for (int k = 0; k < n; ++k) {
                        const quint8 c = quint8(r.data[k]);
                        if ((c >= 0x20 && c < 0x7F) || c == '\n' || c == '\r' || c == '\t')
                            ++printable;
                    }
                    leaf = (n > 0 && printable * 10 > n * 6) ? QStringLiteral("文本.psin")
                                                            : QStringLiteral("数据.psin");
                }
            }
            else if (r.type == QLatin1String("gfx"))
                leaf = QStringLiteral("UI容器.gfx");
            else if (r.type == QLatin1String("xml"))
                leaf = QStringLiteral("清单.xml");
            else if (r.type == QLatin1String("rbf")) {
                // 用 RBF0 头里的类名命名（u16 长度 + 类名 @0x0A）
                QString cls;
                if (r.data.size() >= 0x0C) {
                    const int len = quint8(r.data[0x0A]) | (quint8(r.data[0x0B]) << 8);
                    if (len >= 2 && len <= 64 && 0x0C + len <= r.data.size()) {
                        const QByteArray name = r.data.mid(0x0C, len);
                        bool ok = true;
                        for (char c : name)
                            if (c < 32 || c > 126) { ok = false; break; }
                        if (ok) cls = QString::fromLatin1(name);
                    }
                }
                leaf = (cls.isEmpty() ? QStringLiteral("数据") : cls) + QStringLiteral(".rbf");
            }
            else if (r.type == QLatin1String("chk"))
                leaf = QStringLiteral("校验.chk");
            else if (r.type == QLatin1String("0drp"))
                leaf = QStringLiteral("资源.0drp");
            else if (r.type == QLatin1String("bin")) {
                // 未知二进制里常嵌有真实资源名（武器 w_*、粒子 ptfx_*、*.ydr 等）
                const QStringList names = embeddedAssetNames(r.data, 1);
                leaf = names.isEmpty() ? QStringLiteral("数据.bin") : names.first();
            }
            else
                leaf = QStringLiteral("数据.bin");
            p = leaf;
        }

        // 内嵌归档归组：统一加前缀（若路径已在归档名之下则不重复加）
        if (r.nestedIdx >= 0 && r.nestedIdx < m_nested.size()) {
            QString grp = m_nested[r.nestedIdx].realName;
            if (grp.isEmpty()) grp = QStringLiteral("内嵌归档");
            if (p != grp && !p.startsWith(grp + QLatin1Char('/')))
                p = grp + QLatin1Char('/') + p;
        }

        // 同名消歧：追加 ~2 ~3（导出到文件系统必须唯一）
        const QString key = p;
        int n = used.value(key, 0) + 1;
        used.insert(key, n);
        if (n > 1) {
            const int dot = p.lastIndexOf(QLatin1Char('.'));
            if (dot > p.lastIndexOf(QLatin1Char('/')))
                p.insert(dot, QStringLiteral("~%1").arg(n));
            else
                p += QStringLiteral("~%1").arg(n);
        }
        r.relPath = p;
    }
}

namespace {
QByteArray tsvEscaped(const QString& s) {
    QByteArray b = s.toUtf8();
    b.replace("\\", "\\\\");
    b.replace("\t", "\\t");
    b.replace("\n", "\\n");
    b.replace("\r", "\\r");
    return b;
}
QByteArray csvQuoted(const QString& s) {
    const QByteArray u = s.toUtf8();
    QByteArray b;
    b.reserve(u.size() + 2);
    b += '"';
    for (char c : u) {
        if (c == '"') b += '"';
        b += c;
    }
    b += '"';
    return b;
}
} // namespace

bool RpfReader::exportTextCorpus(const QString& dir, CorpusStats* stats,
                                 QString* error,
                                 const std::function<bool(int, int)>& progress) const {
    if (m_resources.isEmpty()) {
        if (error) *error = QStringLiteral("归档尚未打开");
        return false;
    }
    if (!QDir().mkpath(dir)) {
        if (error) *error = QStringLiteral("无法创建目录：%1").arg(dir);
        return false;
    }

    QHash<QString, QFile*> files;
    QByteArray index = QByteArrayLiteral("seq,language,strings,pool_bytes,rel_path\n");
    CorpusStats st;
    auto cleanup = [&files] {
        for (QFile* f : files) {
            f->close();
            delete f;
        }
        files.clear();
    };
    auto fail = [&](const QString& msg) {
        cleanup();
        if (error) *error = msg;
        return false;
    };

    const int total = m_resources.size();
    for (int i = 0; i < total; ++i) {
        if (progress && !progress(i, total)) return fail(QStringLiteral("已取消"));

        const Resource& r = m_resources.at(i);
        if (r.type != QLatin1String("0drp")) continue;
        const QVector<DrpItem> items = drpItems(r.data);
        const QByteArray pool = drpTextPool(r.data, items);
        if (pool.isEmpty()) continue;
        const QStringList strings = drpPoolStrings(pool, 0);
        if (strings.isEmpty()) continue;

        QString key = languageKeyFromPath(r.relPath);
        if (key.isEmpty()) {
            const QString lang = drpTextLanguage(strings);
            if (lang == QLatin1String("中文")) key = QStringLiteral("zh");
            else if (lang == QLatin1String("日文")) key = QStringLiteral("ja");
            else if (lang == QLatin1String("韩文")) key = QStringLiteral("ko");
            else if (lang == QLatin1String("俄文")) key = QStringLiteral("ru");
            else if (lang.startsWith(QLatin1String("拉丁"))) key = QStringLiteral("latin");
            else key = QStringLiteral("other");
        }

        QFile*& f = files[key];
        if (!f) {
            f = new QFile(QDir(dir).filePath(key + QStringLiteral(".tsv")));
            if (!f->open(QIODevice::WriteOnly | QIODevice::Truncate))
                return fail(QStringLiteral("无法写入：%1").arg(f->fileName()));
        }

        QByteArray block;
        block.reserve(pool.size() + strings.size() * 8);
        for (int k = 0; k < strings.size(); ++k) {
            block += QByteArray::number(r.seq);
            block += '\t';
            block += QByteArray::number(k + 1);
            block += '\t';
            block += tsvEscaped(strings.at(k));
            block += '\n';
        }
        if (f->write(block) != block.size())
            return fail(QStringLiteral("写入失败：%1").arg(f->fileName()));

        ++st.containers;
        st.strings += strings.size();
        st.bytes += pool.size();
        st.perLanguage[key] += strings.size();

        index += QByteArray::number(r.seq);
        index += ',';
        index += key.toUtf8();
        index += ',';
        index += QByteArray::number(strings.size());
        index += ',';
        index += QByteArray::number(pool.size());
        index += ',';
        index += csvQuoted(r.relPath);
        index += '\n';
    }
    if (progress) progress(total, total);
    cleanup();

    QFile idx(QDir(dir).filePath(QStringLiteral("_index.csv")));
    if (!idx.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        if (error) *error = QStringLiteral("无法写入：%1").arg(idx.fileName());
        return false;
    }
    idx.write(index);
    idx.close();

    if (stats) *stats = st;
    return true;
}

void RpfReader::computeCoverage() {
    Coverage c;
    c.fileSize = static_cast<uint64_t>(m_raw.size());
    c.dataStart = m_coverage.dataStart;
    c.resourceCount = m_resources.size();

    QList<const Resource*> sorted;
    sorted.reserve(m_resources.size());
    for (const Resource& r : m_resources) sorted.append(&r);
    std::sort(sorted.begin(), sorted.end(), [](const Resource* a, const Resource* b) {
        return a->offset < b->offset;
    });

    uint64_t bytes = 0;
    uint64_t cursor = c.dataStart;
    auto scanGap = [&](uint64_t from, uint64_t to) {
        if (to <= from) return;
        uint64_t zero = 0;
        for (uint64_t i = from; i < to; ++i)
            if (m_raw[static_cast<int>(i)] == 0) ++zero;
        c.gapZero += zero;
        c.gapNonZero += (to - from) - zero;
        ++c.gapCount;
        if ((to - from) >= 4096 && (to - from) > zero) {
            ++c.rawSpanCount;
            c.rawSpanBytes += (to - from);
            c.rawSpanNonZero += (to - from) - zero;
        }
    };

    for (const Resource* r : sorted) {
        bytes += r->compSize;
        if (r->offset > cursor) scanGap(cursor, r->offset);
        const uint64_t e = r->offset + r->compSize;
        if (e > cursor) cursor = e;
    }
    if (cursor < c.fileSize) scanGap(cursor, c.fileSize);

    c.resourceBytes = bytes;
    c.dataArea = (c.fileSize > c.dataStart) ? (c.fileSize - c.dataStart) : 0;
    // 未计入 = 数据区 - 资源压缩字节（含页间填充、未知结构、未识别数据流）
    c.unaccounted = c.gapZero + c.gapNonZero;
    if (c.unaccounted == 0 && c.dataArea > bytes) c.unaccounted = c.dataArea - bytes;
    m_coverage = c;
}

QString RpfReader::lookupRealName(uint64_t offset, int seq) const {
    Q_UNUSED(offset);
    Q_UNUSED(seq);
    // 真实名只能来自游戏自身清单；本读取器不猜测。
    // 若外部载入过映射（按归档名+序号），在这里查。当前返回空 = 未知。
    return QString();
}

void RpfReader::setKnownNames(const QHash<QString, QString>& map) {
    s_knownNames = map;
}

QHash<QString, QString> RpfReader::knownNames() {
    return s_knownNames;
}
