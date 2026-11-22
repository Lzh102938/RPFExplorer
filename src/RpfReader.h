#pragma once

// ============================================================================
// RPF9 归档读取器 —— 只做「忠实读取」，不臆造任何数据
// ----------------------------------------------------------------------------
// 三条铁律：
//   1) 每个字段都标注来源：FromFile（字节直读）/ Derived（由字节算出）
//      / External（来自游戏自身清单）/ Unknown（含义未解明）
//   2) 名字未知就写「未知」，绝不猜测、绝不套用其它文件的名字
//   3) 覆盖率如实统计：解出多少、多少字节未计入，都要显示
// ============================================================================

#include <QByteArray>
#include <QHash>
#include <QList>
#include <QString>
#include <QStringList>
#include <QVector>
#include <cstdint>
#include <functional>

// 字段来源：这个值是哪来的
enum class Source {
    FromFile,   // 直接从文件字节读出
    Derived,    // 由文件字节计算/扫描得出
    External,   // 来自游戏自身清单 XML（外部佐证）
    Unknown     // 原始字节可读，但含义未解明
};

QString sourceName(Source s);

// 头部字段
struct HeaderField {
    uint32_t offset = 0;      // 字段在归档内的偏移
    QString  size;            // "u32" / "u64" / "char[4]" / ...
    QString  value;           // 显示值（十六进制 + 十进制）
    Source   source = Source::Unknown;
    QString  note;            // 说明 / 含义
};

// 单个资源（归档内的一个数据流）
struct Resource {
    int      seq = 0;         // 物理存储顺序，从 1 开始
    uint64_t offset = 0;      // 在归档内的偏移
    uint32_t compSize = 0;    // 压缩字节合计
    uint32_t size = 0;        // 解压后字节
    int      pages = 0;       // 占用的 64KB 压缩页数
    QString  type;            // 内容魔数判定（gxt/psin/rbf/gfx/xml/chk/bin）
    QString  sha1;            // 解压内容 SHA-1
    QString  realName;        // 真实文件名（仅当有外部佐证时非空）
    QString  nameSource;      // 真实名的来源说明（如「清单自引用」「清单顺序映射」）
    int      nestedIdx = -1;  // 所属内嵌归档下标；-1 = 顶层
    QString  relPath;         // 展示/导出用相对路径（真实名或内容判定名）
    QByteArray data;          // 解压后的字节
};

// 内嵌归档
struct NestedArchive {
    uint64_t offset = 0;
    uint32_t entryCount = 0;  // 头部 +0x24
    uint32_t nameLen = 0;     // 头部 +0x04：TOC 总大小（含 0x40 头）
    uint32_t tocSize = 0;     // 同 nameLen，语义已解明
    uint64_t tocEnd = 0;      // offset + 0x40 + tocSize
    uint64_t dataStart = 0;   // 4 KB 对齐(tocEnd)：数据区起点
    QString  dataKind;        // 数据区起点类型：zlib / rpf / nonzero / zero / 越界
    uint32_t entryBytes = 0;  // entryCount * 16
    uint32_t restBytes = 0;   // tocSize - 0x40 - entryBytes（名字/哈希区）
    int      rawSpans = 0;    // 数据区里 ≥4KB 的非 zlib 非零块（疑似未压缩数据）
    uint64_t rawBytes = 0;
    uint64_t rawNonZero = 0;  // 这些块里的非零字节数（数据密度参考）
    QString  realName;        // 真实名（外部佐证），否则空
    QString  nameSource;      // 真实名来源
    int      resourceCount = 0;
};

// 覆盖率统计：如实反映解出多少、剩多少没计入
struct Coverage {
    uint64_t fileSize = 0;
    uint64_t dataStart = 0;    // 数据区起点（头部 +0x04 推出，4 KB 对齐）
    uint64_t dataArea = 0;     // 数据区字节数
    uint64_t resourceBytes = 0;// 资源压缩字节合计
    uint64_t unaccounted = 0;  // 未计入字节（空隙/未知结构）
    uint64_t gapZero = 0;      // 其中：全零填充字节
    uint64_t gapNonZero = 0;   // 其中：非零未识别字节
    int      gapCount = 0;     // 未计入区间个数
    uint64_t rawSpanBytes = 0; // 其中：≥4KB 的非 zlib 非零块（疑似未压缩数据）
    int      rawSpanCount = 0;
    uint64_t rawSpanNonZero = 0; // 这些块里的非零字节数
    int      resourceCount = 0;
};

// 多语言语料导出统计
struct CorpusStats {
    int containers = 0;       // 有字符串池的 0DRP 容器
    int strings = 0;          // 非空字符串条数
    qint64 bytes = 0;         // 字符串池原始字节
    QHash<QString, int> perLanguage;  // 语言键 -> 字符串条数
};

class RpfReader {
public:
    bool open(const QString& path, QString* error = nullptr);

    bool isOpen() const { return m_open; }
    QString path() const { return m_path; }
    QString archiveName() const;          // 归档文件名（来自路径，非表内名）

    const QList<HeaderField>& headerFields() const { return m_header; }
    const QList<Resource>& resources() const { return m_resources; }
    const QList<NestedArchive>& nested() const { return m_nested; }
    const Coverage& coverage() const { return m_coverage; }

    // 顶层目录表（TOC）：大小来自头部 +0x04，前 32 字节为固定哨兵，其余为加密正文
    uint32_t tocSize() const { return m_tocSize; }
    uint32_t tocEntryBytes() const { return m_tocEntryBytes; }
    uint32_t tocNameBytes() const { return m_tocNameBytes; }
    QByteArray tocSentinel() const { return m_tocSentinel; }
    bool tocSentinelMatches() const { return m_tocSentinelOk; }

    // 原始字节（用于十六进制预览）
    const QByteArray& raw() const { return m_raw; }

    // 已知真实名（来自游戏清单）：路径 -> 真实名
    static void setKnownNames(const QHash<QString, QString>& map);
    static QHash<QString, QString> knownNames();

    // 把所有 0DRP 字符串池按语言导出为 <语言>.tsv + _index.csv
    // progress 返回 false 表示取消；stats/error 可为空
    bool exportTextCorpus(const QString& dir, CorpusStats* stats = nullptr,
                          QString* error = nullptr,
                          const std::function<bool(int, int)>& progress = {}) const;

private:
    void parseHeader();
    void scanNested();
    void scanResources();
    void discoverNames();     // 从归档内的清单 XML 回收真实文件名
    void discoverNestedNames(); // 内嵌归档真名（清单顺序 + GXT 语言内容双验证）
    void assignRelPaths();    // 为每个资源分配展示/导出用相对路径
    void computeCoverage();
    QString lookupRealName(uint64_t offset, int seq) const;

    bool      m_open = false;
    QString   m_path;
    QByteArray m_raw;
    QList<HeaderField>  m_header;
    QList<Resource>     m_resources;
    QList<NestedArchive> m_nested;
    Coverage  m_coverage;

    uint32_t   m_tocSize = 0;
    uint32_t   m_tocEntryBytes = 0;
    uint32_t   m_tocNameBytes = 0;
    QByteArray m_tocSentinel;
    bool       m_tocSentinelOk = false;

    static QHash<QString, QString> s_knownNames;
};
