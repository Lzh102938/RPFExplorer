#pragma once

#include <QByteArray>
#include <QString>
#include <QStringList>
#include <QVector>

// 资源内部嵌入的标准格式（按各自文件头校验，不做语义解析）
struct EmbeddedFile {
    QString kind;      // SWF / BMP / JPEG / RIFF / DDS
    QString ext;       // swf / bmp / jpg / riff / dds
    int     offset = 0;
    int     size = 0;
    quint32 declared = 0;
};

// 扫描一个资源里嵌入的标准文件；重叠的按先到先得丢弃（避免把 BMP 像素里的假头当真）
QVector<EmbeddedFile> scanEmbedded(const QByteArray& d, int maxFiles = 256);

// RBF0：u16 长度 + UTF-8 字符串，返回去重后的可读串（字段名与取值都会包含）
QStringList rbfStrings(const QByteArray& d, int maxStrings = 64);

// PSIN：{4字节标签, 大端 u32 总长度(含8字节头)} 的块链
struct PsinChunk {
    QString tag;
    int     offset = 0;
    int     size = 0;
};
QVector<PsinChunk> psinChunks(const QByteArray& d);

// PSIN 模式记录（LSCH 负载按 32 字节一条）
struct PsinSchemaRecord {
    quint64 hash = 0;   // 字段名哈希（64 位，不可逆成文本）
    quint32 flags = 0;
    quint32 u12 = 0;
    quint64 data = 0;
    quint32 off = 0;
    quint32 aux = 0;
};
QVector<PsinSchemaRecord> psinSchema(const QByteArray& lschPayload);

// 面向导出的结构化报告：块链 + 模式记录 + 取值块头 + 文本片段
QString psinReport(const QByteArray& d);

// 0DRP 子资源表（+0x38/+0x40 指向表首/表尾；每项 16B：u64 段ID+size, u64 0x50指针）
struct DrpItem {
    quint32 id = 0;      // 段 ID（全库仅 11 种；不是文件名哈希）
    quint32 size = 0;
    quint32 offset = 0;
};
QVector<DrpItem> drpItems(const QByteArray& d);

// 段 ID 的可读名；未知返回 "段 0x…"
QString drpSectionName(quint32 id);

// 按段 ID 组合判断容器用途（对白/UI 文本包、资源包、扩展资源包…）
QString drpContainerKind(const QVector<DrpItem>& items);

// 0x10 字符串池（null 分隔 UTF-8）；没有则返回空
QByteArray drpTextPool(const QByteArray& d, const QVector<DrpItem>& items);

// 拆分字符串池；maxStrings <= 0 表示全部
QStringList drpPoolStrings(const QByteArray& pool, int maxStrings = -1);

// 按文字系统判断语言：中文 / 日文 / 韩文 / 俄文 / 拉丁语系 / 未知
QString drpTextLanguage(const QStringList& strings);

// 从任意二进制里提取内嵌资源名（如 w_ar_adb_01.#dr、ptfx_model_x.#dr、*.ydr）
// 只认带合法后缀的 ASCII 名字，去重保序；maxNames <= 0 表示不限
QStringList embeddedAssetNames(const QByteArray& d, int maxNames = 256);

// 从展示路径里的 data/lang/<name>_final.rpf 判断语言；未知返回空
QString languageKeyFromPath(const QString& relPath);
// 语言键 → 中文显示名（american → 英文 …）
QString languageDisplayName(const QString& key);
