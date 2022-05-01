#pragma once

#include "ui_BundleRecovery.h"

#include <bit>
#include <cstdint>
#include <vector>

#include <libdeflate.h>

#include <QDialog>
#include <QDir>
#include <QFile>
#include <QMutex>
#include <QString>
#include <QThread>

class BundleRecovery : public QDialog
{
	Q_OBJECT

public:
	BundleRecovery(QWidget* parent = Q_NULLPTR);
	~BundleRecovery();

	QMutex mutex;
	std::vector<QThread*> threads;

	QString input;
	QString output;
	QString names;
	std::endian endianness = std::endian::native; // Platform
	int versionLimit = 0; // Default to all versions
	uint64_t startOffset = 0;
	uint64_t endOffset = 9007199254740992; // Double precision step limit
	uint64_t interval = 2048;
	uint64_t searchLength = 0; // Do not search for fragments by default

	// The type of corruption occuring in the bundle.
	enum class CorruptionType : int8_t
	{
		Intact,
		DebugData,
		ResourceId,
		ResourceEntries,
		ResourceCompressionInfo,
		ResourceImports,
		ZlibData,
		Uncompressed
	};

	// Stores file information in relation to the image
	struct FileInfo
	{
		// Fragment positions for a single file, or only file start if intact
		std::vector<uint64_t> pos;
		// Fragment sizes for a single file, or only file size if intact
		std::vector<uint32_t> sz;
	};

	// Size and alignment
	struct BundleSAA
	{
		uint32_t size;
		uint32_t alignment;
	};

	// Base bundle structure
	struct Bundle
	{
		// bnd2 v2/v3
		char magic[4];
		uint32_t version; // 16-bit in bnd2 v5
		uint32_t platform; // 16-bit in bnd2 v5
		uint32_t debugDataOffset; // only in bnd2
		uint32_t resourceEntriesCount;
		uint32_t resourceEntriesOffset;
		uint32_t resourceDataOffset[4]; // 1 in bndl, 3 in bnd2 v2, else 4
		uint32_t flags; // not in bndl v3

		// bnd2 v5
		uint64_t defaultResourceId;
		uint32_t defaultStreamIndex;
		char streamNames[4][15];

		// bndl
		BundleSAA chunkSaas[5]; // Like ResourceDataOffset, but using size
		uint32_t chunkMemAddr[5]; // Probably not used
		uint32_t resourceIdsOffset;
		uint32_t importsOffset;
		uint32_t numCompressedResources; // v4/v5
		uint32_t compressionInfoOffset; // v4/v5
		uint32_t unk0; // v5
		uint32_t unk1; // v5
	};

	// Bundle resource entry structure
	struct ResourceEntry
	{
		// bnd2
		uint64_t resourceId;
		uint64_t importHash; // Removed in bnd2 v5
		uint32_t uncompressedSaa[4]; // Only in bnd2
		uint32_t saaOnDisk[4];
		uint32_t diskOffset[4];
		uint32_t importOffset;
		uint32_t resourceTypeId;
		uint16_t importCount;
		uint8_t flags;
		uint8_t streamIndex; // Stream offset in bnd2 v5

		// bndl
		uint32_t resourceDataMemAddr;
		BundleSAA bndlSaaOnDisk[5];
		BundleSAA bndlDiskOffset[5];
		uint32_t memAddr[5];
		BundleSAA compressionInfo[5]; // Separate chunk kept here for ease
	};

	struct ImportEntry
	{
		uint64_t resourceId;
		uint32_t offset;
	};

private:
	Ui::Dialog ui;

	// *************************************************************************
	//                         BundleRecovery.cpp
	// *************************************************************************

	void clearThreads();

	// Returns the nearest multiple of a given number, val, to a given multiple,
	// mult. Useful for aligning to the nearest value rather than the next.
	int nearestMultiple(int val, int mult);

	// Returns the number of resource data chunks in the specified bundle.
	int8_t GetChunkCount(const Bundle& bundle);

	// Returns what the size of the bundle data should be. This excludes debug
	// data in the case of Bundle 2 v3 and v5.
	int GetBundleSize(const Bundle& bundle,
		const std::vector<ResourceEntry>& resources = {});

	int8_t ResourceEntrySize(const Bundle& bundle);

	// Returns size from a Bundle 2 size and alignment field.
	uint32_t GetSizeFromSAA(uint32_t data);

	// Returns alignment from a Bundle 2 size and alignment field.
	uint16_t GetAlignmentFromSAA(uint32_t data);

	// Returns the result code of the libdeflate library's
	// libdeflate_zlib_decompress() function.
	libdeflate_result GetLibdeflateResult(char* resource, int cmp, int ucmp,
		libdeflate_decompressor* dc);

	// Returns the number of bytes read in using the zlib library's inflate()
	// function. Results are imprecise relative to the actual failure point in
	// a zlib stream and should be used with caution.
	uint32_t GetZlibBytesRead(char* resource, int cmp, int ucmp);

	// Outputs a bundle's corruption state to the log window.
	void logCorruption(uint64_t offset, CorruptionType err);

	// Returns true if recovery can begin. Used to enable/disable the Start
	// button.
	bool isReady();

	// Connect UI elements to functions.
	void connectUi();

	// *************************************************************************
	//                         Finder.cpp
	// *************************************************************************

	// Finds and saves the start position of bundles. Also saves the magic and
	// version number.
	void findBundles(std::vector<FileInfo>& info, std::vector<Bundle>& bundles,
		uint64_t start, uint64_t end, int threadId);

	// Sorts the vectors by offset in ascending order
	void sortBundles(std::vector<FileInfo>& info, std::vector<Bundle>& bundles);

	// *************************************************************************
	//                         Reader.cpp
	// *************************************************************************

	// Reads bundle data into vectors for use in validation, defragmentation,
	// and extraction.
	void readBundles(std::vector<FileInfo>& info, std::vector<Bundle>& bundles,
		std::vector<QString>& debugData,
		std::vector<std::vector<ResourceEntry>>& resources,
		int start, int end, int threadId);

	// Reads bundle header data.
	void readHeaders(QFile& img, const FileInfo& info, Bundle& bundle);

	// Reads Bundle 2 debug data (ResourceStringTable XML data).
	void readDebugData(QFile& img, const FileInfo& info, const Bundle& bundle,
		QString& debugData);

	// Reads Bundle 1 resource IDs.
	void readResourceIds(QFile& img, const FileInfo& info, const Bundle& bundle,
		std::vector<ResourceEntry>& resources);

	// Reads bundle resource entries.
	void readResourceEntries(QFile& img, const FileInfo& info,
		const Bundle& bundle, std::vector<ResourceEntry>& resources);

	// Reads Bundle 1 resource compression information.
	void readResourceCompressionInfo(QFile& img, const FileInfo& info,
		const Bundle& bundle, std::vector<ResourceEntry>& resources);

	// Reads Bundle 1 resource imports using valid resource entries.
	// TODO: if (magic == bndl && importsOffset != 0) in validation
	void readResourceImports(QFile& img, const FileInfo& info,
		const Bundle& bundle, std::vector<ResourceEntry>& resources,
		std::vector<std::vector<ImportEntry>>& imports);

	// *************************************************************************
	//                         Validator.cpp
	// *************************************************************************

	// Finds corrupt bundles and sets their corruption type.
	void validateBundles(std::vector<FileInfo>& info,
		std::vector<Bundle>& bundles, std::vector<QString>& debugData,
		std::vector<std::vector<ResourceEntry>>& resources,
		std::vector<std::vector<std::vector<ImportEntry>>>& imports,
		std::vector<CorruptionType>& corrupt, int start, int end,
		int threadId);

	void validateSingleBundle(QFile& img, FileInfo& info, Bundle& bundle,
		QString& debugData, std::vector<ResourceEntry>& resources,
		std::vector<std::vector<ImportEntry>>& imports,
		CorruptionType& corrupt);

	// Returns the position, relative to the start of the bundle, the XML reader
	// fails at while reading bundle debug data. 0 if the debug data is valid.
	int getDebugDataFailPos(const Bundle& bundle, const QString& debugData);

	// Returns the position, relative to the start of the bundle, of the first
	// corrupt resource ID. 0 if all resource IDs are valid.
	int getResourceIdsFailPos(const Bundle& bundle,
		const std::vector<ResourceEntry>& resources);

	// Returns the position, relative to the start of the bundle, of the first
	// corrupt resource entry. 0 if all resource entries are valid.
	int getResourceEntriesFailPos(const Bundle& bundle,
		const std::vector<ResourceEntry>& resources);

	// Returns the position, relative to the start of the bundle, of the first
	// corrupt compression info entry. 0 if all compression info is valid.
	int getResourceCompressionInfoFailPos(const Bundle& bundle,
		const std::vector<ResourceEntry>& resources);

	// Returns the position, relative to the start of the bundle, of the first
	// corrupt import entry. 0 if all import entries are valid.
	int getResourceImportsFailPos(const std::vector<ResourceEntry>& resources,
		const std::vector<std::vector<ImportEntry>>& imports);

	// Returns whether there is a corrupt resource in the specified compressed
	// bundle.
	bool validateCompressedResources(QFile& img, const FileInfo& info,
		const Bundle& bundle, const std::vector<ResourceEntry>& resources);

	// Returns the position, relative to the start of the bundle, of the point
	// of corruption. This may be inaccurate; steps should be taken to mitigate
	// any potential error that may arise.
	int getCompressedResourcesFailPos(QFile& img, const FileInfo& info,
		const Bundle& bundle, const std::vector<ResourceEntry>& resources);

	// *************************************************************************
	//                         Defragmenter.cpp
	// *************************************************************************

	// Attempts to defragments bundles marked as corrupt
	void defragBundles(std::vector<FileInfo>& info,
		const std::vector<Bundle>& bundles, std::vector<QString>& debugData,
		std::vector<std::vector<ResourceEntry>>& resources,
		const std::vector<std::vector<std::vector<ImportEntry>>>& imports,
		std::vector<CorruptionType>& corrupt, int start, int end, int threadId);

	void defragDebugData(QFile& img, FileInfo& info, const Bundle& bundle,
		QString& debugData, std::vector<ResourceEntry>& resources,
		CorruptionType& corrupt, bool& breakLoop, int threadId);

	void defragResourceEntriesBnd2(QFile& img, FileInfo& info,
		const Bundle& bundle, std::vector<ResourceEntry>& resources,
		CorruptionType& corrupt, bool& breakLoop, int threadId);

	void defragZlibData(QFile& img, std::vector<FileInfo>& info,
		const Bundle& bundle, const std::vector<ResourceEntry>& resources,
		CorruptionType& corrupt, int& prevResource, int& prevChunk,
		bool& breakLoop, bool& searchedAll, int p, int threadId);

	// *************************************************************************
	//                         Extractor.cpp
	// *************************************************************************

	// Extracts bundles from the disk image
	void extractBundles(const std::vector<FileInfo>& info,
		const std::vector<CorruptionType>& corrupt, int start, int end,
		int threadId);

	// Get the name of the bundle from known resource IDs matched to file names
	QString bundleName(const FileInfo& info, CorruptionType corrupt);

private slots:
	void selectInputFile();
	void selectOutputFolder();
	void selectNamesFile();
	void recover();
	void stopRecovery();

signals:
	// Outputs a message to the log window.
	void log(const QString& msg);
};