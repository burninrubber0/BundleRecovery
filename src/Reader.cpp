#include "../BundleRecovery.h"

#include <binaryio/binaryreader.hpp>

#include <QDataStream>
#include <QtEndian>

void BundleRecovery::readBundles(std::vector<FileInfo>& info,
	std::vector<Bundle>& bundles, std::vector<QString>& debugData,
	std::vector<std::vector<ResourceEntry>>& resources,
	int start, int end, int threadId)
{
	log("Thread " + QString::number(threadId)
		+ " delegated bundles " + QString::number(start)
		+ " to " + QString::number(end - 1));
	uint64_t dateTimePre = QDateTime::currentSecsSinceEpoch();

	QFile image(input);
	image.open(QIODevice::ReadOnly);

	for (int i = start; i < end; ++i)
	{
		readHeaders(image, info[i], bundles[i]);
		// TODO: Support reading Bundle 2 v3/v5 debug data (flags & 2 for v5)
		// Would come at end of bundle rather than beginning
		if (bundles[i].version == 2 && (bundles[i].flags & 8))
			readDebugData(image, info[i], bundles[i], debugData[i]);
		if (!strncmp(bundles[i].magic, "bndl", 4))
			readResourceIds(image, info[i], bundles[i], resources[i]);
		readResourceEntries(image, info[i], bundles[i], resources[i]);
		if (!strncmp(bundles[i].magic, "bndl", 4)
			&& (bundles[i].flags & 1))
			readResourceCompressionInfo(image, info[i], bundles[i],
				resources[i]);

		log("Read info for bundle at 0x"
			+ QString::number(info[i].pos[0], 16).toUpper());
	}

	image.close();
	uint64_t timeTaken = QDateTime::currentSecsSinceEpoch() - dateTimePre;
	log("Thread " + QString::number(threadId)
		+ " finished in " + QString::number(timeTaken) + " seconds");
}

void BundleRecovery::readHeaders(QFile& img, const FileInfo& info,
	Bundle& bundle)
{
	if (!strncmp(bundle.magic, "bndl", 4))
	{
		int headerLen = 0x5C;
		if (bundle.version >= 4)
			headerLen += 0xC;
		if (bundle.version == 5)
			headerLen += 8;

		// TODO:
		//QDataStream stream;
		//img.seek(info.pos[0]);
		//stream.writeRawData(img.read(headerLen), headerLen);

		const auto& buffer = std::make_shared<std::vector<uint8_t>>(headerLen);
		img.seek(info.pos[0]);
		img.read(reinterpret_cast<char*>(buffer->data()), headerLen);
		auto reader = binaryio::BinaryReader(buffer);
		if (endianness == std::endian::big)
			reader.SetBigEndian(true);

		reader.Seek(8);
		bundle.resourceEntriesCount = reader.Read<uint32_t>();
		for (int i = 0; i < 5; ++i)
		{
			bundle.chunkSaas[i].size = reader.Read<uint32_t>();
			bundle.chunkSaas[i].alignment = reader.Read<uint32_t>();
		}
		for (int i = 0; i < 5; ++i)
			bundle.chunkMemAddr[i] = reader.Read<uint32_t>();
		bundle.resourceIdsOffset = reader.Read<uint32_t>();
		bundle.resourceEntriesOffset = reader.Read<uint32_t>();
		bundle.importsOffset = reader.Read<uint32_t>();
		bundle.resourceDataOffset[0] = reader.Read<uint32_t>();
		bundle.platform = reader.Read<uint32_t>();

		if (bundle.version >= 4)
		{
			bundle.flags = reader.Read<uint32_t>();
			bundle.numCompressedResources = reader.Read<uint32_t>();
			bundle.compressionInfoOffset = reader.Read<uint32_t>();
		}

		if (bundle.version == 5)
		{
			bundle.unk0 = reader.Read<uint32_t>();
			bundle.unk1 = reader.Read<uint32_t>();
		}
	}
	else
	{
		int headerLen = 0x28;
		if (bundle.version == 3)
			headerLen += 0x4;
		if (bundle.version == 5)
			headerLen = 0x70;

		const auto& buffer = std::make_shared<std::vector<uint8_t>>(headerLen);
		img.seek(info.pos[0]);
		img.read(reinterpret_cast<char*>(buffer->data()), headerLen);
		auto reader = binaryio::BinaryReader(buffer);
		if (endianness == std::endian::big)
			reader.SetBigEndian(true);

		if (bundle.version == 5)
		{
			reader.Seek(6);
			bundle.platform = reader.Read<uint16_t>();
		}
		else
		{
			reader.Seek(8);
			bundle.platform = reader.Read<uint32_t>();
		}

		bundle.debugDataOffset = reader.Read<uint32_t>();
		bundle.resourceEntriesCount = reader.Read<uint32_t>();
		bundle.resourceEntriesOffset = reader.Read<uint32_t>();
		if (bundle.version == 2)
		{
			for (int i = 0; i < 3; ++i)
				bundle.resourceDataOffset[i] = reader.Read<uint32_t>();
		}
		else
		{
			for (int i = 0; i < 4; ++i)
				bundle.resourceDataOffset[i] = reader.Read<uint32_t>();
		}
		bundle.flags = reader.Read<uint32_t>();

		if (bundle.version == 5)
		{
			bundle.defaultResourceId = reader.Read<uint64_t>();
			bundle.defaultStreamIndex = reader.Read<uint32_t>();
			for (int i = 0; i < 4; ++i)
			{
				for (int j = 0; j < 15; ++j)
					bundle.streamNames[i][j] = reader.Read<char>();
			}
		}
	}
	if (!ui.pushButtonStop->isEnabled()) // Cancel pressed
		return;
}

void BundleRecovery::readDebugData(QFile& img, const FileInfo& info,
	const Bundle& bundle, QString& debugData)
{
	img.seek(info.pos[0] + bundle.debugDataOffset);
	// TODO: Support reading bundle 2 v3/v5 debug data (comes at end of bundle)
	debugData = img.read(bundle.resourceEntriesOffset - bundle.debugDataOffset);

	// Remove all trailing data
	// This may also remove corrupt data, which is fine
	for (int i = 0; i < debugData.size(); ++i)
	{
		if (debugData.at(i) == '\0')
		{
			debugData.truncate(i);
			break;
		}
	}
}

void BundleRecovery::readResourceIds(QFile& img, const FileInfo& info,
	const Bundle& bundle, std::vector<ResourceEntry>& resources)
{
	int idsLen = bundle.resourceEntriesCount * 8;

	const auto& buffer = std::make_shared<std::vector<uint8_t>>(idsLen);
	img.seek(info.pos[0] + bundle.resourceIdsOffset);
	img.read(reinterpret_cast<char*>(buffer->data()), idsLen);
	auto reader = binaryio::BinaryReader(buffer);
	if (endianness == std::endian::big)
		reader.SetBigEndian(true);

	for (int i = 0; i < bundle.resourceEntriesCount; ++i)
	{
		resources.push_back({});
		resources[i].resourceId = reader.Read<uint64_t>();
	}
}

void BundleRecovery::readResourceEntries(QFile& img, const FileInfo& info,
	const Bundle& bundle, std::vector<ResourceEntry>& resources)
{
	if (!strncmp(bundle.magic, "bndl", 4))
	{
		int entriesLen = bundle.resourceEntriesCount * 0x70;
		const auto& buffer = std::make_shared<std::vector<uint8_t>>(entriesLen);
		img.seek(info.pos[0] + bundle.resourceEntriesOffset);
		img.read(reinterpret_cast<char*>(buffer->data()), entriesLen);
		auto reader = binaryio::BinaryReader(buffer);
		if (endianness == std::endian::big)
			reader.SetBigEndian(true);

		for (int i = 0; i < bundle.resourceEntriesCount; ++i)
		{
			resources.at(i).resourceDataMemAddr = reader.Read<uint32_t>();
			resources.at(i).importOffset = reader.Read<uint32_t>();
			resources.at(i).resourceTypeId = reader.Read<uint32_t>();
			for (int j = 0; j < 5; ++j)
			{
				resources.at(i).bndlSaaOnDisk[j].size = reader.Read<uint32_t>();
				resources.at(i).bndlSaaOnDisk[j].alignment
					= reader.Read<uint32_t>();
			}
			for (int j = 0; j < 5; ++j)
			{
				resources.at(i).bndlDiskOffset[j].size
					= reader.Read<uint32_t>();
				resources.at(i).bndlDiskOffset[j].alignment
					= reader.Read<uint32_t>();
			}
			for (int j = 0; j < 5; ++j)
				resources.at(i).memAddr[j] = reader.Read<uint32_t>();
			if (!ui.pushButtonStop->isEnabled()) // Cancel pressed
				return;
		}
	}
	else
	{
		int entryLen = 0x40;
		if (bundle.version == 3)
			entryLen = 0x4C;
		else if (bundle.version == 5)
			entryLen = 0x48;
		int entriesLen = bundle.resourceEntriesCount * entryLen;
		const auto& buffer = std::make_shared<std::vector<uint8_t>>(entriesLen);
		img.seek(info.pos[0] + bundle.resourceEntriesOffset);
		img.read(reinterpret_cast<char*>(buffer->data()), entriesLen);
		auto reader = binaryio::BinaryReader(buffer);
		if (endianness == std::endian::big)
			reader.SetBigEndian(true);

		// Read resource entries
		int8_t chunkCount = GetChunkCount(bundle);
		for (int i = 0; i < bundle.resourceEntriesCount; ++i)
		{
			resources.push_back({});
			resources.at(i).resourceId = reader.Read<uint64_t>();
			if (bundle.version <= 3)
				resources.at(i).importHash = reader.Read<uint64_t>();
			for (int j = 0; j < chunkCount; ++j)
				resources.at(i).uncompressedSaa[j] = reader.Read<uint32_t>();
			for (int j = 0; j < chunkCount; ++j)
				resources.at(i).saaOnDisk[j] = reader.Read<uint32_t>();
			for (int j = 0; j < chunkCount; ++j)
				resources.at(i).diskOffset[j] = reader.Read<uint32_t>();
			resources.at(i).importOffset = reader.Read<uint32_t>();
			resources.at(i).resourceTypeId = reader.Read<uint32_t>();
			resources.at(i).importCount = reader.Read<uint16_t>();
			resources.at(i).flags = reader.Read<uint8_t>();
			resources.at(i).streamIndex = reader.Read<uint8_t>();
			if (bundle.version == 5)
				reader.Skip<uint32_t>();
			if (!ui.pushButtonStop->isEnabled()) // Cancel pressed
				return;
		}
	}
}

void BundleRecovery::readResourceCompressionInfo(QFile& img,
	const FileInfo& info, const Bundle& bundle,
	std::vector<ResourceEntry>& resources)
{
	int compLen = bundle.numCompressedResources * 0x28;

	const auto& buffer = std::make_shared<std::vector<uint8_t>>(compLen);
	img.seek(info.pos[0] + bundle.compressionInfoOffset);
	img.read(reinterpret_cast<char*>(buffer->data()), compLen);
	auto reader = binaryio::BinaryReader(buffer);
	if (endianness == std::endian::big)
		reader.SetBigEndian(true);

	for (int i = 0; i < bundle.numCompressedResources; ++i)
	{
		for (int j = 0; j < 5; ++j)
		{
			resources.at(i).compressionInfo[j].size
				= reader.Read<uint32_t>();
			resources.at(i).compressionInfo[j].alignment
				= reader.Read<uint32_t>();
		}
		if (!ui.pushButtonStop->isEnabled()) // Cancel pressed
			return;
	}
}

void BundleRecovery::readResourceImports(QFile& img, const FileInfo& info,
	const Bundle& bundle, std::vector<ResourceEntry>& resources,
	std::vector<std::vector<ImportEntry>>& imports)
{
	int importsLen = bundle.resourceDataOffset[0] - bundle.importsOffset;

	const auto& buffer = std::make_shared<std::vector<uint8_t>>(importsLen);
	img.seek(info.pos[0] + bundle.importsOffset);
	img.read(reinterpret_cast<char*>(buffer->data()), importsLen);
	auto reader = binaryio::BinaryReader(buffer);
	if (endianness == std::endian::big)
		reader.SetBigEndian(true);

	for (int i = 0; i < resources.size(); ++i)
	{
		imports.push_back({});
		if (resources[i].importOffset != 0)
		{
			// Reuse bundle 2 import count field
			resources[i].importCount = reader.Read<uint32_t>();
			if (resources[i].importCount > 0x3DB)
				break;
			reader.Skip<uint32_t>();
			for (int j = 0; j < resources[i].importCount; ++j)
			{
				imports[i].push_back({});
				imports[i][j].resourceId = reader.Read<uint64_t>();
				imports[i][j].offset = reader.Read<uint32_t>();
				reader.Skip<uint32_t>();
			}
		}
		if (!ui.pushButtonStop->isEnabled()) // Cancel pressed
			return;
	}
}