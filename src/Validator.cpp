#include "../BundleRecovery.h"

#include <libdeflate.h>

#include <binaryio/binaryreader.hpp>

#include <QByteArray>
#include <QDateTime>
#include <QDataStream>
#include <QXmlStreamReader>

void BundleRecovery::validateBundles(std::vector<FileInfo>& info,
	std::vector<Bundle>& bundles, std::vector<QString>& debugData,
	std::vector<std::vector<ResourceEntry>>& resources,
	std::vector<std::vector<std::vector<ImportEntry>>>& imports,
	std::vector<CorruptionType>& corrupt, int start, int end, int threadId)
{
	log("Thread " + QString::number(threadId)
		+ " delegated bundles " + QString::number(start)
		+ " to " + QString::number(end - 1));
	uint64_t dateTimePre = QDateTime::currentSecsSinceEpoch();

	QFile image(input);
	image.open(QIODevice::ReadOnly);

	for (int i = start; i < end; ++i)
	{
		// Validate Bundle 2 debug data, if present
		// TODO: Support v3/v5 (not used by the bundle, just nice to have)
		if (!strncmp(bundles[i].magic, "bnd2", 4)
			&& (bundles[i].version == 2 && (bundles[i].flags & 8)))
		{
			int failPos = getDebugDataFailPos(bundles[i], debugData[i]);
			if (failPos)
			{
				corrupt[i] = CorruptionType::DebugData;
				info[i].sz.push_back(failPos);
			}
		}
		if (!ui.pushButtonStop->isEnabled()) // Cancel pressed
			return;
		if (corrupt[i] != CorruptionType::Intact)
		{
			logCorruption(info[i].pos[0], corrupt[i]);
			continue;
		}

		// Validate Bundle 1 resource IDs
		if (!strncmp(bundles[i].magic, "bndl", 4))
		{
			int failPos = getResourceIdsFailPos(bundles[i], resources[i]);
			if (failPos)
			{
				corrupt[i] = CorruptionType::ResourceId;
				info[i].sz.push_back(failPos);
			}
		}
		if (!ui.pushButtonStop->isEnabled()) // Cancel pressed
			return;
		if (corrupt[i] != CorruptionType::Intact)
		{
			logCorruption(info[i].pos[0], corrupt[i]);
			continue;
		}

		// Validate bundle resource entries
		int entriesFailPos = getResourceEntriesFailPos(bundles[i], resources[i]);
		if (entriesFailPos)
		{
			corrupt[i] = CorruptionType::ResourceEntries;
			info[i].sz.push_back(entriesFailPos);
		}
		if (!ui.pushButtonStop->isEnabled()) // Cancel pressed
			return;
		if (corrupt[i] != CorruptionType::Intact)
		{
			logCorruption(info[i].pos[0], corrupt[i]);
			continue;
		}

		// Validate Bundle 1 resource compression information
		if (!strncmp(bundles[i].magic, "bndl", 4)
			&& (bundles[i].flags & 1))
		{
			int failPos
				= getResourceCompressionInfoFailPos(bundles[i], resources[i]);
			if (failPos)
			{
				corrupt[i] = CorruptionType::ResourceCompressionInfo;
				info[i].sz.push_back(failPos);
			}
		}
		if (!ui.pushButtonStop->isEnabled()) // Cancel pressed
			return;
		if (corrupt[i] != CorruptionType::Intact)
		{
			logCorruption(info[i].pos[0], corrupt[i]);
			continue;
		}

		// Read in and validate Bundle 1 resource imports
		if (!strncmp(bundles[i].magic, "bndl", 4))
		{
			if (corrupt[i] == CorruptionType::Intact)
				readResourceImports(
					image, info[i], bundles[i], resources[i], imports[i]);
			int failPos
				= getResourceImportsFailPos(resources[i], imports[i]);
			if (failPos)
			{
				corrupt[i] = CorruptionType::ResourceImports;
				info[i].sz.push_back(failPos);
			}
		}
		if (!ui.pushButtonStop->isEnabled()) // Cancel pressed
			return;
		if (corrupt[i] != CorruptionType::Intact)
		{
			logCorruption(info[i].pos[0], corrupt[i]);
			continue;
		}

		// Apply sizes to all bundles not yet marked as corrupt
		if (corrupt[i] == CorruptionType::Intact)
		{
			int bundleSize = 0;
			if (!strncmp(bundles[i].magic, "bndl", 4))
			{
				for (int j = 0; j < 5; ++j)
					bundleSize += bundles[i].chunkSaas[j].size;
				info[i].sz.push_back(bundleSize);
			}
			else // bnd2
			{
				int8_t chunkCount = GetChunkCount(bundles[i]);
				bundleSize += bundles[i].resourceDataOffset[chunkCount - 1];
				for (int j = resources[i].size() - 1; j >= 0; --j)
				{
					if (resources[i][j].saaOnDisk[chunkCount - 1] != 0)
					{
						bundleSize += resources[i][j].diskOffset[chunkCount - 1];
						bundleSize += GetSizeFromSAA(
							resources[i][j].saaOnDisk[chunkCount - 1]);
						break;
					}
				}
				
				info[i].sz.push_back(bundleSize);
			}
		}
		if (!ui.pushButtonStop->isEnabled()) // Cancel pressed
			return;
		if (corrupt[i] != CorruptionType::Intact)
		{
			logCorruption(info[i].pos[0], corrupt[i]);
			continue;
		}

		// Mark as uncompressed if intact up to the start of the data
		if (!(bundles[i].flags & 1))
			corrupt[i] = CorruptionType::Uncompressed;
		if (!ui.pushButtonStop->isEnabled()) // Cancel pressed
			return;
		if (corrupt[i] != CorruptionType::Intact)
		{
			logCorruption(info[i].pos[0], corrupt[i]);
			continue;
		}

		// Validate the integrity of compressed resources
		if (validateCompressedResources(image, info[i], bundles[i], resources[i]))
			corrupt[i] = CorruptionType::ZlibData;
		if (corrupt[i] == CorruptionType::ZlibData)
			info[i].sz[0] = getCompressedResourcesFailPos(
				image, info[i], bundles[i], resources[i]);
		if (!ui.pushButtonStop->isEnabled()) // Cancel pressed
			return;
		if (corrupt[i] != CorruptionType::Intact)
		{
			logCorruption(info[i].pos[0], corrupt[i]);
			continue;
		}
	}

	image.close();
	uint64_t timeTaken = QDateTime::currentSecsSinceEpoch() - dateTimePre;
	log("Thread " + QString::number(threadId)
		+ " finished in " + QString::number(timeTaken) + " seconds");
}

void BundleRecovery::validateSingleBundle(QFile& img, FileInfo& info,
	Bundle& bundle, QString& debugData, std::vector<ResourceEntry>& resources,
	std::vector<std::vector<ImportEntry>>& imports, CorruptionType& corrupt)
{
	// Validate Bundle 2 debug data, if present
	// TODO: Support v3/v5
	if (!strncmp(bundle.magic, "bnd2", 4)
		&& (bundle.version == 2 && (bundle.flags & 8)))
	{
		if (getDebugDataFailPos(bundle, debugData))
			corrupt = CorruptionType::DebugData;
	}
	if (!ui.pushButtonStop->isEnabled()) // Cancel pressed
		return;
	if (corrupt != CorruptionType::Intact)
		return;

	// Validate Bundle 1 resource IDs
	if (!strncmp(bundle.magic, "bndl", 4))
	{
		if (getResourceIdsFailPos(bundle, resources))
			corrupt = CorruptionType::ResourceId;
	}
	if (!ui.pushButtonStop->isEnabled()) // Cancel pressed
		return;
	if (corrupt != CorruptionType::Intact)
		return;

	// Validate bundle resource entries
	if (getResourceEntriesFailPos(bundle, resources))
		corrupt = CorruptionType::ResourceEntries;
	if (!ui.pushButtonStop->isEnabled()) // Cancel pressed
		return;
	if (corrupt != CorruptionType::Intact)
		return;

	// Validate Bundle 1 resource compression information
	if (!strncmp(bundle.magic, "bndl", 4)
		&& (bundle.flags & 1))
	{
		if (getResourceCompressionInfoFailPos(bundle, resources))
			corrupt = CorruptionType::ResourceCompressionInfo;
	}
	if (!ui.pushButtonStop->isEnabled()) // Cancel pressed
		return;
	if (corrupt != CorruptionType::Intact)
		return;

	// Read in and validate Bundle 1 resource imports
	if (!strncmp(bundle.magic, "bndl", 4))
	{
		// TODO: Re-read the imports
		//if (corrupt == CorruptionType::Intact)
		//	readResourceImports(
		//		img, info, bundle, resources, imports);
		//if (validateResourceImports(bundle, resources, imports))
		//	corrupt = CorruptionType::ResourceImports;
	}
	if (!ui.pushButtonStop->isEnabled()) // Cancel pressed
		return;
	if (corrupt != CorruptionType::Intact)
		return;

	// Mark as uncompressed if intact up to the start of the data
	if (!(bundle.flags & 1))
		corrupt = CorruptionType::Uncompressed;
	if (!ui.pushButtonStop->isEnabled()) // Cancel pressed
		return;

	// Validate the integrity of compressed resources
	if (validateCompressedResources(img, info, bundle, resources))
		corrupt = CorruptionType::ZlibData;
	if (!ui.pushButtonStop->isEnabled()) // Cancel pressed
		return;
}

int BundleRecovery::getDebugDataFailPos(const Bundle& bundle,
	const QString& debugData)
{
	QXmlStreamReader debugDataReader(debugData);
	while (!debugDataReader.atEnd() && !debugDataReader.hasError())
		debugDataReader.readNext();

	int end = binaryio::Align(bundle.debugDataOffset
		+ debugDataReader.characterOffset(), 0x10);

	if (debugDataReader.hasError())
	{
		// Remove potential error from the XML reader reading beyond the
		// fragment end
		if (end > 0x4000 && (end & 0xFFF) != 0)
			return end & 0xFFFFC000;

		return end;
	}

	return 0;
}

int BundleRecovery::getResourceIdsFailPos(const Bundle& bundle,
	const std::vector<ResourceEntry>& resources)
{
	for (int i = 0; i < resources.size(); ++i)
	{
		if (resources.at(i).resourceId > 0xFFFFFFFF)
			return bundle.resourceIdsOffset + i * 8;
	}

	return 0;
}

int BundleRecovery::getResourceEntriesFailPos(const Bundle& bundle,
	const std::vector<ResourceEntry>& resources)
{
	int8_t chunkCount = GetChunkCount(bundle);

	// Version-specific validation
	if (!strncmp(bundle.magic, "bndl", 4))
	{
		for (int i = 0; i < resources.size(); ++i)
		{
			// Validate resource type
			// TODO: Make this more specific (most of the 0x11k aren't type ids)
			if (resources[i].resourceTypeId > 0x11004)
				return bundle.resourceEntriesOffset + i * 0x70 + 8;

			for (int j = 0; j < chunkCount; ++j)
			{
				// Is resource on disk less than 8 MiB?
				if (resources[i].bndlSaaOnDisk[j].size > 0x800000)
					return bundle.resourceEntriesOffset + i * 0x70 + 0xC + j * 8;

				// Is the resource in its respective chunk?
				if (bundle.chunkSaas[j].size != 0)
				{
					// Get chunk end offset via sizes in bundle header
					// Chunk 1 size is always chunk 1 end offset
					int chunkEnd = 0;
					for (int k = 0; k <= j; ++k)
						chunkEnd += bundle.chunkSaas[j].size;

					// For each entry, check that the resource in this chunk
					// doesn't overflow into the next chunk
					if (resources[i].bndlSaaOnDisk[j].size != 0)
					{
						if (resources[i].bndlDiskOffset[j].size
							+ resources[i].bndlSaaOnDisk[j].size > chunkEnd)
							return bundle.resourceEntriesOffset + i * 0x70 + 0xC + j * 8;
					}
				}
				else
					continue;
			}
		}
	}
	else
	{
		for (int i = 0; i < resources.size(); ++i)
		{
			// Is resource ID and import hash valid?
			if (bundle.version == 2)
			{
				if (resources[i].resourceId > 0xFFFFFFFF
					|| resources[i].importHash > 0xFFFFFFFF)
					return bundle.resourceEntriesOffset + i * 0x40;
			}
			else
			{
				// V3 and V5 use first byte as ID type and have additional
				// fields
				uint8_t idType
					= ((resources[i].resourceId & 0xFF00000000000000) >> 56);
				uint8_t idResourceType
					= ((resources[i].resourceId & 0x000000FF00000000) >> 32);
				uint8_t idResourceId
					= (resources[i].resourceId & 0x00000000FFFFFFFF);
				if (idType != 0 && idType != 1
					&& idType != 0x80 && idType != 0xC0)
				{
					if (bundle.version == 3)
						return bundle.resourceEntriesOffset + i * 0x50;
					else
						return bundle.resourceEntriesOffset + i * 0x48;
				}
				if ((idType == 0
					&& (resources[i].resourceId & 0x00FFFFFFFFFFFFFF) > 0xFFFFFFFF)
					|| ((idType == 1 && idResourceType == 0)
						&& idResourceId > 0x300000 && idResourceId < 0xFFFFFFF8))
				{
					if (bundle.version == 3)
						return bundle.resourceEntriesOffset + i * 0x50;
					else
						return bundle.resourceEntriesOffset + i * 0x48;
				}
			}

			// Is resource ID order correct?
			if (bundle.version == 2)
			{
				if (i != resources.size() - 1) // Not last resource
				{
					if (resources[i].resourceId > resources[i + 1].resourceId)
						return bundle.resourceEntriesOffset + i * 0x40;
				}
			}

			for (int j = 0; j < chunkCount; ++j)
			{
				// Is the uncompressed size with headroom greater than the
				// compressed size?
				if (GetSizeFromSAA(resources[i].uncompressedSaa[j]) + 13
					< GetSizeFromSAA(resources[i].saaOnDisk[j]))
				{
					if (bundle.version == 2)
						return bundle.resourceEntriesOffset + i * 0x40;
					else if (bundle.version == 3)
						return bundle.resourceEntriesOffset + i * 0x50;
					else if (bundle.version == 5)
						return bundle.resourceEntriesOffset + i * 0x48;
				}

				// Validate resource is within its respective chunk, for all but
				// the last chunk as that cannot be tested if corrupt
				if (j < chunkCount - 1)
				{
					if (resources[i].saaOnDisk[j] == 0)
						continue;
					int endOffset = 0;
					endOffset += bundle.resourceDataOffset[j];
					endOffset += resources[i].diskOffset[j];
					endOffset += GetSizeFromSAA(resources[i].saaOnDisk[j]);
					if (endOffset > bundle.resourceDataOffset[j + 1])
					{
						if (bundle.version == 2)
							return bundle.resourceEntriesOffset + i * 0x40;
						else if (bundle.version == 3)
							return bundle.resourceEntriesOffset + i * 0x50;
						else if (bundle.version == 5)
							return bundle.resourceEntriesOffset + i * 0x48;
					}
				}
			}

			// Validate resource type
			// TODO: Make this more specific (most aren't type ids)
			if (bundle.version <= 3)
			{
				if (resources[i].resourceTypeId > 0x11004)
				{
					if (bundle.version == 2)
						return bundle.resourceEntriesOffset + i * 0x40 + 0x38;
					else
						return bundle.resourceEntriesOffset + i * 0x50 + 0x44;
				}
			}
			else
			{
				if (resources[i].resourceTypeId > 0x701)
					return bundle.resourceEntriesOffset + i * 0x48 + 0x3C;
			}
		}
	}

	return 0;
}

int BundleRecovery::getResourceCompressionInfoFailPos(const Bundle& bundle,
	const std::vector<ResourceEntry>& resources)
{
	int8_t chunkCount = GetChunkCount(bundle);

	for (int i = 0; i < resources.size(); ++i)
	{
		for (int j = 0; j < chunkCount; ++j)
		{
			// Is uncompressed resource less than 8 MiB?
			if (resources[i].compressionInfo[j].size > 0x800000)
				return bundle.compressionInfoOffset + i * 0x28;

			// Is the uncompressed size with headroom greater than the
			// compressed size?
			if (resources[i].compressionInfo[j].size + 13
				< resources[i].bndlSaaOnDisk[j].size)
				return bundle.compressionInfoOffset + i * 0x28 + j * 8;
		}
	}

	return 0;
}

int BundleRecovery::getResourceImportsFailPos(
	const std::vector<ResourceEntry>& resources,
	const std::vector<std::vector<ImportEntry>>& imports)
{
	for (int i = 0; i < resources.size(); ++i)
	{
		// Is import count valid?
		if (resources[i].importCount > 0x3DB)
			return resources[i].importOffset;

		for (int j = 0; j < imports[i].size(); ++j)
		{
			// Is offset valid?
			if (imports[i][j].offset > 0x4A0DC)
				return resources[i].importOffset + 8 + j * 0x10;

			// Is resource ID valid?
			if (imports[i][j].resourceId > 0xFFFFFFFF)
				return resources[i].importOffset + 8 + j * 0x10;
		}
	}

	return 0;
}

bool BundleRecovery::validateCompressedResources(QFile& img,
	const FileInfo& info, const Bundle& bundle,
	const std::vector<ResourceEntry>& resources)
{
	QByteArray bundleData;
	for (int i = 0; i < info.pos.size(); ++i)
	{
		img.seek(info.pos[i]);
		bundleData.append(img.read(info.sz[i]));
	}
	QDataStream stream(&bundleData, QIODevice::ReadOnly);
	if (endianness == std::endian::little)
		stream.setByteOrder(QDataStream::LittleEndian);

	libdeflate_decompressor* dc = libdeflate_alloc_decompressor();

	int8_t chunkCount = GetChunkCount(bundle);

	if (!strncmp(bundle.magic, "bndl", 4))
	{
		for (int i = 0; i < resources.size(); ++i)
		{
			for (int j = 0; j < chunkCount; ++j)
			{
				int cSz = resources[i].bndlSaaOnDisk[j].size;
				int uSz = resources[i].compressionInfo[j].size;
				if (cSz != 0)
				{
					std::unique_ptr<char[]> resourceData(new char[cSz]);
					int resourcePos = 0;
					for (int k = 0; k < j; ++k)
						resourcePos += bundle.chunkSaas[k].size;
					resourcePos += resources[i].bndlDiskOffset[j].size;
					stream.device()->seek(resourcePos);
					stream.readRawData(resourceData.get(), cSz);
					if (GetLibdeflateResult(resourceData.get(), cSz, uSz, dc)
						!= LIBDEFLATE_SUCCESS)
						return true;
				}
			}
		}
	}
	else
	{
		for (int i = 0; i < resources.size(); ++i)
		{
			for (int j = 0; j < chunkCount; ++j)
			{
				int cSz = GetSizeFromSAA(resources[i].saaOnDisk[j]);
				int uSz = GetSizeFromSAA(resources[i].uncompressedSaa[j]);
				if (resources[i].saaOnDisk[j] != 0)
				{
					std::unique_ptr<char[]> resourceData(new char[cSz]);
					stream.device()->seek(bundle.resourceDataOffset[j]
						+ resources[i].diskOffset[j]);
					stream.readRawData(resourceData.get(), cSz);
					if (GetLibdeflateResult(resourceData.get(), cSz, uSz, dc)
						!= LIBDEFLATE_SUCCESS)
						return true;
				}
			}
		}
	}

	delete dc;

	return false;
}

int BundleRecovery::getCompressedResourcesFailPos(QFile& img,
	const FileInfo& info, const Bundle& bundle,
	const std::vector<ResourceEntry>& resources)
{
	// TODO: Switch to using libdeflate exclusively, getting the fail position
	// via the index and chunk index of the resource where it fails

	QByteArray bundleData;
	for (int i = 0; i < info.pos.size(); ++i)
	{
		img.seek(info.pos[i]);
		bundleData.append(img.read(info.sz[i]));
	}
	QDataStream stream(&bundleData, QIODevice::ReadOnly);
	if (endianness == std::endian::little)
		stream.setByteOrder(QDataStream::LittleEndian);

	int8_t chunkCount = GetChunkCount(bundle);

	if (!strncmp(bundle.magic, "bndl", 4))
	{
		for (int j = 0; j < chunkCount; ++j)
		{
			for (int i = 0; i < resources.size(); ++i)
			{
				int cSz = resources[i].bndlSaaOnDisk[j].size;
				int uSz = resources[i].compressionInfo[j].size;
				if (cSz != 0)
				{
					std::unique_ptr<char[]> resourceData(new char[cSz]);
					int resourcePos = 0;
					for (int k = 0; k < j; ++k)
						resourcePos += bundle.chunkSaas[k].size;
					resourcePos += resources[i].bndlDiskOffset[j].size;
					
					// Check header, since zlib seemingly doesn't do it
					stream.device()->seek(resourcePos);
					uint16_t header = 0;
					stream >> header;
					if (header != 0x78DA)
						return resourcePos;

					// Check for invalid or extremely unlikely bytecode
					for (int k = interval; k < cSz; k += interval)
					{
						stream.device()->seek(
							(resourcePos + k) & (~(interval - 1)));
						uint32_t toCheck = 0;
						stream >> toCheck;
						if (toCheck == 0x626E6432 || toCheck == 0x626E646C
							|| toCheck == 0x3C3F786D || toCheck == 0x126AF046
							|| toCheck == 0)
							return resourcePos + k;
					}

					// Check data
					stream.device()->seek(resourcePos);
					stream.readRawData(resourceData.get(), cSz);
					int read = GetZlibBytesRead(resourceData.get(), cSz, uSz);
					if (read != cSz)
						return resourcePos + read;
				}
			}
		}
	}
	else
	{
		for (int j = 0; j < chunkCount; ++j)
		{
			for (int i = 0; i < resources.size(); ++i)
			{
				int cSz = GetSizeFromSAA(resources[i].saaOnDisk[j]);
				int uSz = GetSizeFromSAA(resources[i].uncompressedSaa[j]);
				if (resources[i].saaOnDisk[j] != 0)
				{
					std::unique_ptr<char[]> resourceData(new char[cSz]);
					int resourcePos = bundle.resourceDataOffset[j]
						+ resources[i].diskOffset[j];

					// Check header, since zlib seemingly doesn't do it
					stream.device()->seek(resourcePos);
					uint16_t header = 0;
					stream >> header;
					if (header != 0x78DA)
						return resourcePos/* & (~(interval - 1))*/;

					// Check for invalid or extremely unlikely bytecode
					for (int k = interval; k < cSz; k += interval)
					{
						stream.device()->seek(
							(resourcePos + k) & (~(interval - 1)));
						uint32_t toCheck = 0;
						stream >> toCheck;
						if (toCheck == 0x626E6432 || toCheck == 0x626E646C
							|| toCheck == 0x3C3F786D || toCheck == 0x126AF046
							|| toCheck == 0)
							return resourcePos + k;
					}

					// Check data
					stream.device()->seek(resourcePos);
					stream.readRawData(resourceData.get(), cSz);
					int read = GetZlibBytesRead(resourceData.get(), cSz, uSz);
					if (read != cSz)
						return resourcePos + read;
				}
			}
		}
	}

	return 0;
}