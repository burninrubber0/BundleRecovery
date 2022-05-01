#include "../BundleRecovery.h"

#include <chrono>
//#include <sstream>

#include <binaryio/util.hpp>

#include <QDateTime>

void BundleRecovery::defragBundles(std::vector<FileInfo>& info,
	const std::vector<Bundle>& bundles, std::vector<QString>& debugData,
	std::vector<std::vector<ResourceEntry>>& resources,
	const std::vector<std::vector<std::vector<ImportEntry>>>& imports,
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
		// Skip intact bundles
		if (corrupt[i] == CorruptionType::Intact
			|| corrupt[i] == CorruptionType::Uncompressed)
			continue;

		//log("Defragging bundle at 0x"
		//	+ QString::number(info[i].pos[0], 16).toUpper());

		// Hold potential fragment info here
		// TODO: Switch to using this vector instead of info[i] in zlib defrag
		std::vector<FileInfo> potentials = { info[i] };

		int prevResourceIndex = -1;
		int prevChunkIndex = -1;
		// Find valid bundle fragments
		while (corrupt[i] != CorruptionType::Intact
			&& corrupt[i] != CorruptionType::Uncompressed)
		{
			bool breakLoop = false;
			bool searchedAll = false;

			// Different fragment validation process per corruption type
			switch (corrupt[i])
			{
			case CorruptionType::DebugData:
				defragDebugData(image, info[i], bundles[i], debugData[i],
					resources[i], corrupt[i], breakLoop, threadId);
				//breakLoop = true;
				break;
			case CorruptionType::ResourceId:
				break;
			case CorruptionType::ResourceEntries:
				if (!strncmp(bundles[i].magic, "bndl", 4))
				{
					// TODO
				}
				else
				{
					defragResourceEntriesBnd2(image, info[i], bundles[i],
						resources[i], corrupt[i], breakLoop, threadId);
				}
				break;
			case CorruptionType::ResourceCompressionInfo:
				break;
			case CorruptionType::ResourceImports:
				break;
			case CorruptionType::ZlibData:
				// For each potential fragment
				for (int p = 0; p < potentials.size(); ++p)
				{
					defragZlibData(image, potentials, bundles[i],
						resources[i], corrupt[i], prevResourceIndex,
						prevChunkIndex, breakLoop, searchedAll, p, threadId);
				}
				//breakLoop = true;
				break;
			}

			if (breakLoop)
				break;
		}

		// Add the potential fragments to info for extraction
		//info[i] = potentials[0];
		//for (int j = 1; j < potentials.size(); ++j)
		//	info.push_back(potentials[j]);
	}

	image.close();
	uint64_t timeTaken = QDateTime::currentSecsSinceEpoch() - dateTimePre;
	log("Thread " + QString::number(threadId)
		+ " finished in " + QString::number(timeTaken) + " seconds");
}

void BundleRecovery::defragDebugData(QFile& img, FileInfo& info,
	const Bundle& bundle, QString& debugData,
	std::vector<ResourceEntry>& resources, CorruptionType& corrupt,
	bool& breakLoop, int threadId)
{
	// Exact offset of the fragmentation in the bundle and debug data
	int bndlCorruptOffset = nearestMultiple(
		getDebugDataFailPos(bundle, debugData), interval);

	// Get known bundle data
	QByteArray data;
	for (int i = 0; i < info.pos.size(); ++i)
	{
		img.seek(info.pos[i]);
		data.append(img.read(nearestMultiple(info.sz[i], interval)));
	}

	// Append corrupt data up to the start of the resource entries
	int remaining = bundle.resourceEntriesOffset - bndlCorruptOffset;
	data.append(img.read(remaining));

	// Create stream
	QDataStream stream(&data, QIODevice::ReadWrite);
	if (endianness == std::endian::little)
		stream.setByteOrder(QDataStream::LittleEndian);

	// Get the offsets to search from and to in the image
	uint64_t imgStartOffset = info.pos.back()
		+ nearestMultiple(info.sz.back(), interval);
	uint64_t imgEndOffset = imgStartOffset + searchLength;

	bool defragged = false;
	for (uint64_t i = imgStartOffset; i < imgEndOffset; i += interval)
	{
		img.seek(i);
		stream.device()->seek(bndlCorruptOffset);
		stream.writeRawData(img.read(remaining), remaining);
		stream.device()->seek(bundle.debugDataOffset);

		// Test string
		QString testDebugData = stream.device()->readAll();
		// Remove trailing null data
		for (int i = 0; i < testDebugData.size(); ++i)
		{
			if (testDebugData.at(i) == '\0')
			{
				testDebugData.truncate(i);
				break;
			}
		}
		if (!getDebugDataFailPos(bundle, testDebugData)
			&& testDebugData.size() >= bundle.resourceEntriesOffset
			- bundle.debugDataOffset - 0x10
			&& testDebugData.size() <= bundle.resourceEntriesOffset
			- bundle.debugDataOffset)
		{
			defragged = true;

			// Update info
			debugData = testDebugData;
			info.sz[0] = nearestMultiple(info.sz[0], interval); // Always 1 frag
			info.pos.push_back(i);
			info.sz.push_back(bundle.resourceDataOffset[0] - info.sz[0]); // Tmp

			// Read in resource entries for determining corruption type
			img.seek(info.pos[1] + bundle.resourceEntriesOffset - info.sz[0]);
			stream.device()->seek(bundle.resourceEntriesOffset);
			int entSizeToRead = ResourceEntrySize(bundle)
				* bundle.resourceEntriesCount;
			stream.writeRawData(img.read(entSizeToRead), entSizeToRead);
			stream.device()->seek(bundle.resourceEntriesOffset);
			int chunkCount = GetChunkCount(bundle);
			for (int j = 0; j < bundle.resourceEntriesCount; ++j)
			{
				stream >> resources[j].resourceId;
				if (bundle.version <= 3)
					stream >> resources[j].importHash;
				for (int k = 0; k < chunkCount; ++k)
					stream >> resources[j].uncompressedSaa[k];
				for (int k = 0; k < chunkCount; ++k)
					stream >> resources[j].saaOnDisk[k];
				for (int k = 0; k < chunkCount; ++k)
					stream >> resources[j].diskOffset[k];
				stream >> resources[j].importOffset;
				stream >> resources[j].resourceTypeId;
				stream >> resources[j].importCount;
				stream >> resources[j].flags;
				stream >> resources[j].streamIndex;
				if (bundle.version == 5)
					stream.skipRawData(4);
			}
			int intendedSize = GetBundleSize(bundle, resources);

			// Determine if resource entries are corrupt
			int entFailPos = getResourceEntriesFailPos(bundle, resources);
			if (entFailPos)
			{
				info.sz.back() = nearestMultiple(entFailPos, interval);
				for (int j = 0; j < info.sz.size() - 1; ++i)
					info.sz.back() -= info.sz[j];
				corrupt = CorruptionType::ResourceEntries;
				break;
			}
			else
				info.sz[1] = intendedSize - info.sz[0];

			// Read in resources for determining corruption type
			img.seek(info.pos[1] + bundle.resourceDataOffset[0] - info.sz[0]);
			stream.device()->seek(bundle.resourceDataOffset[0]);
			int resSizeToRead = intendedSize - bundle.resourceDataOffset[0];
			stream.writeRawData(img.read(resSizeToRead), resSizeToRead);
			stream.device()->seek(bundle.resourceDataOffset[0]);

			// Determine if bundle resources are corrupt
			if (!(bundle.flags & 1))
			{
				corrupt = CorruptionType::Uncompressed;
				break;
			}
			else
			{
				int resFailPos = getCompressedResourcesFailPos(
					img, info, bundle, resources);
				if (resFailPos)
				{
					info.sz.back() = resFailPos;
					corrupt = CorruptionType::ZlibData;
				}
				else
					corrupt = CorruptionType::Intact;
			}
			break;
		}
	}

	if (defragged)
	{
		log("Bundle at 0x" + QString::number(info.pos[0], 16).toUpper()
		+ ": defragged debug data");
	}
	else
	{
		log("Bundle at 0x" + QString::number(info.pos[0], 16).toUpper()
			+ ": failed to defrag debug data");
		breakLoop = true;
	}
}

void BundleRecovery::defragResourceEntriesBnd2(QFile& img, FileInfo& info,
	const Bundle& bundle, std::vector<ResourceEntry>& resources,
	CorruptionType& corrupt, bool& breakLoop, int threadId)
{
	// Exact offset of the fragmentation in the bundle and entries
	int bndlCorruptOffset = nearestMultiple(
		getResourceEntriesFailPos(bundle, resources), interval);
	int entCorruptOffset = bndlCorruptOffset - bundle.resourceEntriesOffset;

	// Get known bundle data
	QByteArray data;
	for (int i = 0; i < info.pos.size(); ++i)
	{
		img.seek(info.pos[i]);
		data.append(img.read(nearestMultiple(info.sz[i], interval)));
	}

	// Append corrupt data up to the start of the resource data, then remove
	// anything not meant as part of the resource entries
	int remaining = bundle.resourceDataOffset[0] - bndlCorruptOffset;
	data.append(img.read(remaining));
	data.remove(0, bundle.resourceEntriesOffset);
	data.squeeze();

	// Create stream
	QDataStream stream(&data, QIODevice::ReadWrite);
	if (endianness == std::endian::little)
		stream.setByteOrder(QDataStream::LittleEndian);

	// Get the offsets to search from and to in the image
	uint64_t imgStartOffset = info.pos.back()
		+ nearestMultiple(info.sz.back(), interval);
	uint64_t imgEndOffset = imgStartOffset + searchLength;

	// Index of the first resource entry with corruption
	int entryIndex = entCorruptOffset / ResourceEntrySize(bundle);

	// Append data equal in size to the remaining resource entries and validate
	std::vector<ResourceEntry> testResources = resources;
	int8_t chunkCount = GetChunkCount(bundle);
	bool defragged = false;
	for (uint64_t i = imgStartOffset; i < imgEndOffset; i += interval)
	{
		// Read the new entries into data, then into the entries vector
		img.seek(i);
		stream.device()->seek(entCorruptOffset);
		stream.writeRawData(img.read(remaining), remaining);
		stream.device()->seek(ResourceEntrySize(bundle) * entryIndex);
		for (int j = entryIndex; j < bundle.resourceEntriesCount; ++j)
		{
			stream >> testResources[j].resourceId;
			if (bundle.version <= 3)
				stream >> testResources[j].importHash;
			for (int k = 0; k < chunkCount; ++k)
				stream >> testResources[j].uncompressedSaa[k];
			for (int k = 0; k < chunkCount; ++k)
				stream >> testResources[j].saaOnDisk[k];
			for (int k = 0; k < chunkCount; ++k)
				stream >> testResources[j].diskOffset[k];
			stream >> testResources[j].importOffset;
			stream >> testResources[j].resourceTypeId;
			stream >> testResources[j].importCount;
			stream >> testResources[j].flags;
			stream >> testResources[j].streamIndex;
			if (bundle.version == 5)
				stream.skipRawData(4);
		}

		if (!getResourceEntriesFailPos(bundle, testResources))
		{
			resources = testResources;
			int intendedSize = GetBundleSize(bundle, resources);
			info.pos.push_back(i);
			// Use sz.size() - 2 in case there is more than one frag
			info.sz.push_back(0);
			info.sz[info.sz.size() - 2]
				= nearestMultiple(info.sz[info.sz.size() - 2], interval);
			info.sz.back() = intendedSize - info.sz[info.sz.size() - 2];
			int failPos = getCompressedResourcesFailPos(
				img, info, bundle, resources);
			//if (!failPos)
			//{
			//	info.sz.back() = (intendedSize - bundle.resourceDataOffset[0]);
			//	corrupt = CorruptionType::Intact;
			//}
			if (failPos)
			{
				info.sz.back() = failPos;
				corrupt = CorruptionType::ZlibData;
			}
			else
			{
				if (bundle.flags & 1)
					corrupt = CorruptionType::Intact;
				else
					corrupt = CorruptionType::Uncompressed;
			}
			defragged = true;
			break;
		}
	}

	if (defragged)
	{
		log("Bundle at 0x" + QString::number(info.pos[0], 16).toUpper()
			+ ": defragged entries");
	}
	else
	{
		log("Bundle at 0x" + QString::number(info.pos[0], 16).toUpper()
			+ ": failed to defrag entries");
		breakLoop = true;
	}
}

void BundleRecovery::defragZlibData(QFile& img, std::vector<FileInfo>& info,
	const Bundle& bundle, const std::vector<ResourceEntry>& resources,
	CorruptionType& corrupt, int& prevResource, int& prevChunk, bool& breakLoop,
	bool& searchedAll, int p, int threadId)
{
	int intendedSize = GetBundleSize(bundle, resources);

	libdeflate_decompressor* dc = libdeflate_alloc_decompressor();

	if (!strncmp(bundle.magic, "bndl", 4))
	{
		// TODO
		// No bundles have zlib corruption - need samples
	}
	else
	{
		// Get known bundle data
		QByteArray bundleData;
		for (int i = 0; i < info[p].pos.size(); ++i)
		{
			img.seek(info[p].pos[i]);
			bundleData.append(img.read(info[p].sz[i]));
		}

		// Append corrupt data so the corrupt resource index can be
		// gotten
		int notRead = intendedSize - bundleData.size();
		bundleData.append(img.read(notRead));

		// Create stream
		QDataStream stream(&bundleData, QIODevice::ReadOnly);
		if (endianness == std::endian::little)
			stream.setByteOrder(QDataStream::LittleEndian);

		// Use libdeflate to find the corrupt resource and store its
		// index and chunk index
		int resourceIndex = -1;
		int chunkIndex = -1;
		bool hasSetCorruptIndex = false;
		for (int i = 0; i < GetChunkCount(bundle); ++i)
		{
			for (int j = 0; j < resources.size(); ++j)
			{
				if (!GetSizeFromSAA(resources[j].saaOnDisk[i]))
					continue;
				int cSz = GetSizeFromSAA(resources[j].saaOnDisk[i]);
				int uSz = GetSizeFromSAA(resources[j].uncompressedSaa[i]);
				std::unique_ptr<char[]> resourceData(new char[cSz]);
				stream.device()->seek(bundle.resourceDataOffset[i]
					+ resources[j].diskOffset[i]);
				stream.readRawData(resourceData.get(), cSz);
				int result = GetLibdeflateResult(
					resourceData.get(), cSz, uSz, dc);
				if (result != 0)
				{
					resourceIndex = j;
					chunkIndex = i;
					hasSetCorruptIndex = true;
					break;
				}
			}
			if (hasSetCorruptIndex)
				break;
		}

		// Check if the current indices match the previous
		// This indicates failure to defragment, so break out
		if (resourceIndex == prevResource
			&& chunkIndex == prevChunk)
		{
			//if (ui.checkBoxSearchAll->isChecked())
			//{
			//	logger->log("T" + QString::number(threadId) + " Bundle at 0x"
			//		+ QString::number(info[p].pos[0], 16).toUpper()
			//		+ ": fragment not within search length, searching all");
			//
			//	// Make end size the remainder of the bundle, if it isn't already
			//	info[p].sz.back() = intendedSize;
			//	for (int i = 0; i < info[p].sz.size() - 1; ++i)
			//		info[p].sz.back() -= info[p].sz[i];
			//}
			//else
			//{
				log("T" + QString::number(threadId) + " Bundle at 0x"
					+ QString::number(info[p].pos[0], 16).toUpper()
					+ ": failed to defrag resources");

				// Make end size the remainder of the bundle, if it isn't already
				info[p].sz.back() = intendedSize;
				for (int i = 0; i < info[p].sz.size() - 1; ++i)
					info[p].sz.back() -= info[p].sz[i];
				breakLoop = true;
				return;
			//}
		}

		// Offset to start truncating the data at
		int bndlStartOffset = binaryio::Align(
			bundle.resourceDataOffset[chunkIndex]
			+ resources[resourceIndex].diskOffset[chunkIndex],
			interval);

		// Offset to stop truncating the data at
		int bndlEndOffset = bundle.resourceDataOffset[chunkIndex]
			+ resources[resourceIndex].diskOffset[chunkIndex]
			+ resources[resourceIndex].saaOnDisk[chunkIndex];

		// Offset in the image to start searching for valid fragments
		uint64_t imgStartOffset = bndlStartOffset;
		// Make it relative to the last known file fragment
		for (int i = 0; i < info[p].sz.size() - 1; ++i)
			imgStartOffset -= info[p].sz[i];
		imgStartOffset += info[p].pos.back();

		// The offset to stop searching the image at
		uint64_t imgEndOffset = imgStartOffset + searchLength;
		if (imgEndOffset > endOffset)
			imgEndOffset = endOffset;

		// For decompression
		int cSz = GetSizeFromSAA(
			resources[resourceIndex].saaOnDisk[chunkIndex]);
		int uSz = GetSizeFromSAA(
			resources[resourceIndex].uncompressedSaa[chunkIndex]);
		int resourceOffset = bundle.resourceDataOffset[chunkIndex]
			+ resources[resourceIndex].diskOffset[chunkIndex];

		bool resourceDefragged = false;

		// Truncate data from every interval until reaching end of resource
		// TODO: Somehow optimize this so it takes 1/6th the time, like FF does
		for (int i = bndlStartOffset; i < bndlEndOffset; i += interval)
		{
			int corruptionOffset = i - resourceOffset; // Corruption in resource
			int resourceRemaining = cSz - corruptionOffset;
			QByteArray testData(bundleData.sliced(resourceOffset, cSz));
			//QDataStream testStream(&testData, QIODevice::ReadWrite);
			//char* unFragmented = new char[corruptionOffset];
			//stream.device()->seek(resourceOffset);
			//stream.readRawData(unFragmented, corruptionOffset);
			//std::stringstream* t = new std::stringstream;
			//t->write(unFragmented, corruptionOffset);

			// Read in data from every interval as the remaining data
			for (uint64_t j = imgStartOffset; j < imgEndOffset; j += interval)
			{
				const auto timeForJ = std::chrono::steady_clock::now();
				const auto timeForIf = std::chrono::steady_clock::now();
				if (searchedAll == true && (j & 0xFFFFFF) == 0)
				{
					log("T" + QString::number(threadId) + " Bundle at 0x"
						+ QString::number(info[p].pos[0], 16).toUpper()
						+ ": searching 0x" + QString::number(j, 16).toUpper());
				}
				const auto durForIf = std::chrono::steady_clock::now() - timeForIf;

				const auto timeForSeek1 = std::chrono::steady_clock::now();
				img.seek(j);
				const auto durForSeek1 = std::chrono::steady_clock::now() - timeForSeek1;
				//const auto timeForSeek2 = std::chrono::steady_clock::now();
				//testStream.device()->seek(corruptionOffset);
				//const auto durForSeek2 = std::chrono::steady_clock::now() - timeForSeek2;
				const auto timeForWrite = std::chrono::steady_clock::now();
				//testStream.writeRawData(img.read(resourceRemaining),
				//	resourceRemaining);
				testData.replace(corruptionOffset, resourceRemaining,
					img.read(resourceRemaining));
				const auto durForWrite = std::chrono::steady_clock::now() - timeForWrite;
				//const auto timeForSeek3 = std::chrono::steady_clock::now();
				//testStream.device()->seek(0);
				//const auto durForSeek3 = std::chrono::steady_clock::now() - timeForSeek3;

				//char* buffer = new char[resourceRemaining];
				//stream.device()->seek(resourceOffset);
				//stream.readRawData(buffer, resourceRemaining);
				//t->seekp(corruptionOffset);
				//t->write(buffer, resourceRemaining);
				//char* resource = new char[cSz];
				//t->seekg(0);
				//t->read(resource, cSz);

				//if (GetLibdeflateResult(
				//	resource, cSz, uSz) == LIBDEFLATE_SUCCESS)

				const auto timeForZlibTest = std::chrono::steady_clock::now();
				if (GetLibdeflateResult(/*testStream.device()->readAll().data()*/testData.data(),
					cSz, uSz, dc) == LIBDEFLATE_SUCCESS)
				{
					// Set new sizes
					info[p].sz.back() = i;
					for (int k = 0; k < info[p].sz.size() - 1; ++k)
						info[p].sz.back() -= info[p].sz[k];
					info[p].pos.push_back(j);

					// Set size to remaining size until it can be confirmed
					int remaining = intendedSize;
					for (int k = 0; k < info[p].sz.size(); ++k)
						remaining -= info[p].sz[k];
					info[p].sz.push_back(remaining);

					//delete[] buffer;
					//delete[] resource;

					resourceDefragged = true;
					break;
				}
				const auto durForZlibTest = std::chrono::steady_clock::now() - timeForZlibTest;

				const auto durForJ = std::chrono::steady_clock::now() - timeForJ;
				if (info[p].pos[0] == 0x4F3D11000 && searchedAll)
					if (true);

				//delete[] buffer;
				//delete[] resource;
			}
			//delete[] unFragmented;
			//delete t;
			if (resourceDefragged)
				break;
			else if (!resourceDefragged && i + interval > bndlEndOffset
				&& ui.checkBoxSearchAll->isChecked())
			{
				log("T" + QString::number(threadId) + " Bundle at 0x"
					+ QString::number(info[p].pos[0], 16).toUpper()
					+ ": searching whole image");

				i = bndlStartOffset;
				imgStartOffset = startOffset;
				imgEndOffset = endOffset;
				searchedAll = true;
			}
		}

		// Check what the new corrupt resource is, or if there is
		// no longer a corrupt resource, set the size to the remainder
		if (resourceDefragged)
		{
			bool invalid = validateCompressedResources(
				img, info[p], bundle, resources);

			if (invalid)
			{
				// Get an estimate of the correct fragment size
				info[p].sz.back() = getCompressedResourcesFailPos(
					img, info[p], bundle, resources);
				for (int i = 0; i < info[p].sz.size() - 1; ++i)
					info[p].sz.back() -= info[p].sz[i];
				searchedAll = false; // New resource
			}

			log("T" + QString::number(threadId)
				+ " Bundle at 0x" + QString::number(info[p].pos[0], 16).toUpper()
				+ ": data fragment at 0x"
				+ QString::number(info[p].pos.back(), 16).toUpper() + " for 0x"
				+ QString::number(info[p].sz.back(), 16).toUpper());

			if (!invalid)
			{
				corrupt = CorruptionType::Intact;
				log("T" + QString::number(threadId) + " Bundle at 0x"
					+ QString::number(info[p].pos[0], 16).toUpper()
					+ " is intact");
			}
		}

		prevResource = resourceIndex;
		prevChunk = chunkIndex;
	}
}