#include "../BundleRecovery.h"

#include <binaryio/util.hpp>

#include <QDateTime>
#include <QtEndian>

void BundleRecovery::findBundles(std::vector<FileInfo>& info,
	std::vector<Bundle>& bundles, uint64_t start, uint64_t end,
	int threadId)
{
	log("Thread " + QString::number(threadId)
		+ " delegated 0x" + QString::number(start, 16).toUpper()
		+ " to 0x" + QString::number(end - 1, 16).toUpper());
	uint64_t dateTimePre = QDateTime::currentSecsSinceEpoch();

	QFile image(input);
	image.open(QIODevice::ReadOnly);
	image.seek(start);

	while (image.pos() < end)
	{
		// Cancel pressed
		if (!ui.pushButtonStop->isEnabled())
		{
			image.close();
			return;
		}

		image.seek(binaryio::Align((uint64_t)image.pos(), interval));
		uint64_t offset = image.pos();
		if ((offset & 0xFFFFFFF) == 0)
		{
			log("Scanning offset 0x" + QString::number(offset, 16).toUpper());
		}
		char magic[4] = {};
		image.read(magic, 4);
		if (!strncmp(magic, "bndl", 4))
		{
			// Verify validity via version number
			uint32_t version;
			image.read(reinterpret_cast<char*>(&version), 4);
			if (endianness == std::endian::big)
				version = qToBigEndian(version);

			int limit = 0;
			if (versionLimit != 0)
				limit = versionLimit + 2;

			if ((version >= 1 && version <= 5)
				&& (limit == 0 || limit == version))
			{
				mutex.lock();
				info.push_back({ { offset }, {} });
				bundles.push_back({});
				strncpy(bundles.back().magic, "bndl", 4);
				bundles.back().version = version;
				mutex.unlock();
				log("Found file at 0x"
					+ QString::number(offset, 16).toUpper()
					+ ", Bundle 1 v" + QString::number(version));
			}
		}
		else if (!strncmp(magic, "bnd2", 4))
		{
			// Verify validity via version number
			uint32_t version;
			image.read(reinterpret_cast<char*>(&version), 4);
			if (endianness == std::endian::big)
				version = qToBigEndian(version);
			// Handle version 5 (16-bit version and platform)
			if (version > 5)
			{
				if (version == 0x00010005) // PC
					version = 5;
				else if (version == 0x00050002
					|| version == 0x00050003) // Console
					version = 5;
			}

			int limit = 0;
			switch (versionLimit)
			{
			case 4:
				limit = 2;
				break;
			case 5:
				limit = 3;
				break;
			case 6:
				limit = 5;
				break;
			}

			if ((version >= 1 && version <= 5)
				&& (limit == 0 || limit == version))
			{
				mutex.lock();
				info.push_back({ { offset }, {} });
				bundles.push_back({});
				strncpy(bundles.back().magic, "bnd2", 4);
				bundles.back().version = version;
				mutex.unlock();
				log("Found file at 0x" + QString::number(offset, 16).toUpper()
					+ ", Bundle 2 v" + QString::number(version));
			}
		}
	}

	image.close();
	uint64_t timeTaken = QDateTime::currentSecsSinceEpoch() - dateTimePre;
	log("Thread " + QString::number(threadId)
		+ " finished in " + QString::number(timeTaken) + " seconds");
}

void BundleRecovery::sortBundles(std::vector<FileInfo>& info,
	std::vector<Bundle>& bundles)
{
	std::vector<std::pair<uint64_t, Bundle>> sorted;
	for (int i = 0; i < info.size(); ++i)
		sorted.push_back(std::make_pair(info[i].pos[0], bundles[i]));
	std::sort(sorted.rbegin(), sorted.rend(),
		[&](const auto& a, const auto& b)
		{
			return a.first > b.first;
		});
	for (int i = 0; i < sorted.size(); ++i)
	{
		info[i].pos[0] = sorted[i].first;
		bundles[i] = sorted[i].second;
	}
}
