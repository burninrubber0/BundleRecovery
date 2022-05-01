#include "../BundleRecovery.h"

#include <CRC.h>

#include <binaryio/binaryreader.hpp>
#include <binaryio/binarywriter.hpp>

#include <QDataStream>
#include <QDateTime>
#include <QFileInfo>

void BundleRecovery::extractBundles(const std::vector<FileInfo>& info,
	const std::vector<CorruptionType>& corrupt, int start, int end,
	int threadId)
{
	log("Thread " + QString::number(threadId)
		+ " delegated bundles " + QString::number(start)
		+ " to " + QString::number(end - 1));
	uint64_t dateTimePre = QDateTime::currentSecsSinceEpoch();

	QFile image(input);
	image.open(QIODevice::ReadOnly);

	for (int i = start; i < end; ++i)
	{
		QByteArray bundleData;
		for (int j = 0; j < info[i].pos.size(); ++j)
		{
			image.seek(info[i].pos[j]);
			bundleData.append(image.read(info[i].sz[j]));
		}

		QString outPath = bundleName(info[i], corrupt[i]);
		QFile out(outPath);
		out.open(QIODevice::WriteOnly);
		QDataStream outStream(&out);
		outStream.writeRawData(bundleData, bundleData.size());
		out.close();
		QFileInfo outInfo(out);
		log("Extracted " + outInfo.fileName());
	}

	image.close();
	uint64_t timeTaken = QDateTime::currentSecsSinceEpoch() - dateTimePre;
	log("Thread " + QString::number(threadId)
		+ " finished in " + QString::number(timeTaken) + " seconds");
}

QString BundleRecovery::bundleName(const FileInfo& info, CorruptionType corrupt)
{
	QString name;

	// Assign a prefix based on corruption
	switch (corrupt)
	{
	case CorruptionType::Intact:
		name = (output + "/"
			+ QString::number(info.pos[0], 16).toUpper());
		break;
	case CorruptionType::DebugData:
		name = (output + "/corrupt-debug-data_"
			+ QString::number(info.pos[0], 16).toUpper());
		break;
	case CorruptionType::ResourceId:
		name = (output + "/corrupt-ids_"
			+ QString::number(info.pos[0], 16).toUpper());
		break;
	case CorruptionType::ResourceEntries:
		name = (output + "/corrupt-entries_"
			+ QString::number(info.pos[0], 16).toUpper());
		break;
	case CorruptionType::ResourceCompressionInfo:
		name = (output + "/corrupt-compression-info_"
			+ QString::number(info.pos[0], 16).toUpper());
		break;
	case CorruptionType::ResourceImports:
		name = (output + "/corrupt-imports"
			+ QString::number(info.pos[0], 16).toUpper());
		break;
	case CorruptionType::ZlibData:
		name = (output + "/corrupt-data_"
			+ QString::number(info.pos[0], 16).toUpper());
		break;
	case CorruptionType::Uncompressed:
		name = (output + "/uncompressed_"
			+ QString::number(info.pos[0], 16).toUpper());
		break;
	default:
		name = (output + "/unknown_"
			+ QString::number(info.pos[0], 16).toUpper());
		break;
	}

	// TODO: Rename based on known resource IDs


	// If there is no extension, add a default one
	if (!name.contains('.'))
		name.append(".BNDL");

	return name;
}