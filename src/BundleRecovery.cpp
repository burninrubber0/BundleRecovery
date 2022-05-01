// A Bundle recovery tool. It is similar to a file carver, but has multiple
// features specific to the Bundle container format. Though accessible from
// RED, it is designed to be separate from it.
// 
// Recovery is split into four stages:
//     -Finding bundles by detecting bndl/bnd2 magics and validating versions
//     -Determining whether each is corrupt and the form of corruption
//     -Defragmenting each by appending data at the suspected fragment point
//     -Naming each based on known names and extracting it
// 
// Corruption is primarily detected in compressed data. The libdeflate library
// is used where possible for speed reasons; where it may fail, the original
// zlib library is used.
// 
// Bundle naming is based on a list of known Bundle Resource IDs matched to
// a file name. This list is provided by the user. The IDs are converted to
// CRC32 hashes for searching. For example, the following names any file 
// containing WorldMapData AI.<offset>.DAT:
//     AI.DAT|WorldMapData
// Having multiple comma-separated IDs requires all of them to be present:
//     VEHICLES/VEH_XUSRCB1_AT.BIN|XUSRCB1_AttribSys,XUSRCB1DeformationModel

#include "../BundleRecovery.h"

#include <QtZlib/zlib.h>

#include <QFileDialog>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonValue>
#include <QStandardPaths>

void BundleRecovery::selectInputFile()
{
	QString in = QFileDialog::getOpenFileName(this, "Open",
		QDir::currentPath(), "All Files (*.*)");
	if (!in.isEmpty())
		ui.lineEditInput->setText(in);
	if (isReady())
		ui.pushButtonStart->setEnabled(true);
}

void BundleRecovery::selectOutputFolder()
{
	QString out = QFileDialog::getExistingDirectory(this, "Save",
		QDir::currentPath());
	if (!out.isEmpty())
		ui.lineEditOutput->setText(out);
	if (isReady())
		ui.pushButtonStart->setEnabled(true);
}

void BundleRecovery::selectNamesFile()
{
	QString names = QFileDialog::getOpenFileName(this, "Open",
		QDir::currentPath(), "All Files (*.*)");
	if (!names.isEmpty())
		ui.lineEditOutput->setText(names);
	if (isReady())
		ui.pushButtonStart->setEnabled(true);
}

void BundleRecovery::recover()
{
	log("Beginning recovery");

	input = ui.lineEditInput->text();
	output = ui.lineEditOutput->text();
	names = ui.lineEditNames->text();
	if (ui.comboBoxPlatform->currentIndex() == 0)
		endianness = std::endian::big;
	else
		endianness = std::endian::little;
	versionLimit = ui.comboBoxVersion->currentIndex();
	startOffset = ui.doubleSpinBoxStart->value();
	endOffset = ui.doubleSpinBoxEnd->value();
	interval = ui.doubleSpinBoxInterval->value();
	searchLength = ui.doubleSpinBoxLength->value();

	log("Input file: " + input);
	log("Start offset: 0x" + QString::number(startOffset, 16));
	log("End offset: 0x" + QString::number(endOffset, 16));
	log("Search interval: 0x" + QString::number(interval, 16));
	log("Platform: " + ui.comboBoxPlatform->currentText());
	log("Search limited to version: " + ui.comboBoxVersion->currentText());
	if (ui.checkBoxDefrag->isChecked())
	{
		log("Fragment search length: 0x" + QString::number(searchLength, 16));
		if (ui.checkBoxSearchAll->isChecked())
			log("Search whole image: true");
		else
			log("Search whole image: false");
	}
	if (ui.checkBoxExtract->isChecked())
	{
		log("Output file: " + output);
	}
	if (ui.checkBoxRename->isChecked())
	{
		log("Names file: " + names);
	}

	// Open and check stream, then close (threads use their own ifstream)
	QFile in(input);
	
	if (!in.open(QIODevice::ReadOnly | QIODevice::ExistingOnly))
	{
		log("Failed to open input file");
		return;
	}
	in.close();

	// Set end offset to file size if file is smaller
	uint64_t imgSize = in.size();
	if (imgSize < endOffset)
		endOffset = in.size();

	// Storage for the information that recovery requires
	std::vector<FileInfo> fileInfo; // Bundle/fragment positions and sizes
	std::vector<Bundle> bundleList; // Bundle headers
	std::vector<QString> debugDataList; // Bundle debug data
	std::vector<std::vector<ResourceEntry>> resourceLists; // Resource entries
	std::vector<std::vector<std::vector<ImportEntry>>> importLists; // Resource imports
	std::vector<CorruptionType> isBundleCorrupt; // Corruption states

	// JSON file for writing/reading information to/from
	QFile jsonFile(QStandardPaths::standardLocations(
		QStandardPaths::AppDataLocation)[0] + "/../burninrubber0/BundleRecovery.json");
	QJsonDocument jsonDoc;
	jsonFile.open(QFile::ReadWrite);
	//if (jsonFile.isOpen())
	//	jsonDoc = QJsonDocument::fromJson(jsonFile.readAll());
	QJsonArray jsonArray; // Top-level JSON array - bundles

	// Get thread count
	int numThreads = QThread::idealThreadCount();
	log("Detected " + QString::number(numThreads) + " logical threads");

	// Find bundles
	log("Finding bundles");
	for (int i = 0; i < numThreads; ++i)
	{
		// Split the image evenly between threads
		uint64_t s = (imgSize / (numThreads)) * i;
		uint64_t e = (imgSize / (numThreads)) * (i + 1);
		if (i == numThreads - 1)
			e = imgSize; // End of image
		threads.push_back(QThread::create(
			[this, &fileInfo, &bundleList, s, e, i]
			{
				findBundles(fileInfo, bundleList, s, e, i);
			}));
		connect(threads[i], &QThread::finished, threads[i],
			&QThread::deleteLater);
		threads[i]->start();
	}
	for (int i = 0; i < threads.size(); ++i)
		threads[i]->wait();
	if (!ui.pushButtonStop->isEnabled()) // Cancel pressed
	{
		clearThreads();
		return;
	}
	clearThreads();
	log("Found " + QString::number(bundleList.size()) + " bundles");

	// Sort bundles and populate the other vectors with the correct amount
	// of elements
	sortBundles(fileInfo, bundleList);
	for (int i = 0; i < fileInfo.size(); ++i)
	{
		debugDataList.push_back({});
		resourceLists.push_back({});
		importLists.push_back({});
		isBundleCorrupt.push_back({});
	}
	if (!ui.pushButtonStop->isEnabled()) // Cancel pressed
		return;

	// Write found file info to JSON
	for (int i = 0; i < fileInfo.size(); ++i)
	{
		QJsonArray potentialsArray; // One potential until defrag
		QJsonObject fileInfoObject; // Only offset for now, size found later
		fileInfoObject.insert("position", (qint64)fileInfo[i].pos[0]);
		fileInfoObject.insert("size", 0); // No bundle ever has a 0 size
		potentialsArray.append(fileInfoObject);
		jsonArray.append(potentialsArray);
	}
	jsonDoc.setArray(jsonArray);
	jsonFile.write(jsonDoc.toJson());
	jsonFile.close(); // Temp - move down after finishing

	// Read data into the vectors
	log("Reading bundle info");
	for (int i = 0; i < numThreads; ++i)
	{
		// Each thread works on a set of bundles
		int s = bundleList.size() / (numThreads) * i;
		int e = bundleList.size() / (numThreads) * (i + 1);
		if (i == numThreads - 1)
			e = bundleList.size();
		threads.push_back(QThread::create(
			[this, &fileInfo, &bundleList, &debugDataList, &resourceLists,
			s, e, i]
			{
				readBundles(fileInfo, bundleList, debugDataList, resourceLists,
					s, e, i);
			}));
		connect(threads[i], &QThread::finished, threads[i],
			&QThread::deleteLater);
		threads[i]->start();
	}
	for (int i = 0; i < threads.size(); ++i)
		threads[i]->wait();
	if (!ui.pushButtonStop->isEnabled()) // Cancel pressed
	{
		clearThreads();
		return;
	}
	clearThreads();

	// Validate bundle integrity
	log("Validating bundles");
	for (int i = 0; i < numThreads; ++i)
	{
		// Each thread works on a set of bundles
		int s = bundleList.size() / (numThreads) * i;
		int e = bundleList.size() / (numThreads) * (i + 1);
		if (i == numThreads - 1)
			e = bundleList.size();
		threads.push_back(QThread::create(
			[this, &fileInfo, &bundleList, &debugDataList, &resourceLists,
			&importLists, &isBundleCorrupt, s, e, i]
			{
				validateBundles(fileInfo, bundleList, debugDataList,
					resourceLists, importLists, isBundleCorrupt, s, e, i);
			}));
		connect(threads[i], &QThread::finished, threads[i],
			&QThread::deleteLater);
		threads[i]->start();
	}
	for (int i = 0; i < threads.size(); ++i)
		threads[i]->wait();
	if (!ui.pushButtonStop->isEnabled()) // Cancel pressed
	{
		clearThreads();
		return;
	}
	clearThreads();
	int numCorrupt = 0;
	for (int i = 0; i < isBundleCorrupt.size(); ++i)
		if (isBundleCorrupt[i] != CorruptionType::Intact
			&& isBundleCorrupt[i] != CorruptionType::Uncompressed)
			++numCorrupt;
	log(QString::number(numCorrupt) + " bundles corrupt");

	// Attempt to defragment fragmented bundles
	if (ui.checkBoxDefrag->isChecked())
	{
		log("Defragmenting bundles");
		for (int i = 0; i < numThreads; ++i)
		{
			// Each thread works on a set of bundles
			int s = bundleList.size() / (numThreads) * i;
			int e = bundleList.size() / (numThreads) * (i + 1);
			if (i == numThreads - 1)
				e = bundleList.size();
			threads.push_back(QThread::create(
				[this, &fileInfo, bundleList, &debugDataList, &resourceLists,
				&importLists, &isBundleCorrupt, s, e, i]
				{
					defragBundles(fileInfo, bundleList, debugDataList,
						resourceLists, importLists, isBundleCorrupt, s, e, i);
				}));
			connect(threads[i], &QThread::finished, threads[i],
				&QThread::deleteLater);
			threads[i]->start();
		}
		for (int i = 0; i < threads.size(); ++i)
			threads[i]->wait();
		if (!ui.pushButtonStop->isEnabled()) // Cancel pressed
		{
			clearThreads();
			return;
		}
		clearThreads();
		int newNumCorrupt = 0;
		for (int i = 0; i < isBundleCorrupt.size(); ++i)
			if (isBundleCorrupt[i] != CorruptionType::Intact
				&& isBundleCorrupt[i] != CorruptionType::Uncompressed)
				++newNumCorrupt;
		log(QString::number(numCorrupt - newNumCorrupt) + "/"
			+ QString::number(numCorrupt) + " bundles defragmented");
	}

	// Extract bundles from image
	if (ui.checkBoxExtract->isChecked())
	{
		// Rename using provided names if option selected
		if (ui.checkBoxRename->isChecked())
		{
			log("TODO: Renamer");
		}
		
		log("Extracting bundles");
		for (int i = 0; i < numThreads; ++i)
		{
			// Each thread works on a set of bundles
			int s = bundleList.size() / (numThreads) * i;
			int e = bundleList.size() / (numThreads) * (i + 1);
			if (i == numThreads - 1)
				e = bundleList.size();
			threads.push_back(QThread::create(
				[this, &in, fileInfo, bundleList, isBundleCorrupt, s, e, i]
				{
					extractBundles(fileInfo, isBundleCorrupt, s, e, i);
				}));
			connect(threads[i], &QThread::finished, threads[i],
				&QThread::deleteLater);
			threads[i]->start();
		}
		for (int i = 0; i < threads.size(); ++i)
			threads[i]->wait();
		if (!ui.pushButtonStop->isEnabled()) // Cancel pressed
		{
			clearThreads();
			return;
		}
		clearThreads();
		log("Finished extracting");
	}

	log("Done");
}

void BundleRecovery::stopRecovery()
{
	log("Recovery cancelled.");
}

void BundleRecovery::clearThreads()
{
	for (int i = 0; i < threads.size(); ++i)
	{
		threads[i]->quit();
		threads[i]->wait();
		delete threads[i];
	}
	threads.clear();
}

int BundleRecovery::nearestMultiple(int val, int mult)
{
	if (mult > val)
		return mult;

	val = val + mult / 2;
	val = val - (val % mult);
	return val;
}

int8_t BundleRecovery::GetChunkCount(const Bundle& bundle)
{
	if (!strncmp(bundle.magic, "bndl", 4))
		return 5;
	else
	{
		if (bundle.version == 2)
			return 3;
		else if (bundle.version >= 3)
			return 4;
	}

	// TODO: Properly catch errors here
	return 0;
}

int BundleRecovery::GetBundleSize(const Bundle& bundle,
	const std::vector<ResourceEntry>& resources)
{
	int size = 0;
	if (!strncmp(bundle.magic, "bndl", 4))
	{
		for (int i = 0; i < GetChunkCount(bundle); ++i)
			size += bundle.chunkSaas[i].size;
	}
	else
	{
		int8_t chunkCount = GetChunkCount(bundle);
		size += bundle.resourceDataOffset[chunkCount - 1];
		// If there are no entries in the last chunk, the data offset will be
		// the end position
		for (int i = resources.size() - 1; i >= 0; --i)
		{
			if (GetSizeFromSAA(resources[i].saaOnDisk[chunkCount - 1]))
			{
				size += resources[i].diskOffset[chunkCount - 1];
				break;
			}
		}
		for (int i = resources.size() - 1; i >= 0; --i)
		{
			int lastSize = GetSizeFromSAA(resources[i].saaOnDisk[chunkCount - 1]);
			if (lastSize)
			{
				size += lastSize;
				break;
			}
		}
	}

	return size;
}

int8_t BundleRecovery::ResourceEntrySize(const Bundle& bundle)
{
	int8_t size;
	if (!strncmp(bundle.magic, "bndl", 4))
		size = 0x70;
	else
	{
		if (bundle.version == 2)
			size = 0x40;
		else if (bundle.version == 3)
			size = 0x50;
		else if (bundle.version == 5)
			size = 0x48;
	}

	return size;
}

uint32_t BundleRecovery::GetSizeFromSAA(uint32_t data)
{
	return data & 0x0FFFFFFF;
}

uint16_t BundleRecovery::GetAlignmentFromSAA(uint32_t data)
{
	return (1 << ((data & 0xF0000000) >> 28));
}

libdeflate_result BundleRecovery::GetLibdeflateResult(char* resource, int cmp,
	int ucmp, libdeflate_decompressor* dc)
{
	char* resourceUncompressed = new char[ucmp];

	libdeflate_result result = libdeflate_zlib_decompress(
		dc, resource, cmp, resourceUncompressed, ucmp, NULL);

	delete[] resourceUncompressed;

	return result;
}

uint32_t BundleRecovery::GetZlibBytesRead(char* resource, int cmp, int ucmp)
{
	Bytef* resourceUncompressed = new Bytef[ucmp];
	z_stream strm;
	strm.zalloc = Z_NULL;
	strm.zfree = Z_NULL;
	strm.opaque = Z_NULL;
	strm.avail_in = cmp;
	strm.next_in = reinterpret_cast<Bytef*>(resource);
	strm.avail_out = ucmp;
	strm.next_out = resourceUncompressed;

	inflateInit(&strm);
	inflate(&strm, Z_NO_FLUSH);
	uint32_t bytesRead = strm.total_in;
	inflateEnd(&strm);

	delete[] resourceUncompressed;

	return bytesRead;
}

void BundleRecovery::logCorruption(uint64_t offset, CorruptionType err)
{
	switch (err)
	{
	case CorruptionType::Intact:
		break;
	case CorruptionType::DebugData:
		log("Bundle at 0x" + QString::number(offset, 16).toUpper()
			+ ": Debug data corrupt");
		break;
	case CorruptionType::ResourceId:
		log("Bundle at 0x" + QString::number(offset, 16).toUpper()
			+ ": Resource IDs corrupt");
		break;
	case CorruptionType::ResourceEntries:
		log("Bundle at 0x" + QString::number(offset, 16).toUpper()
			+ ": Entries corrupt");
		break;
	case CorruptionType::ResourceCompressionInfo:
		log("Bundle at 0x" + QString::number(offset, 16).toUpper()
			+ ": Compression info corrupt");
		break;
	case CorruptionType::ResourceImports:
		log("Bundle at 0x" + QString::number(offset, 16).toUpper()
			+ ": Entries corrupt");
		break;
	case CorruptionType::ZlibData:
		log("Bundle at 0x" + QString::number(offset, 16).toUpper()
			+ ": zlib data corrupt");
		break;
	case CorruptionType::Uncompressed:
		log("Bundle at 0x" + QString::number(offset, 16).toUpper()
			+ ": Uncompressed, state unknown");
		break;
	default:
		log("Bundle at 0x" + QString::number(offset, 16).toUpper()
			+ ": Unknown corruption state");
		break;
	}
}

bool BundleRecovery::isReady()
{
	if (ui.lineEditInput->text().isEmpty())
		return false;

	if (ui.checkBoxExtract->isChecked())
	{
		if (ui.lineEditOutput->text().isEmpty())
			return false;
	}

	if (ui.checkBoxRename->isChecked())
	{
		if (ui.lineEditNames->text().isEmpty())
			return false;
	}

	return true;
}

void BundleRecovery::connectUi()
{
	connect(ui.toolButtonBrowseInput, &QToolButton::clicked, this,
		&BundleRecovery::selectInputFile);
	connect(ui.checkBoxDefrag, &QCheckBox::stateChanged, this,
		[this]
		{
			ui.labelLength->setEnabled(ui.checkBoxDefrag->isChecked());
			ui.doubleSpinBoxLength->setEnabled(ui.checkBoxDefrag->isChecked());
			ui.checkBoxSearchAll->setEnabled(ui.checkBoxDefrag->isChecked());
		});
	connect(ui.checkBoxExtract, &QCheckBox::stateChanged, this,
		[this]
		{
			ui.labelOutput->setEnabled(ui.checkBoxExtract->isChecked());
			ui.toolButtonBrowseOutput->
				setEnabled(ui.checkBoxExtract->isChecked());
			ui.checkBoxRename->setEnabled(ui.checkBoxExtract->isChecked());
			if (ui.checkBoxRename->isChecked())
			{
				ui.toolButtonBrowseNames->
					setEnabled(ui.checkBoxExtract->isChecked());
				ui.checkBoxRename->setChecked(ui.checkBoxExtract->isChecked());
			}
			ui.pushButtonStart->
				setEnabled(isReady());
		});
	connect(ui.toolButtonBrowseOutput, &QToolButton::clicked, this,
		&BundleRecovery::selectOutputFolder);
	connect(ui.checkBoxRename, &QCheckBox::stateChanged, this,
		[this]
		{
			ui.labelNames->setEnabled(ui.checkBoxRename->isChecked());
			ui.toolButtonBrowseNames->
				setEnabled(ui.checkBoxRename->isChecked());
			ui.pushButtonStart->setEnabled(isReady());
		});
	connect(ui.toolButtonBrowseNames, &QToolButton::clicked, this,
		&BundleRecovery::selectNamesFile);
	connect(ui.pushButtonStart, &QPushButton::clicked, this,
		[this]
		{
			ui.pushButtonStart->setEnabled(false);
			ui.pushButtonStop->setEnabled(true);
			// Put recovery on another thread
			QThread* thread = QThread::create([this] { recover(); });
			connect(thread, &QThread::finished, this,
				[this]
				{
					ui.pushButtonStart->setEnabled(true);
					ui.pushButtonStop->setEnabled(false);
				});
			connect(thread, &QThread::finished, thread, &QThread::deleteLater);
			thread->start();
		});
	connect(ui.pushButtonStop, &QPushButton::clicked, this,
		[this]
		{
			stopRecovery();
			ui.pushButtonStart->setEnabled(true);
			ui.pushButtonStop->setEnabled(false);
		});
}

BundleRecovery::BundleRecovery(QWidget* parent)
	: QDialog(parent)
{
	ui.setupUi(this);
	setModal(false);
	setWindowFlags(Qt::Dialog | Qt::MSWindowsFixedSizeDialogHint);
	setAttribute(Qt::WA_DeleteOnClose);
	connectUi();

	connect(this, &BundleRecovery::log, ui.plainTextEditLog,
		&QPlainTextEdit::appendPlainText);
}

BundleRecovery::~BundleRecovery()
{
	clearThreads();
}