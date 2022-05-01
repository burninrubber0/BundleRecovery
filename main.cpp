#include "BundleRecovery.h"

int main(int argc, char* argv[])
{
	QApplication* a = new QApplication(argc, argv);
	BundleRecovery* m = new BundleRecovery();
	m->show();
	a->exec();
}