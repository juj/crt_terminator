#ifndef S3_H
#define S3_H

#include "pci.h"

int s3_enable_feature_connector(pcidev_t vga);

int detect_s3(char *dst);

#endif
