#include "pci_str.h"
#include <stdio.h>

static char tmp[154] = {0};
static const char unknown[] = "(unknown)";

static const char *read_pci_str(FILE *f, uint32 offset)
{
	fseek(f, 679804ul + offset, SEEK_SET);
	int read = fread(tmp, 1, 153, f);
	fclose(f);
	return read > 0 ? tmp : unknown;
}

const char *pci_vendor_str(uint16 vendor)
{
	FILE *f = fopen("pci_id.hsh", "rb");
	if (!f) return "";
	uint32 idx = ((uint32)vendor * 165) % 4093;
#define VENDOR_HASH_SIZE 6
	fseek(f, idx*VENDOR_HASH_SIZE, SEEK_SET);
#define LONGEST_VENDOR_PROBE 6
	struct { uint16 vendor; uint16 ofsLo; uint16 ofsHi; } hash[LONGEST_VENDOR_PROBE] = {0};
	fread(hash, VENDOR_HASH_SIZE, LONGEST_VENDOR_PROBE, f);
	for(int i = 0; i < LONGEST_VENDOR_PROBE; ++i)
		if (hash[i].vendor == vendor)
		{
			uint32 offset = (uint32)hash[i].ofsLo | ((uint32)hash[i].ofsHi << 16);
			return read_pci_str(f, offset);
		}
	fclose(f);
	return unknown;
}

const char *pci_device_str(uint16 vendor, uint16 device)
{
	FILE *f = fopen("pci_id.hsh", "rb");
	if (!f) return "";
	uint32 vd = ((uint32)vendor << 16) | device;
  uint32 idx = (vd * 30195) % 32749;
#define DEV_HASH_SIZE 8
  fseek(f, 24588ul + idx*DEV_HASH_SIZE, SEEK_SET);
#define LONGEST_DEV_PROBE 14
  struct { uint32 vd; uint32 ofs; } hash[LONGEST_DEV_PROBE] = {0};
  fread(hash, DEV_HASH_SIZE, LONGEST_DEV_PROBE, f);
  for(int i = 0; i < LONGEST_DEV_PROBE; ++i)
    if (hash[i].vd == vd)
      return read_pci_str(f, hash[i].ofs);
  fclose(f);
  return unknown;
}

const char *pci_subdevice_str(uint16 vendor, uint16 device, uint16 subvendor, uint16 subdevice)
{
  FILE *f = fopen("pci_id.hsh", "rb");
	if (!f) return "";
  uint32 vd = ((uint32)vendor << 16) | device;
  uint32 svd = ((uint32)subvendor << 16) | subdevice;
  uint32 idx = (vd * 16025929ul) ^ (svd * 15448861ul);
  idx = (idx * 4962) % 32749;
#define SUBDEV_HASH_SIZE 12
  fseek(f, 286684ul + idx*SUBDEV_HASH_SIZE, SEEK_SET);
#define LONGEST_SUBDEV_PROBE 12
  struct { uint32 vd; uint32 svd; uint32 ofs; } hash[LONGEST_SUBDEV_PROBE] = {0};
  fread(hash, SUBDEV_HASH_SIZE, LONGEST_SUBDEV_PROBE, f);
  for(int i = 0; i < LONGEST_SUBDEV_PROBE; ++i)
    if (hash[i].vd == vd && hash[i].svd == svd)
      return read_pci_str(f, hash[i].ofs);
  fclose(f);
  return unknown;
}
