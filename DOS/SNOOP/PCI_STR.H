#ifndef PCI_STR_H
#define PCI_STR_H

#if defined(__TURBOC__) && defined(__MSDOS__)
typedef unsigned int  uint16;
typedef unsigned long uint32;
#else
typedef unsigned short uint16;
typedef unsigned long uint32;
#endif
const char *pci_vendor_str(uint16 vendor);
const char *pci_device_str(uint16 vendor, uint16 device);
const char *pci_subdevice_str(uint16 vendor, uint16 device, uint16 subvendor, uint16 subdevice);
#endif
