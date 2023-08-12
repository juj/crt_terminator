#ifndef PCI_H
#define PCI_H

typedef unsigned int pcidev_t;

int pci_get_num_buses(void);
pcidev_t pci_find_nth_device_by_class(unsigned long cls, int n);
unsigned int pci_read_u16(pcidev_t dev, int reg_number);
void pci_write_u16(pcidev_t dev, int reg_number, unsigned int word);

#endif
