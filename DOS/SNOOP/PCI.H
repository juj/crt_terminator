#ifndef PCI_H
#define PCI_H

typedef unsigned int pcidev_t;

int pci_get_num_buses(void);
pcidev_t pci_find_nth_device_by_class(unsigned long cls, int n);
unsigned int pci_read_u16(pcidev_t dev, int reg_number);
void pci_write_u16(pcidev_t dev, int reg_number, unsigned int word);

int pci_is_palette_snoop_enabled(pcidev_t vga);
void enable_vga_palette_snoop(pcidev_t vga);
void disable_vga_palette_snoop(pcidev_t vga);
pcidev_t find_pci_vga_adapter();

void print_pci_info(pcidev_t dev);

#endif
