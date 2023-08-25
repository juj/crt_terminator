#ifndef PCI_H
#define PCI_H

typedef unsigned int pcidev_t;

int detect_pci_20_bios_supported(void);

int pci_get_num_buses(void);
pcidev_t pci_find_nth_device_by_class(unsigned long cls, int n);
unsigned int pci_read_u16(pcidev_t dev, int reg_number);
void pci_write_u16(pcidev_t dev, int reg_number, unsigned int word);

int pci_is_palette_snoop_enabled(pcidev_t vga);
int pci_support_66mhz(pcidev_t dev);
void enable_vga_palette_snoop(pcidev_t vga);
void disable_vga_palette_snoop(pcidev_t vga);
pcidev_t find_pci_vga_adapter();

int print_pci_info(pcidev_t dev);

#endif
