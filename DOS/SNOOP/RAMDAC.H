#ifndef RAMDAC_H
#define RAMDAC_H

void detect_hidden_ramdac_register(void);
int has_hidden_ramdac_register(void);
unsigned char read_hidden_ramdac_register(void);
void write_hidden_ramdac_register(unsigned char value);
void print_ramdac_info(void);

#endif
