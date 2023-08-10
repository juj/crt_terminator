#ifndef RAMDAC_H
#define RAMDAC_H

void detect_hidden_ramdac_register();
int has_hidden_ramdac_register();
unsigned char read_hidden_ramdac_register(int numreads);
void write_hidden_ramdac_register(int numreads, unsigned char value);

#endif
