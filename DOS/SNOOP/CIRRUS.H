#ifndef CIRRUS_H
#define CIRRUS_H

int read_cirrus_hidden_dac(void);
void write_cirrus_hidden_dac(int val);
int detect_cirrus_logic(char *dst);

#endif
