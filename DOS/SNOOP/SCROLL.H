#ifndef SCROLL_H
#define SCROLL_H

int crtt_test_hs_latch_position(void);
int crtt_test_ds_latch_position(void);
int benchmark_hblank_length(void);

void print_ds_hs_test_result(int ds, int hs, int hblank_length);

#endif
