extern unsigned short screen_width;
extern unsigned short screen_height;
extern int current_mode_is_unchained;

void set_video_mode(int mode);
void vga_regs(unsigned short addr, const char *params, int num);
void crtc2(const char *lo, const char *hi);
void crtc(const char regs[25]);
void seq(const char regs[5]);
void gfx(const char regs[9]);
void attr(const char regs[20]);
void misc(int val);
void print_text_test_screen();

unsigned char read_attr(unsigned char subreg);
void write_attr(unsigned char subreg, unsigned char value);

void identify_crtc_address();
unsigned char read_crtc(unsigned char subreg);
void write_crtc(unsigned char subreg, unsigned char value);
