#ifndef VGA_H
#define VGA_H

#include <dos.h>

int inp_vga(int port, int idx);
int inp_3c4(int idx);
int inp_3d4(int idx);
int inp_3ce(int idx);
int inp_3c0(int idx);
int vga_read_attr_port(int port, int idx); // identical to vga_read_attr(), just passes a dummy port value

void outp_vga(int port, int idx, int value);
void vga_set_bits(int port, int idx, unsigned char bits);
void vga_clear_bits(int port, int idx, unsigned char bits);
void vga_replace_bits(int port, int idx, unsigned char bitmask, unsigned char bits);
void outp_3c4(int idx, int value);
void outp_3d4(int idx, int value);
void outp_3ce(int idx, int value);
void outp_3c0(int idx, int value);

int is_vga_mode_possibly_supported(int mode);
void set_video_mode(int mode);
int get_cur_video_mode();
void random_fill_vga_memory(int is_gfx_mode);

int get_cur_text_screen_width(void);
int get_cur_text_screen_height(void);

int in_vsync(void);
void wait_for_vsync(void);

void print_vga_state_info(int mode);

struct vga_mode_table
{
	unsigned char mode_supported[7];
	unsigned char scanlines_supported; // bits [0-2] specify if [200, 350, 400] scanlines supported
	unsigned char num_char_blocks;
	unsigned char max_char_blocks;
	unsigned int misc_function_support;
	unsigned int reserved;
	unsigned char save_ptr_flags;
	unsigned char reserved2;
};

struct vga_state_info
{
	vga_mode_table far *mode_table;
	unsigned char cur_video_mode;
	unsigned int num_columns;
	unsigned int regen_buf_length;
	unsigned int regen_start_addr;
	unsigned int cursor_pos[8];
	unsigned int cursor_type;
	unsigned char active_page;
	unsigned int crtc_port_address;
	unsigned char port_03x8, port_03x9;
	unsigned char num_rows;
	unsigned int bytes_per_char;
	unsigned char dcc_active_display, dcc_alternate_display;
	unsigned int num_colors; // 0 or 1 is mono
	unsigned char num_pages;
	unsigned char num_scanlines; // [0,3] correspond to [200, 350, 400, 480]
	unsigned char reserved[64]; // size of this struct is 64 bytes total, but overcount padding as 64 bytes total to avoid programming errors
};

vga_state_info get_vga_state_info(void);
vga_mode_table far *get_vga_mode_table(void);

// If read_port==-1, read from same port as 'port'. Otherwise,
// write to 'port', and read from read_port.
int port_writable(int port, int bitpattern, int read_port = -1);

int port_register_writable(int port, int idx, int bitpattern);

class scoped_set_video_mode
{
	int prev_mode;
public:
	scoped_set_video_mode(int new_mode) { prev_mode = get_cur_video_mode(); set_video_mode(new_mode); }
	~scoped_set_video_mode() { if (get_cur_video_mode() != prev_mode) set_video_mode(prev_mode); }
};
#define SCOPED_VIDEO_MODE() scoped_set_video_mode scoped_mode(get_cur_video_mode());
#define SCOPED_SET_VIDEO_MODE(mode) scoped_set_video_mode scoped_mode(mode);

class vga_port
{
	int port, reg;
public:
	vga_port(int port, int reg):port(port), reg(reg) {}

	void write(unsigned char val)
	{
		outp_vga(port, reg, val);
	}
	unsigned char read() { return inp_vga(port, reg); }
	int writable(unsigned char mask)
	{
		return port_register_writable(port, reg, mask);
	}
	void clear_bits(unsigned char bitmask)
	{
		outp_vga(port, reg, inp_vga(port, reg) & ~bitmask);
	}
	void set_bits(unsigned char bitmask)
	{
		outp_vga(port, reg, inp_vga(port, reg) | bitmask);
	}
};

class vga_port_save
{
	vga_port &p;
public:
	unsigned char value;
	vga_port_save(vga_port &p):p(p){ value = p.read(); }
	~vga_port_save() { p.write(value); }
};

class port
{
	int read_io_addr, write_io_addr;
public:
	port(int io_addr):read_io_addr(io_addr), write_io_addr(io_addr) {}
	port(int read_io_addr, int write_io_addr):read_io_addr(read_io_addr), write_io_addr(write_io_addr) {}

	void write(unsigned char val)
	{
		outp(write_io_addr, val);
	}
	unsigned char read() { return inp(read_io_addr); }
	int writable(unsigned char mask)
	{
		return port_writable(write_io_addr, mask, read_io_addr);
	}
	void clear_bits(unsigned char bitmask)
	{
		outp(write_io_addr, inp(read_io_addr) & ~bitmask);
	}
	void set_bits(unsigned char bitmask)
	{
		outp(write_io_addr, inp(read_io_addr) | bitmask);
	}
};

class port_save
{
	port &p;
public:
	unsigned char value;
	port_save(port &p):p(p){ value = p.read(); }
	~port_save() { p.write(value); }
};

void view_vga_registers(int (*read_func)(int port, int subreg), int port, const char *title, int detect_rw);
int print_display_combination_code(void);

extern port vga_misc_output;

#endif
