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
void outp_3c4(int idx, int value);
void outp_3d4(int idx, int value);
void outp_3ce(int idx, int value);
void outp_3c0(int idx, int value);

void set_video_mode(int mode);
int get_cur_video_mode();
void random_fill_vga_memory(int is_gfx_mode);

int port_writable(int port, int bitpattern);
int port_register_writable(int port, int idx, int bitpattern);

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
	int io_addr;
public:
	port(int io_addr):io_addr(io_addr) {}

	void write(unsigned char val)
	{
		outp(io_addr, val);
	}
	unsigned char read() { return inp(io_addr); }
	int writable(unsigned char mask)
	{
		return port_writable(io_addr, mask);
	}
	void clear_bits(unsigned char bitmask)
	{
		outp(io_addr, inp(io_addr) & ~bitmask);
	}
	void set_bits(unsigned char bitmask)
	{
		outp(io_addr, inp(io_addr) | bitmask);
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

#endif
