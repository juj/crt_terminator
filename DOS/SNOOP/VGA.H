#ifndef VGA_H
#define VGA_H

int inp_vga(int port, int idx);
int inp_3c4(int idx);
int inp_3d4(int idx);
int vga_read_attr(int sub);
int vga_read_attr_port(int port, int sub); // identical to vga_read_attr(), just passes a dummy port value

void outp_vga(int port, int idx, int value);
void outp_3c4(int idx, int value);
void outp_3d4(int idx, int value);
void vga_write_attr(int sub, int val);

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

void view_vga_registers(int (*read_func)(int port, int subreg), int port, const char *title);

#endif
