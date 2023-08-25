#include "vesaxga.h"
#include "log.h"
#include "debug.h"
#include "text.h"
#include <dos.h>
#include <stdio.h>

struct VesaXga
{
	unsigned char signature[4]; // "VESA"
	unsigned int version;
	char far *oem;
	unsigned long env_flags;
	unsigned int num_adapters;
	unsigned char reserved[240];
};

VesaXga xga;

int xga_get_feature_connector_state()
{
	REGS r;
	r.x.ax = 0x4E06;
	r.x.dx = 0;
	int86(0x10, &r, &r);
	if (r.x.ax == 0x004E) return r.x.bx;
	return 0;
}

void xga_set_feature_connector_state(int enabled, int is_output)
{
	REGS r;
	r.x.ax = 0x4E05;
	r.x.bx = enabled | (is_output << 1);
	r.x.dx = 0;
	int86(0x10, &r, &r);
	if (r.x.ax != 0x004E) log("XGA set feature connector state failed!");
	else log("XGA feature connector is now in output mode!");
}

void print_field(int pad_length, const char *field_name, char far *value, int nl);

int detect_vesa_xga()
{
	DEBUG("XGA", "Detects whether adapter supports the XGA graphics BIOS interface.");
	REGS r;
	SREGS s;
	r.x.ax = 0x4E00;
	r.x.di = FP_OFF(&xga);
	s.es = FP_SEG(&xga);
	int86x(0x10, &r, &r, &s);
	if (r.x.ax == 0x004E)
	{
		const char *bus[4] = { "MCA", "ISA", "EISA", "?" };
		Log << "VESA XGA: Is supported on bus: " << bus[xga.env_flags&0x03];
		if ((xga.env_flags&4)) Log << ", bus mastering.\n";
		else Log << ", not bus mastering.\n";
		Log << "Flags: " << hex(xga.env_flags) << "\n";
		Log << "# of XGA adapters: " << xga.num_adapters << "\n";
		Log << "XGA OEM: " << xga.oem << "\n";
//		print_field(10, "XGA OEM", xga.oem, 1);
		int state = xga_get_feature_connector_state();
		if (!(state & 1)) Log << "XGA: Feature connector disabled.\n";
		else Log << "XGA: Feature connector enabled as " << ((state & 2) ? "output" : "input") << "\n";
		if ((state & 3) != 3)
		{
			xga_set_feature_connector_state(1, 1);
			if ((xga_get_feature_connector_state() & 3) == 3)
				Printf("Successfully enabled XGA feature connector as output.\n");
			else
				Printf("Failed to enable XGA feature connector as output!\n");
		}
		return 1;
	}
	Log << "Not detected.\n";
	return 0;
}


