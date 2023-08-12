#include "vesaxga.h"
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
	if (r.x.ax != 0x004E)
		printf("XGA set feature connector state failed!\n");
	else
		printf("XGA feature connector is now in output mode!\n");
}

void print_field(int pad_length, const char *field_name, char far *value, int nl);

void detect_vesa_xga()
{
	REGS r;
	SREGS s;
	r.x.ax = 0x4E00;
	r.x.di = FP_OFF(&xga);
	s.es = FP_SEG(&xga);
	int86x(0x10, &r, &r, &s);
	if (r.x.ax == 0x004E)
	{
		const char *bus[4] = { "MCA", "ISA", "EISA", "?" };
		printf("VESA XGA: Supported on bus: %s. ", bus[xga.env_flags&0x03]);
		if ((xga.env_flags&4)) printf("Bus mastering.\n");
		else printf("No bus mastering.\n");
		/*
		printf("Flags: %08lXh. # of XGA adapters: %d\n",
			bus[xga.env_flags&0x03], ?1:0,
			xga.env_flags, xga.num_adapters);
		*/
		print_field(10, "XGA OEM", xga.oem, 1);
		int state = xga_get_feature_connector_state();
		if (!(state & 1)) printf("XGA: Feature connector disabled.\n");
		else printf("XGA: Feature connector enabled as %s.\n", (state & 2) ? "output" : "input");
		if ((state & 3) != 3)
		{
			xga_set_feature_connector_state(1, 1);
			if ((xga_get_feature_connector_state() & 3) == 3)
				printf("Successfully enabled feature connector as output.\n");
			else
				printf("Failed to enable feature connector as output!\n");
		}
	}
	/*
	else
		printf("VESA XGA not detected.\n");
	*/
}


