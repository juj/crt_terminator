#include <dos.h>
#include <stdio.h>
#include <stdlib.h>
#include <conio.h>
#include <ctype.h>
#include <string.h>
#include <process.h>
#include "crtt.h"
#include "pci.h"

int quiet = 0;

int parse_value(const char *str)
{
	if (!strcmpi(str, "on") || !strcmpi(str, "1") || !strcmpi(str, "true")) return 1;
	if (!strcmpi(str, "off") || !strcmpi(str, "0") || !strcmpi(str, "false")) return 0;
	if (!strcmpi(str, "toggle") || !strcmpi(str, "2")) return 2;
	fprintf(stderr, "Failed to parse command value \"%s\"! (Please specify one of \"on\", \"off\" or \"toggle\").");
	exit(2);
	return 0;
}

void help(char *argv0)
{
	printf("CRT Terminator configuration utility. %s %s\n", __DATE__, __TIME__);
	printf("Usage: %s --cmd1=param1 [--cmd2=param2] ...\n", argv0);
	printf("\nwhere command is one of:\n\n");
	printf("  --6bpp=<on|off|toggle>: If on, CRT Terminator snoops the 6bpp VGA RAMDAC\n");
	printf("                          palette reads. If off, palette updates are ignored.\n");
	printf("                          Set this OFF if developing code that directly feeds\n");
	printf("                          CRT Terminator with 8bpp palette data in port 0x124.\n");
	printf("  --vsync=<on|off|toggle>: If on, video upscaling will be triple-buffered to\n");
	printf("                           implement vertical retrace synchronization\n");
	printf("                           without tearing. If off, video upscaling will be\n");
	printf("                           single-buffered and video will tear.\n");
	printf("                           If output is in passthrough mode, this state will\n");
	printf("                           have no effect.\n");
	printf("  --border=<on|off|toggle>: If on, the CGA/EGA/VGA border will be preserved.\n");
	printf("                            If off, the border will be cropped away. Note\n");
	printf("                            that enabling border will prevent pixel-perfect\n");
	printf("                            integer upscaling from 320x200, 320x240 and\n");
	printf("                            800x600 modes up to 1600x1200.\n");
	printf("  --snoop=<on|off>: Enables or disables PCI VGA palette snoop.\n");
	printf("  --quiet: Performs given operations without any printing.\n");
}

unsigned char find_option_bit(const char *cmd)
{
	if (!strcmpi(cmd, "6bpp")) return 0x1;
	else if (!strcmpi(cmd, "vsync")) return 0x2;
	else if (!strcmpi(cmd, "border")) return 0x4;

	fprintf(stderr, "Invalid command \"%s\"!\n", cmd);
	exit(3);
	return 0;
}

void apply_option_bit(unsigned char &options, const char *cmd, const char *value)
{
	unsigned char bit = find_option_bit(cmd);
	int val = parse_value(value);
	if (bit == 1 && val != 2) val = 1-val; // Option "6bpp" is reversed, 0-enables, 1-disables
	if (val == 2) options ^= bit;
	else if (val == 1) options |= bit;
	else options &= ~bit;
	if (!quiet) printf("%s: %s\n", cmd, (options & bit) ? "ON" : "OFF");
}

int main(int argc, char **argv)
{
	if (argc <= 1)
	{
		help(argv[0]);
		exit(0);
	}

	// Convert all cmdline args to lowercase (i.e. accept both upper and lower cases)
	for(int i = 1; i < argc; ++i)
		for(int j = 0; argv[i][j]; ++j)
			if (argv[i][j] >= 'A' && argv[i][j] <= 'Z')
				argv[i][j] = tolower(argv[i][j]);

	// Handle the no-arg --quiet param up front.
	for(i = 1; i < argc; ++i)
		if (strstr(argv[i], "quiet")) quiet = 1;

	if (!crtt_detect())
	{
		if (!quiet) printf("CRT Terminator not detected!\n");
		return 1;
	}

	unsigned char options = crtt_options();
	for(i = 1; i < argc; ++i)
	{
		if (!argv[i] || argv[i][0] != '-' || strstr(argv[i], "quiet")) continue;
		char *cmd = argv[i];
		while(*cmd == '-') ++cmd;

		// Detect one-param "--cmd=value" vs two-param "--cmd value" forms.
		char *value = strstr(cmd, "=");
		if (!value) value = strstr(cmd, ":");
		if (value)
		{
			*value = '\0';
			++value;
		}
		else
		{
			if (i+1 >= argc)
			{
				fprintf(stderr, "No parameter value specified for cmd:\"%s\"!\n", argv[i]);
				exit(4);
			}
			value = argv[i+1];
			if (!value || value[0] == '-')
			{
				fprintf(stderr, "Failed to parse parameter cmd:\"%s\" value:\"%s\"\n",
					argv[i], argv[i+1]);
				exit(5);
			}
		}
		if (strstr(cmd, "snoop"))
		{
			pcidev_t vga = find_pci_vga_adapter();
			if (!vga)
			{
				printf("Unable to adjust PCI snoop setting: no PCI VGA adapter was found!\n");
				exit(3);
			}
			if (parse_value(value))
			{
				enable_vga_palette_snoop(vga);
				if (!quiet) printf("PCI VGA palette snoop: ON.\n");
			}
			else
			{
				disable_vga_palette_snoop(vga);
				if (!quiet) printf("PCI VGA palette snoop: OFF.\n");
			}
		}
		else
			apply_option_bit(options, cmd, value);
	}
	crtt_write_options(options);
	return 0;
}
