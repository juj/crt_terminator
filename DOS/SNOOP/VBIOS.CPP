#include "vbios.h"
#include "vec.h"

#include <dos.h>
#include <ctype.h>
#include <conio.h>
#include <stdio.h>
#include <string.h>

long get_video_bios_size()
{
	unsigned char far *ptr = (unsigned char far *)MK_FP(0xC000, 0);
	if (ptr[0] != 0x55 || ptr[1] != 0xAA) return -1; // Not an option ROM space
	return (unsigned long)ptr[2] * 512;
}

unsigned long crc32(unsigned char huge *ptr, long len)
{
	unsigned long crc = 0xFFFFFFFFul;
	for(long i = 0; i < len; ++i)
	{
		crc ^= ptr[i];
		for(int j = 0; j < 8; ++j)
			crc = (crc >> 1) ^ (0xEDB88320ul & (-(crc & 1)));
	}
	return ~crc;
}

unsigned long calculate_video_bios_crc32()
{
	unsigned char huge *ptr = (unsigned char huge *)MK_FP(0xC000, 0);
	return crc32(ptr, get_video_bios_size());
}

void advancex(int x)
{
	if (wherex() >= x) return;
	int n = x - wherex();
	for(int i = 0; i < n; ++i) printf(" ");
}

static int is_vowel(char ch)
{
	switch(tolower(ch))
	{ case 'a': case 'e': case 'i': case 'o': case 'u': case 'y': return 1; }
	return 0;
}

static int count_vowels(const vec<unsigned char> &alphas)
{
	int vowels = 0;
	for(int i = 0; i < alphas.size(); ++i)
		if (is_vowel(alphas[i])) ++vowels;
	return vowels;
}

static int longest_run_of_consonants(const huge char *str, int len)
{
	int max_count = 0;
	int count = 0;
	for(int i = 0; i < len; ++i)
	{
		if (str[i] == ' ' || is_vowel(str[i])) count = 0;
		else if (isalpha(str[i]) && ++count > max_count) max_count = count;
	}
	return max_count;
}

static vec<unsigned long> seen_strings;

static void print_strings(unsigned long addr, unsigned long size)
{
	unsigned char huge *ptr = (unsigned char huge*)MK_FP((unsigned int)(addr>>4), 0);
	for(unsigned long i = 0; i < size; ++i)
	{
//		if (ptr[i] <= 0x20 || ptr[i] >= 0x75) continue;
		if (!isalpha(ptr[i]) && ptr[i] != '(' && ptr[i] != '*') continue;
		// This char starts a potential string, find how far it stretches to
		int special = 0; // allow one special char in string in a row
		vec<unsigned char> alphas;
		for(unsigned long j = i+1; j < size && ptr[j]; ++j)
		{
			if ((ptr[j] >= 'a' && ptr[j] <= 'z') || (ptr[j] >= 'A' && ptr[j] <= 'Z'))
				if (alphas.find(ptr[j]) < 0) alphas.push(ptr[j]);
			if (ptr[j] == '\t' || ptr[j] == '\n' || (ptr[j] >= 0x20 && ptr[j] < 0x7F))
				special = 0;
			else if (ptr[j] < 0x20 || special) break; // cannot have two specials in row
			special = 1;
		}
		if (j - i >= 4)
		if (/*ptr[j] == 0 &&*/ alphas.size() >= 3 && count_vowels(alphas) > 0)
		if (longest_run_of_consonants(&ptr[i], j-i) < 5)
		{
			unsigned long crc = crc32(ptr+i, j-i);
			if (seen_strings.find(crc) < 0)
			{
				seen_strings.push(crc); // Don't print duplicate strings
				textcolor(BROWN);
				cprintf("%04lX:%04lXh", addr>>4, i);
				textcolor(LIGHTGRAY);
				cprintf(": ");
				textcolor(CYAN);
				while(i < j) cprintf("%c", ptr[i++]);
				textcolor(LIGHTGRAY);
				cprintf("\r\n");
			}
			i = j;
		}
	}
}

void print_rom_strings()
{
	printf("\nROM strings:\n");
	unsigned long addr = 0xC0000u;
	while(addr < 0x100000ul)
	{
		unsigned char far *ptr = (unsigned char far*)MK_FP((unsigned int)(addr>>4), 0);
		if (ptr[0] == 0x55 && ptr[1] == 0xAA)
		{
			unsigned long size = (unsigned long)ptr[2] * 512;
			print_strings(addr, size);
			addr += (size + 2047) & ~2047ul;
		}
		else
			addr += 2048;
	}
}

void print_video_bios_info()
{
	long video_bios_size = get_video_bios_size();
	textcolor(LIGHTGRAY);
	cprintf("      Video BIOS: ");
	textcolor(LIGHTCYAN);
	if (video_bios_size < 0) cprintf("Unknown\r\n");
	else
	{
		cprintf("C0000h-%05lXh ",
			0xC0000ul + video_bios_size - 1);
		if (video_bios_size % 1024 == 0) cprintf("(%lu KB)", video_bios_size / 1024);
		else cprintf("(%lu B)", video_bios_size);

		textcolor(LIGHTGRAY);
		advancex(RIGHT_COLUMN - strlen("VBIOS CRC32"));
		cprintf("VBIOS CRC32: ");
		textcolor(LIGHTCYAN);
		cprintf("%08lXh\r\n", calculate_video_bios_crc32());
		textcolor(LIGHTGRAY);
	}
	textcolor(LIGHTGRAY);

	unsigned long addr = (0xC0000u + video_bios_size + 2047) & ~2047ul;
	int found_roms = 0;
	while(addr < 0x100000ul)
	{
		unsigned char far *ptr = (unsigned char far*)MK_FP((unsigned int)(addr>>4), 0);
		if (ptr[0] == 0x55 && ptr[1] == 0xAA)
		{
			unsigned long size = (unsigned long)ptr[2] * 512;
			if (!found_roms) cprintf("     Option ROMs: ");
			textcolor(CYAN);
			found_roms = 1;
			cprintf("%05lXh-%05lXh ", addr, addr + size - 1);
			if (size % 1024 == 0) cprintf("(%lu KB) ", size / 1024);
			else cprintf("(%lu B) ", size);
			addr += (size + 2047) & ~2047ul;
		}
		else
			addr += 2048;
	}
	textcolor(LIGHTGRAY);
	if (found_roms) cprintf("\r\n");
//	print_vga_state_info();
}

int far_strncmp(const char far *s1, const char *s2, int n)
{
	for(int i = 0; i < n; ++i)
		if (s1[i] != s2[i]) return 0;
	return 1;
}

int find_vbios_string(const char *string)
{
	int len = strlen(string);
	long end = get_video_bios_size() - len;
	char far *vbios = (char far *)MK_FP(0xC000, 0);
	for(long i = 0; i < end; ++i)
		if (far_strncmp(vbios+i, string, len)) return 1;
	return 0;
}
