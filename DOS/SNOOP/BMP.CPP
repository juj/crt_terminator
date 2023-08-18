#include "bmp.h"
#include <stdio.h>
#include <alloc.h>
#include <mem.h>
#include <dos.h>

#define MIN(x,y) ((x) < (y) ? (x) : (y))

static int screen_width = 320;

void set_screen_width(int w) { screen_width = w; }

long fread32(void huge *ptr, long size, long n, FILE *stream)
{
	char *buf = (char*)malloc(2048);
	long bytes = size*n;
	long nr = 0;
	while(bytes > 0)
	{
		long read = bytes > 2048 ? 2048 : bytes;
		long numRead = fread(buf, 1, read, stream);
		_fmemcpy(ptr, buf, numRead);
		nr += numRead;
		if (numRead < read)
			break;
		bytes -= read;
		ptr = (unsigned char huge *)ptr + read;
	}
	free(buf);
	return nr;
}

BMP LoadBMP(const char *filename)
{
   FILE *handle = fopen(filename, "rb");
   assert(handle);
   fseek(handle, 0, SEEK_END);
   long size = ftell(handle);
	 assert(size > 0);
	 fseek(handle, 0, SEEK_SET);
	 uint8_t huge *data = (uint8_t huge *)farmalloc(size);
	 assert(data);
	 unsigned short magic = 0;
	 long bytesRead = fread(&magic, 1, 2, handle);
	 assert(bytesRead == 2);
	 assert(magic == 0x4D42/*'BM'*/);
	 bytesRead += fread32(data, 1, size, handle);
	 fclose(handle);
	 assert(bytesRead == size);

	 BMP bmp;
	 bmp.header = (BMPHeader huge*)data;
	 assert(bmp.header->size <= (uint32_t)size);
	 assert(bmp.header->structSize == 40);
	 assert((int32_t)bmp.header->width > 0);
	 assert((int32_t)bmp.header->height > 0);
	 assert(bmp.header->numColorPlanes == 1);
	 assert(bmp.header->bitsPerPixel <= 32);
	 assert(bmp.header->compressionType == 0/*BI_RGB*/);
	 if (bmp.header->bitsPerPixel <= 8)
	 {
			assert(bmp.header->numColors <= 1 << bmp.header->bitsPerPixel);
			if (bmp.header->numColors == 0) bmp.header->numColors = 1 << bmp.header->bitsPerPixel;
	 }
	 bmp.palette = (uint8_t huge*)(data + sizeof(BMPHeader));
	 bmp.pixels = (uint8_t huge*)(data + (bmp.header->offset - 2));
	 uint32_t paletteByteSize = (uint8_t huge*)bmp.pixels - bmp.palette;
	 assert(paletteByteSize == 4*bmp.header->numColors);
	 uint32_t numBytes = (uint32_t)(data + size - 2 - (uint8_t huge*)bmp.pixels);
	 bmp.width = bmp.header->width;
	 bmp.height = bmp.header->height;
	 assert(numBytes == bmp.width*bmp.height*(bmp.header->bitsPerPixel/8));
	 return bmp;
}

void FreeBMP(BMP *bmp)
{
	 farfree((unsigned char huge *)bmp->header - 2);
}

void draw_bitmap_unchained(BMP *bmp)
{
	unsigned short copyWidth = MIN(screen_width, bmp->width) >> 2;

	for(int plane = 0; plane < 4; ++plane)
	{
		unsigned char far *screen = (unsigned char far *)MK_FP(0xA000, 0);
		outpw(0x3C4, (0x100 << plane) | 0x02);
		for(int j = 0; j < bmp->height; ++j)
		{
			unsigned char huge *bitmap = bmp->pixels + (bmp->height-1-j)*bmp->width + plane;
			for(int x = 0; x < copyWidth; ++x)
				screen[x] = bitmap[x<<2];
			screen += screen_width>>2;
		}
	}
}

void blit_bitmap_unchained(BMP *bmp, int sx, int sy, int w, int h, int dx, int dy)
{
	const unsigned short copyWidth = w >> 2;

	for(int plane = 0; plane < 4; ++plane)
	{
		unsigned char far *screen = (unsigned char far *)
			MK_FP(0xA000, dy*(screen_width>>2)+(dx>>2));
		outpw(0x3C4, (0x100 << plane) | 0x02);
		for(int j = sy; j < sy+h; ++j)
		{
			unsigned char huge *bitmap = bmp->pixels +
				(bmp->height-1-j)*bmp->width + sx + plane;
			for(int x = 0; x < copyWidth; ++x)
				screen[x] = bitmap[x<<2];
			screen += screen_width>>2;
		}
	}
}

void draw_bitmap_chained(BMP *bmp)
{
	unsigned char far *screen = (unsigned char far *)MK_FP(0xA000, 0);
	unsigned short copyWidth = MIN(screen_width, bmp->width) >> 2;
	for(int y = 0; y < bmp->height; ++y)
	{
		unsigned char huge *bitmap = bmp->pixels + (bmp->height-1-y)*bmp->width;
		_fmemcpy(screen, bitmap, copyWidth);
		screen += screen_width;
	}
}

void blit_bitmap_chained(BMP *bmp, int sx, int sy, int w, int h, int dx, int dy)
{
	unsigned char far *screen = (unsigned char far *)
		MK_FP(0xA000, dy*screen_width+dx);
	unsigned long copyWidth = w;
	for(int y = sy; y < sy+h; ++y)
	{
		unsigned char huge *bitmap = bmp->pixels + (bmp->height-1-y)*bmp->width + sx;
		_fmemcpy(screen, bitmap, copyWidth);
		screen += screen_width;
	}
}

/*
void blit_bitmap(BMP *bmp, int sx, int sy, int w, int h, int dx, int dy)
{
	if (current_mode_is_unchained) blit_bitmap_unchained(bmp, sx, sy, w, h, dx, dy);
	else blit_bitmap_chained(bmp, sx, sy, w, h, dx, dy);
}
*/
static void draw_bmp(BMP *bmp, int chained)
{
	if (!chained) draw_bitmap_unchained(bmp);
	else draw_bitmap_chained(bmp);
}

void set_palette(BMP *bmp)
{
	outp(0x3C8, 0);
	for(int i = 0; i < 256; ++i)
	{
		outp(0x3C9, bmp->palette[(i<<2)+2]>>2);
		outp(0x3C9, bmp->palette[(i<<2)+1]>>2);
		outp(0x3C9, bmp->palette[(i<<2)+0]>>2);
	}
}

void display_image_from_disk(const char *filename, int chained)
{
	BMP bmp = LoadBMP(filename);
	set_palette(&bmp);
	draw_bmp(&bmp, chained);
	FreeBMP(&bmp);
}
