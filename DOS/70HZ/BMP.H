#include <assert.h>

typedef unsigned char uint8_t;
typedef unsigned short uint16_t;
typedef unsigned long uint32_t;
typedef long int32_t;

struct BMPHeader
{
	 // Bitmap file header:
//	 uint16_t type;
	 uint32_t size, reserved, offset;
	 // DIB header (Bitmap information header):
	 uint32_t structSize, width, height;
	 uint16_t numColorPlanes, bitsPerPixel;
	 uint32_t compressionType, imageSize, xPixelsPerMeter, yPixelsPerMeter, numColors, numImportantColors;
};

struct BMP
{
	 BMPHeader huge *header;
	 uint8_t huge *palette;
	 uint8_t huge *pixels;
	 uint32_t width, height;
};

BMP LoadBMP(const char *filename);
void FreeBMP(BMP *bmp);

void blit_bitmap(BMP *bmp, int sx, int sy, int w, int h, int dx, int dy);
void draw_bmp(BMP *bmp);
void set_palette(BMP *bmp);
void display_image_from_disk(const char *filename);
