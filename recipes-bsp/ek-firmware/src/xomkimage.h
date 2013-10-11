#ifndef XO_MK_IMAGE_H
#define XO_MK_IMAGE_H 1

#define XO_CURRENT_HDR_VERSION 0

/*
 * The format of the file downloaded is as follows:
 *
 *   GLOBAL HEADER
 *   IMAGE HEADER #1
 *   IMAGE HEADER #2
 *   ...
 *   IMAGE HEADER #n
 *   RAW DATA
 *
 *  where raw data is the concatenation of all images.
 */

struct GlobalHdr
{
	uint32_t hdr_version;  /* header version       */
	uint32_t nimages;      /* Number of images     */
	uint32_t raw_size;     /* length of raw data combining all images  */
	uint8_t digest[16];    /* md5sum over raw data */
};


enum PartType {
	PartType_invalid = 0, // unset
	PartType_MtdPart = 1,  // MTD partition
	PartType_ubiVolume = 2, // Ubi volume
	PartType_raw = 3,  // raw image with offset used from 0 of Flash device
	
	PartType_last  // Last /invalid
};

struct ImageHeader
{
	enum PartType part_type;
	int32_t partition;    // MTD partition number or  UBI partition
	uint32_t size;         /* Length of image data */
	uint32_t offset;  // Offset to start writing.  NOTE not used now, possible future use
	char name[16];    // UBI volume name  or MTD partition name
};

#endif
/* EOF */

