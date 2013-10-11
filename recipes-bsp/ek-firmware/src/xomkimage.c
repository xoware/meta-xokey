#define _GNU_SOURCE 
#define _BSD_SOURCE
 
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <netinet/in.h>
#include <termios.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <string.h>
#include <malloc.h>
#include <endian.h>
#include <string.h>

#include "xomkimage.h"
#include "md5.h"


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
#define PROG_NAME "xomkimage"

#define DBG(FMT,ARG...) \
	fprintf(stderr, PROG_NAME ":%s:%d: " FMT, __FUNCTION__, __LINE__, ##ARG); \

#define ERROR(FMT,ARG...) \
	fprintf(stderr, PROG_NAME ":%s:%d: ERROR: " FMT, __FUNCTION__, __LINE__, ##ARG); \
	
const char *PartTypeStr[] = {
	"invalid",
	"mtd",
	"ubivol",
	"raw",
	"last",
	NULL
};


static void
fatal(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	fprintf(stderr, "Fatal: ");
	vfprintf(stderr, fmt, ap);
	va_end(ap);

	exit(EXIT_FAILURE);
}

static void
usage(const char *s)
{
	fprintf(stderr, "Usage: %s file1:type1:n1:offset:name [file2:type2:n2:offset:name ...] > output.img\n", s);
	fprintf(stderr, "where: \n");
	fprintf(stderr, "\tfile# is a relative path to a binary image\n");
	fprintf(stderr, "\ttype# is partition type (mtd,ubivol) \n");
	fprintf(stderr, "\tn# is the partition number, or UBI partition (usually 0  for /dev/ubi0) \n");
	fprintf(stderr, "\tofsset.   Always set to zero unless raw image \n");
	fprintf(stderr, "The output file will be printed to stdout\n");
	exit(EXIT_FAILURE);
}
enum PartType PartType_fromAscii(const char *str)
{
	enum PartType ptype = PartType_invalid;
	int i;
	
	for (i = 0; PartTypeStr[i] ; i++) {
		if (strcasestr(str, PartTypeStr[i])) {
			ptype = i;
			return ptype;
		}
	}
	fatal("Invalid type=%s\n", str);
	return PartType_invalid; //will not return but silence warning
}


static void
process_arg(const char *__arg, void ***__fmaps, struct ImageHeader **__images, struct GlobalHdr *hdr)
{
	char *arg = strdup(__arg);
	void **fmaps = *__fmaps;
	struct ImageHeader *images = *__images;
	struct stat st;
	int fd;
	void *fmap;
	char *stringp = arg;
	char *token, *file_name = NULL, *type_str = NULL, *partnum_str = NULL, *offset_str = NULL, *name = NULL;
	int i;
	enum PartType ptype;
	
	if (arg == NULL)
		fatal("Not enough memory\n");
	
	
	for (i = 0; i < 5 ; i++) {
		token = strsep(&stringp, ":");
		if (token == NULL && (i < 5)) {
			ERROR(" too few paramaters see ussage\n");
			usage(PROG_NAME);
		}
		switch (i)
		{
			case 0:
				file_name = token;
			break;
			case 1:
				type_str = token;
			break;
			case 2:
				partnum_str = token;
			break;
			case 3:
				offset_str = token;
				if (atoi(offset_str)) {
					fatal("offset other than 0 not supported yet");
				}
			break;
			case 4:
				name = token;
				break;
			default:
				fatal(" Invalid usage token=%s\n", token);
				break;
				
		}
	}
	
	DBG("file: %s\n", file_name);
	ptype = PartType_fromAscii(type_str);
	DBG("type: %s=%d\n", type_str,ptype);
	DBG("partnum: %s\n", partnum_str);
	DBG("offset: %s\n", offset_str);
	DBG("name: %s\n", name);
	if (strlen(name) > 14) {
		fatal("name too long:%s\n",name);
	}
	
	if ((fd = open(file_name, O_RDONLY)) < 0)
		fatal("Could not open file %s: %s\n", file_name, strerror(errno));
	
	DBG("file: %s\n", file_name);

	if (fstat(fd, &st) < 0)
		fatal("Count not stat file %s: %s\n", file_name, strerror(errno));

	fmap = mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
	close(fd);

	if (fmap == MAP_FAILED)
		fatal("Count not mmap file %s: %s\n", file_name, strerror(errno));

	hdr->raw_size = htole32(le32toh(hdr->raw_size) + st.st_size); // increment size in global header
	hdr->nimages = htole32(le32toh(hdr->nimages) + 1);
	fmaps = realloc(fmaps, sizeof(void *) * le32toh(hdr->nimages));  // alloc space for pointers to firmware mmaped files

	// realloc space for additional image header
	images = realloc(images, sizeof(struct ImageHeader) * le32toh(hdr->nimages));

	if (fmaps == NULL || images == NULL)
		fatal("Not enough memory\n");

	fmaps[le32toh(hdr->nimages) - 1] = fmap;
	memset(&images[le32toh(hdr->nimages) - 1], 0, sizeof(struct ImageHeader)); // init
	images[le32toh(hdr->nimages) - 1].size = htole32(st.st_size);
	images[le32toh(hdr->nimages) - 1].part_type = htole32(ptype);
	images[le32toh(hdr->nimages) - 1].partition = htole32(strtoul(partnum_str, NULL, 10));
	images[le32toh(hdr->nimages) - 1].offset = htole32(0);
	strcpy(images[le32toh(hdr->nimages) - 1].name, name);
	
	DBG("size: %d = 0x%x\n", (int) st.st_size, (int) st.st_size);
	
	*__images = images;
	*__fmaps = fmaps;
	free(arg);
}
		
int
main(int argc, char *argv[])
{
	void **fmaps = NULL;
	struct GlobalHdr hdr;
	struct ImageHeader *images = NULL;
	struct termios tios;
	int i;
	MD5_CTX ctx;
	
	if (argc < 2)
		usage(argv[0]);

	if (tcgetattr(1, &tios) == 0)
		fatal("Won't write binary data to a terminal\n");

	hdr.hdr_version = htole32(XO_CURRENT_HDR_VERSION);
	hdr.nimages = 0;
	hdr.raw_size = 0;
	for (i = 1; i < argc; i++) {
		if (strchr(argv[i], ':') == NULL)
			usage(argv[0]);

		process_arg(argv[i], &fmaps, &images, &hdr);
	}

	MD5Init(&ctx);
	for (i = 0; i < le32toh(hdr.nimages); i++)  
		MD5Update(&ctx, fmaps[i], le32toh(images[i].size));
	MD5Final(&hdr.digest, &ctx);

	write(1, &hdr, sizeof(hdr));
	write(1, images, sizeof(struct ImageHeader) * le32toh(hdr.nimages));
	for (i = 0; i < le32toh(hdr.nimages); i++) {
		write(1, fmaps[i], le32toh(images[i].size));
		munmap(fmaps[i], le32toh(images[i].size));
	}

	free(fmaps);
	free(images);

	exit(EXIT_SUCCESS);
}

/* EOF */
