#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#define  SAMPLE_MNT  "/sys/kernel/debug/cwl"
#define  SAMPLE_FILE SAMPLE_MNT"/cwlite"


void
opencwl(int *fd)
{
	*fd = open(SAMPLE_FILE, O_RDWR);
	if(*fd < 0){
		fprintf(stderr, "could not open\n");
		exit(1);
	}
}

void
main(int argc, char **argv)
{
	int fd;
	char buf[1];
	opencwl(&fd);
	if(write(fd, "1", 1) != 1){
		fprintf(stderr, "could not write\n");
		exit(2);
	}
	lseek(fd, 0, SEEK_SET);
	if(read(fd, buf, 1) != 1){
		fprintf(stderr, "could not read\n");
		exit(3);
	}
	if(buf[0] != '1'){
		fprintf(stderr, "did not read back the right value\n");
		exit(4);
	}
	if(write(fd, "0", 1) != 1){
		fprintf(stderr, "did not write back 0 properly\n");
		exit(5);
	}
}
