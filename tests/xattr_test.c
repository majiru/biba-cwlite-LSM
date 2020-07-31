#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/xattr.h>
#include <assert.h>

int
cwlite_open(void)
{
	return open("/sys/kernel/debug/cwl/cwlite", O_RDWR);
}

int
cwlite_on(int fd)
{
	char on = '1';
	return (write(fd, &on, 1) == 1);
}

int
cwlite_off(int fd)
{
	char off = '0';
	return (write(fd, &off, 1) == 1);
}

int
cwlite_close(int fd)
{
	cwlite_off(fd);
	return close(fd);
}

#define LIMIT 20

int main( int argc, char *argv[] )
{
	int cwl_fd, fd;
	int ret;
	char buf1[LIMIT], buf2[LIMIT], attrbuf[LIMIT];
	char attr[] = "trusted";
	char attr2[] = "untrusted";

	assert( argc == 3 );

	cwl_fd = cwlite_open();
	assert( cwl_fd > 0 );


	setxattr( argv[1], "security.sample", attr, sizeof attr - 1, 0);
	setxattr( argv[2], "security.sample", attr2, sizeof attr2 - 1, 0);

	fd = open(argv[1], O_RDONLY);
	if ( fd < 0 ) {
		printf( "user: %s open failed - probably no file\n", argv[1] );
	}
	else {
		ret = getxattr( argv[1], "security.sample", attrbuf, LIMIT );
		if ( ret >  0 ) {
			attrbuf[ret] = 0;
			printf( "user: %s attribute %s\n", argv[1], attrbuf );
		}
		else {
			printf( "user: %s attribute retrieval problem\n", argv[1] );
		}
	}

	ret = read( fd, buf1, LIMIT );
	buf1[ret] = 0;
	printf("cw OFF & file is trusted:\n");
	printf( "%s\n", buf1 );
	close( fd );

	cwlite_on( cwl_fd );
	fd = open(argv[2], O_RDONLY);
	cwlite_off( cwl_fd );

	if ( fd < 0 ) {
		printf( "user: %s open failed - probably no file\n", argv[2] );
	}
	else {
		ret = getxattr( argv[2], "security.sample", attrbuf, LIMIT );
		if ( ret >  0 ) {
			attrbuf[ret] = 0;
			printf( "user: %s attribute %s\n", argv[2], attrbuf );
		}
		else {
			printf( "user: %s attribute retrieval problem\n", argv[2] );
		}
	}

	cwlite_on( cwl_fd );
	printf("cw ON & file is UNTRUSTED:\n");
	ret = read( fd, buf2, LIMIT );
	cwlite_off( cwl_fd );
	printf( "%s\n", buf2 );

	close(fd);
	fd = open(argv[2], O_RDONLY);

	printf("cw OFF & file in UNTRUSTED:\n");
	ret = read( fd, buf2, LIMIT );
	printf( "%s\n", buf2 );

	close( fd );
	cwlite_close( cwl_fd );

	return 0;
}
