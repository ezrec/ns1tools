#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <math.h>
#include <ctype.h>
#include <inttypes.h>

#include "ns1.h"

#define NS1_MAGIC 0x5374654e

#ifdef DEBUG
#define DPRINT(fmt, x...) fprintf(stdout,"%.4x: " fmt , (int)lseek(fd,0,SEEK_CUR) , ## x )
#else
#define DPRINT(fmt, x...) do { } while(0)
#endif

#ifndef HAVE_LLABS
static inline int64_t llabs(int64_t v)
{
	if (v < 0)
		return -v;
	return v;
}
#endif

#define CREAD(type, fd, out) \
	do { int cread_err=read_##type(fd, (void *)out); \
	  if (cread_err < 0) return cread_err; } while (0)

static int read_le32(int fd,uint32_t *out)
{
	uint32_t tmp=0;
	uint8_t byte;
	int i,err;

	for (i = 0; i < 4; i++) {
		err=read(fd,&byte,1);
		if (err <= 0)
			return err;
		tmp |= (byte << (i * 8));
	}

	*out=tmp;
DPRINT("\tuint32 0x%.8x (%d)\n",tmp,tmp);
	return 4;
}

static int read_le64(int fd,uint64_t *out)
{
	uint64_t tmp=0;
	uint8_t byte;
	int i,err;

	for (i = 0; i < 8; i++) {
		err=read(fd,&byte,1);
		if (err <= 0)
			return err;
		tmp |= ((uint64_t)byte << (i * 8));
	}

	*out=tmp;
DPRINT("\tuint64 0x%.16llx (%.lld)\n",tmp,tmp);
	return 8;
}

static int read_double(int fd,double *out)
{
	double d;
	int err;

	err=read(fd,&d,sizeof(d));
	*out=d;
DPRINT("\tieee64 %f\n",d);
	return err;
}

static int read_string(int fd,char buff[256])
{
	int err;
	uint8_t len;

	err=read(fd,&len,1);
	if (err <= 0)
		return err;

	if (len > 0) {
		err=read(fd,buff,len);
		if (err <= 0)
			return err;
	}

	buff[len]=0;
DPRINT("Read string: %d \"%s\"\n",len,buff);
	return len+1;
}

static int read_mac(int fd,uint8_t mac[6])
{
	int err;

	err=read(fd,mac,6);
DPRINT("\tmac ad %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n",
		mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);

	return err;
}

static int ns1_read_apdata(int fd, int version, struct apdata_s *packet)
{
	CREAD(le64,fd,&packet->timestamp);
	CREAD(le32,fd,&packet->signal);
	CREAD(le32,fd,&packet->noise);
	CREAD(le32,fd,&packet->location_source);
	if (packet->location_source) {
		CREAD(double,fd, &packet->latitude);
		CREAD(double,fd, &packet->longitude);
		CREAD(double,fd, &packet->altitude);
		if (packet->altitude < -1000.0)
			packet->altitude=0.0;
	
		CREAD(le32,fd, &packet->gps.sats);
	
		CREAD(double,fd, &packet->gps.speed);
		CREAD(double,fd, &packet->gps.track);
		CREAD(double,fd, &packet->gps.mag_variation);
		CREAD(double,fd, &packet->gps.hdop);
	}

	return 0;
}

static int ns1_read_apinfo(int fd, int version, struct apinfo_s *packet)
{
	int err,i;
	uint32_t dummy;

	CREAD(string,fd, packet->ssid);
	CREAD(mac,fd, packet->bssid);
	CREAD(le32,fd, &packet->signal.max);
	CREAD(le32,fd, &packet->noise.min);
	CREAD(le32,fd, &packet->max_snr);
	if (version == 1) {
		CREAD(le32, fd, &dummy);
	} else if (version == 6) {
		CREAD(le32,fd, &dummy);
		packet->channel_mask = dummy;
	}

	CREAD(le32,fd, &packet->flags);
	CREAD(le32,fd, &packet->beacon_interval);

	if (version == 1)
		return 0;

	CREAD(le64,fd, &packet->first_timestamp);
	CREAD(le64,fd, &packet->last_timestamp);
	CREAD(double,fd, &packet->latitude);
	CREAD(double,fd, &packet->longitude);
	CREAD(le32,fd, &packet->apdata_count);
	packet->apdata = calloc(packet->apdata_count,sizeof(struct apdata_s));
	for (i = 0; i < packet->apdata_count; i++) {
		err=ns1_read_apdata(fd, version, &packet->apdata[i]);
		if (err < 0) return err;
	}
	CREAD(string, fd, packet->name);

	if (version == 6)
		return 0;

	CREAD(le64,fd,&packet->channel_mask);
	CREAD(le32,fd,&dummy);	/* Last reported channel */
	CREAD(le32,fd,&packet->ip_addr);

	if (version == 8)
		return 0;

	CREAD(le32,fd,&packet->signal.min);
	CREAD(le32,fd,&packet->noise.max);
	CREAD(le32,fd,&packet->data_rate);
	CREAD(le32,fd,&packet->ip_network);
	CREAD(le32,fd,&packet->ip_netmask);

	if (version == 11)
		return 0;

	CREAD(le32,fd,&packet->misc_flags);
	CREAD(le32,fd,&dummy);	/* IE length */
	lseek(fd,dummy,SEEK_CUR);

	return 0;
}

struct ns1_file_s *ns1_open_fd(int fd)
{
	struct ns1_file_s *ns1;
	int i,err;

	ns1=calloc(sizeof(struct ns1_file_s),1);

	read_le32(fd,&ns1->signature);
	if (ns1->signature != NS1_MAGIC) {
		fprintf(stderr,"fd %d: Not a NetStumber .ns1 file\n",fd);
		free(ns1);
		return NULL;
	}

	err=read_le32(fd, &ns1->version);
	if (err <= 0) {
		free(ns1);
		return NULL;
	}

	if (ns1->version > 12) {
		fprintf(stderr,"NetStumber version %d files not (yet) supported\n",ns1->version);
		free(ns1);
		return NULL;
	}

	err=read_le32(fd,(void *)&ns1->apinfo_count);
	if (err <= 0) {
		ns1->apinfo_count=0;
		return ns1;
	}

	ns1->apinfo=calloc(ns1->apinfo_count,sizeof(struct apinfo_s));
	for (i=0; i < ns1->apinfo_count; i++) {
		err=ns1_read_apinfo(fd, ns1->version, &ns1->apinfo[i]);
		if (err < 0) {
			fprintf(stderr, "Error reading record %d: %s\n", i, strerror(err));
			free(ns1->apinfo);
			free(ns1);
			return NULL;
		}
	}

	return ns1;
}

void ns1_close(struct ns1_file_s *ns1)
{
	int i;

	for (i=0; i < ns1->apinfo_count; i++) {
		struct apinfo_s *info = &ns1->apinfo[i];

		if (info->apdata_count > 0)
			free(info->apdata);
	}
	free(ns1->apinfo);
	free(ns1);
}

