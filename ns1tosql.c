#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <math.h>
#include <ctype.h>
#include <inttypes.h>

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
	do { int cread_err=read_##type(fd, out); \
	  if (cread_err < 0) return cread_err; } while (0)

int read_le32(int fd,uint32_t *out)
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

int read_le64(int fd,uint64_t *out)
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

int read_double(int fd,double *out)
{
	double d;
	int err;

	err=read(fd,&d,sizeof(d));
	*out=d;
DPRINT("\tieee64 %f\n",d);
	return err;
}

int read_string(int fd,char buff[256])
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

int read_mac(int fd,uint8_t mac[6])
{
	int err;

	err=read(fd,mac,6);
DPRINT("\tmac ad %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n",
		mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
}

const char *progname=NULL;

struct ns1_file_s {
	uint32_t	signature;
	uint32_t	version;
	int		apinfo_count;
	struct apinfo_s *apinfo;
};

struct apinfo_s {
	char ssid[256];
	uint8_t bssid[6];
	char name[256];
	uint32_t flags;
	int32_t beacon_interval;
	struct {
		int32_t	min;
		int32_t	max;
	} signal,noise;
	int64_t	first_timestamp;
	int64_t	last_timestamp;
	double latitude,longitude;
	uint32_t channel_mask;
	int32_t max_snr;
	uint32_t ip_addr;
	uint32_t ip_network;
	uint32_t ip_netmask;
	uint32_t data_rate;
	uint32_t misc_flags;
	uint32_t apflags;
	int	apdata_count;
	struct apdata_s *apdata;
};

struct apdata_s {
	int64_t	timestamp;
	int32_t	signal;
	int32_t	noise;
	enum { APDATA_NONE=0, APDATA_GPS=1 } location_source;
	double latitude;
	double longitude;
	double altitude;
	struct gpsdata_s {
		uint32_t sats;
		double speed;
		double track;
		double mag_variation;
		double hdop;
	} gps;
};

static inline time_t time_winfile_to_unix(int64_t wtime)
{
	time_t tm;

	wtime -= 116444736000000000LL;
	wtime /= 10000000LL;
	tm=wtime;
	return (time_t)tm;
}

#if 0
void dump_packet(FILE *ouf, struct packet_s *packet)
{
	time_t tm = time_winfile_to_unix(packet->timestamp);
	struct tm *ptime = localtime(&tm);

	fprintf(ouf,"%c %lf\t%c %lf\t",
		packet->latitude >= 0.0 ? 'N' : 'S',
		fabs(packet->latitude),
		packet->longitude >= 0.0 ? 'E' : 'W',
		fabs(packet->longitude));
//	fprintf(ouf,"%lf ft\t",packet->elevation);
	fprintf(ouf,"( %s )\t",packet->ssid);
	fprintf(ouf,"BBS\t");
	fprintf(ouf,"( %.2x:%.2x:%.2x:%.2x:%.2x:%.2x )\t",
		packet->mac[0],packet->mac[1],packet->mac[2],
		packet->mac[3],packet->mac[4],packet->mac[5]);
	fprintf(ouf,"%d:%.2d:%.2d (GMT)\t",ptime->tm_hour,ptime->tm_min,ptime->tm_sec);
	fprintf(ouf,"%d %d %d\t",0,149+packet->signal,149+packet->noise);
	fprintf(ouf,"# ( %s )\t",packet->name);
	fprintf(ouf,"%.4x\t%.4x\t%d\n",packet->flags,packet->channelbits,packet->beacon_interval);
}
#endif

int ns1_read_apdata(int fd, int version, struct apdata_s *packet)
{
	CREAD(le64,fd,&packet->timestamp);
	CREAD(le32,fd,&packet->signal);
	CREAD(le32,fd,&packet->noise);
	CREAD(le32,fd,&packet->location_source);
	if (packet->location_source == 1) {
		CREAD(double,fd, &packet->latitude);
		CREAD(double,fd, &packet->longitude);
		CREAD(double,fd, &packet->altitude);
	
		CREAD(le32,fd, &packet->gps.sats);
	
		CREAD(double,fd, &packet->gps.speed);
		CREAD(double,fd, &packet->gps.track);
		CREAD(double,fd, &packet->gps.mag_variation);
		CREAD(double,fd, &packet->gps.hdop);
	}
}

int ns1_read_apinfo(int fd, int version, struct apinfo_s *packet)
{
	int err,i;
	uint64_t t;
	uint32_t dummy;

	CREAD(string,fd, packet->ssid);
	CREAD(mac,fd, packet->bssid);
	CREAD(le32,fd, &packet->signal.max);
	CREAD(le32,fd, &packet->noise.min);
	CREAD(le32,fd, &packet->max_snr);
	if (version == 1) {
		CREAD(le32, fd, &dummy);
	} else if (version == 6) {
		CREAD(le32,fd, &packet->channel_mask);
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

	CREAD(le32,fd,&packet->channel_mask);
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

	return err;
}

struct ns1_file_s *ns1_read_fd(int fd)
{
	struct ns1_file_s *ns1;
	int i,err;

	ns1=calloc(sizeof(struct ns1_file_s),1);

	read_le32(fd,&ns1->signature);
	if (ns1->signature != NS1_MAGIC) {
		fprintf(stderr,"%s: Not a NetStumber .ns1 file\n",progname);
		free(ns1);
		return NULL;
	}

	err=read_le32(fd, &ns1->version);
	if (err <= 0) {
		free(ns1);
		return NULL;
	}

	if (ns1->version > 12) {
		fprintf(stderr,"%s: NetStumber version %d files not (yet) supported\n",ns1->version);
		free(ns1);
		return NULL;
	}

	err=read_le32(fd,&ns1->apinfo_count);
	if (err <= 0) {
		ns1->apinfo_count=0;
		return ns1;
	}

	ns1->apinfo=calloc(ns1->apinfo_count,sizeof(struct apinfo_s));
	for (i=0; i < ns1->apinfo_count; i++) {
		err=ns1_read_apinfo(fd, ns1->version, &ns1->apinfo[i]);
		if (err < 0)
			return ns1;
	}

	return ns1;
}



int main(int argc, char **argv)
{
	int ifd=0;
	FILE *ofile=stdout;
	uint32_t type=0;
	int err,aps;
	time_t tm;
	struct tm *ptime;
	struct ns1_file_s *ns1;

	setenv("TZ","GMT",1);
	tzset();

	progname = argv[0];

	if (argc>1) {
		fprintf(stderr,"Usage:\n\n%s <somefile.ns1 >somefile.txt\n",argv[0]);
		exit(1);
	}

	ns1=ns1_read_fd(ifd);
	if (ns1 == NULL)
		exit(1);

	return 0;
}
	

