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
	uint64_t channel_mask;
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

struct sql_record {
	const char *attr;
	off_t offset;
	enum rec_type_e {
		REC_NONE=0,
		REC_STRING,
		REC_MAC,
		REC_TIME64,
		REC_DOUBLE,
		REC_IP4,
		REC_INT32,
		REC_UINT32
	} type;
};

#define RECLOC(type,sub) ((void *)(&((type *)NULL)->sub) - NULL)

void sql_insert(FILE *ouf, const char *table, struct sql_record *recs, const void *data)
{
	int i;
	fprintf(ouf,"insert into %s (",table);
	for (i=0; recs[i].attr != NULL; i++) {
		if (i != 0)
			fprintf(ouf,",");
		fprintf(ouf,"%s",recs[i].attr);
	}

	fprintf(ouf,") values (");

	for (i=0; recs[i].attr != NULL; i++) {
		int j;
		if (i != 0)
			fprintf(ouf,",");
		switch (recs[i].type) {
			case REC_STRING:
				fprintf(ouf,"\"%s\"",(const char *)(data+recs[i].offset));
				break;
			case REC_MAC: {
				const uint8_t *cp = (const uint8_t *)(data+recs[i].offset);
				for (j=0; j < 6; j++) {
					if (j!=0) fprintf(ouf,":");
					fprintf(ouf,"%.2x",cp[j]);
				}
				break; }	
			case REC_IP4: {
				uint32_t val = *(const uint32_t *)(data+recs[i].offset);
				fprintf(ouf,"%d.%d.%d.%d",
						val & 0xff,
						(val>>8)&0xff,
						(val>>16)&0xff,
						(val>>24)&0xff
						);
				break; }
			case REC_TIME64: {
				uint64_t val = *(const uint64_t *)(data+recs[i].offset);
				time_t tm = time_winfile_to_unix(val);
				fprintf(ouf,"%d",tm);
				break; }
			case REC_DOUBLE: {
				double val = *(const double *)(data+recs[i].offset);
				fprintf(ouf,"%g",val);
				break; }
			case REC_INT32: {
				int32_t val = *(const int32_t *)(data+recs[i].offset);
				fprintf(ouf,"%d",val);
				break; }
			case REC_UINT32: {
				uint32_t val = *(const uint32_t *)(data+recs[i].offset);
				fprintf(ouf,"%u",val);
				break; }
			case REC_NONE:
			default:
				fprintf(stderr,"ARGH - internal error for REC_NONE!\n");
				exit(1);
				break;
		}

	}

	fprintf(ouf,");\n");
}


void dump_apdata(FILE *ouf, struct apdata_s *packet)
{
	struct sql_record recs[]={
		{ "timestamp", RECLOC(struct apdata_s,timestamp), REC_TIME64 },
		{ "signal", RECLOC(struct apdata_s, signal), REC_INT32 },
		{ "noise", RECLOC(struct apdata_s, noise), REC_INT32 },
		{ "location_source", RECLOC(struct apdata_s, location_source), REC_UINT32 },
		{ "latitude", RECLOC(struct apdata_s,latitude), REC_DOUBLE },
		{ "longitude", RECLOC(struct apdata_s,longitude), REC_DOUBLE },
		{ "altitude", RECLOC(struct apdata_s,altitude), REC_DOUBLE },
		{ NULL, 0, 0 } };
	
	sql_insert(ouf,"apdata",recs,packet);
}

void dump_apinfo(FILE *ouf, struct apinfo_s *packet)
{
	struct sql_record recs[]={
		{ "ssid", RECLOC(struct apinfo_s,ssid[0]), REC_STRING },
		{ "mac",  RECLOC(struct apinfo_s,bssid[0]), REC_MAC },
		{ "name", RECLOC(struct apinfo_s,name[0]), REC_STRING },
		{ "timestamp", RECLOC(struct apinfo_s,first_timestamp), REC_TIME64 },
		{ "latitude", RECLOC(struct apinfo_s,latitude), REC_DOUBLE },
		{ "longitude", RECLOC(struct apinfo_s,longitude), REC_DOUBLE },
		{ "ip_addr", RECLOC(struct apinfo_s,ip_addr), REC_IP4 },
		{ "ip_network", RECLOC(struct apinfo_s,ip_network), REC_IP4 },
		{ "ip_netmask", RECLOC(struct apinfo_s,ip_netmask), REC_IP4 },
		{ "apflags", RECLOC(struct apinfo_s,apflags), REC_UINT32 },
		{ NULL, 0, 0 } };
	int i;

	sql_insert(ouf,"apinfo",recs,packet);
	for (i=0; i < packet->apdata_count; i++)
		dump_apdata(ouf,&packet->apdata[i]);
}

int ns1_read_apdata(int fd, int version, struct apdata_s *packet)
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
		// printf("Location 0x%x\n",lseek(fd,0,SEEK_CUR));
		dump_apinfo(stdout, &ns1->apinfo[i]);
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
	

