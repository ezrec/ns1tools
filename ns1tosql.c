#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <time.h>
#include <math.h>
#include <ctype.h>
#include <inttypes.h>

#include <ns1.h>

#define NS1_MAGIC 0x5374654e

#ifdef DEBUG
#define DPRINT(fmt, x...) fprintf(stdout,"%.4x: " fmt , (int)lseek(fd,0,SEEK_CUR) , ## x )
#else
#define DPRINT(fmt, x...) do { } while(0)
#endif

const char *progname=NULL;

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
				time_t tm = ns1_time_to_unix(val);
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

int main(int argc, char **argv)
{
	int ifd=0;
	FILE *ofile=stdout;
	uint32_t type=0;
	int i;
	struct ns1_file_s *ns1;

	setenv("TZ","GMT",1);
	tzset();

	progname = argv[0];

	if (argc>1) {
		fprintf(stderr,"Usage:\n\n%s <somefile.ns1 >somefile.txt\n",argv[0]);
		exit(1);
	}

	ns1=ns1_open_fd(ifd);
	if (ns1 == NULL)
		exit(1);

	for (i=0; i < ns1->apinfo_count; i++) {
		dump_apinfo(stdout, &ns1->apinfo[i]);
	}

	return 0;
}
	

