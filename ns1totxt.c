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

#ifdef DEBUG
#define DPRINT(fmt, x...) fprintf(stdout,"%.4x: " fmt , (int)lseek(fd,0,SEEK_CUR) , ## x )
#else
#define DPRINT(fmt, x...) do { } while(0)
#endif

const char *progname=NULL;

void dump_packet(FILE *ouf, struct apinfo_s *info, struct apdata_s *packet)
{
	time_t tm = ns1_time_to_unix(packet->timestamp);
	struct tm *ptime = localtime(&tm);

	fprintf(ouf,"%c %lf\t%c %lf\t",
		packet->latitude >= 0.0 ? 'N' : 'S',
		fabs(packet->latitude),
		packet->longitude >= 0.0 ? 'E' : 'W',
		fabs(packet->longitude));
//	fprintf(ouf,"%lf ft\t",packet->elevation);
	fprintf(ouf,"( %s )\t",info->ssid);
	fprintf(ouf,"BBS\t");
	fprintf(ouf,"( %.2x:%.2x:%.2x:%.2x:%.2x:%.2x )\t",
		info->bssid[0],info->bssid[1],info->bssid[2],
		info->bssid[3],info->bssid[4],info->bssid[5]);
	fprintf(ouf,"%d:%.2d:%.2d (GMT)\t",ptime->tm_hour,ptime->tm_min,ptime->tm_sec);
	fprintf(ouf,"%d %d %d\t",0,149+packet->signal,149+packet->noise);
	fprintf(ouf,"# ( %s )\t",info->name);
	fprintf(ouf,"%.4x\t%.4x\t%d\n",info->flags,(uint32_t)info->channel_mask,info->beacon_interval);
}

int main(int argc, char **argv)
{
	int ifd=0;
	FILE *ofile=stdout;
	struct ns1_file_s *ns1;
	time_t tm;
	struct tm *ptime;
	int i,j;

	setenv("TZ","GMT",1);
	tzset();

	progname = argv[0];

	if (argc>1) {
		fprintf(stderr,"Usage:\n\n%s <somefile.ns1 >somefile.txt\n",argv[0]);
		exit(1);
	}

	ns1 = ns1_open_fd(ifd);
	if (ns1 == NULL)
		return 1;

	if (ns1->apinfo_count == 0)
		return 0;

	tm = ns1_time_to_unix(ns1->apinfo[0].first_timestamp);
	ptime = localtime(&tm);
	fprintf(ofile,"# $Creator: Network Stumbler Versin 0.3.23 Compatible Format\n"
		      "# $Format: wi-scan with extensions\n"
		      "# Latitude\tLongitude\t( SSID )\tType\t( BSSID )\tTime (GMT)\t[ SNR Sig Noise ]\t# ( Name )\tFlags\tChannelbits\tBcnIntvl\n");
	fprintf(ofile,"# $DateGMT: %d-%d-%d\n",
			ptime->tm_year+1900,ptime->tm_mon,ptime->tm_mday);

	for (i=0; i < ns1->apinfo_count; i++)
		for (j = 0; j < ns1->apinfo[i].apdata_count; j++)
			dump_packet(stdout,&ns1->apinfo[i],&ns1->apinfo[i].apdata[j]);

	return 0;
}
	

