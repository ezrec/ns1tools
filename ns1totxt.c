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

struct packet_s {
	int	version;
	int	type;
	int	subtype;
	char ssid[256];
	char name[256];
	uint8_t mac[6];
	int32_t poop[3];
	int32_t channelbits;
	int32_t flags;
	int32_t bcnintvl;
	double latitude,longitude,elevation;
	int64_t timestamp;
	int32_t	signal;
	int32_t	noise;
	int32_t	len;
};

static inline time_t time_winfile_to_unix(int64_t wtime)
{
	time_t tm;

	wtime -= 116444736000000000LL;
	wtime /= 10000000LL;
	tm=wtime;
	return (time_t)tm;
}

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
	fprintf(ouf,"%.4x\t%.4x\t%d\n",packet->flags,packet->channelbits,packet->bcnintvl);
}

int read_packet_zero(int fd, struct packet_s *packet)
{
	return 0;
}

int read_packet_gps(int fd, struct packet_s *packet)
{
	double runs[4];
	int i,err;

	err=read_double(fd, &packet->latitude); if (err <= 0) return err;
	err=read_double(fd, &packet->longitude); if (err <= 0) return err;
	err=read_double(fd, &packet->elevation); if (err <= 0) return err;

	err=read_le32(fd, &packet->subtype); if (err <= 0) return err;
fprintf(stderr,"  Subtype: %d\n",packet->subtype);

	for (i=0; i < 4; i++) {
		err=read_double(fd, &runs[i]); if (err <= 0) return err;
DPRINT("%d: runs[%d]=(%.16llx),%lf\n",packet->type,i,*(uint64_t *)(&runs[i]),runs[i]);
	}

	return 0;
}

int read_packet_ssid(int fd, struct packet_s *packet)
{
	int err,i;
	uint64_t t;

	err=read_string(fd, packet->ssid); if (err <= 0) return err;
	err=read_mac(fd, packet->mac); if (err <= 0) return err;
	err=read_le32(fd, &packet->poop[0]); if (err <= 0) return err;
	err=read_le32(fd, &packet->poop[1]); if (err <= 0) return err;
	if (packet->version == 6)
		err=read_le32(fd, &packet->poop[2]); if (err <= 0) return err;
	err=read_le32(fd, &packet->channelbits); if (err <= 0) return err;
	err=read_le32(fd, &packet->flags); if (err <= 0) return err;
	err=read_le32(fd, &packet->bcnintvl); if (err <= 0) return err;
	err=read_le64(fd, &t); if (err <= 0) return err;
	err=read_le64(fd, &packet->timestamp); if (err <= 0) return err;
	err=read_double(fd, &packet->latitude); if (err <= 0) return err;
	err=read_double(fd, &packet->longitude); if (err <= 0) return err;
	err=read_le32(fd, &packet->len); if (err <= 0) return err;

	return err;
}

int read_packet(int fd, struct packet_s *packet)
{
	int err;
	int tlen=0;
	int64_t seq;
	char junk[16];

	if (packet->len == 0) {
		err=read_string(fd, packet->name); if (err <= 0) return err;
		err=read_packet_ssid(fd, packet); if (err <= 0) return err;
	}

	err=read_le64(fd, &seq); if (err <= 0) return err;
	tlen += err;

	if (llabs(seq-packet->timestamp) > 0x10000000000ULL) {
		fprintf(stderr,"%s: Packet sanity chaing failed at 0x%.8x\n",progname, lseek(fd,0,SEEK_CUR));
		return -1;
	}
	packet->timestamp=seq;
	err=read_le32(fd, &packet->signal); if (err <= 0) return err;
	tlen+=err;
	err=read_le32(fd, &packet->noise); if (err <= 0) return err;
	tlen+=err;

	err=read_le32(fd, &packet->type); if (err <= 0) return err;
	tlen+=err;

fprintf(stderr,"Type: %d\n",packet->type);
	switch (packet->type) {
		case 0:
			err=read_packet_zero(fd, packet);
			tlen+=err;
			break;
		case 1:
		case 3:
			err=read_packet_gps(fd, packet);
			tlen+=err;
			break;
		default:
			fprintf(stderr,"%s: 0x%x: bad packet format %d\n",
				progname, (int)lseek(fd,0,SEEK_CUR),packet->type);
			exit(0);
	}

	packet->len--;

	if (packet->len == 0 && packet->version==8) {
		err = read(fd, junk, 16); if (err <= 0) return err;
		tlen += err;
	}

	return tlen;
}

int main(int argc, char **argv)
{
	int ifd=0;
	FILE *ofile=stdout;
	uint32_t type=0;
	int err,aps;
	struct packet_s packet;
	time_t tm;
	struct tm *ptime;

	setenv("TZ","GMT",1);
	tzset();

	progname = argv[0];
	memset(&packet,0,sizeof(packet));

	if (argc>1) {
		fprintf(stderr,"Usage:\n\n%s <somefile.ns1 >somefile.txt\n",argv[0]);
		exit(1);
	}

	err=read_le32(ifd,&type); if (err <= 0) return -1;
	if (type != NS1_MAGIC) {
		fprintf(stderr,"%s: Not a NetStumber .ns1 file\n",progname);
		return 1;
	}

	err=read_le32(ifd,&packet.version); if (err <= 0) return -1;

	if (packet.version != 6 && packet.version != 8) {
		fprintf(stderr,"%s: fileformat type %d not supported\n",progname,packet.version);
		return 1;
	}
	err=read_le32(ifd,&aps); if (err <= 0) return -1;
	err=read_packet_ssid(ifd,&packet); if (err <= 0) return -1;

	tm = time_winfile_to_unix(packet.timestamp);
	ptime = localtime(&tm);
	fprintf(ofile,"# $Creator: Network Stumbler Versin 0.3.23 Compatible Format\n"
		      "# $Format: wi-scan with extensions\n"
		      "# Latitude\tLongitude\t( SSID )\tType\t( BSSID )\tTime (GMT)\t[ SNR Sig Noise ]\t# ( Name )\tFlags\tChannelbits\tBcnIntvl\n");
	fprintf(ofile,"# $DateGMT: %d-%d-%d\n",
			ptime->tm_year+1900,ptime->tm_mon,ptime->tm_mday);

	while (read_packet(ifd, &packet) > 0)
		dump_packet(ofile,&packet);

	return 0;
}
	

