/* NS1 parser
 * Copyright 2004, Jason McMullan <gus@www.evillabs.net>
 */

#ifndef NS1_H
#define NS1_H

struct ns1_file_s {
	uint32_t	signature;
	uint32_t	version;
	int		apinfo_count;
	struct apinfo_s *apinfo;
};

struct apinfo_s {
// I had to add this line to create a SQL column for the relation value. -drew
	int32_t iuin;

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
	// I did the same here, adding this line for the relation -drew
	// took me a while to figure out where they were defined.
	int32_t duin;

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


/* Read in the whole file to memory.
 * Parse it at your leisure.
 */
struct ns1_file_s *ns1_open_fd(int fd);
void ns1_close(struct ns1_file_s *ns1);


/* Useful helper functions
 */
static inline time_t ns1_time_to_unix(int64_t wtime)
{
	time_t tm;

	wtime -= 116444736000000000LL;
	wtime /= 10000000LL;
	tm=wtime;
	return (time_t)tm;
}


#endif /* NS1_H */
