#ifndef CS241_ANALYSIS_H
#define CS241_ANALYSIS_H

#include <pcap.h>

void analyse(const unsigned char *packet, int verbose);

extern uint SYN_count;
extern uint uniqueIP_count;

extern uint ARP_count;
extern uint google_count;
extern uint facebook_count;

#endif
