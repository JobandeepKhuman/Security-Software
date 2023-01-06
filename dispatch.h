#ifndef CS241_DISPATCH_H
#define CS241_DISPATCH_H

#include <pcap.h>

void dispatch(u_char *args, const struct pcap_pkthdr *header,const u_char *packet);

void threadInitialisation(int *verbose);

extern pthread_mutex_t queueMutex;
extern pthread_cond_t queueCond;

extern pthread_t threadID[3];

extern int run;

extern struct queue *taskQueue;

#endif
