#include "dispatch.h"

#include <pcap.h>

#include "analysis.h"
#include "sniff.h"
#include <pthread.h>
#include "queue.h"

#include <stdlib.h>
#include <signal.h>

#define threadNum 3

struct queue *taskQueue;

pthread_mutex_t queueMutex=PTHREAD_MUTEX_INITIALIZER;

pthread_cond_t queueCond=PTHREAD_COND_INITIALIZER;

pthread_t threadID[3];

void *threadFunction(void *arg);

int run = 1;

void threadInitialisation(int *verbosePtr){
  taskQueue=create_queue();
  void *v = (void*)verbosePtr;
  for(int i=0;i<threadNum;i++){

		pthread_create(&threadID[i],NULL,threadFunction,v);
	}
}


//parameter 1=last parameter of pcap_loop
//parameter2 = pcap header
//parameter3 = points to the first byte of a chunk of data containing the entire packet
void dispatch(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
  // This method should handle dispatching of work to threads. At present
  // it is a simple passthrough as this skeleton is single-threaded.
  //Adding the packet to the queue and enuring all threads are sychronised by using mutex locks
  pthread_mutex_lock(&queueMutex);
	enqueue(taskQueue,packet,header);
	pthread_cond_broadcast(&queueCond); 
	pthread_mutex_unlock(&queueMutex);
}

void *threadFunction(void *arg){
  pthread_mutex_lock(&queueMutex);
  int *vPtr = (int*) arg;
  int v = *vPtr;
  if(vPtr==NULL){
  }
  pthread_mutex_unlock(&queueMutex);
  while(run==1){
    pthread_mutex_lock(&queueMutex);//Aquire mutex lock for the queue
    //Wait whilst the queue is empty to save resources
		while(isempty(taskQueue)){  
			pthread_cond_wait(&queueCond,&queueMutex);
		}
    //Dequeue the packet from the queue
    const u_char *packet = taskQueue->head->packet;
    const struct pcap_pkthdr *header = taskQueue->head->header;
    
		dequeue(taskQueue); 
		pthread_mutex_unlock(&queueMutex);//Release mutex lock once packet is dequeued
    if(packet!=NULL){//If the packet read from queue is valid analyse it and dump if necessary
      if(v){
      //Locking the dump function so that the output of different threads displaying packet contents
      // does not jumble up with one another
      pthread_mutex_lock(&queueMutex);
      dump(packet, header->len); 
      pthread_mutex_unlock(&queueMutex);
      }
      analyse(packet, v);
    }
  }
  printf("\n threadFunction terminating \n");
  return NULL;
}
