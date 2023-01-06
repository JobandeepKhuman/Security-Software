#include "analysis.h"
#include "dispatch.h"

#include <pcap.h>
#include <netinet/if_ether.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
//#include <netinet/if_arp.h>

#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <pthread.h>

#define threadNum 3

uint array_size=0;
uint SYN_count=0;
uint uniqueIP_count=0;
char** uniqueIP_arr;

uint ARP_count=0;
uint google_count=0;
uint facebook_count=0;

pthread_mutex_t SYNMutex=PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t ARPMutex=PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t BlacklistMutex=PTHREAD_MUTEX_INITIALIZER;

char destAddr[16];
char sourceAddr[16];


void syn_track(const struct ip *ipheader);

void analyse(const u_char *packet, int verbose) {
  // TODO your part 2 code here

  //Extracting the ether header from the packet
  const struct ether_header *eth_header = (struct ether_header *) packet;

  //Extracting the IP header from the packet
  const struct ip *IP_Header = (struct ip*)(packet + ETH_HLEN);
  u_int IP_Header_Length = IP_Header->ip_hl*4;

  //Extracting TCP Header of the packet
  const struct tcphdr *TCP_Header = (struct tcphdr*)(packet + ETH_HLEN + IP_Header_Length);
  u_int TCP_Header_Length = TCP_Header->th_off*4;

  if(TCP_Header->th_flags == TH_SYN){
    pthread_mutex_lock(&SYNMutex);
    syn_track(IP_Header);
    pthread_mutex_unlock(&SYNMutex);
  }
  if(ntohs(eth_header->ether_type)==ETHERTYPE_ARP){
    struct ether_arp * ARP_Pointer = (struct ether_arp*) (packet + ETH_HLEN);
    struct arphdr *ARP_Header = (struct arphdr*) (&ARP_Pointer->ea_hdr);
    if(ntohs(ARP_Header->ar_op) == ARPOP_REPLY){
      pthread_mutex_lock(&ARPMutex);
      ARP_count++;
      pthread_mutex_unlock(&ARPMutex);
    }
  }

  if(ntohs(TCP_Header->dest)==80){
    int check;
    const u_char *payload = packet + ETH_HLEN + IP_Header_Length + TCP_Header_Length;
    char* hostnamePtr = strstr((char*) payload, "www.google.co.uk");
    if(hostnamePtr!=NULL){
      pthread_mutex_lock(&BlacklistMutex);
      google_count++;
      pthread_mutex_unlock(&BlacklistMutex);
      check = 1;
    }
    else{
      hostnamePtr = strstr((char*) payload, "www.facebook.com");
      if(hostnamePtr!=NULL){
        pthread_mutex_lock(&BlacklistMutex);
        facebook_count++;
        pthread_mutex_unlock(&BlacklistMutex);
        check = 1;
      }
    }
    if(check==1){
      strcpy(sourceAddr, inet_ntoa(IP_Header->ip_src));
      strcpy(destAddr, inet_ntoa(IP_Header->ip_dst));
      pthread_mutex_lock(&BlacklistMutex);
      printf("\n ==============================");
      printf("\n Blacklisted URL violation detected");
      printf("\n Source IP address: %s", sourceAddr);
      printf("\n Destination IP address: %s", destAddr);
      printf("\n ============================== \n");
      pthread_mutex_unlock(&BlacklistMutex);
    }
  }


}


void syn_track(const struct ip *ipheader){
    SYN_count++;
    char *sourceAddr = (char*) inet_ntoa(ipheader->ip_src);
    int contains=0; //Boolean variable to see if array contains source IP address

    if(array_size==0){//Initialising array if it is empty
      uniqueIP_arr=malloc(sizeof(u_char *));
      uniqueIP_arr[0]=malloc(18*sizeof(u_char *));//Try with values other than 18 - 12digits and 3 decimal places not max?
      strcpy(uniqueIP_arr[0], sourceAddr);
      uniqueIP_count++;
      array_size=1;
    }
    else{
      for(int index=0; index<uniqueIP_count; index++){
        if(strcmp(uniqueIP_arr[index],sourceAddr)==0){
          contains=1;
        }
      }
        if(contains==0){
          if(uniqueIP_count>=array_size-1){
            array_size*=2;
            //realloc may move location of array as it may not be possible to extend the contiguous memory location
            //Therefore pointer to start of array will change
            uniqueIP_arr=realloc(uniqueIP_arr, array_size*sizeof(sourceAddr));
            if(uniqueIP_arr==NULL){
              printf("Unable to reallocate meomry to unique IP array");
            }
          }
          uniqueIP_arr[uniqueIP_count] = malloc(18*sizeof(unsigned char));
          strcpy(uniqueIP_arr[uniqueIP_count], sourceAddr);
          uniqueIP_count++;
      }
  }
}
    
