#include "sniff.h"

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <netinet/if_ether.h>
//Including headers that contain the data structures required to store TCP and IP headers
#include <netinet/tcp.h>
#include <netinet/ip.h>
//Including header for ntohs function which is used toconvert data recieved from the network byte order 
//to the host byte order
#include <netinet/in.h>
#include "dispatch.h"
#include "analysis.h"

#include <pthread.h>
#include <signal.h>
#include "queue.h"
#include <string.h>

#define threadNum 3



static pcap_t *pcap_handle;

pthread_mutex_t EndMutex=PTHREAD_MUTEX_INITIALIZER;

void programOutput (int signum) {
  clearQueue(taskQueue);
  pcap_breakloop(pcap_handle);
  pcap_close(pcap_handle);
  //run++;
  /*for (int i=0; i<threadNum; i++){
     // printf("On iteration %d",i);
      pthread_join(threadID[i], (void**) NULL);
    }*/
  printf("Intrusion Detection Report:\n");
  printf(" %d SYN  packets detected from %d different IPs (syn attack) \n", SYN_count, uniqueIP_count);
  printf(" %d ARP responses (cache poisoning) \n", ARP_count);
  printf("%d URL Blacklist violations (%d google and %d facebook) \n", google_count+facebook_count, google_count, facebook_count);
  exit(0);
 }


// Application main sniffing loop
//The pointer to theinterface to be sniffed is passed as a parameter from the main file
void sniff(char *interface, int verbose) {
  signal(SIGINT, programOutput);
  char errbuf[PCAP_ERRBUF_SIZE]; //A buffer (represented as a string) to store error messages

  // Open the specified network interface for packet capture. pcap_open_live() returns the handle to be used for the packet
  // capturing session. check the man page of pcap_open_live()
  //4096=maximum number of bytes to be captured by pacap
  //Parameter2=1 implies the interface is set to promiscuous mode therefore the program is able to sniff all traffic on the wire
  //not just traffic directed to the host
  //1000=read timeout in milliseconds
  pcap_handle = pcap_open_live(interface, 4096, 1, 1000, errbuf);
  if (pcap_handle == NULL) {
    fprintf(stderr, "Unable to open interface %s\n", errbuf);
    exit(EXIT_FAILURE);
  } else {
    printf("SUCCESS! Opened %s for capture\n", interface);
  }
  threadInitialisation(&verbose);

  u_char* verbosePtr = (u_char*) &verbose;
  int howManyToSniff = -1; //-negative values implies sniff until error occurs
  pcap_loop(pcap_handle, howManyToSniff, (pcap_handler) dispatch, verbosePtr);
}

//Part 1 - added by joban based on lab tutor advice
// Utility/Debugging method for dumping raw packet data
//data is a pointer to the start of a packet
void dump(const unsigned char *data, int length) {
  unsigned int i;
  static unsigned long pcount = 0;
  //Selecting the bit that corresponds to the first bit of each packet header then type casting it to the appropriate 
  //strucutre name so that fields that specific sequences of bits can be mapped to fields of those structures and therefore
  //can be easily accessed.
  const struct ether_header *eth_header = (struct ether_header *) data; //Data is pointer adding ETH_HLEN points to IP header

  // Decode Packet Header
  printf("\n\n === PACKET %ld HEADER ===", pcount);
  printf("\nSource MAC: ");
  for (i = 0; i < 6; ++i) {
    printf("%02x", eth_header->ether_shost[i]);
    if (i < 5) {
      printf(":");
    }
  }
  printf("\nDestination MAC: ");
  for (i = 0; i < 6; ++i) {
    printf("%02x", eth_header->ether_dhost[i]);
    if (i < 5) {
      printf(":");
    }
  }
  //Anything over a byte long needs to be converted to network byte order use ntohs()
  printf("\nType: %hu\n", ntohs(eth_header->ether_type));

  //DECODING THE IP HEADER (Possibly need to dereference before printing? nthos before printing?)
  const struct ip *IP_Header = (struct ip*)(data + ETH_HLEN);
  u_int IP_Header_Length = IP_Header->ip_hl*4;
  char sourceAddr[16];
  char destAddr[16];
  strcpy(sourceAddr, inet_ntoa(IP_Header->ip_src));
  strcpy(destAddr, inet_ntoa(IP_Header->ip_dst));
  printf("\n Source IP address: %s\n", sourceAddr);
	printf("\n Destination IP address: %s\n", destAddr);
  printf("\n IP Protocol: %hu\n", ntohs(IP_Header->ip_p));

  //Decoding the TCP HEADER
  const struct tcphdr *TCP_Header = (struct tcphdr*)(data + ETH_HLEN + IP_Header_Length);
  u_int TCP_Header_Length = TCP_Header->th_off*4;
  printf("\n Source port: %d\n", ntohs(TCP_Header->source));
	printf("\n Destination port: %d\n", ntohs(TCP_Header->dest));



  printf("\n\n === PAYLOAD OF PACKET %ld ===", pcount);
  // Decode Packet Data (Skipping over the header)
  int data_bytes = length - ETH_HLEN - IP_Header_Length - TCP_Header_Length;
  const unsigned char *payload = data + ETH_HLEN + IP_Header_Length + TCP_Header_Length;


  const static int output_sz = 20; // Output this many bytes at a time
  while (data_bytes > 0) {
    int output_bytes = data_bytes < output_sz ? data_bytes : output_sz;
    // Print data in raw hexadecimal form
    for (i = 0; i < output_sz; ++i) {
      if (i < output_bytes) {
        printf("%02x ", payload[i]);
      } else {
        printf ("   "); // Maintain padding for partial lines
      }
    }
    printf ("| ");
    // Print data in ascii form
    for (i = 0; i < output_bytes; ++i) {
      char byte = payload[i];
      if (byte > 31 && byte < 127) {
        // Byte is in printable ascii range
        printf("%c", byte);
      } else {
        printf(".");
      }
    }
    printf("\n");
    payload += output_bytes;
    data_bytes -= output_bytes;
  }
  pcount++;
}

