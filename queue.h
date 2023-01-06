struct node{ // data structure for each node
  u_char *packet;
  const struct pcap_pkthdr *header;
  struct node *next;
};

struct queue{ // data structure for queue
  struct node *head;
  struct node *tail;
};

struct queue *create_queue(void);

int isempty(struct queue *q);

void enqueue(struct queue *q, const u_char* packet,  const struct pcap_pkthdr *header);

void dequeue(struct queue *q);

void clearQueue(struct queue *q);

