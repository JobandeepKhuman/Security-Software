#include <stdio.h>
#include <stdlib.h>

struct node{ // data structure for each node
  const u_char *packet;
  const struct pcap_pkthdr *header;
  struct node *next;
};

struct queue{ // data structure for queue
  struct node *head;
  struct node *tail;
};

struct queue *create_queue(void){ //creates a queue and returns its pointer
  struct queue *q=(struct queue *)malloc(sizeof(struct queue));
  if(q==NULL){
    printf("\n Could Not allocate memory to the queue \n");
  }
  q->head=NULL;
  q->tail=NULL;
  return(q);
}

int isempty(struct queue *q){ // checks if queue is empty
  return(q->head==NULL);
}

void enqueue(struct queue *q, const u_char *packet, const struct pcap_pkthdr *header){ //enqueues a node with an item
  struct node *new_node=(struct node *)malloc(sizeof(struct node));
  if(new_node==NULL){
    printf("\n Could Not allocate memory to the node \n");
  }
  new_node->packet=packet;
  new_node->header=header;
  new_node->next=NULL;
  if(isempty(q)){
    q->head=new_node;
    q->tail=new_node;
  }
  else{
    q->tail->next=new_node;
    q->tail=new_node;
  }
}

void dequeue(struct queue *q){ //dequeues a the head node
  struct node *head_node;
  if(isempty(q)){
    printf("Error: attempt to dequeue from an empty queue");
  }
  else{
    head_node=q->head;
    q->head=q->head->next;
    if(q->head==NULL)
      q->tail=NULL;
    free(head_node);
  }
}

void clearQueue(struct queue *q){

  while(!(isempty(q))){
    dequeue(q);
  }

}