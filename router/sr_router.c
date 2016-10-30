/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <time.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

/* TODO: Add constant definitions here... */

/* TODO: Add helper functions here... */

/* See pseudo-code in sr_arpcache.h */
void handle_arpreq(struct sr_instance* sr, struct sr_arpreq *req){
  /* TODO: Fill this in */
  
}

/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    /* TODO: (opt) Add initialization code here */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT free either (signified by "lent" comment).  
 * Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */){

  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d\n",len);

  /* TODO: Add forwarding logic here */
  struct sr_ethernet_hdr * eth_hdr = (struct sr_ethernet_hdr *) packet;
  
  uint16_t frame_type = ntohs(eth_hdr->ether_type);
  
  if(frame_type == ethertype_ip)
  {
    printf("IP TYPE RECEIVED\n");
    sr_process_ip_packet(sr,packet,len,interface);
  }
  else if (frame_type == ethertype_arp)
  {
    printf("ARP TYPE RECEIVED\n");
    sr_process_arp_data(sr, (struct sr_arp_hdr*) (packet + sizeof(struct sr_ethernet_hdr)), interface);
  }
  else
  {
    printf("UNKNOWN TYPE RECEIVED\n");    
  }

}/* -- sr_handlepacket -- */



void sr_process_arp_data(struct sr_instance * inst, struct sr_arp_hdr * request, char * interface)
{
    switch(ntohs(request->ar_op))
    {
    case arp_op_request:
        printf("Its a Request\n");
        sr_arp_reply_to_request(inst,request,interface);
        break;
    case arp_op_reply:
        printf("Its a Reply\n");
        sr_process_arp_reply(inst,request);
        break;
    }
}

void sr_process_arp_reply(struct sr_instance * inst, struct sr_arp_hdr * reply)
{
  ;  
}

void sr_arp_reply_to_request(struct sr_instance *inst, struct sr_arp_hdr * request, char *interface)
{
 ; 
}



unsigned short ipheader_checksum(struct sr_ip_hdr * ip_hdr)
{
    struct sr_ip_hdr *iph = ip_hdr;
    iph->ip_sum = 0;
    return cksum((unsigned short *)iph,sizeof(struct sr_ip_hdr));
}

void sr_process_ip_packet(struct sr_instance * sr, uint8_t * packet, unsigned int len, char* interface)
{
    struct sr_ip_hdr *ip_hdr = (struct sr_ip_hdr *)(packet + sizeof(struct sr_ethernet_hdr));
    if( ip_hdr->ip_sum  != ipheader_checksum(ip_hdr))
    {
        printf("\nchecksums differ %x, %x\n", ip_hdr->ip_sum, ipheader_checksum(ip_hdr));
    }
    else if(ip_hdr->ip_v != 4)
    {
        printf("\nip version is %d; only accepting 4\n",ip_hdr->ip_v);
    }
    else
    {
       printf("LOL\n"); 
    }
}