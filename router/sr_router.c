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

    struct sr_if *ifaces;
    time_t current_time = time(NULL);
    if(difftime(current_time, req->sent) > 1.0)
    {
        if(req->times_sent >= 5)
        {
            /*
                We tried so hard (5 times) but still didn't get a reply
            */
            Debug("\nNo ARP reply found, dropping the packet\n");

            /*
                Send corresponding ICMP packets.
                Destination host unreachable (type 3, code 1)
            */
            struct sr_packet *packet = req->packets;
            while(packet)
            {
                ifaces = sr_get_interface(sr, packet->iface);
                sr_send_icmp_t3(
                    sr, 
                    (uint8_t *)(packet->buf), 
                    packet->len , 
                    0x1, 
                    ifaces->ip, 
                    ifaces
                );
                packet = packet->next;
            }
            sr_arpreq_destroy(&(sr->cache), req); 

        }
        else
        {

            printf("\nSending ARP request %d\n",req->times_sent);
            
            /*
                We'll send a ethernet packet (a arp packet) in response
            */
            ifaces = sr_get_interface(sr, (req->packets)->iface);
            sr_send_arp_request_ip(sr,req->ip,ifaces);
            req->sent = time(NULL);
            req->times_sent = req->times_sent + 1;
        }
    }
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

    printf("\n%s -> Received packet of length %d\n",interface,len);

    /* TODO: Add forwarding logic here */
    struct sr_ethernet_hdr * eth_hdr = (struct sr_ethernet_hdr *) packet;
    
    uint16_t frame_type = ntohs(eth_hdr->ether_type);
    
    if(frame_type == ethertype_ip)
    {
        printf("\nIP PACKET RECEIVED\n");
        sr_process_ip_packet(sr,packet,len,interface);
    }
    else if (frame_type == ethertype_arp)
    {
        printf("\nARP PACKET RECEIVED\n");
        sr_process_arp_packet(sr, packet, len, interface);
    }
    else
    {
        printf("UNKNOWN TYPE RECEIVED\n");    
    }

}/* -- sr_handlepacket -- */








