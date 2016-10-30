#include "sr_arp_handler.h"
void sr_process_arp_packet(struct sr_instance * inst, struct sr_arp_hdr * request, char * interface)
{
    switch(ntohs(request->ar_op))
    {
        case arp_op_request:
            Debug("Its an ARP Request\n");
            sr_arp_reply_to_request(inst,request,interface);
            break;
        case arp_op_reply:
            Debug("Its an ARP Reply\n");
            sr_process_arp_reply(inst,request,interface);
            break;
        default:
            Debug("WTF is this ARP packet\n");
    }
}

void sr_arp_reply_to_request(struct sr_instance *inst, struct sr_arp_hdr * request, char *interface)
{
 ; 
}

void sr_process_arp_reply(struct sr_instance * inst, struct sr_arp_hdr * reply, char * interface)
{
    Debug("\tCaching the Request\n");
    struct sr_arpreq *arp_request = sr_arpcache_insert(
        &inst->cache,
        reply->ar_sha,
        reply->ar_sip
    );
    struct sr_if *iface =sr_get_interface(inst, interface);
    
    if(arp_request == NULL)
    {
        Debug("\tNothing to do here... Its an empty reply\n");
    }
    else
    {
        Debug("\tSending out packets in the resolution queue\n");

        struct sr_packet *packets = arp_request->packets;
        while(packets)
        {
            /* Create a forward Packer */
            uint8_t *forward_packet = packets->buf;
            sr_ethernet_hdr_t *forward_eth_header = (sr_ethernet_hdr_t *)forward_packet;


            /* Doing the MAC copying stuff */
            memcpy(
                forward_eth_header->ether_dhost,
                reply->ar_sha,
                ETHER_ADDR_LEN
            );

            memcpy(
                forward_eth_header->ether_shost,
                iface->addr,
                ETHER_ADDR_LEN
            );
            

            /* Checksum related stuff */
            sr_ip_hdr_t *forward_ip_header = (sr_ip_hdr_t*)(forward_packet + sizeof(sr_ethernet_hdr_t));
            forward_ip_header->ip_sum = 0;
            forward_ip_header->ip_sum = cksum(forward_ip_header, sizeof(sr_ip_hdr_t));

            /* Send this shit now */
            sr_send_packet(
                inst,
                forward_packet,
                packets->len,
                iface->name
            );

            /*Move on to see if there are more  :( */
            packets = packets->next;
        }
        sr_arpreq_destroy(&inst->cache, arp_request);
    }
}