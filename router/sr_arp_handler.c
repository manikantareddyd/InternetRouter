#include "sr_arp_handler.h"
void sr_process_arp_packet(struct sr_instance * inst,uint8_t * packet, unsigned int len,char* interface)
{
    struct sr_arp_hdr* request = (struct sr_arp_hdr*)(packet + sizeof(struct sr_ethernet_hdr));
    switch(ntohs(request->ar_op))
    {
        case arp_op_request:
            Debug("Its an ARP Request\n");
            sr_arp_reply_to_request(inst, packet,len,interface);
            break;
        case arp_op_reply:
            Debug("Its an ARP Reply\n");
            sr_process_arp_reply(inst,packet,len,interface);
            break;
        default:
            Debug("WTF is this ARP packet\n");
    }
}

void sr_arp_reply_to_request(struct sr_instance *inst, uint8_t *packet, unsigned int len, char *interface)
{
    struct sr_arp_hdr* request = (struct sr_arp_hdr*)(packet + sizeof(struct sr_ethernet_hdr));
    struct sr_if *iface =sr_get_interface(inst, interface);

    if(iface->ip == request->ar_tip)
    {
        Debug("\tThis packet is indeed for this router. Sending an ARP Reply \n");
        /*
            We'll send a ethernet packet (a arp packet) in response
        */
        sr_send_arp_request(inst, packet, iface);
    }
    else
    {
        Debug("\tThis ARP packet is not for this. Dropping it :P\n");
    }

}

void sr_process_arp_reply(struct sr_instance * inst, uint8_t *packet, unsigned int len, char * interface)
{
    struct sr_arp_hdr* arp_reply = (struct sr_arp_hdr*)(packet + sizeof(struct sr_ethernet_hdr));
    Debug("\tCaching the Request\n");
    struct sr_arpreq *arp_request = sr_arpcache_insert(
        &inst->cache,
        arp_reply->ar_sha,
        arp_reply->ar_sip
    );
    struct sr_if *iface =sr_get_interface(inst, interface);
    
    if(arp_request == NULL)
    {
        Debug("\tNothing to do here... Its an empty arp_reply\n");
    }
    else
    {
        Debug("\tSending out packets in the resolution queue\n");
        struct sr_packet *packets = arp_request->packets;
        while(packets)
        {
            /* Create a forward Packer */
            
            sr_forward_packet(inst,packets->buf,arp_reply->ar_sha,packets->len,iface);
            /*Move on to see if there are more  :( */
            packets = packets->next;
        }
        sr_arpreq_destroy(&inst->cache, arp_request);
    }
}