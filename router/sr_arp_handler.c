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
            We'll send a ethernet packet and a arp packet in response

        */
        /* len = sizeof(struct sr_ethernet_hdr); */

        /* headers */
        sr_ethernet_hdr_t *request_eth_hdr = (sr_ethernet_hdr_t *)(packet);
        sr_arp_hdr_t *request_arp_hdr = (sr_arp_hdr_t *)(packet + sizeof(struct sr_ethernet_hdr));

        /* Create a Reply Packer */
        uint8_t *arp_reply_packet = (uint8_t *) malloc(len);
        memset(arp_reply_packet, 0, len * sizeof(uint8_t));

        /* Fill in the reply ethernet Header*/
        sr_ethernet_hdr_t *reply_eth_hdr = (sr_ethernet_hdr_t *)(arp_reply_packet);
        reply_eth_hdr->ether_type = htons(ethertype_arp);
        
        /*Doing the MAC copying stuff */
        memcpy(
            reply_eth_hdr->ether_dhost,
            request_eth_hdr->ether_shost,
            ETHER_ADDR_LEN
        );

        memcpy(
            reply_eth_hdr->ether_shost,
            iface->addr,
            ETHER_ADDR_LEN
        );

        /* Fill in the reply arp header  */
        sr_arp_hdr_t *reply_arp_hdr = (sr_arp_hdr_t *)(arp_reply_packet+sizeof(struct sr_ethernet_hdr));
        reply_arp_hdr->ar_op = htons(arp_op_reply);
        /* Since almost everything remains same. We'll copy all */
        memcpy(
            reply_arp_hdr,
            request_arp_hdr,
            sizeof(sr_arp_hdr_t)
        );

        /* More MAC copying */
        memcpy(
            reply_arp_hdr->ar_sha,
            iface->addr,
            ETHER_ADDR_LEN
        );
        memcpy(
            reply_arp_hdr->ar_tha,
            request_arp_hdr->ar_sha,
            ETHER_ADDR_LEN
        );

        reply_arp_hdr->ar_sip = iface->ip;
        reply_arp_hdr->ar_tip = request_arp_hdr->ar_sip;

        sr_send_packet(
            inst,
            arp_reply_packet,
            len,
            iface->name
        );

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
            uint8_t *forward_packet = packets->buf;
            sr_ethernet_hdr_t *forward_eth_header = (sr_ethernet_hdr_t *)forward_packet;


            /* Doing the MAC copying stuff */
            memcpy(
                forward_eth_header->ether_dhost,
                arp_reply->ar_sha,
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