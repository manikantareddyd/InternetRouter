#include "sr_packet_handler.h"
void sr_forward_packet(struct sr_instance *inst, uint8_t *packet, unsigned char *sender_hardware_address, unsigned int len, struct sr_if *iface)
{
    Debug("\nOriginal packet to forward\n");
    /*print_hdrs(packet, len);*/
    sr_ethernet_hdr_t *forward_eth_header = (sr_ethernet_hdr_t *)packet;

    /* Doing the MAC copying stuff */
    memcpy(
        forward_eth_header->ether_dhost,
        sender_hardware_address,
        ETHER_ADDR_LEN
    );

    memcpy(
        forward_eth_header->ether_shost,
        iface->addr,
        ETHER_ADDR_LEN
    );
    

    /* Checksum related stuff */
    sr_ip_hdr_t *forward_ip_header = (sr_ip_hdr_t*)(packet+sizeof(sr_ethernet_hdr_t));
    forward_ip_header->ip_sum = 0;
    forward_ip_header->ip_sum = cksum(forward_ip_header, sizeof(sr_ip_hdr_t));

    Debug("\nModified packet to forward\n");
    /*print_hdrs(packet, len);*/


    /* Send this shit now */
    sr_send_packet(
        inst,
        packet,
        len,
        iface->name
    );
}

void sr_send_arp_request(struct sr_instance *inst, uint8_t *packet, unsigned int len, struct sr_if *iface)
{
    /* headers */
    
    sr_ethernet_hdr_t *request_eth_hdr = (sr_ethernet_hdr_t *)(packet);
    sr_arp_hdr_t *request_arp_hdr = (sr_arp_hdr_t *)(packet + sizeof(struct sr_ethernet_hdr));
    int arp_reply_packet_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
    /* Create a Reply Packer */
    uint8_t *arp_reply_packet = (uint8_t *) malloc(arp_reply_packet_len);
    memset(arp_reply_packet, 0,  arp_reply_packet_len );
    Debug("\nOriginal arp packet\n");
    /*print_hdrs(packet, len);*/
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
    /* Since almost everything remains same. We'll copy all and set what's required*/
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
    Debug("\nARP Reply Packet for arp request\n");
    /*print_hdrs(arp_reply_packet,arp_reply_packet_len);*/
    sr_send_packet(
        inst,
        arp_reply_packet,
        arp_reply_packet_len,
        iface->name
    );
}

void sr_send_arp_request_ip(struct sr_instance *inst, uint8_t *packet,  uint32_t req_ip, unsigned int len, struct sr_if *iface)
{
    /* headers */
    sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
    int arp_reply_packet_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
    /* Create a Reply Packer */
    uint8_t *arp_reply_packet = (uint8_t *) malloc(arp_reply_packet_len);
    memset(arp_reply_packet, 0,  arp_reply_packet_len );
    Debug("\nOriginal ip packet\n");
    /*print_hdrs(packet, len);*/
    /* Fill in the reply ethernet Header*/
    sr_ethernet_hdr_t *reply_eth_hdr = (sr_ethernet_hdr_t *)(arp_reply_packet);
    reply_eth_hdr->ether_type = htons(ethertype_arp);
    
    /*Doing the MAC copying stuff */

    memcpy(
        reply_eth_hdr->ether_shost,
        iface->addr,
        ETHER_ADDR_LEN
    );

    /* Fill in the reply arp header  */
    sr_arp_hdr_t *reply_arp_hdr = (sr_arp_hdr_t *)(arp_reply_packet+sizeof(struct sr_ethernet_hdr));
    reply_arp_hdr->ar_op = htons(arp_op_reply);

    /* More MAC copying */
    memcpy(
        reply_arp_hdr->ar_sha,
        iface->addr,
        ETHER_ADDR_LEN
    );


    reply_arp_hdr->ar_sip = iface->ip;
    reply_arp_hdr->ar_tip = ip_hdr->ip_dst;
    Debug("\nARP Broadcast Packet for ip packet\n");
    /*print_hdrs(arp_reply_packet,arp_reply_packet_len);*/
    sr_send_packet(
        inst,
        arp_reply_packet,
        arp_reply_packet_len,
        iface->name
    );
}