#include "sr_icmp_handler.h"
void sr_send_icmp_t3(struct sr_instance* sr, uint8_t * packet, unsigned int len, uint8_t icmp_type, uint8_t icmp_code, uint32_t src_ip, struct sr_if* recv_iface)
{
    unsigned int reply_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
    uint8_t *icmp_t3_reply_packet = (uint8_t *)malloc(reply_len);
    memset(icmp_t3_reply_packet, 0, reply_len);

    sr_ethernet_hdr_t *received_eth_hdr = (sr_ethernet_hdr_t *)(packet);
    sr_ip_hdr_t *received_ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

    sr_ethernet_hdr_t *reply_eth_hdr = (sr_ethernet_hdr_t *)icmp_t3_reply_packet;
    reply_eth_hdr->ether_type = htons(ethertype_ip);
    memcpy(reply_eth_hdr->ether_dhost, received_eth_hdr->ether_shost, ETHER_ADDR_LEN);
    memcpy(reply_eth_hdr->ether_shost, recv_iface->addr, ETHER_ADDR_LEN);

    /* set ip header */
    sr_ip_hdr_t *reply_ip_hdr = (sr_ip_hdr_t *)(icmp_t3_reply_packet + sizeof(sr_ethernet_hdr_t));
    memcpy(reply_ip_hdr, received_ip_hdr, sizeof(sr_ip_hdr_t));
    reply_ip_hdr->ip_len  = htons(reply_len - sizeof(sr_ethernet_hdr_t));
    reply_ip_hdr->ip_p    = ip_protocol_icmp;
    reply_ip_hdr->ip_src  = src_ip;
    reply_ip_hdr->ip_dst  = received_ip_hdr->ip_src;
    reply_ip_hdr->ip_ttl  = INIT_TTL;
    reply_ip_hdr->ip_sum  = 0;
    reply_ip_hdr->ip_sum  = cksum(reply_ip_hdr, sizeof(sr_ip_hdr_t));


    /* set icmp header */
    sr_icmp_t3_hdr_t *reply_icmp_t3_hdr = (sr_icmp_t3_hdr_t*)(icmp_t3_reply_packet + sizeof(sr_ethernet_hdr_t)+ sizeof(sr_ip_hdr_t));
    reply_icmp_t3_hdr->icmp_type = icmp_type;
    reply_icmp_t3_hdr->icmp_code = icmp_code;
    memcpy(reply_icmp_t3_hdr->data, received_ip_hdr, ICMP_DATA_SIZE);
    reply_icmp_t3_hdr->icmp_sum = 0;
    reply_icmp_t3_hdr->icmp_sum = cksum(reply_icmp_t3_hdr, sizeof(sr_icmp_t3_hdr_t));

    

    sr_send_packet(sr, icmp_t3_reply_packet, reply_len, recv_iface->name);
}

void sr_send_icmp_t11(struct sr_instance* inst, uint8_t *packet, unsigned int len, struct sr_if *iface)
{

}