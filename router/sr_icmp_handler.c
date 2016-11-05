#include "sr_icmp_handler.h"
void sr_send_icmp(struct sr_instance* sr, uint8_t * packet,  uint8_t icmp_type, uint8_t icmp_code, uint32_t src_ip, struct sr_if* recv_iface)
{
    unsigned int reply_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
    uint8_t *icmp_reply_packet = (uint8_t *)malloc(reply_len);
    memset(icmp_reply_packet, 0, reply_len);

    sr_ethernet_hdr_t *received_eth_hdr = (sr_ethernet_hdr_t *)(packet);
    sr_ip_hdr_t *received_ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

    sr_ethernet_hdr_t *reply_eth_hdr = (sr_ethernet_hdr_t *)icmp_reply_packet;
    reply_eth_hdr->ether_type = htons(ethertype_ip);
    memcpy(reply_eth_hdr->ether_dhost, received_eth_hdr->ether_shost, ETHER_ADDR_LEN);
    memcpy(reply_eth_hdr->ether_shost, recv_iface->addr, ETHER_ADDR_LEN);

    /* set ip header */
    sr_ip_hdr_t *reply_ip_hdr = (sr_ip_hdr_t *)(icmp_reply_packet + sizeof(sr_ethernet_hdr_t));
    memcpy(reply_ip_hdr, received_ip_hdr, sizeof(sr_ip_hdr_t));
    reply_ip_hdr->ip_len  = htons(reply_len - sizeof(sr_ethernet_hdr_t));
    reply_ip_hdr->ip_p    = ip_protocol_icmp;
    reply_ip_hdr->ip_src  = src_ip;
    reply_ip_hdr->ip_dst  = received_ip_hdr->ip_src;
    reply_ip_hdr->ip_ttl  = INIT_TTL;
    reply_ip_hdr->ip_sum  = 0;
    reply_ip_hdr->ip_sum  = cksum(reply_ip_hdr, sizeof(sr_ip_hdr_t));


    /* set icmp header */
    sr_icmp_t3_hdr_t *reply_icmp_t3_hdr = (sr_icmp_t3_hdr_t*)(icmp_reply_packet + sizeof(sr_ethernet_hdr_t)+ sizeof(sr_ip_hdr_t));
    reply_icmp_t3_hdr->icmp_type = icmp_type;
    reply_icmp_t3_hdr->icmp_code = icmp_code;
    memcpy(reply_icmp_t3_hdr->data, received_ip_hdr, ICMP_DATA_SIZE);
    reply_icmp_t3_hdr->icmp_sum = 0;
    reply_icmp_t3_hdr->icmp_sum = cksum(reply_icmp_t3_hdr, sizeof(sr_icmp_t3_hdr_t));

    

    sr_send_packet(sr, icmp_reply_packet, reply_len, recv_iface->name);
}

void sr_send_icmp_t3(struct sr_instance* inst, uint8_t *packet,  uint8_t icmp_t3_code ,uint32_t src_ip, struct sr_if *iface)
{
    sr_send_icmp(inst, packet,  0x03, icmp_t3_code, src_ip, iface);
}


void sr_send_icmp_t11(struct sr_instance* inst, uint8_t *packet,  uint32_t src_ip, struct sr_if *iface)
{
    sr_send_icmp(inst, packet,  0x0b, 0x0, src_ip, iface);
}

void sr_send_icmp_echo_reply(struct sr_instance *sr, uint8_t *packet, unsigned int len, struct sr_if *dest_iface, struct sr_if *recv_iface )
{
    sr_ethernet_hdr_t *req_eth_hdr = (sr_ethernet_hdr_t *)(packet);
    sr_ip_hdr_t *req_ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
    sr_icmp_hdr_t *req_icmp_hdr = (sr_icmp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

    uint8_t *icmp_echo_rely_packet;
    icmp_echo_rely_packet = (uint8_t *) malloc(len);
    memset(icmp_echo_rely_packet, 0, len * sizeof(uint8_t));

    sr_ethernet_hdr_t *rply_eth_hdr = (sr_ethernet_hdr_t *)(icmp_echo_rely_packet);
    rply_eth_hdr->ether_type = htons(ethertype_ip);
    memcpy(rply_eth_hdr->ether_dhost, req_eth_hdr->ether_shost, ETHER_ADDR_LEN);
    memcpy(rply_eth_hdr->ether_shost, recv_iface->addr, ETHER_ADDR_LEN);

    sr_ip_hdr_t *rply_ip_hdr = (sr_ip_hdr_t *)(icmp_echo_rely_packet + sizeof(sr_ethernet_hdr_t));
    memcpy(rply_ip_hdr, req_ip_hdr, sizeof(sr_ip_hdr_t));
    rply_ip_hdr->ip_src = dest_iface->ip;
    rply_ip_hdr->ip_dst = req_ip_hdr->ip_src;
    rply_ip_hdr->ip_sum = 0;
    rply_ip_hdr->ip_sum = cksum(rply_ip_hdr, sizeof(sr_ip_hdr_t));

    sr_icmp_hdr_t *rply_icmp_hdr = (sr_icmp_hdr_t *)(icmp_echo_rely_packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
    memcpy(rply_icmp_hdr, req_icmp_hdr, sizeof(sr_icmp_hdr_t));

    rply_icmp_hdr->icmp_type = htons(0x00);
    rply_icmp_hdr->icmp_code = htons(0x00);

    unsigned int total_hdr_len = sizeof(sr_ethernet_hdr_t) +
    sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_hdr_t);
    if(total_hdr_len < len)
    memcpy(icmp_echo_rely_packet + total_hdr_len, packet + total_hdr_len,
    len - total_hdr_len);

    rply_icmp_hdr->icmp_sum = 0;
    rply_icmp_hdr->icmp_sum = cksum(rply_icmp_hdr, len -
    sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));

    sr_send_packet(sr, icmp_echo_rely_packet, len, recv_iface->name);
}