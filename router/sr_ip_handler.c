#include "sr_ip_handler.h"
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
       printf("Received a Good IP Packet\n"); 
    }
}