#include "sr_ip_handler.h"
void sr_process_ip_packet(struct sr_instance * inst, uint8_t * packet, unsigned int len, char* interface)
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

       /* Find Destination !*/
       struct sr_if *ifaces = inst->if_list;
       struct sr_if *destination_iface = NULL;
       /* We'll loop through all the interfaces to find out which interface has the destination ip */
       while(ifaces)
       {
           if(ifaces->ip == ip_hdr->ip_dst)
           {
               destination_iface = ifaces;
               break;
           }
           ifaces = ifaces->next;
       }
       
       if(destination_iface == NULL)
       {
           Debug("\tThis packet is not meant for us. We'll re-route\n");

           ip_hdr->ip_ttl = ip_hdr->ip_ttl - 1;
           if(ip_hdr->ip_ttl == 0)
           {
               Debug("\tThis packet has also expired. Simply dropping it\n\tSending a ICMP packet for consistency.\n");

               /*
                To do write code to send ICMP ttl
               */
               return;
           }

           /*Packet not expired. Forwarding it to right interface*/
           
       }
    }
}