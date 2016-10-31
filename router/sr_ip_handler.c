#include "sr_ip_handler.h"
void sr_process_ip_packet(struct sr_instance * inst, uint8_t * packet, unsigned int len, char* interface)
{
    struct sr_ip_hdr *ip_hdr = (struct sr_ip_hdr *)(packet + sizeof(struct sr_ethernet_hdr));
    struct sr_if *iface =sr_get_interface(inst, interface);
    if( ip_hdr->ip_sum  != ipheader_checksum(ip_hdr))
    {
        printf("\nchecksums differ %x, %x\n", ip_hdr->ip_sum, ipheader_checksum(ip_hdr));
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

           /* Decreasing the ttl*/
           ip_hdr->ip_ttl = ip_hdr->ip_ttl - 1;
           /* Recomputing Checksum */
           ip_hdr->ip_sum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));

           if(ip_hdr->ip_ttl == 0)
           {
               Debug("\tThis packet has expired. Simply dropping it\n\tSending a ICMP packet for consistency.\n");

               /*
                To do write code to send ICMP ttl
               */
               return;
           }

           /*Packet not expired. Forwarding it to right interface*/
           struct sr_rt *forward_rt_entry = NULL;

           /* This is no way Longest Prefix Match */
           /* Exact matching has been done to find the destination :(*/
           struct sr_rt* routing_table = inst->routing_table;
           while(routing_table)
           {
               if(forward_rt_entry == NULL || 
               routing_table->mask.s_addr > forward_rt_entry->mask.s_addr )
               {
                   if((ip_hdr->ip_dst & routing_table->mask.s_addr) == 
                   (routing_table->dest.s_addr & routing_table->mask.s_addr))
                   {
                       forward_rt_entry = routing_table;
                   }
               }
               routing_table = routing_table->next;
           }

           if(forward_rt_entry)
           {

               Debug("\tFound a routing table entry to forward the packet\n");
               /*
                    Check the ARP cache for the next-hop MAC address corresponding to the next-hop IP.
               */
               struct sr_arpentry *arp_entry = sr_arpcache_lookup(
                   &(inst->cache),
                   ip_hdr->ip_dst
               );

               if(arp_entry)
               {
                   /*
                        ARP entry found. We'll send it directly. :P
                   */
                   
                   Debug("\tFound a ARP entry in cache.");
                   sr_ethernet_hdr_t *forward_eth_header = (sr_ethernet_hdr_t *)packet;

                    /* Doing the MAC copying stuff */
                    memcpy(
                        forward_eth_header->ether_dhost,
                        arp_entry->mac,
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

                    /* Send this shit now */
                    sr_send_packet(
                        inst,
                        packet,
                        len,
                        iface->name
                    );
               }
               else
               {
                   
               }

           }


       }
    }
}