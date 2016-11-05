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
                Send corresponding ICMP packet
                Time exceeded (type 11, code 0)
               */
               sr_send_icmp_t11(inst, packet, iface->ip, iface);
               return;
           }

           /*Packet not expired. Forwarding it to right interface*/
           struct sr_rt *forward_rt_entry = sr_find_routing_table_entry(inst->routing_table, ip_hdr);

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
                        ARP entry found. We'll forward it directly. :P
                   */
                   Debug("\tFound a ARP entry in cache. Forwarding it.\n");
                   sr_forward_packet(inst, packet, arp_entry->mac, len, iface);
                   free(arp_entry);
                   return;
               }
               else
               {
                   /*
                        Send an ARP request for the next-hop IP (if one hasn't been
                        sent within the last second), and add the packet to the queue 
                        of packets waiting on this ARP request.
                   */
                   Debug("\tNo ARP entry found in cache. Enqueing this request.\n");
                   /* Enqueing */
                   struct sr_arpreq *arp_req = sr_arpcache_queuereq(
                       &inst->cache,
                       ip_hdr->ip_dst,
                       packet,
                       len,
                       forward_rt_entry->interface
                   );
                   handle_arpreq(inst,arp_req);
                   
               }

           }
           else
           {
               Debug("No routing table entry was found.\n");
               /*JK LOL*/

               /*
                    Send corresponding ICMP packet.
                    Destination net unreachable (type 3, code 0)
               */
               sr_send_icmp_t3(inst, packet, 0x0 ,iface->ip, iface);
           }
       }
       else
       {
            /*
                This packet was for us.
            */   

            Debug("Packet is meant for this router!\n");

            if(ip_hdr->ip_p == ip_protocol_icmp)
            {
                Debug("\tReceived a ICMP packet\n");
                /*
                    Send corresponding ICMP packet
                    Echo reply (type 0)
                */
                sr_send_icmp_echo_reply(inst, packet, len, destination_iface, iface);
            }
            else
            {
                /*
                    Send corresponding ICMP packet
                    Port unreachable (type 3, code 3)
                */
                sr_send_icmp_t3(inst, packet, 0x3, destination_iface->ip, iface);
            }
       }
    }
}