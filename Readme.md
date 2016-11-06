# Router Implemetation

The router is built over mininet, a network emulation.

## Implemented functionality.

+ ping requests are well handled
    + Directed towards router interfaces
    + Directed towards servers
    + Directed to unreachable hosts
    + Directed to unreachable nets
    + Timed out pings (Not Tested)

+ wget (A http request works well and retrieves corresponding data)

+ traceroute succesfully traces a route (There is an issue with the time it takes for the first time)

## Implementation Details

### ARP

When an ARP packet is received *sr_process_arp_packet* is called and it checks if it is a request or a reply to a request.

In the case of it being request, we send out a reply if the packet was meant for us, else it is dropped, this is being handled in *sr_arp_reply_to_request*.

In the case of it being a reply, we check if any ip requests are pending in the request queue that might use this request and appropriately forward such packets, handled in *sr_process_arp_reply*.

### IP

When an IP packet is received a sanity check is performed on it in, *sr_process_ip_packet*. Then we search for an entry in the routing table and look if we have a arp reply for the entry in cache for our packet. If there is arp request in cache we forward the packet, else we enque it in cache. If we don't have an entry then we understand that such a destination is unreachable and send out corresponding icmp packet.

We also handle ttl just after sanity checks.