#include "sr_router.h"
void sr_process_arp_packet(struct sr_instance * inst, struct sr_arp_hdr * request, char * interface);
void sr_process_arp_reply(struct sr_instance * inst, struct sr_arp_hdr * reply, char *interface);
void sr_arp_reply_to_request(struct sr_instance * inst, struct sr_arp_hdr * request, char * interface);