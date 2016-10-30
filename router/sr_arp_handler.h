#include "sr_router.h"
void sr_process_arp_packet(struct sr_instance * sr,uint8_t * packet, unsigned int len, char* interface);

void sr_process_arp_reply(struct sr_instance *inst, uint8_t *packet, unsigned int len, char *interface);
void sr_arp_reply_to_request(struct sr_instance *inst, uint8_t *packet, unsigned int len,char *interface);