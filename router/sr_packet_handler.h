#include "sr_router.h"
void sr_forward_packet(struct sr_instance *inst, uint8_t *packet, unsigned char *sender_hardware_address, unsigned int len, struct sr_if *iface);
void sr_send_arp_request(struct sr_instance *inst, uint8_t *packet, struct sr_if *iface);