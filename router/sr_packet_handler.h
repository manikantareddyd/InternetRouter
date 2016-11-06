#include "sr_router.h"
void sr_forward_packet(struct sr_instance *inst, uint8_t *packet, unsigned char *sender_hardware_address,  unsigned char *destination_hardware_address, unsigned int len, struct sr_if *iface);
void sr_send_arp_request(struct sr_instance *inst, uint8_t *packet, unsigned int len, struct sr_if *iface);
void sr_send_arp_request_ip(struct sr_instance *inst,   uint32_t req_ip,struct sr_if *iface);
void sr_send_icmp(struct sr_instance* sr, uint8_t * packet, unsigned int len,  uint8_t icmp_type, uint8_t icmp_code, uint32_t src_ip, struct sr_if* recv_iface);
void sr_send_icmp_echo_reply(struct sr_instance *inst, uint8_t *packet, unsigned int len, struct sr_if *destination_iface, struct sr_if *recv_iface );