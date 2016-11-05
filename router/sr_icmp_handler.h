#include "sr_router.h"
#include "sr_protocol.h"
void sr_send_icmp(struct sr_instance* sr, uint8_t * packet, unsigned int len,  uint8_t icmp_type, uint8_t icmp_code, uint32_t src_ip, struct sr_if* recv_iface);
void sr_send_icmp_t3(struct sr_instance* inst, uint8_t *packet, unsigned int len,  uint8_t icmp_t3_code, uint32_t src_ip, struct sr_if *iface);
void sr_send_icmp_t11(struct sr_instance* inst, uint8_t *packet, unsigned int len, uint32_t src_ip, struct sr_if *iface);
void sr_send_icmp_echo_reply(struct sr_instance *inst, uint8_t *packet, unsigned int len, struct sr_if *destination_iface, struct sr_if *recv_iface );