#include "sr_icmp_handler.h"


void sr_send_icmp_t3(struct sr_instance* inst, uint8_t *packet, unsigned int len,  uint8_t icmp_t3_code ,uint32_t src_ip, struct sr_if *iface)
{
    sr_send_icmp(inst, packet, len, 0x03, icmp_t3_code, src_ip, iface);
}


void sr_send_icmp_t11(struct sr_instance* inst, uint8_t *packet, unsigned int len,  uint32_t src_ip, struct sr_if *iface)
{
    sr_send_icmp(inst, packet, len, 0x0b, 0x0, src_ip, iface);
}
