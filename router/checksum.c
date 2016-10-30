
#include "checksum.h"

unsigned short ipheader_checksum(struct sr_ip_hdr * ip_hdr)
{
    struct sr_ip_hdr *iph = ip_hdr;
    iph->ip_sum = 0;
    return cksum((unsigned short *)iph,sizeof(struct sr_ip_hdr));
}
