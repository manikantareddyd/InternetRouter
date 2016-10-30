#include "sr_arp_handler.h"
void sr_process_arp_packet(struct sr_instance * inst, struct sr_arp_hdr * request, char * interface)
{
    switch(ntohs(request->ar_op))
    {
      case arp_op_request:
          printf("Its a Request\n");
          sr_arp_reply_to_request(inst,request,interface);
          break;
      case arp_op_reply:
          printf("Its a Reply\n");
          sr_process_arp_reply(inst,request);
          break;
    }
}

void sr_process_arp_reply(struct sr_instance * inst, struct sr_arp_hdr * reply)
{
  ;  
}

void sr_arp_reply_to_request(struct sr_instance *inst, struct sr_arp_hdr * request, char *interface)
{
 ; 
}