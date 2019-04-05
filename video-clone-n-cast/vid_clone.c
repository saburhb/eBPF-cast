#include <bcc/proto.h>

#define ETH_LEN 14

struct out_interface_list
{
    u64 out[100];
    //u64 out2;
    u64 counter;
};

BPF_TABLE("hash", u64, u64, tsmap, 1024);
BPF_TABLE("hash", u64, struct out_interface_list, portmap, 1024);
BPF_TABLE("hash", u64, u64, revport, 1024);

static inline int check_frame_type(struct __sk_buff *skb, u32 start, int *new_flag)
{
        int flag = 0;
        u8 first, second, third, fourth, fifth, sixth;
        first = load_byte(skb, start);
        second = load_byte(skb, start+1);
        third = load_byte(skb, start+2);
        fourth = load_byte(skb, start+3);
        fifth = load_byte(skb, start+4);
        sixth = load_byte(skb, start+5);

        if(0x47 == first)
        {
                //if( 0x4100 == (((second & 0x1F) << 8) | third) ){
                if( (0x41 == second) && (0x00 == third) ){ 
                        if( ( fourth & 0x20 ) && ( fifth > 0 ) ) { // have AF
                                if ( sixth & 0x40 ) { //have random access indicator bit 1
                                        *new_flag = 1;
                                }else{
                                        *new_flag = 2;
                                }
                        }else{
                                *new_flag = 2;
                        }
                }

        }

        return flag;
}


int replicate_forward(struct __sk_buff *skb)
{
  u8 *cursor = 0;
  u32  udp_header_length = 0;
  u32  ip_header_length = 0;
  u32  payload_offset = 0;
  u32  payload_length = 0;

  u8 first, second, third, fourth, fifth, sixth;
  int flag;
  int flag1;
  int new_flag;
  u32 start;
  int current_frame_type = 0;

  u64 ts_key = 1;
  u64 ts_val;
  u64 new_ts_val;
  int k=0;
  int pkt_drop_percent;
  int redirect_flag=0;


  //Get the input and output interface mapping
    u64 in_ifindex = skb->ifindex;
    u64 out_ifindex1;
    u64 out_ifindex2;
    u64 count_val;
    struct out_interface_list* oifl = portmap.lookup(&in_ifindex);

    if(oifl)
    {
	out_ifindex1 = oifl->out[0];
	out_ifindex2 = oifl->out[1];
	count_val = oifl->counter;
    }
    else
    {
        return 1;
    }


    lock_xadd(&oifl->counter, 1);

  //bpf_trace_printk("test_dpi count %d \n", count_val);

  u64 *tsval = tsmap.lookup(&ts_key);
  if(tsval){
        ts_val = *tsval;
  }else{
	bpf_clone_redirect(skb, out_ifindex1, 0);		
	return 1;
  }

  // Check of ethernet/IP frame.
  ethernet: {
    struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(*ethernet));

    if(ethernet->type == ETH_P_IP)
    {
        struct ip_t *ip = cursor_advance(cursor, sizeof(*ip));

        if(ip->nextp == 17)  //protocol value 17 for udp
        {
            struct udp_t *udp = cursor_advance(cursor, sizeof(*udp));

            //if(udp->dport == 1234)

            ip_header_length = 20;
            udp_header_length = 8;

            //calculate payload offset and length
            payload_offset = ETH_HLEN + ip_header_length + udp_header_length;
            payload_length = ip->tlen - ip_header_length - udp_header_length;

            if((payload_length % 188) != 0) {
                goto EOP;
            }

            flag = 0;
            start = payload_offset+4;
            flag1 = check_frame_type(skb, payload_offset, &flag);

            switch(flag){

        case 1:
                bpf_trace_printk("test_dpi Reference-Frame starts\n");
                new_ts_val = 1;
                break;

        case 2:
                bpf_trace_printk("test_dpi nonReference-Frame starts\n");
                new_ts_val = 2;
                break;

        default:
                new_ts_val = 0;
                break;
            }

	if(new_ts_val == 0){
		current_frame_type = ts_val;
	}else{
        	//update the ts map with new frame type
        	tsmap.update(&ts_key, &new_ts_val);
		current_frame_type = new_ts_val;
	}

        }
    }


   pkt_drop_percent = 2;
   if((count_val % pkt_drop_percent) != 0){
	redirect_flag = 1;
   }


   // bpf_clone_redirect(skb, out_ifindex1, 0); //always clone and redirect for out interface 1
    //bpf_clone_redirect(skb, out_ifindex2, 0); //always clone and redirect for out interface 1

    for(k=0; k<12; k++){
	if(oifl->out[k] != 1){ 
		if(redirect_flag == 1){
    			bpf_clone_redirect(skb, oifl->out[k], 0); 
		}
	}
    }

    for(k=12; k<25; k++){
	if(oifl->out[k] != 1){ 
    		if(redirect_flag == 1){
                        bpf_clone_redirect(skb, oifl->out[k], 0);
                }
 
	}
    }
    for(k=25; k<37; k++){
	if(oifl->out[k] != 1){ 
    		if(redirect_flag == 1){
                        bpf_clone_redirect(skb, oifl->out[k], 0);
                }
 
	}
    }
    for(k=37; k<50; k++){
	if(oifl->out[k] != 1){ 
    		if(redirect_flag == 1){
                        bpf_clone_redirect(skb, oifl->out[k], 0);
                }
 
	}
    }
    for(k=50; k<62; k++){
	if(oifl->out[k] != 1){ 
    		if(redirect_flag == 1){
                        bpf_clone_redirect(skb, oifl->out[k], 0);
                }
 
	}
    }
    for(k=62; k<75; k++){
	if(oifl->out[k] != 1){ 
    		if(redirect_flag == 1){
                        bpf_clone_redirect(skb, oifl->out[k], 0);
                }
 
	}
    }
    for(k=75; k<87; k++){
	if(oifl->out[k] != 1){ 
    		if(redirect_flag == 1){
                        bpf_clone_redirect(skb, oifl->out[k], 0);
                }
 
	}
    }
    for(k=87; k<100; k++){
	if(oifl->out[k] != 1){ 
    		if(redirect_flag == 1){
                        bpf_clone_redirect(skb, oifl->out[k], 0);
                }
 
	}
    }
/*    if((count_val % 10) != 0){
	    bpf_clone_redirect(skb, out_ifindex1, 0);
            //bpf_clone_redirect(skb, out_ifindex2, 0);
        }
*/ 
/* 
    if(current_frame_type == 1){
        //Always clone and redirect
        bpf_clone_redirect(skb, out_ifindex1, 0);
    }else{
	//selectively redirect
	if((count_val % 2) != 0){
            bpf_clone_redirect(skb, out_ifindex1, 0);
        }
    }

*/
    goto EOP;
  }

EOP:
  return 1;

}

