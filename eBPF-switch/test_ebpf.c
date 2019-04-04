#include <bcc/proto.h>

#define ETH_LEN 14


BPF_TABLE("hash", u64, u64, portmap, 1024);
BPF_TABLE("hash", u64, u64, revport, 1024);

int test_switching(struct __sk_buff *skb)
{
  u8 *cursor = 0;
  // Check of ethernet/IP frame.
  ethernet: {
    struct ethernet_t *ethernet = cursor_advance(cursor, sizeof(*ethernet));


    u64 in_ifindex = skb->ifindex;
    u64 out_ifindex;
    u64 *val = portmap.lookup(&in_ifindex);

    if(val)
    {
	out_ifindex = *val;
    }
    else
    {
	u64 *rev = revport.lookup(&in_ifindex);
	if(rev)
        {
            out_ifindex = *rev;
        }
        else
        {
            return 1;
        }
    }

    bpf_trace_printk("%x %x \n", in_ifindex, out_ifindex);

    bpf_clone_redirect(skb, out_ifindex, 0);

    goto EOP;
  }

EOP:
  return 1;

}

