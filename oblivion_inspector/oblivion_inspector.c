#include <linux/module.h>
#include <linux/kprobes.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/inet.h>
#include <net/sock.h>

#define MAX_TCP_PAYLOAD 1460
#define TCP_DUMP_LEN 64

static int handler_pre(struct kprobe *p, struct pt_regs *regs) {
    struct sk_buff *skb = (struct sk_buff *)regs->di;

    if (!skb)
        return 0;

    // MAC Address print
    if (skb_mac_header_was_set(skb)) {
        const unsigned char *src_mac = eth_hdr(skb)->h_source;
        const unsigned char *dst_mac = eth_hdr(skb)->h_dest;
        printk(KERN_INFO "OblivionEdge: SRC MAC: %pM -> DST MAC: %pM\n", src_mac, dst_mac);
    }

    struct iphdr *iph = ip_hdr(skb);
    struct tcphdr *tcph = tcp_hdr(skb);

    if (iph->version == 4) {
        __be32 saddr = iph->saddr;
        __be32 daddr = iph->daddr;

        printk(KERN_INFO "OblivionEdge: IPv4 %pI4:%d -> %pI4:%d\n",
               &saddr,
               ntohs(tcph->source),
               &daddr,
               ntohs(tcph->dest));
    }

    // Socket state
    if (skb->sk)
        printk(KERN_INFO "Socket state: %d\n", skb->sk->sk_state);

    // Payload logic
    unsigned int ip_len = ntohs(iph->tot_len);
    unsigned int ip_hdr_len = iph->ihl * 4;
    unsigned int tcp_hdr_len = tcph->doff * 4;
    unsigned int payload_len = ip_len - ip_hdr_len - tcp_hdr_len;

    static unsigned char payload_buf[MAX_TCP_PAYLOAD] = {0};

    if (payload_len > 0 && payload_len <= MAX_TCP_PAYLOAD) {
        // Copy safely
        unsigned char *payload_start = (unsigned char *)tcph + tcp_hdr_len;
        memcpy(payload_buf, payload_start, payload_len);

        // Truncate to first 64 bytes for preview
        char hex_dump[TCP_DUMP_LEN * 2 + 1] = {0};
        int dump_len = min(payload_len, TCP_DUMP_LEN);
        for (int i = 0; i < dump_len; i++)
            snprintf(hex_dump + i * 2, 3, "%02x", payload_buf[i]);

        printk(KERN_INFO "OblivionEdge: TCP Payload Length: %u bytes\n", payload_len);
        printk(KERN_INFO "OblivionEdge: TCP Data Preview (hex): %s\n", hex_dump);
    }

    return 0;
}

static struct kprobe kp = {
    .symbol_name = "tcp_v4_rcv",
    .pre_handler = handler_pre,
};

static int __init oblivion_init(void)
{
    printk(KERN_INFO "OblivionEdge: Registering tcp_v4_rcv probe...\n");
    return register_kprobe(&kp);
}

static void __exit oblivion_exit(void)
{
    unregister_kprobe(&kp);
    printk(KERN_INFO "OblivionEdge: Unregistered probe.\n");
}

module_init(oblivion_init);
module_exit(oblivion_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("1337_Tech");
MODULE_DESCRIPTION("Oblivion Edge Secure Kernel Inspector");
