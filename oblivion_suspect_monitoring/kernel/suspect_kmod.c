// Copyright © 1337_TECH, July 2025. All rights reserved.
// Provided "AS IS", without warranty of any kind, express or implied.
// Use at your own risk — the authors are not liable for any damages or losses.
// Built for research, experimentation, and security-conscious development.

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/ip.h>
#include <linux/tcp.h>

#define DEVICE_NAME "suspect_kmod"
#define CLASS_NAME "suspect"

static struct nf_hook_ops nfho;
static struct file *log_file;

static unsigned int hook_func(void *priv, struct sk_buff *skb,
                              const struct nf_hook_state *state) {
    struct iphdr *iph;
    struct tcphdr *tcph;
    unsigned char *payload;
    unsigned int payload_len;

    if (!skb) return NF_ACCEPT;
    iph = ip_hdr(skb);
    if (iph->protocol != IPPROTO_TCP) return NF_ACCEPT;

    tcph = (void *)iph + (iph->ihl * 4);
    payload = (unsigned char *)tcph + (tcph->doff * 4);
    payload_len = ntohs(iph->tot_len) - (iph->ihl * 4) - (tcph->doff * 4);

    if (payload_len > 0 && payload[0] == 0x03 && payload[1] == 0x02) {
        printk(KERN_INFO "[suspect_kmod] Suspicious IKEv2-like packet detected.
");
    }

    return NF_ACCEPT;
}

static int __init suspect_init(void) {
    nfho.hook = hook_func;
    nfho.hooknum = NF_INET_PRE_ROUTING;
    nfho.pf = PF_INET;
    nfho.priority = NF_IP_PRI_FIRST;
    nf_register_net_hook(&init_net, &nfho);
    printk(KERN_INFO "[suspect_kmod] Loaded
");
    return 0;
}

static void __exit suspect_exit(void) {
    nf_unregister_net_hook(&init_net, &nfho);
    printk(KERN_INFO "[suspect_kmod] Unloaded
");
}

module_init(suspect_init);
module_exit(suspect_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("1337_TECH");
MODULE_DESCRIPTION("Suspicious packet monitoring module for exploit analysis");
