// Copyright © 1337_TECH, July 2025. All rights reserved.
// Provided "AS IS", without warranty of any kind, express or implied.
// Use at your own risk — the authors are not liable for any damages or losses.
// Built for research, experimentation, and security-conscious development.

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/inet.h>

#define DEVICE_NAME "suspect_udp_kmod"
#define CLASS_NAME "suspect"

static struct nf_hook_ops nfho;

/* Helper: read big-endian 16/32 from unsigned char buffer */
static inline uint16_t be16(const unsigned char *p) {
    return (uint16_t)(p[0] << 8 | p[1]);
}
static inline uint32_t be32(const unsigned char *p) {
    return (uint32_t)(p[0] << 24 | p[1] << 16 | p[2] << 8 | p[3]);
}

static unsigned int udp_hook_func(void *priv, struct sk_buff *skb,
                                  const struct nf_hook_state *state)
{
    struct iphdr *iph;
    struct udphdr *udph;
    unsigned char *payload;
    unsigned int payload_len;
    uint16_t sport, dport;

    if (!skb) return NF_ACCEPT;

    /* ensure skb linear so pointer arithmetic is safe */
    if (skb_linearize(skb) != 0) {
        /* couldn't linearize — skip inspection */
        return NF_ACCEPT;
    }

    iph = ip_hdr(skb);
    if (!iph) return NF_ACCEPT;
    if (iph->protocol != IPPROTO_UDP) return NF_ACCEPT;

    /* UDP header is immediately after IP header */
    udph = (struct udphdr *)((unsigned char *)iph + (iph->ihl * 4));

    /* basic sanity: ensure skb has at least IP+UDP headers */
    if ((unsigned char *)udph + sizeof(struct udphdr) > skb_tail_pointer(skb))
        return NF_ACCEPT;

    sport = ntohs(udph->source);
    dport = ntohs(udph->dest);

    /* compute UDP payload pointer and length */
    payload = (unsigned char *)udph + sizeof(struct udphdr);
    payload_len = ntohs(iph->tot_len) - (iph->ihl * 4) - sizeof(struct udphdr);

    if ((int)payload_len <= 0) return NF_ACCEPT;

    /*
     * Detect IKEv2:
     * - UDP/500: IKEv2 messages start at payload (IKE header first 28 bytes).
     * - UDP/4500: per RFC 3947 / RFC 8229, a 4-byte non-ESP marker (0x00000000)
     *   precedes IKE messages on 4500. We check that marker then the IKE header.
     *
     * Minimal heuristics:
     * - Major version nibble of IKE header == 2
     * - IKE header length field (last 4 bytes in header) is sane (>= 28)
     * - For 4500 we expect marker present
     */

    /* Case: UDP/500 (classic IKEv2 on UDP) */
    if (sport == 500 || dport == 500) {
        if (payload_len < 28) goto out_accept; /* too small for IKE header */

        /* payload[0..3] are initiator SPI (8 bytes total in header, but start check at offset 8) */
        /* IKEv2 header layout: SPIi(8) | SPIr(8) | NextPayload(1) | Version(1) | Exchange(1) | Flags(1) | MsgID(4) | Len(4) */
        /* Version byte is at offset 9 (0-based) from start of IKE header */
        if ((unsigned long)payload + 9 >= (unsigned long)skb_tail_pointer(skb)) goto out_accept;

        {
            unsigned char ver = payload[9];
            unsigned char major = (ver >> 4) & 0x0F;
            if (major == 2) {
                /* check ike total length field at offset 24..27 (0-based) exists */
                if (payload_len >= 28) {
                    uint32_t ike_len = be32(payload + 24);
                    if (ike_len >= 28 && ike_len <= payload_len) {
                        printk(KERN_INFO "[%s] Suspicious IKEv2 (UDP/500) detected: src=%pI4:%u dst=%pI4:%u ike_len=%u payload_len=%u\n",
                               DEVICE_NAME,
                               &iph->saddr, sport, &iph->daddr, dport, ike_len, payload_len);
                    } else {
                        /* still suspicious if version matches but lengths odd */
                        printk(KERN_INFO "[%s] IKEv2-version match on UDP/500 but length mismatch: src=%pI4:%u dst=%pI4:%u ike_len=%u payload_len=%u\n",
                               DEVICE_NAME, &iph->saddr, sport, &iph->daddr, dport, ike_len, payload_len);
                    }
                }
            }
        }
        goto out_accept;
    }

    /* Case: UDP/4500 (NAT-T — non-ESP marker may precede IKE) */
    if (sport == 4500 || dport == 4500) {
        /* Need at least 4 bytes marker + 28 bytes IKE header */
        if (payload_len < (4 + 28)) goto out_accept;

        /* ensure marker lies within skb bounds */
        if ((unsigned long)payload + 3 >= (unsigned long)skb_tail_pointer(skb)) goto out_accept;

        /* check non-ESP marker (4 bytes of zero) */
        if (payload[0] == 0x00 && payload[1] == 0x00 && payload[2] == 0x00 && payload[3] == 0x00) {
            unsigned char *ike = payload + 4;
            unsigned int ike_len;
            /* ensure we can read version byte at ike + 9 */
            if ((unsigned long)ike + 9 >= (unsigned long)skb_tail_pointer(skb)) goto out_accept;

            {
                unsigned char ver = ike[9];
                unsigned char major = (ver >> 4) & 0x0F;
                if (major == 2) {
                    if ((unsigned long)ike + 27 >= (unsigned long)skb_tail_pointer(skb)) {
                        /* not enough bytes to read length field */
                        goto out_accept;
                    }
                    ike_len = be32(ike + 24);
                    /* rec_len should be 4 (marker) + ike_len; we have payload_len available */
                    if (ike_len >= 28 && (4 + ike_len) <= payload_len) {
                        printk(KERN_INFO "[%s] Suspicious IKEv2 (UDP/4500 NAT-T) detected: src=%pI4:%u dst=%pI4:%u ike_len=%u payload_len=%u\n",
                               DEVICE_NAME, &iph->saddr, sport, &iph->daddr, dport, ike_len, payload_len);
                    } else {
                        printk(KERN_INFO "[%s] IKEv2-version match on UDP/4500 but length mismatch: src=%pI4:%u dst=%pI4:%u ike_len=%u payload_len=%u\n",
                               DEVICE_NAME, &iph->saddr, sport, &iph->daddr, dport, ike_len, payload_len);
                    }
                }
            }
        }
        goto out_accept;
    }

out_accept:
    return NF_ACCEPT;
}

static int __init suspect_udp_init(void)
{
    memset(&nfho, 0, sizeof(nfho));
    nfho.hook = udp_hook_func;
    nfho.hooknum = NF_INET_PRE_ROUTING;
    nfho.pf = PF_INET;
    nfho.priority = NF_IP_PRI_FIRST;

    if (nf_register_net_hook(&init_net, &nfho) != 0) {
        printk(KERN_ERR "[%s] Failed to register netfilter hook\n", DEVICE_NAME);
        return -EFAULT;
    }

    printk(KERN_INFO "[%s] Loaded\n", DEVICE_NAME);
    return 0;
}

static void __exit suspect_udp_exit(void)
{
    nf_unregister_net_hook(&init_net, &nfho);
    printk(KERN_INFO "[%s] Unloaded\n", DEVICE_NAME);
}

module_init(suspect_udp_init);
module_exit(suspect_udp_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("1337_TECH");
MODULE_DESCRIPTION("Suspicious UDP IKEv2 detector for exploit analysis (ports 500 / 4500)");
