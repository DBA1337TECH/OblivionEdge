// Copyright © 1337_TECH
// Full-frame packet capture kernel module for Wireshark-compatible PCAP output.

#include <linux/module.h>
#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/cdev.h>
#include <linux/wait.h>
#include <linux/mutex.h>
#include <linux/slab.h>

#define DEVICE_NAME "suspect_kmod"
#define CLASS_NAME  "suspect"

#define RING_SIZE     4096
#define MAX_PKT_SIZE  4096    /* Full jumbo-safe frame buffer */

static struct nf_hook_ops nfho;

/* Each ring entry MUST match userspace ABI: [u32 len][packet bytes] */
struct packet_entry {
    u32 len;
    u8  data[MAX_PKT_SIZE];
};

static struct packet_entry ring[RING_SIZE];
static int head = 0, tail = 0;

static DEFINE_MUTEX(ring_lock);
static DECLARE_WAIT_QUEUE_HEAD(ring_wq);

static dev_t dev_number;
static struct class* suspect_class = NULL;
static struct cdev suspect_cdev;

/* -------------------- RING BUFFER -------------------- */

static inline bool ring_is_full(void)
{
    return ((head + 1) % RING_SIZE) == tail;
}

static inline bool ring_is_empty(void)
{
    return head == tail;
}

/* ALWAYS writes: [u32 len] + data[] */
static inline void ring_push(const u8 *buf, u32 len)
{
    if (ring_is_full()) {
        printk(KERN_WARNING "[suspect_kmod] Ring full, dropping packet\n");
        return;
    }

    ring[head].len = len;
    memcpy(ring[head].data, buf, len);

    head = (head + 1) % RING_SIZE;
    wake_up_interruptible(&ring_wq);
}

static inline int ring_pop(u8 *dst, u32 *len)
{
    if (ring_is_empty())
        return 0;

    *len = ring[tail].len;
    memcpy(dst, ring[tail].data, *len);

    tail = (tail + 1) % RING_SIZE;
    return 1;
}

/* -------------------- NETFILTER HOOK -------------------- */

static unsigned int hook_func(void *priv, struct sk_buff *skb,
                              const struct nf_hook_state *state)
{
    if (!skb)
        return NF_ACCEPT;

    unsigned int pkt_len = skb->len;
    if (pkt_len == 0)
        return NF_ACCEPT;

    if (pkt_len > MAX_PKT_SIZE)
        pkt_len = MAX_PKT_SIZE;

    printk(KERN_INFO "[suspect_kmod] hook fired skb_len=%u\n", skb->len);

    /* Allocate safe temp buffer */
    u8 *tmp = kmalloc(pkt_len, GFP_ATOMIC);
    if (!tmp)
        return NF_ACCEPT;

    /* Safe full-frame copy (handles nonlinear SKBs) */
    if (skb_copy_bits(skb, 0, tmp, pkt_len) < 0) {
        printk(KERN_WARNING "[suspect_kmod] skb_copy_bits failed\n");
        kfree(tmp);
        return NF_ACCEPT;
    }

    /* Insert into ring buffer */
    mutex_lock(&ring_lock);
    ring_push(tmp, pkt_len);
    mutex_unlock(&ring_lock);

    kfree(tmp);
    return NF_ACCEPT;
}

/* -------------------- CHAR DEVICE: Userspace Reader -------------------- */

static ssize_t dev_read(struct file *file, char __user *ubuf,
                        size_t count, loff_t *ppos)
{
    u32 len;
    u8 *kbuf;

    if (count < sizeof(u32))
        return -EINVAL;

    kbuf = kmalloc(MAX_PKT_SIZE, GFP_KERNEL);
    if (!kbuf)
        return -ENOMEM;

    /* Sleep until packet exists */
    wait_event_interruptible(ring_wq, !ring_is_empty());

    mutex_lock(&ring_lock);
    if (!ring_pop(kbuf, &len)) {
        mutex_unlock(&ring_lock);
        kfree(kbuf);
        return 0;
    }
    mutex_unlock(&ring_lock);

    if (sizeof(u32) + len > count) {
        kfree(kbuf);
        return -EINVAL;
    }

    if (copy_to_user(ubuf, &len, sizeof(u32))) {
        kfree(kbuf);
        return -EFAULT;
    }

    if (copy_to_user(ubuf + sizeof(u32), kbuf, len)) {
        kfree(kbuf);
        return -EFAULT;
    }

    kfree(kbuf);
    return sizeof(u32) + len;
}

static const struct file_operations fops = {
    .owner = THIS_MODULE,
    .read  = dev_read,
};

/* -------------------- MODULE LIFECYCLE -------------------- */

static int __init suspect_init(void)
{
    alloc_chrdev_region(&dev_number, 0, 1, DEVICE_NAME);

    cdev_init(&suspect_cdev, &fops);
    cdev_add(&suspect_cdev, dev_number, 1);

#if LINUX_VERSION_CODE >= KERNEL_VERSION(6,3,0)
    suspect_class = class_create(CLASS_NAME);
#else
    suspect_class = class_create(THIS_MODULE, CLASS_NAME);
#endif

    device_create(suspect_class, NULL, dev_number, NULL, DEVICE_NAME);

    /* Capture BEFORE routing, NAT, conntrack, etc */
    nfho.hook     = hook_func;
    nfho.hooknum  = NF_INET_PRE_ROUTING;
    nfho.pf       = PF_INET;
    nfho.priority = NF_IP_PRI_FIRST;

    nf_register_net_hook(&init_net, &nfho);

    printk(KERN_INFO "[suspect_kmod] Packet capture module loaded.\n");
    return 0;
}

static void __exit suspect_exit(void)
{
    nf_unregister_net_hook(&init_net, &nfho);
    device_destroy(suspect_class, dev_number);
    class_destroy(suspect_class);
    unregister_chrdev_region(dev_number, 1);

    printk(KERN_INFO "[suspect_kmod] Unloaded.\n");
}

module_init(suspect_init);
module_exit(suspect_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("1337_TECH");
MODULE_DESCRIPTION("Full-frame packet capture module for Oblivion Edge");
