// read_suspect_packets.c
// Copyright © 1337_TECH, July 2025.
// Provided "AS IS", without warranty of any kind.

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/netdevice.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/cdev.h>
#include <linux/kfifo.h>
#include <linux/wait.h>
#include <linux/slab.h>
#include <linux/poll.h>

#define DEVICE_NAME "suspect_kmod"
#define CLASS_NAME  "suspect"
#define KFIFO_BYTES (1 << 20)     /* 1 MiB pipe */
#define MAX_PKT_COPY (64 * 1024)  /* per-frame cap */

static struct nf_hook_ops nfho;
static dev_t devt;
static struct cdev suspect_cdev;
static struct class *suspect_class;
static struct device *suspect_device;

/* FIFO holds framed records: [u32 LE len][payload bytes] */
static struct kfifo fifo;
static DECLARE_WAIT_QUEUE_HEAD(fifo_wait);
static DEFINE_MUTEX(fifo_lock);

static int fifo_push_frame(const unsigned char *data, uint32_t len)
{
    uint32_t le_len = cpu_to_le32(len);
    if (!len || len > MAX_PKT_COPY) return -EINVAL;

    mutex_lock(&fifo_lock);
    if (kfifo_avail(&fifo) < len + sizeof(le_len)) {
        mutex_unlock(&fifo_lock);
        return -ENOSPC;
    }
    if (kfifo_in(&fifo, &le_len, sizeof(le_len)) != sizeof(le_len) ||
        kfifo_in(&fifo, data, len) != len) {
        mutex_unlock(&fifo_lock);
        return -EIO;
    }
    wake_up_interruptible(&fifo_wait);
    mutex_unlock(&fifo_lock);
    return 0;
}

/* Netfilter hook for IPv4 TCP
 * NOTE: name must NOT be 'nf_hookfn' (that's a typedef in <linux/netfilter.h>)
 */
static unsigned int tcp_nf_hook(void *priv, struct sk_buff *skb,
                                const struct nf_hook_state *state)
{
    struct iphdr *iph;
    struct tcphdr *tcph;
    unsigned char *payload;
    unsigned int payload_len;
    int ret;

    if (!skb) return NF_ACCEPT;
    if (skb_linearize(skb) != 0) return NF_ACCEPT;

    iph = ip_hdr(skb);
    if (!iph || iph->protocol != IPPROTO_TCP) return NF_ACCEPT;

    tcph = (struct tcphdr *)((unsigned char *)iph + (iph->ihl * 4));
    if ((unsigned char *)tcph + sizeof(*tcph) > skb_tail_pointer(skb)) return NF_ACCEPT;

    payload = (unsigned char *)tcph + (tcph->doff * 4);
    if ((unsigned long)payload > (unsigned long)skb_tail_pointer(skb)) return NF_ACCEPT;

    payload_len = ntohs(iph->tot_len) - (iph->ihl * 4) - (tcph->doff * 4);
    if ((int)payload_len <= 0) return NF_ACCEPT;

    /* Simple heuristic (as before): 0x03 0x02 at payload start */
    if (payload_len >= 2 && payload[0] == 0x03 && payload[1] == 0x02) {
        uint32_t to_copy = payload_len;
        if (to_copy > MAX_PKT_COPY) to_copy = MAX_PKT_COPY;

        ret = fifo_push_frame(payload, to_copy);
        if (ret == -ENOSPC) {
            printk(KERN_WARNING "[" DEVICE_NAME "] FIFO full — dropping suspicious TCP payload (%u bytes)\n", to_copy);
        } else if (ret) {
            printk(KERN_ERR "[" DEVICE_NAME "] FIFO push error: %d\n", ret);
        } else {
            printk(KERN_INFO "[" DEVICE_NAME "] Enqueued suspicious TCP payload (%u bytes)\n", to_copy);
        }
    }

    return NF_ACCEPT;
}

/* Character device file ops */

static ssize_t suspect_read(struct file *file, char __user *buf, size_t count, loff_t *ppos)
{
    unsigned int copied = 0;
    int ret;

    if (count == 0) return 0;

    if (kfifo_is_empty(&fifo)) {
        if (file->f_flags & O_NONBLOCK) return -EAGAIN;
        ret = wait_event_interruptible(fifo_wait, !kfifo_is_empty(&fifo));
        if (ret) return ret;
    }

    mutex_lock(&fifo_lock);
    ret = kfifo_to_user(&fifo, buf, count, &copied);
    mutex_unlock(&fifo_lock);

    return ret ? ret : copied;
}

static unsigned int suspect_poll(struct file *file, poll_table *wait)
{
    unsigned int mask = 0;
    poll_wait(file, &fifo_wait, wait);
    if (!kfifo_is_empty(&fifo)) mask |= POLLIN | POLLRDNORM;
    return mask;
}

static int suspect_open(struct inode *inode, struct file *file)   { return 0; }
static int suspect_release(struct inode *inode, struct file *file){ return 0; }

static const struct file_operations suspect_fops = {
    .owner   = THIS_MODULE,
    .read    = suspect_read,
    .poll    = suspect_poll,
    .open    = suspect_open,
    .release = suspect_release,
};

static int __init read_suspect_init(void)
{
    int ret;

    ret = alloc_chrdev_region(&devt, 0, 1, DEVICE_NAME);
    if (ret) return ret;

    cdev_init(&suspect_cdev, &suspect_fops);
    suspect_cdev.owner = THIS_MODULE;
    ret = cdev_add(&suspect_cdev, devt, 1);
    if (ret) {
        unregister_chrdev_region(devt, 1);
        return ret;
    }

    /* Newer API: class_create(const char *name) */
    suspect_class = class_create(CLASS_NAME);
    if (IS_ERR(suspect_class)) {
        cdev_del(&suspect_cdev);
        unregister_chrdev_region(devt, 1);
        return PTR_ERR(suspect_class);
    }

    suspect_device = device_create(suspect_class, NULL, devt, NULL, DEVICE_NAME);
    if (IS_ERR(suspect_device)) {
        class_destroy(suspect_class);
        cdev_del(&suspect_cdev);
        unregister_chrdev_region(devt, 1);
        return PTR_ERR(suspect_device);
    }

    if (kfifo_alloc(&fifo, KFIFO_BYTES, GFP_KERNEL)) {
        device_destroy(suspect_class, devt);
        class_destroy(suspect_class);
        cdev_del(&suspect_cdev);
        unregister_chrdev_region(devt, 1);
        return -ENOMEM;
    }

    memset(&nfho, 0, sizeof(nfho));
    nfho.hook     = tcp_nf_hook;
    nfho.hooknum  = NF_INET_PRE_ROUTING;
    nfho.pf       = PF_INET;
    nfho.priority = NF_IP_PRI_FIRST;

    ret = nf_register_net_hook(&init_net, &nfho);
    if (ret) {
        kfifo_free(&fifo);
        device_destroy(suspect_class, devt);
        class_destroy(suspect_class);
        cdev_del(&suspect_cdev);
        unregister_chrdev_region(devt, 1);
        return ret;
    }

    printk(KERN_INFO "[" DEVICE_NAME "] loaded, device=/dev/%s\n", DEVICE_NAME);
    return 0;
}

static void __exit read_suspect_exit(void)
{
    nf_unregister_net_hook(&init_net, &nfho);
    kfifo_free(&fifo);
    device_destroy(suspect_class, devt);
    class_destroy(suspect_class);
    cdev_del(&suspect_cdev);
    unregister_chrdev_region(devt, 1);
    printk(KERN_INFO "[" DEVICE_NAME "] unloaded\n");
}

module_init(read_suspect_init);
module_exit(read_suspect_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("1337_TECH");
MODULE_DESCRIPTION("read_suspect_packets — expose suspicious TCP payloads on /dev/suspect_kmod");
