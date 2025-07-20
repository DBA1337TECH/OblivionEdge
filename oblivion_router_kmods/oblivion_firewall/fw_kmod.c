#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/ioctl.h>

#define DEVICE_NAME "fw_kmod"
#define CLASS_NAME  "fw"
#define IOCTL_ADD_FW_RULE _IOW('F', 1, struct fw_rule)

MODULE_LICENSE("GPL");

struct fw_rule {
    __be32 src_ip;
    __be16 dst_port;
    char action[8];  // "DROP" or "ACCEPT"
};

static struct fw_rule current_rule;

static struct nf_hook_ops nfho;

static unsigned int fw_hook(void *priv, struct sk_buff *skb,
                            const struct nf_hook_state *state) {
    struct iphdr *ip_header;
    struct tcphdr *tcp_header;

    ip_header = ip_hdr(skb);
    if (ip_header->protocol != IPPROTO_TCP) return NF_ACCEPT;

    tcp_header = (struct tcphdr *)((__u32 *)ip_header + ip_header->ihl);
    if (ip_header->saddr == current_rule.src_ip &&
        tcp_header->dest == current_rule.dst_port) {
        if (strncmp(current_rule.action, "DROP", 4) == 0) {
            printk(KERN_INFO "[fw_kmod] Packet dropped\n");
            return NF_DROP;
        }
    }
    return NF_ACCEPT;
}

static long fw_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {
    if (cmd != IOCTL_ADD_FW_RULE)
        return -EINVAL;

    if (copy_from_user(&current_rule, (void __user *)arg, sizeof(current_rule)))
        return -EFAULT;

    pr_info("[fw_kmod] New rule: src=%pI4 dst_port=%hu action=%s\n",
            &current_rule.src_ip, ntohs(current_rule.dst_port), current_rule.action);

    return 0;
}

static struct file_operations fops = {
    .unlocked_ioctl = fw_ioctl,
    .owner = THIS_MODULE,
};

static int major;
static struct class*  fw_class  = NULL;
static struct device* fw_device = NULL;

static int __init fw_init(void) {
    major = register_chrdev(0, DEVICE_NAME, &fops);
    fw_class = class_create(THIS_MODULE, CLASS_NAME);
    fw_device = device_create(fw_class, NULL, MKDEV(major, 0), NULL, DEVICE_NAME);

    nfho.hook = fw_hook;
    nfho.hooknum = NF_INET_PRE_ROUTING;
    nfho.pf = PF_INET;
    nfho.priority = NF_IP_PRI_FIRST;
    nf_register_net_hook(&init_net, &nfho);

    printk(KERN_INFO "[fw_kmod] Loaded\n");
    return 0;
}

static void __exit fw_exit(void) {
    nf_unregister_net_hook(&init_net, &nfho);
    device_destroy(fw_class, MKDEV(major, 0));
    class_unregister(fw_class);
    class_destroy(fw_class);
    unregister_chrdev(major, DEVICE_NAME);
    printk(KERN_INFO "[fw_kmod] Unloaded\n");
}

module_init(fw_init);
module_exit(fw_exit);
