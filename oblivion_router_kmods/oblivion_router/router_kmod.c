// Copyright © 1337_TECH, July 2025. All rights reserved.
// Provided "AS IS", without warranty of any kind, express or implied.
// Use at your own risk — the authors are not liable for any damages or losses.
// Built for research, experimentation, and security-conscious development.


#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <linux/fs.h>
#include <linux/uaccess.h>
#include <linux/ioctl.h>

#define DEVICE_NAME "router_kmod"
#define CLASS_NAME  "router"

#define IOCTL_ADD_ROUTE _IOW('R', 1, struct route_entry)

MODULE_LICENSE("GPL");

struct route_entry {
    __be32 dest;
    __be32 gateway;
    __be32 netmask;
    char ifname[IFNAMSIZ];
};

static int major;
static struct class*  router_class  = NULL;
static struct device* router_device = NULL;

static long router_ioctl(struct file *file, unsigned int cmd, unsigned long arg) {
    struct route_entry route;

    if (cmd != IOCTL_ADD_ROUTE)
        return -EINVAL;

    if (copy_from_user(&route, (void __user *)arg, sizeof(route)))
        return -EFAULT;

    pr_info("[router_kmod] Adding route: dst=%pI4 gw=%pI4 if=%s\n",
            &route.dest, &route.gateway, route.ifname);

    // NOTE: In practice, route manipulation uses rtnetlink from user space.
    // Here we just simulate for the PoC (e.g., for a learning/controlled kernel lab)
    return 0;
}

static struct file_operations fops = {
    .unlocked_ioctl = router_ioctl,
    .owner = THIS_MODULE,
};

static int __init router_init(void) {
    major = register_chrdev(0, DEVICE_NAME, &fops);
    router_class = class_create(THIS_MODULE, CLASS_NAME);
    router_device = device_create(router_class, NULL, MKDEV(major, 0), NULL, DEVICE_NAME);
    pr_info("[router_kmod] Module loaded\n");
    return 0;
}

static void __exit router_exit(void) {
    device_destroy(router_class, MKDEV(major, 0));
    class_unregister(router_class);
    class_destroy(router_class);
    unregister_chrdev(major, DEVICE_NAME);
    pr_info("[router_kmod] Module unloaded\n");
}

module_init(router_init);
module_exit(router_exit);
