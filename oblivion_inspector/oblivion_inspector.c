/* SPDX-License-Identifier: Proprietary */
/*
 * Oblivion Edge Secure Kernel Module
 * Copyright (c) 2025, 1337_Tech, DBA: Austin, Texas
 *
 * This software is proprietary and confidential. Unauthorized copying,
 * distribution, or modification of this file is strictly prohibited.
 *
 * Licensed for use only under the terms of a separate commercial agreement.
 * For OEM licensing, contact: security@oblivionedge.io
 *
 * Redistribution or disclosure without written permission is prohibited.
 */

#include <linux/kprobes.h>
#include <linux/net.h>

static int handler_pre(struct kprobe *p, struct pt_regs *regs) {
    printk(KERN_INFO "OblivionEdge: TCP packet received!\n");
    return 0;
}

static struct kprobe kp = {
    .symbol_name = "tcp_v4_rcv",
    .pre_handler = handler_pre,   // this is what links it
};


static int __init oblivion_init(void) {
    return register_kprobe(&kp);
}

static void __exit oblivion_exit(void) {
    unregister_kprobe(&kp);
}

module_init(oblivion_init)
module_exit(oblivion_exit)
MODULE_LICENSE("GPL");

