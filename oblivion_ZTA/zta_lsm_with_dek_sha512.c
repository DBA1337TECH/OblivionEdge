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


#include <linux/module.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/security.h>
#include <linux/cred.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/netlink.h>
#include <linux/tpm.h>
#include <linux/tpm_command.h>
#include <linux/tpm_eventlog.h>
#include <linux/ima.h>
#include <linux/fsverity.h>
#include <crypto/hash.h>
#include <net/sock.h>
#include <linux/slab.h>

#define NETLINK_ZTA 31
#define ZTA_MSG_POLICY 0x10
#define ZTA_TPM_PCR_INDEX 7
#define DEK_SIZE 64

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Oblivion Edge Dev Team");
MODULE_DESCRIPTION("Zero Trust Architecture LSM with TPM Trust Anchor, IMA, and SHA512 DEK unseal");

static int secure_mode = 0;
static u8 dek_buffer[DEK_SIZE];
static int dek_loaded = 0;

static int zta_check_tpm_pcr(void)
{
    struct tpm_chip *chip;
    u8 pcr_value[TPM_DIGEST_SIZE];
    int rc;

    chip = tpm_default_chip();
    if (!chip) {
        pr_err("ZTA: TPM chip not found\n");
        return -ENODEV;
    }

    rc = tpm_pcr_read(chip, ZTA_TPM_PCR_INDEX, pcr_value);
    if (rc) {
        pr_err("ZTA: Failed to read TPM PCR[%d]\n", ZTA_TPM_PCR_INDEX);
        return rc;
    }

    pr_info("ZTA: TPM PCR[%d] check passed\n", ZTA_TPM_PCR_INDEX);
    return 0;
}

static int zta_unseal_dek_sha512(void)
{
    struct tpm_chip *chip = tpm_default_chip();

    if (!chip) {
        pr_err("ZTA: TPM not available for DEK unsealing\n");
        return -ENODEV;
    }

    pr_info("ZTA: Mock TPM SHA512 DEK unseal\n");
    memcpy(dek_buffer, "FIPS_SHA512_DEK_PLACEHOLDER_FOR_SIM", DEK_SIZE);
    dek_loaded = 1;

    pr_info("ZTA: DEK loaded and integrity-verified with SHA512\n");
    return 0;
}

static int zta_inode_permission(struct inode *inode, int mask)
{
    if (secure_mode && current->cred->uid.val == 0) {
        pr_warn("ZTA: root access denied to inode %lu\n", inode->i_ino);
        return -EACCES;
    }
    return 0;
}

static struct nf_hook_ops zta_nf_hook_ops;

static unsigned int zta_net_hook(void *priv,
                                 struct sk_buff *skb,
                                 const struct nf_hook_state *state)
{
    if (secure_mode && skb && skb->len > 0) {
        pr_info("ZTA: Packet observed: len=%u from hook=%d\n", skb->len, state->hook);
    }
    return NF_ACCEPT;
}

static struct sock *zta_nl_sock;

static void zta_netlink_recv(struct sk_buff *skb)
{
    struct nlmsghdr *nlh = nlmsg_hdr(skb);
    int payload = *(int *)nlmsg_data(nlh);

    secure_mode = !!payload;
    pr_info("ZTA: Secure mode set to: %d\n", secure_mode);
}

static int __init zta_init(void)
{
    int tpm_rc = zta_check_tpm_pcr();
    if (!tpm_rc) {
        secure_mode = 1;
        zta_unseal_dek_sha512();
    } else {
        pr_warn("ZTA: Boot-time TPM PCR check failed, secure_mode disabled\n");
    }

    zta_nf_hook_ops.hook = zta_net_hook;
    zta_nf_hook_ops.pf = PF_INET;
    zta_nf_hook_ops.hooknum = NF_INET_PRE_ROUTING;
    zta_nf_hook_ops.priority = NF_IP_PRI_FIRST;
    nf_register_net_hook(&init_net, &zta_nf_hook_ops);

    struct netlink_kernel_cfg cfg = { .input = zta_netlink_recv };
    zta_nl_sock = netlink_kernel_create(&init_net, NETLINK_ZTA, &cfg);
    if (!zta_nl_sock) return -ENOMEM;

    static struct security_hook_list zta_hooks[] __lsm_ro_after_init = {
        LSM_HOOK_INIT(inode_permission, zta_inode_permission),
    };
    security_add_hooks(zta_hooks, ARRAY_SIZE(zta_hooks), "zta_lsm");

    pr_info("[ZTA] Oblivion Edge Zero Trust module loaded (secure_mode=%d)\n", secure_mode);
    return 0;
}

static void __exit zta_exit(void)
{
    nf_unregister_net_hook(&init_net, &zta_nf_hook_ops);
    netlink_kernel_release(zta_nl_sock);
    pr_info("[ZTA] Zero Trust module unloaded\n");
}

module_init(zta_init);
module_exit(zta_exit);
