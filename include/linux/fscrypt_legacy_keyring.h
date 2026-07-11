/*
 * Copyright (C) 2026 The LineageOS Project
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#ifndef _LINUX_FSCRYPT_LEGACY_KEYRING_H
#define _LINUX_FSCRYPT_LEGACY_KEYRING_H

#include <linux/fs.h>
#include <linux/key.h>

struct key *fscrypt_legacy_request_key(const char *description);

int fscrypt_legacy_ioctl_add_key(struct file *filp, void __user *uarg);
int fscrypt_legacy_ioctl_remove_key(struct file *filp, void __user *uarg);
int fscrypt_legacy_ioctl_remove_key_all_users(struct file *filp,
					      void __user *uarg);
int fscrypt_legacy_ioctl_get_key_status(struct file *filp,
					void __user *uarg);

#endif /* _LINUX_FSCRYPT_LEGACY_KEYRING_H */
