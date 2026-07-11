/*
 * Copyright (C) 2026 The LineageOS Project
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <keys/user-type.h>
#include <linux/capability.h>
#include <linux/cred.h>
#include <linux/dcache.h>
#include <linux/export.h>
#include <linux/fs.h>
#include <linux/fscrypt_legacy_keyring.h>
#include <linux/key.h>
#include <linux/kernel.h>
#include <linux/mutex.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/uidgid.h>

#define FSCRYPT_LEGACY_DESCRIPTION_SIZE \
	(FS_KEY_DESC_PREFIX_SIZE + 2 * FSCRYPT_KEY_DESCRIPTOR_SIZE + 1)

static const char * const fscrypt_legacy_key_prefixes[] = {
	"ext4:",
	"f2fs:",
	FS_KEY_DESC_PREFIX,
};

static DEFINE_MUTEX(fscrypt_legacy_keyring_mutex);
static struct key *fscrypt_legacy_keyring;

static void fscrypt_legacy_format_description(
		char description[FSCRYPT_LEGACY_DESCRIPTION_SIZE],
		const char *prefix,
		const u8 descriptor[FSCRYPT_KEY_DESCRIPTOR_SIZE])
{
	sprintf(description, "%s%*phN", prefix,
		FSCRYPT_KEY_DESCRIPTOR_SIZE, descriptor);
}

/* Caller must hold fscrypt_legacy_keyring_mutex. */
static struct key *fscrypt_legacy_find_key_locked(const char *description)
{
	key_ref_t keyref;
	int err;

	if (!fscrypt_legacy_keyring)
		return ERR_PTR(-ENOKEY);

	keyref = keyring_search(make_key_ref(fscrypt_legacy_keyring, true),
				&key_type_logon, description);
	if (!IS_ERR(keyref))
		return key_ref_to_ptr(keyref);

	err = PTR_ERR(keyref);
	if (err == -EAGAIN || err == -EKEYREVOKED)
		err = -ENOKEY;
	return ERR_PTR(err);
}

struct key *fscrypt_legacy_request_key(const char *description)
{
	struct key *key;

	mutex_lock(&fscrypt_legacy_keyring_mutex);
	key = fscrypt_legacy_find_key_locked(description);
	mutex_unlock(&fscrypt_legacy_keyring_mutex);
	if (!IS_ERR(key))
		return key;

	/* Preserve support for keys installed by legacy userspace. */
	return request_key(&key_type_logon, description, NULL);
}
EXPORT_SYMBOL_GPL(fscrypt_legacy_request_key);

/* Caller must hold fscrypt_legacy_keyring_mutex. */
static int fscrypt_legacy_alloc_keyring_locked(void)
{
	struct key *keyring;

	if (fscrypt_legacy_keyring)
		return 0;

	keyring = keyring_alloc(".fscrypt_legacy", GLOBAL_ROOT_UID,
				GLOBAL_ROOT_GID, current_cred(),
				KEY_POS_ALL | KEY_USR_VIEW | KEY_USR_SEARCH,
				KEY_ALLOC_NOT_IN_QUOTA, NULL);
	if (IS_ERR(keyring))
		return PTR_ERR(keyring);

	fscrypt_legacy_keyring = keyring;
	pr_info("fscrypt: enabled legacy v1 key ioctl compatibility\n");
	return 0;
}

static int fscrypt_legacy_validate_spec(
		const struct fscrypt_key_specifier *spec)
{
	if (spec->type != FSCRYPT_KEY_SPEC_TYPE_DESCRIPTOR)
		return -EOPNOTSUPP;
	if (spec->__reserved)
		return -EINVAL;
	if (memchr_inv(spec->u.__reserved + FSCRYPT_KEY_DESCRIPTOR_SIZE, 0,
		       sizeof(spec->u.__reserved) - FSCRYPT_KEY_DESCRIPTOR_SIZE))
		return -EINVAL;
	return 0;
}

/* Caller must hold fscrypt_legacy_keyring_mutex. */
static int fscrypt_legacy_add_keys_locked(
		const u8 descriptor[FSCRYPT_KEY_DESCRIPTOR_SIZE],
		const struct fscrypt_key *payload)
{
	char description[FSCRYPT_LEGACY_DESCRIPTION_SIZE];
	key_ref_t keyref;
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(fscrypt_legacy_key_prefixes); i++) {
		fscrypt_legacy_format_description(description,
					  fscrypt_legacy_key_prefixes[i],
					  descriptor);
		keyref = key_create_or_update(
				make_key_ref(fscrypt_legacy_keyring, true),
				"logon", description, payload, sizeof(*payload),
				KEY_POS_ALL | KEY_USR_VIEW,
				KEY_ALLOC_NOT_IN_QUOTA);
		if (IS_ERR(keyref))
			return PTR_ERR(keyref);
		key_ref_put(keyref);
	}
	return 0;
}

int fscrypt_legacy_ioctl_add_key(struct file *filp, void __user *_uarg)
{
	struct fscrypt_add_key_arg __user *uarg = _uarg;
	struct fscrypt_add_key_arg arg;
	struct fscrypt_key payload;
	int err;

	if (copy_from_user(&arg, uarg, sizeof(arg)))
		return -EFAULT;

	err = fscrypt_legacy_validate_spec(&arg.key_spec);
	if (err)
		return err;
	if (memchr_inv(arg.__reserved, 0, sizeof(arg.__reserved)))
		return -EINVAL;
	if (!capable(CAP_SYS_ADMIN))
		return -EACCES;
	if (arg.key_id || arg.flags || arg.__flags)
		return -EOPNOTSUPP;
	if (arg.raw_size != FS_MAX_KEY_SIZE)
		return -EINVAL;

	memset(&payload, 0, sizeof(payload));
	payload.size = arg.raw_size;
	if (copy_from_user(payload.raw, uarg->raw, arg.raw_size)) {
		err = -EFAULT;
		goto out_wipe_key;
	}

	mutex_lock(&fscrypt_legacy_keyring_mutex);
	err = fscrypt_legacy_alloc_keyring_locked();
	if (!err)
		err = fscrypt_legacy_add_keys_locked(arg.key_spec.u.descriptor,
						     &payload);
	mutex_unlock(&fscrypt_legacy_keyring_mutex);

out_wipe_key:
	memzero_explicit(&payload, sizeof(payload));
	return err;
}
EXPORT_SYMBOL_GPL(fscrypt_legacy_ioctl_add_key);

/* Caller must hold fscrypt_legacy_keyring_mutex. */
static int fscrypt_legacy_unlink_keys_locked(
		const u8 descriptor[FSCRYPT_KEY_DESCRIPTOR_SIZE])
{
	char description[FSCRYPT_LEGACY_DESCRIPTION_SIZE];
	struct key *key;
	bool found = false;
	int first_error = 0;
	int err;
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(fscrypt_legacy_key_prefixes); i++) {
		fscrypt_legacy_format_description(description,
					  fscrypt_legacy_key_prefixes[i],
					  descriptor);
		key = fscrypt_legacy_find_key_locked(description);
		if (IS_ERR(key)) {
			err = PTR_ERR(key);
			if (err != -ENOKEY && !first_error)
				first_error = err;
			continue;
		}

		found = true;
		err = key_unlink(fscrypt_legacy_keyring, key);
		key_put(key);
		if (err && !first_error)
			first_error = err;
	}

	if (first_error)
		return first_error;
	return found ? 0 : -ENOKEY;
}

static int fscrypt_legacy_do_remove_key(struct file *filp, void __user *_uarg)
{
	struct fscrypt_remove_key_arg __user *uarg = _uarg;
	struct fscrypt_remove_key_arg arg;
	struct super_block *sb = file_inode(filp)->i_sb;
	int err;

	if (copy_from_user(&arg, uarg, sizeof(arg)))
		return -EFAULT;
	err = fscrypt_legacy_validate_spec(&arg.key_spec);
	if (err)
		return err;
	if (memchr_inv(arg.__reserved, 0, sizeof(arg.__reserved)))
		return -EINVAL;
	if (!capable(CAP_SYS_ADMIN))
		return -EACCES;

	mutex_lock(&fscrypt_legacy_keyring_mutex);
	err = fscrypt_legacy_unlink_keys_locked(arg.key_spec.u.descriptor);
	mutex_unlock(&fscrypt_legacy_keyring_mutex);
	if (err)
		return err;

	/* Approximate the old userspace sync + drop_caches=2 fallback. */
	(void)sync_filesystem(sb);
	shrink_dcache_sb(sb);

	if (put_user(0, &uarg->removal_status_flags))
		return -EFAULT;
	return 0;
}

int fscrypt_legacy_ioctl_remove_key(struct file *filp, void __user *uarg)
{
	return fscrypt_legacy_do_remove_key(filp, uarg);
}
EXPORT_SYMBOL_GPL(fscrypt_legacy_ioctl_remove_key);

int fscrypt_legacy_ioctl_remove_key_all_users(struct file *filp,
					      void __user *uarg)
{
	return fscrypt_legacy_do_remove_key(filp, uarg);
}
EXPORT_SYMBOL_GPL(fscrypt_legacy_ioctl_remove_key_all_users);

/* Caller must hold fscrypt_legacy_keyring_mutex. */
static int fscrypt_legacy_key_present_locked(
		const u8 descriptor[FSCRYPT_KEY_DESCRIPTOR_SIZE])
{
	char description[FSCRYPT_LEGACY_DESCRIPTION_SIZE];
	struct key *key;
	int err;
	unsigned int i;

	for (i = 0; i < ARRAY_SIZE(fscrypt_legacy_key_prefixes); i++) {
		fscrypt_legacy_format_description(description,
					  fscrypt_legacy_key_prefixes[i],
					  descriptor);
		key = fscrypt_legacy_find_key_locked(description);
		if (!IS_ERR(key)) {
			key_put(key);
			return 1;
		}
		err = PTR_ERR(key);
		if (err != -ENOKEY)
			return err;
	}
	return 0;
}

int fscrypt_legacy_ioctl_get_key_status(struct file *filp, void __user *_uarg)
{
	struct fscrypt_get_key_status_arg __user *uarg = _uarg;
	struct fscrypt_get_key_status_arg arg;
	int present;
	int err;

	if (copy_from_user(&arg, uarg, sizeof(arg)))
		return -EFAULT;
	err = fscrypt_legacy_validate_spec(&arg.key_spec);
	if (err)
		return err;
	if (memchr_inv(arg.__reserved, 0, sizeof(arg.__reserved)))
		return -EINVAL;

	mutex_lock(&fscrypt_legacy_keyring_mutex);
	present = fscrypt_legacy_key_present_locked(arg.key_spec.u.descriptor);
	mutex_unlock(&fscrypt_legacy_keyring_mutex);
	if (present < 0)
		return present;

	arg.status = present ? FSCRYPT_KEY_STATUS_PRESENT :
			       FSCRYPT_KEY_STATUS_ABSENT;
	arg.status_flags = 0;
	arg.user_count = 0;
	memset(arg.__out_reserved, 0, sizeof(arg.__out_reserved));
	if (copy_to_user(uarg, &arg, sizeof(arg)))
		return -EFAULT;
	return 0;
}
EXPORT_SYMBOL_GPL(fscrypt_legacy_ioctl_get_key_status);
