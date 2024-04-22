#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/time.h>
#include <linux/types.h>
#include <linux/efi.h>
#include <linux/slab.h>
#include <linux/memblock.h>
#include <linux/bootmem.h>
#include <linux/acpi.h>
#include <asm/efi.h>
#include <asm/uv/uv.h>
#include <asm/cpu_device_id.h>

#define EFI_MIN_RESERVE 5120

#define EFI_DUMMY_GUID \
	EFI_GUID(0x4424ac57, 0xbe4b, 0x47dd, 0x9e, 0x97, 0xed, 0x50, 0xf0, 0x9f, 0x92, 0xa9)

#define QUARK_CSH_SIGNATURE		0x5f435348	/* _CSH */
#define QUARK_SECURITY_HEADER_SIZE	0x400

/*
 * Header prepended to the standard EFI capsule on Quark systems the are based
 * on Intel firmware BSP.
 * @csh_signature:	Unique identifier to sanity check signed module
 * 			presence ("_CSH").
 * @version:		Current version of CSH used. Should be one for Quark A0.
 * @modulesize:		Size of the entire module including the module header
 * 			and payload.
 * @security_version_number_index: Index of SVN to use for validation of signed
 * 			module.
 * @security_version_number: Used to prevent against roll back of modules.
 * @rsvd_module_id:	Currently unused for Clanton (Quark).
 * @rsvd_module_vendor:	Vendor Identifier. For Intel products value is
 * 			0x00008086.
 * @rsvd_date:		BCD representation of build date as yyyymmdd, where
 * 			yyyy=4 digit year, mm=1-12, dd=1-31.
 * @headersize:		Total length of the header including including any
 * 			padding optionally added by the signing tool.
 * @hash_algo:		What Hash is used in the module signing.
 * @cryp_algo:		What Crypto is used in the module signing.
 * @keysize:		Total length of the key data including including any
 * 			padding optionally added by the signing tool.
 * @signaturesize:	Total length of the signature including including any
 * 			padding optionally added by the signing tool.
 * @rsvd_next_header:	32-bit pointer to the next Secure Boot Module in the
 * 			chain, if there is a next header.
 * @rsvd:		Reserved, padding structure to required size.
 *
 * See also QuartSecurityHeader_t in
 * Quark_EDKII_v1.2.1.1/QuarkPlatformPkg/Include/QuarkBootRom.h
 * from https://downloadcenter.intel.com/download/23197/Intel-Quark-SoC-X1000-Board-Support-Package-BSP
 */
struct quark_security_header {
	u32 csh_signature;
	u32 version;
	u32 modulesize;
	u32 security_version_number_index;
	u32 security_version_number;
	u32 rsvd_module_id;
	u32 rsvd_module_vendor;
	u32 rsvd_date;
	u32 headersize;
	u32 hash_algo;
	u32 cryp_algo;
	u32 keysize;
	u32 signaturesize;
	u32 rsvd_next_header;
	u32 rsvd[2];
};

static efi_char16_t efi_dummy_name[6] = { 'D', 'U', 'M', 'M', 'Y', 0 };

static bool efi_no_storage_paranoia;

/*
 * Some firmware implementations refuse to boot if there's insufficient
 * space in the variable store. The implementation of garbage collection
 * in some FW versions causes stale (deleted) variables to take up space
 * longer than intended and space is only freed once the store becomes
 * almost completely full.
 *
 * Enabling this option disables the space checks in
 * efi_query_variable_store() and forces garbage collection.
 *
 * Only enable this option if deleting EFI variables does not free up
 * space in your variable store, e.g. if despite deleting variables
 * you're unable to create new ones.
 */
static int __init setup_storage_paranoia(char *arg)
{
	efi_no_storage_paranoia = true;
	return 0;
}
early_param("efi_no_storage_paranoia", setup_storage_paranoia);

/*
 * Deleting the dummy variable which kicks off garbage collection
*/
void efi_delete_dummy_variable(void)
{
	efi.set_variable(efi_dummy_name, &EFI_DUMMY_GUID,
			 EFI_VARIABLE_NON_VOLATILE |
			 EFI_VARIABLE_BOOTSERVICE_ACCESS |
			 EFI_VARIABLE_RUNTIME_ACCESS,
			 0, NULL);
}

/*
 * Some firmware implementations refuse to boot if there's insufficient space
 * in the variable store. Ensure that we never use more than a safe limit.
 *
 * Return EFI_SUCCESS if it is safe to write 'size' bytes to the variable
 * store.
 */
efi_status_t efi_query_variable_store(u32 attributes, unsigned long size)
{
	efi_status_t status;
	u64 storage_size, remaining_size, max_size;

	if (!(attributes & EFI_VARIABLE_NON_VOLATILE))
		return 0;

	status = efi.query_variable_info(attributes, &storage_size,
					 &remaining_size, &max_size);
	if (status != EFI_SUCCESS)
		return status;

	/*
	 * We account for that by refusing the write if permitting it would
	 * reduce the available space to under 5KB. This figure was provided by
	 * Samsung, so should be safe.
	 */
	if ((remaining_size - size < EFI_MIN_RESERVE) &&
		!efi_no_storage_paranoia) {

		/*
		 * Triggering garbage collection may require that the firmware
		 * generate a real EFI_OUT_OF_RESOURCES error. We can force
		 * that by attempting to use more space than is available.
		 */
		unsigned long dummy_size = remaining_size + 1024;
		void *dummy = kzalloc(dummy_size, GFP_ATOMIC);

		if (!dummy)
			return EFI_OUT_OF_RESOURCES;

		status = efi.set_variable(efi_dummy_name, &EFI_DUMMY_GUID,
					  EFI_VARIABLE_NON_VOLATILE |
					  EFI_VARIABLE_BOOTSERVICE_ACCESS |
					  EFI_VARIABLE_RUNTIME_ACCESS,
					  dummy_size, dummy);

		if (status == EFI_SUCCESS) {
			/*
			 * This should have failed, so if it didn't make sure
			 * that we delete it...
			 */
			efi_delete_dummy_variable();
		}

		kfree(dummy);

		/*
		 * The runtime code may now have triggered a garbage collection
		 * run, so check the variable info again
		 */
		status = efi.query_variable_info(attributes, &storage_size,
						 &remaining_size, &max_size);

		if (status != EFI_SUCCESS)
			return status;

		/*
		 * There still isn't enough room, so return an error
		 */
		if (remaining_size - size < EFI_MIN_RESERVE)
			return EFI_OUT_OF_RESOURCES;
	}

	return EFI_SUCCESS;
}
EXPORT_SYMBOL_GPL(efi_query_variable_store);

/*
 * The UEFI specification makes it clear that the operating system is free to do
 * whatever it wants with boot services code after ExitBootServices() has been
 * called. Ignoring this recommendation a significant bunch of EFI implementations 
 * continue calling into boot services code (SetVirtualAddressMap). In order to 
 * work around such buggy implementations we reserve boot services region during 
 * EFI init and make sure it stays executable. Then, after SetVirtualAddressMap(), it
* is discarded.
*/
void __init efi_reserve_boot_services(void)
{
	void *p;

	for (p = memmap.map; p < memmap.map_end; p += memmap.desc_size) {
		efi_memory_desc_t *md = p;
		u64 start = md->phys_addr;
		u64 size = md->num_pages << EFI_PAGE_SHIFT;

		if (md->type != EFI_BOOT_SERVICES_CODE &&
		    md->type != EFI_BOOT_SERVICES_DATA)
			continue;
		/* Only reserve where possible:
		 * - Not within any already allocated areas
		 * - Not over any memory area (really needed, if above?)
		 * - Not within any part of the kernel
		 * - Not the bios reserved area
		*/
		if ((start + size > __pa_symbol(_text)
				&& start <= __pa_symbol(_end)) ||
			!e820_all_mapped(start, start+size, E820_RAM) ||
			memblock_is_region_reserved(start, size)) {
			/* Could not reserve, skip it */
			md->num_pages = 0;
			memblock_dbg("Could not reserve boot range [0x%010llx-0x%010llx]\n",
				     start, start+size-1);
		} else
			memblock_reserve(start, size);
	}
}

void __init efi_free_boot_services(void)
{
	void *p;

	for (p = memmap.map; p < memmap.map_end; p += memmap.desc_size) {
		efi_memory_desc_t *md = p;
		unsigned long long start = md->phys_addr;
		unsigned long long size = md->num_pages << EFI_PAGE_SHIFT;

		if (md->type != EFI_BOOT_SERVICES_CODE &&
		    md->type != EFI_BOOT_SERVICES_DATA)
			continue;

		/* Could not reserve boot area */
		if (!size)
			continue;

		free_bootmem_late(start, size);
	}

	efi_unmap_memmap();
}

/*
 * A number of config table entries get remapped to virtual addresses
 * after entering EFI virtual mode. However, the kexec kernel requires
 * their physical addresses therefore we pass them via setup_data and
 * correct those entries to their respective physical addresses here.
 *
 * Currently only handles smbios which is necessary for some firmware
 * implementation.
 */
int __init efi_reuse_config(u64 tables, int nr_tables)
{
	int i, sz, ret = 0;
	void *p, *tablep;
	struct efi_setup_data *data;

	if (!efi_setup)
		return 0;

	if (!efi_enabled(EFI_64BIT))
		return 0;

	data = early_memremap(efi_setup, sizeof(*data));
	if (!data) {
		ret = -ENOMEM;
		goto out;
	}

	if (!data->smbios)
		goto out_memremap;

	sz = sizeof(efi_config_table_64_t);

	p = tablep = early_memremap(tables, nr_tables * sz);
	if (!p) {
		pr_err("Could not map Configuration table!\n");
		ret = -ENOMEM;
		goto out_memremap;
	}

	for (i = 0; i < efi.systab->nr_tables; i++) {
		efi_guid_t guid;

		guid = ((efi_config_table_64_t *)p)->guid;

		if (!efi_guidcmp(guid, SMBIOS_TABLE_GUID))
			((efi_config_table_64_t *)p)->table = data->smbios;
		p += sz;
	}
	early_memunmap(tablep, nr_tables * sz);

out_memremap:
	early_memunmap(data, sizeof(*data));
out:
	return ret;
}

void __init efi_apply_memmap_quirks(void)
{
	/*
	 * Once setup is done earlier, unmap the EFI memory map on mismatched
	 * firmware/kernel architectures since there is no support for runtime
	 * services.
	 */
	if (!efi_runtime_supported()) {
		pr_info("efi: Setup done, disabling due to 32/64-bit mismatch\n");
		efi_unmap_memmap();
	}

	/*
	 * UV doesn't support the new EFI pagetable mapping yet.
	 */
	if (is_uv_system())
		set_bit(EFI_OLD_MEMMAP, &efi.flags);
}

/*
 * For most modern platforms the preferred method of powering off is via
 * ACPI. However, there are some that are known to require the use of
 * EFI runtime services and for which ACPI does not work at all.
 *
 * Using EFI is a last resort, to be used only if no other option
 * exists.
 */
bool efi_reboot_required(void)
{
	if (!acpi_gbl_reduced_hardware)
		return false;

	efi_reboot_quirk_mode = EFI_RESET_WARM;
	return true;
}

bool efi_poweroff_required(void)
{
	return !!acpi_gbl_reduced_hardware;
}

#ifdef CONFIG_EFI_CAPSULE_QUIRK_QUARK_CSH

static int qrk_capsule_setup_info(struct capsule_info *cap_info, void **pkbuff,
				  size_t hdr_bytes)
{
	struct quark_security_header *csh = *pkbuff;

	/* Only process data block that is larger than the security header */
	if (hdr_bytes < sizeof(struct quark_security_header))
		return 0;

	if (csh->csh_signature != QUARK_CSH_SIGNATURE ||
	    csh->headersize != QUARK_SECURITY_HEADER_SIZE)
		return 1;

	/* Only process data block if EFI header is included */
	if (hdr_bytes < QUARK_SECURITY_HEADER_SIZE +
			sizeof(efi_capsule_header_t))
		return 0;

	pr_debug("Quark security header detected\n");

	if (csh->rsvd_next_header != 0) {
		pr_err("multiple Quark security headers not supported\n");
		return -EINVAL;
	}

	*pkbuff += csh->headersize;
	cap_info->total_size = csh->headersize;

	/*
	 * Update the first page pointer to skip over the CSH header.
	 */
	cap_info->pages[0] += csh->headersize;

	return 1;
}

#define ICPU(family, model, quirk_handler) \
	{ X86_VENDOR_INTEL, family, model, X86_FEATURE_ANY, \
	  (unsigned long)&quirk_handler }

static const struct x86_cpu_id efi_capsule_quirk_ids[] = {
	ICPU(5, 9, qrk_capsule_setup_info),	/* Intel Quark X1000 */
	{ }
};

int efi_capsule_setup_info(struct capsule_info *cap_info, void *kbuff,
			   size_t hdr_bytes)
{
	int (*quirk_handler)(struct capsule_info *, void **, size_t);
	const struct x86_cpu_id *id;
	int ret;

	if (hdr_bytes < sizeof(efi_capsule_header_t))
		return 0;

	cap_info->total_size = 0;

	id = x86_match_cpu(efi_capsule_quirk_ids);
	if (id) {
		/*
		 * The quirk handler is supposed to return
		 *  - a value > 0 if the setup should continue, after advancing
		 *    kbuff as needed
		 *  - 0 if not enough hdr_bytes are available yet
		 *  - a negative error code otherwise
		 */
		quirk_handler = (typeof(quirk_handler))id->driver_data;
		ret = quirk_handler(cap_info, &kbuff, hdr_bytes);
		if (ret <= 0)
			return ret;
	}

	memcpy(&cap_info->header, kbuff, sizeof(cap_info->header));

	cap_info->total_size += cap_info->header.imagesize;

	return __efi_capsule_setup_info(cap_info);
}

#endif
