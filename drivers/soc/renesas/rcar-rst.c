/*
 * R-Car Gen2 and RZ/G RST Driver
 *
 * Copyright (C) 2016 Glider bvba
 *
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 */

#include <linux/err.h>
#include <linux/io.h>
#include <linux/of_address.h>
#include <linux/soc/renesas/rcar-rst.h>

#define WDTRSTCR_RESET		0xA55A0002
#define WDTRSTCR		0x0054

static int rcar_rst_enable_wdt_reset(void __iomem *base)
{
	iowrite32(WDTRSTCR_RESET, base + WDTRSTCR);
	return 0;
}

struct rst_config {
	int (*configure)(void *base);	/* Platform specific configuration */
};

static const struct rst_config rcar_rst_gen2 __initconst = {
	.configure = rcar_rst_enable_wdt_reset,
};

static const struct of_device_id rcar_rst_matches[] __initconst = {
	/* RZ/G is handled like R-Car Gen2 */
	{ .compatible = "renesas,r8a7743-rst", .data = &rcar_rst_gen2 },
	{ .compatible = "renesas,r8a7745-rst", .data = &rcar_rst_gen2 },
	{ .compatible = "renesas,r8a77470-rst", .data = &rcar_rst_gen2 },
	/* R-Car Gen2 */
	{ .compatible = "renesas,r8a7790-rst", .data = &rcar_rst_gen2 },
	{ .compatible = "renesas,r8a7791-rst", .data = &rcar_rst_gen2 },
	{ .compatible = "renesas,r8a7792-rst", .data = &rcar_rst_gen2 },
	{ .compatible = "renesas,r8a7793-rst", .data = &rcar_rst_gen2 },
	{ .compatible = "renesas,r8a7794-rst", .data = &rcar_rst_gen2 },
	{ /* sentinel */ }
};

static void __iomem *rcar_rst_base __initdata;

void __init rcar_rst_init(void)
{
	const struct of_device_id *match;
	const struct rst_config *cfg;
	struct device_node *np;
	void __iomem *base;

	if (rcar_rst_base)
		return;

	np = of_find_matching_node_and_match(NULL, rcar_rst_matches, &match);
	if (!np)
		return;

	base = of_iomap(np, 0);
	if (!base) {
		pr_warn("%s: Cannot map regs\n", np->full_name);
		goto out_put;
	}

	rcar_rst_base = base;
	cfg = match->data;
	if (cfg->configure)
		if (cfg->configure(base))
			pr_warn("%pOF: Cannot run SoC specific configuration\n",
				np);

out_put:
	of_node_put(np);
}
