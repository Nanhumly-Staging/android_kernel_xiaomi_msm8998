/*
 * GPIO handling for Exar XR17V35X chip
 *
 * Copyright (c) 2017 Siemens AG
 *
 * Written by Jan Kiszka <jan.kiszka@siemens.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef __GPIO_EXAR_PDATA_H
#define __GPIO_EXAR_PDATA_H

struct gpio_exar_pdata {
	unsigned int first_pin;
	unsigned int ngpios;
};

#endif /* __GPIO_EXAR_PDATA_H */
