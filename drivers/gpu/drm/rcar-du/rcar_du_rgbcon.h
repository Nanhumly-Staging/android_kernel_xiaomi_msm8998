/*
 * rcar_du_rgbcon.h  --  R-Car Display Unit RGB Connector
 *
 * Copyright (C) 2013-2020 Renesas Electronics Corporation
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#ifndef __RCAR_DU_RGBCON_H__
#define __RCAR_DU_RGBCON_H__

struct rcar_du_device;
struct rcar_du_encoder;

int rcar_du_rgb_connector_init(struct rcar_du_device *rcdu,
			       struct rcar_du_encoder *renc,
			       struct drm_panel *drmpanel);

#endif /* __RCAR_DU_RGBCON_H__ */
