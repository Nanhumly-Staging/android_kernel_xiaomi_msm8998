/*
 * rcar_du_rgbcon.c  --  R-Car Display Unit RGB Connector
 *
 * Copyright (C) 2013-2020 Renesas Electronics Corporation
 *
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 */

#include <drm/drmP.h>
#include <drm/drm_atomic_helper.h>
#include <drm/drm_crtc.h>
#include <drm/drm_crtc_helper.h>
#include <drm/drm_panel.h>

#include "rcar_du_drv.h"
#include "rcar_du_encoder.h"
#include "rcar_du_kms.h"
#include "rcar_du_rgbcon.h"

struct rcar_du_rgb_connector {
	struct rcar_du_connector connector;
	struct drm_panel *drmpanel;
};

#define to_rcar_rgb_connector(c) \
	container_of(c, struct rcar_du_rgb_connector, connector.connector)

static int rcar_du_rgb_connector_get_modes(struct drm_connector *connector)
{
	struct rcar_du_rgb_connector *rgbcon =
		to_rcar_rgb_connector(connector);

	return drm_panel_get_modes(rgbcon->drmpanel);
}

static const struct drm_connector_helper_funcs connector_helper_funcs = {
	.get_modes = rcar_du_rgb_connector_get_modes,
	.best_encoder = rcar_du_connector_best_encoder,
};

static enum drm_connector_status
rcar_du_rgb_connector_detect(struct drm_connector *connector, bool force)
{
	return connector_status_connected;
}

static void rcar_du_rgb_connector_destroy(struct drm_connector *connector)
{
	struct rcar_du_rgb_connector *rgbcon =
		to_rcar_rgb_connector(connector);

	drm_panel_detach(rgbcon->drmpanel);
	drm_connector_cleanup(connector);
}

static const struct drm_connector_funcs connector_funcs = {
	.dpms = drm_atomic_helper_connector_dpms,
	.reset = drm_atomic_helper_connector_reset,
	.detect = rcar_du_rgb_connector_detect,
	.fill_modes = drm_helper_probe_single_connector_modes,
	.destroy = rcar_du_rgb_connector_destroy,
	.atomic_duplicate_state = drm_atomic_helper_connector_duplicate_state,
	.atomic_destroy_state = drm_atomic_helper_connector_destroy_state,
};

int rcar_du_rgb_connector_init(struct rcar_du_device *rcdu,
			       struct rcar_du_encoder *renc,
			       struct drm_panel *drmpanel)
{
	struct drm_encoder *encoder = rcar_encoder_to_drm_encoder(renc);
	struct rcar_du_rgb_connector *rgbcon;
	struct drm_connector *connector;
	int ret;

	rgbcon = devm_kzalloc(rcdu->dev, sizeof(*rgbcon), GFP_KERNEL);
	if (!rgbcon)
		return -ENOMEM;

	rgbcon->drmpanel = drmpanel;
	connector = &rgbcon->connector.connector;
	ret = drm_connector_init(rcdu->ddev, connector, &connector_funcs,
				 DRM_MODE_CONNECTOR_DPI);
	if (ret < 0)
		return ret;

	drm_connector_helper_add(connector, &connector_helper_funcs);

	connector->dpms = DRM_MODE_DPMS_OFF;
	drm_object_property_set_value(&connector->base,
				      rcdu->ddev->mode_config.dpms_property,
				      DRM_MODE_DPMS_OFF);

	ret = drm_mode_connector_attach_encoder(connector, encoder);
	if (ret < 0)
		return ret;

	drm_panel_attach(rgbcon->drmpanel, connector);
	rgbcon->connector.encoder = renc;

	return 0;
}
