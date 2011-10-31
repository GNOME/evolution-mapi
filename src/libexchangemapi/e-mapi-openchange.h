/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) version 3.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with the program; if not, see <http://www.gnu.org/licenses/>
 *
 *
 * Authors:
 *    Milan Crha <mcrha@redhat.com>
 *
 * Copyright (C) 2011 Red Hat, Inc. (www.redhat.com)
 *
 */

/* till it's available in OpenChange's API */

#ifndef E_MAPI_OPENCHANGE_H
#define E_MAPI_OPENCHANGE_H

#include <glib.h>

#include <libmapi/libmapi.h>

G_BEGIN_DECLS

enum MAPISTATUS e_mapi_nameid_lid_lookup_canonical (uint16_t lid, const char *OLEGUID, uint32_t *propTag);
enum MAPISTATUS e_mapi_nameid_string_lookup_canonical(const char *Name, const char *OLEGUID, uint32_t *propTag);

struct e_mapi_fx_parser_context;
typedef enum MAPISTATUS (*e_mapi_fxparser_marker_callback_t)(uint32_t, void *);
typedef enum MAPISTATUS (*e_mapi_fxparser_delprop_callback_t)(uint32_t, void *);
typedef enum MAPISTATUS (*e_mapi_fxparser_namedprop_callback_t)(uint32_t, struct MAPINAMEID, void *);
typedef enum MAPISTATUS (*e_mapi_fxparser_property_callback_t)(struct SPropValue, void *);

struct e_mapi_fx_parser_context *e_mapi_fxparser_init(TALLOC_CTX *, void *);
void e_mapi_fxparser_set_marker_callback(struct e_mapi_fx_parser_context *, e_mapi_fxparser_marker_callback_t);
void e_mapi_fxparser_set_delprop_callback(struct e_mapi_fx_parser_context *, e_mapi_fxparser_delprop_callback_t);
void e_mapi_fxparser_set_namedprop_callback(struct e_mapi_fx_parser_context *, e_mapi_fxparser_namedprop_callback_t);
void e_mapi_fxparser_set_property_callback(struct e_mapi_fx_parser_context *, e_mapi_fxparser_property_callback_t);
enum MAPISTATUS e_mapi_fxparser_parse(struct e_mapi_fx_parser_context *, DATA_BLOB *);

G_END_DECLS

#endif /* E_MAPI_OPENCHANGE_H */
