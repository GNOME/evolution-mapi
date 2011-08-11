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
 * Copyright (C) 2011 Red Hat, Inc. (www.redhat.com)
 *
 */

/* debugging stuff for evolution-mapi */

#ifndef EXCHANGE_MAPI_DEBUG_H
#define EXCHANGE_MAPI_DEBUG_H

#include "exchange-mapi-connection.h"

G_BEGIN_DECLS

gboolean	exchange_mapi_debug_is_enabled (void);
void		exchange_mapi_debug_print (const gchar *format, ...);
void		exchange_mapi_debug_dump_properties (ExchangeMapiConnection *conn, mapi_id_t fid, struct mapi_SPropValue_array *properties);

G_END_DECLS

#endif /* EXCHANGE_MAPI_DEBUG_H */
