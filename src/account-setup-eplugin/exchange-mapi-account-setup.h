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
 *		Srinivasa Ragavan <sragavan@novell.com>
 *		Johnny Jacob  <jjohnny@novell.com>
 *
 * Copyright (C) 1999-2008 Novell, Inc. (www.novell.com)
 *
 */


#ifndef EXCHANGE_MAPI_ACCOUNT_SETUP_H
#define EXCHANGE_MAPI_ACCOUNT_SETUP_H

#include "exchange-mapi-account-listener.h"

/* This definition should be in-sync with the definition in camel-mapi-store.c */
#define EXCHANGE_MAPI_PASSWORD_COMPONENT "ExchangeMAPI"

#define DEFAULT_PROF_PATH ".evolution/mapi-profiles.ldb"

#define MAPI_URI_PREFIX   "mapi://" 
#define MAPI_PREFIX_LENGTH 7

ExchangeMAPIAccountListener *
exchange_mapi_accounts_peek_config_listener (void); 

gboolean 
exchange_mapi_create_profile(const char *username, const char *password, const char *domain, const char *server);

gboolean
exchange_mapi_delete_profile (const char *profile); 

#endif /* EXCHANGE_MAPI_ACCOUNT_SETUP_H */
