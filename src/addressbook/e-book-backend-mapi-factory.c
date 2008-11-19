/* -*- Mode: C; tab-width: 8; indent-tabs-mode: t; c-basic-offset: 8 -*- */
/*
 *  Authors: 
 *    Srinivasa Ragavan <sragavan@novell.com>
 *
 *  Copyright (C) 1999-2008 Novell, Inc. (www.novell.com)
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of version 2 of the GNU Lesser General Public
 *  License as published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public 
 *  License along with this program; if not, write to: 
 *  Free Software Foundation, 51 Franklin Street, Fifth Floor,
 *  Boston, MA 02110-1301, USA.
 *
 */


#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <libebackend/e-data-server-module.h>
#include <libedata-book/e-book-backend-factory.h>
#include "e-book-backend-mapi.h"

E_BOOK_BACKEND_FACTORY_SIMPLE (mapi,
			       MAPI,
			       e_book_backend_mapi_new)

static GType mapi_type;

void	eds_module_initialize (GTypeModule *module)
{
	mapi_type = _mapi_factory_get_type (module);
}

void	eds_module_shutdown   (void)
{
}

void	eds_module_list_types (const GType **types, int *num_types)
{
	*types = &mapi_type;
	*num_types = 1;
}
