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
 *    Suman Manjunath <msuman@novell.com>
 *
 * Copyright (C) 1999-2008 Novell, Inc. (www.novell.com)
 *
 */

#include <config.h>

#include <libedata-cal/libedata-cal.h>

#include "e-source-mapi-folder.h"
#include "e-cal-backend-mapi.h"

#define FACTORY_NAME "mapi"

typedef ECalBackendFactory ECalBackendMapiEventsFactory;
typedef ECalBackendFactoryClass ECalBackendMapiEventsFactoryClass;

typedef ECalBackendFactory ECalBackendMapiJournalFactory;
typedef ECalBackendFactoryClass ECalBackendMapiJournalFactoryClass;

typedef ECalBackendFactory ECalBackendMapiTodosFactory;
typedef ECalBackendFactoryClass ECalBackendMapiTodosFactoryClass;

/* Module Entry Points */
void e_module_load (GTypeModule *type_module);
void e_module_unload (GTypeModule *type_module);

/* Forward Declarations */
GType e_cal_backend_mapi_events_factory_get_type (void);
GType e_cal_backend_mapi_journal_factory_get_type (void);
GType e_cal_backend_mapi_todos_factory_get_type (void);

G_DEFINE_DYNAMIC_TYPE (
	ECalBackendMapiEventsFactory,
	e_cal_backend_mapi_events_factory,
	E_TYPE_CAL_BACKEND_FACTORY)

G_DEFINE_DYNAMIC_TYPE (
	ECalBackendMapiJournalFactory,
	e_cal_backend_mapi_journal_factory,
	E_TYPE_CAL_BACKEND_FACTORY)

G_DEFINE_DYNAMIC_TYPE (
	ECalBackendMapiTodosFactory,
	e_cal_backend_mapi_todos_factory,
	E_TYPE_CAL_BACKEND_FACTORY)

static void
e_cal_backend_mapi_events_factory_class_init (ECalBackendFactoryClass *class)
{
	class->factory_name = FACTORY_NAME;
	class->component_kind = ICAL_VEVENT_COMPONENT;
	class->backend_type = E_TYPE_CAL_BACKEND_MAPI;
}

static void
e_cal_backend_mapi_events_factory_class_finalize (ECalBackendFactoryClass *class)
{
}

static void
e_cal_backend_mapi_events_factory_init (ECalBackendFactory *factory)
{
}

static void
e_cal_backend_mapi_journal_factory_class_init (ECalBackendFactoryClass *class)
{
	class->factory_name = FACTORY_NAME;
	class->component_kind = ICAL_VJOURNAL_COMPONENT;
	class->backend_type = E_TYPE_CAL_BACKEND_MAPI;
}

static void
e_cal_backend_mapi_journal_factory_class_finalize (ECalBackendFactoryClass *class)
{
}

static void
e_cal_backend_mapi_journal_factory_init (ECalBackendFactory *factory)
{
}

static void
e_cal_backend_mapi_todos_factory_class_init (ECalBackendFactoryClass *class)
{
	class->factory_name = FACTORY_NAME;
	class->component_kind = ICAL_VTODO_COMPONENT;
	class->backend_type = E_TYPE_CAL_BACKEND_MAPI;
}

static void
e_cal_backend_mapi_todos_factory_class_finalize (ECalBackendFactoryClass *class)
{
}

static void
e_cal_backend_mapi_todos_factory_init (ECalBackendFactory *factory)
{
}

G_MODULE_EXPORT void
e_module_load (GTypeModule *type_module)
{
	e_source_mapi_folder_type_register (type_module);

	e_cal_backend_mapi_events_factory_register_type (type_module);
	e_cal_backend_mapi_journal_factory_register_type (type_module);
	e_cal_backend_mapi_todos_factory_register_type (type_module);
}

G_MODULE_EXPORT void
e_module_unload (GTypeModule *type_module)
{
}

