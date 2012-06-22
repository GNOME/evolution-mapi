/*
 * e-mail-config-mapi-backend.h
 *
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
 */

#ifndef E_MAIL_CONFIG_MAPI_BACKEND_H
#define E_MAIL_CONFIG_MAPI_BACKEND_H

#include <mail/e-mail-config-service-backend.h>

/* Standard GObject macros */
#define E_TYPE_MAIL_CONFIG_MAPI_BACKEND \
	(e_mail_config_mapi_backend_get_type ())
#define E_MAIL_CONFIG_MAPI_BACKEND(obj) \
	(G_TYPE_CHECK_INSTANCE_CAST \
	((obj), E_TYPE_MAIL_CONFIG_MAPI_BACKEND, EMailConfigMapiBackend))
#define E_MAIL_CONFIG_MAPI_BACKEND_CLASS(cls) \
	(G_TYPE_CHECK_CLASS_CAST \
	((cls), E_TYPE_MAIL_CONFIG_MAPI_BACKEND, EMailConfigMapiBackendClass))
#define E_IS_MAIL_CONFIG_MAPI_BACKEND(obj) \
	(G_TYPE_CHECK_INSTANCE_TYPE \
	((obj), E_TYPE_MAIL_CONFIG_MAPI_BACKEND))
#define E_IS_MAIL_CONFIG_MAPI_BACKEND_CLASS(cls) \
	(G_TYPE_CHECK_CLASS_TYPE \
	((cls), E_TYPE_MAIL_CONFIG_MAPI_BACKEND))
#define E_MAIL_CONFIG_MAPI_BACKEND_GET_CLASS(obj) \
	(G_TYPE_INSTANCE_GET_CLASS \
	((obj), E_TYPE_MAIL_CONFIG_MAPI_BACKEND, EMailConfigMapiBackendClass))

G_BEGIN_DECLS

typedef struct _EMailConfigMapiBackend EMailConfigMapiBackend;
typedef struct _EMailConfigMapiBackendClass EMailConfigMapiBackendClass;
typedef struct _EMailConfigMapiBackendPrivate EMailConfigMapiBackendPrivate;

struct _EMailConfigMapiBackend {
	EMailConfigServiceBackend parent;
	EMailConfigMapiBackendPrivate *priv;
};

struct _EMailConfigMapiBackendClass {
	EMailConfigServiceBackendClass parent_class;
};

GType	e_mail_config_mapi_backend_get_type		(void) G_GNUC_CONST;
void	e_mail_config_mapi_backend_type_register	(GTypeModule *type_module);

G_END_DECLS

#endif /* E_MAIL_CONFIG_MAPI_BACKEND_H */
