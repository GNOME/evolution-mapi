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
 */

#ifndef CAMEL_MAPI_SASL_KRB_H
#define CAMEL_MAPI_SASL_KRB_H

#include <camel/camel.h>

/* Standard GObject macros */
#define CAMEL_TYPE_MAPI_SASL_KRB \
	(camel_mapi_sasl_krb_get_type ())
#define CAMEL_MAPI_SASL_KRB(obj) \
	(G_TYPE_CHECK_INSTANCE_CAST \
	((obj), CAMEL_TYPE_MAPI_SASL_KRB, CamelMapiSaslKrb))
#define CAMEL_MAPI_SASL_KRB_CLASS(cls) \
	(G_TYPE_CHECK_CLASS_CAST \
	((cls), CAMEL_TYPE_MAPI_SASL_KRB, CamelMapiSaslKrbClass))
#define CAMEL_IS_MAPI_SASL_KRB(obj) \
	(G_TYPE_CHECK_INSTANCE_TYPE \
	((obj), CAMEL_TYPE_MAPI_SASL_KRB))
#define CAMEL_IS_MAPI_SASL_KRB_CLASS(cls) \
	(G_TYPE_CHECK_CLASS_TYPE \
	((cls), CAMEL_TYPE_MAPI_SASL_KRB))
#define CAMEL_MAPI_SASL_KRB_GET_CLASS(obj) \
	(G_TYPE_INSTANCE_GET_CLASS \
	((obj), CAMEL_TYPE_MAPI_SASL_KRB, CamelMapiSaslKrbClass))

G_BEGIN_DECLS

typedef struct _CamelMapiSaslKrb CamelMapiSaslKrb;
typedef struct _CamelMapiSaslKrbClass CamelMapiSaslKrbClass;

struct _CamelMapiSaslKrb {
	CamelSasl parent;
};

struct _CamelMapiSaslKrbClass {
	CamelSaslClass parent_class;
};

GType camel_mapi_sasl_krb_get_type (void);

G_END_DECLS

#endif /* CAMEL_MAPI_SASL_KRB_H */
