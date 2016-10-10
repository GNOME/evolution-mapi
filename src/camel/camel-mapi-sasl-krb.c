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

#include "evolution-mapi-config.h"

#include <string.h>

#include <glib/gi18n-lib.h>

#include "camel-mapi-sasl-krb.h"

static CamelServiceAuthType mapi_sasl_krb_auth_type = {
	N_("Kerberos"),

	N_("This option will connect to the server using kerberos key."),

	"MAPIKRB",
	FALSE
};

G_DEFINE_TYPE (CamelMapiSaslKrb, camel_mapi_sasl_krb, CAMEL_TYPE_SASL)

static GByteArray *
mapi_sasl_krb_challenge_sync (CamelSasl *sasl,
                              GByteArray *token,
                              GCancellable *cancellable,
                              GError **error)
{
	camel_sasl_set_authenticated (sasl, TRUE);

	return NULL;
}

static void
camel_mapi_sasl_krb_class_init (CamelMapiSaslKrbClass *class)
{
	CamelSaslClass *sasl_class;

	sasl_class = CAMEL_SASL_CLASS (class);
	sasl_class->auth_type = &mapi_sasl_krb_auth_type;
	sasl_class->challenge_sync = mapi_sasl_krb_challenge_sync;
}

static void
camel_mapi_sasl_krb_init (CamelMapiSaslKrb *mapi_sasl_krb)
{
}
