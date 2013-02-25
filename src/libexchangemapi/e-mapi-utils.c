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

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <glib.h>
#include <gio/gio.h>

#include <libedataserver/libedataserver.h>

#include "e-mapi-utils.h"
#include "e-mapi-mail-utils.h"
#include "e-source-mapi-folder.h"

#ifdef G_OS_WIN32
/* Undef the similar macro from pthread.h, it doesn't check if
 * gmtime() returns NULL.
 */
#undef gmtime_r

/* The gmtime() in Microsoft's C library is MT-safe */
#define gmtime_r(tp,tmp) (gmtime(tp)?(*(tmp)=*gmtime(tp),(tmp)):0)
#endif

#define DEFAULT_PROF_NAME "mapi-profiles.ldb"

/* Used for callout to krb5-auth-dialog */
#define KRB_DBUS_PATH               "/org/gnome/KrbAuthDialog"
#define KRB_DBUS_INTERFACE          "org.gnome.KrbAuthDialog"

void
e_mapi_cancellable_rec_mutex_init (EMapiCancellableRecMutex *rec_mutex)
{
	g_return_if_fail (rec_mutex != NULL);

	g_rec_mutex_init (&rec_mutex->rec_mutex);
	g_mutex_init (&rec_mutex->cond_mutex);
	g_cond_init (&rec_mutex->cond);
}

void
e_mapi_cancellable_rec_mutex_clear (EMapiCancellableRecMutex *rec_mutex)
{
	g_return_if_fail (rec_mutex != NULL);

	g_rec_mutex_clear (&rec_mutex->rec_mutex);
	g_mutex_clear (&rec_mutex->cond_mutex);
	g_cond_clear (&rec_mutex->cond);
}

static void
cancellable_rec_mutex_cancelled_cb (GCancellable *cancellable,
				    EMapiCancellableRecMutex *rec_mutex)
{
	g_return_if_fail (rec_mutex != NULL);

	/* wake-up any waiting threads */
	g_mutex_lock (&rec_mutex->cond_mutex);
	g_cond_broadcast (&rec_mutex->cond);
	g_mutex_unlock (&rec_mutex->cond_mutex);
}

/* returns FALSE if cancelled, in which case the lock is not held */
gboolean
e_mapi_cancellable_rec_mutex_lock (EMapiCancellableRecMutex *rec_mutex,
				   GCancellable *cancellable,
				   GError **error)
{
	gulong handler_id;
	gboolean res = TRUE;

	g_return_val_if_fail (rec_mutex != NULL, FALSE);

	g_mutex_lock (&rec_mutex->cond_mutex);
	if (!cancellable) {
		g_mutex_unlock (&rec_mutex->cond_mutex);
		g_rec_mutex_lock (&rec_mutex->rec_mutex);
		return TRUE;
	}

	if (g_cancellable_is_cancelled (cancellable)) {
		if (error && !*error)
			g_cancellable_set_error_if_cancelled (cancellable, error);
		g_mutex_unlock (&rec_mutex->cond_mutex);
		return FALSE;
	}

	handler_id = g_signal_connect (cancellable, "cancelled",
		G_CALLBACK (cancellable_rec_mutex_cancelled_cb), rec_mutex);

	while (!g_rec_mutex_trylock (&rec_mutex->rec_mutex)) {
		/* recheck once per 10 seconds, just in case */
		g_cond_wait_until (&rec_mutex->cond, &rec_mutex->cond_mutex,
			g_get_monotonic_time () + (10 * G_TIME_SPAN_SECOND));

		if (g_cancellable_is_cancelled (cancellable)) {
			if (error && !*error)
				g_cancellable_set_error_if_cancelled (cancellable, error);
			res = FALSE;
			break;
		}
	}

	g_signal_handler_disconnect (cancellable, handler_id);

	g_mutex_unlock (&rec_mutex->cond_mutex);

	return res;
}

void
e_mapi_cancellable_rec_mutex_unlock (EMapiCancellableRecMutex *rec_mutex)
{
	g_return_if_fail (rec_mutex != NULL);

	g_rec_mutex_unlock (&rec_mutex->rec_mutex);

	g_mutex_lock (&rec_mutex->cond_mutex);
	/* also wake-up any waiting threads */
	g_cond_broadcast (&rec_mutex->cond);
	g_mutex_unlock (&rec_mutex->cond_mutex);
}

static gboolean
manage_global_lock (gboolean lock,
		    GCancellable *cancellable,
		    GError **error)
{
	static EMapiCancellableRecMutex global_lock;
	gboolean res = TRUE;

	if (lock)
		res = e_mapi_cancellable_rec_mutex_lock (&global_lock, cancellable, error);
	else
		e_mapi_cancellable_rec_mutex_unlock (&global_lock);

	return res;
}

gboolean
e_mapi_utils_global_lock (GCancellable *cancellable,
			  GError **error)
{
	return manage_global_lock (TRUE, cancellable, error);
}

void
e_mapi_utils_global_unlock (void)
{
	manage_global_lock (FALSE, NULL, NULL);
}

inline gchar *
e_mapi_util_mapi_id_to_string (mapi_id_t id)
{
	return g_strdup_printf ("%016" G_GINT64_MODIFIER "X", id);
}

inline gboolean
e_mapi_util_mapi_id_from_string (const gchar *str, mapi_id_t *id)
{
	gint n = 0;

	if (str && *str)
		n = sscanf (str, "%016" G_GINT64_MODIFIER "X", id);

	return (n == 1);
}

/*
 * Retrieve the property value for a given SPropValue and property tag.
 *
 * If the property type is a string: fetch PT_STRING8 then PT_UNICODE
 * in case the desired property is not available in first choice.
 *
 * Fetch property normally for any others properties
 */
/* NOTE: For now, since this function has special significance only for
 * 'string' type properties, callers should (preferably) use it for fetching
 * such properties alone. If callers are sure that proptag would, for instance,
 * return an 'int' or a 'systime', they should prefer get_SPropValue.
 */
gconstpointer
e_mapi_util_find_SPropVal_array_propval (struct SPropValue *values, uint32_t proptag)
{
	if (((proptag & 0xFFFF) == PT_STRING8) ||
	    ((proptag & 0xFFFF) == PT_UNICODE)) {
		const void	*str = NULL;

		proptag = (proptag & 0xFFFF0000) | PT_UNICODE;
		str = get_SPropValue(values, proptag);
		if (str)
			return str;

		proptag = (proptag & 0xFFFF0000) | PT_STRING8;
		str = get_SPropValue(values, proptag);
		if (str)
			return str;

		return NULL;
	}

	/* NOTE: Similar generalizations (if any) for other property types
	 * can be made here.
	 */

	return (get_SPropValue(values, proptag));
}

/*
 * Retrieve the property value for a given SRow and property tag.
 *
 * If the property type is a string: fetch PT_STRING8 then PT_UNICODE
 * in case the desired property is not available in first choice.
 *
 * Fetch property normally for any others properties
 */
/* NOTE: For now, since this function has special significance only for
 * 'string' type properties, callers should (preferably) use it for fetching
 * such properties alone. If callers are sure that proptag would, for instance,
 * return an 'int' or a 'systime', they should prefer find_SPropValue_data.
 */
gconstpointer
e_mapi_util_find_row_propval (struct SRow *aRow, uint32_t proptag)
{
	if (((proptag & 0xFFFF) == PT_STRING8) ||
	    ((proptag & 0xFFFF) == PT_UNICODE)) {
		const void	*str = NULL;

		proptag = (proptag & 0xFFFF0000) | PT_UNICODE;
		str = find_SPropValue_data(aRow, proptag);
		if (str)
			return str;

		proptag = (proptag & 0xFFFF0000) | PT_STRING8;
		str = find_SPropValue_data(aRow, proptag);
		if (str)
			return str;

		return NULL;
	}

	/* NOTE: Similar generalizations (if any) for other property types
	 * can be made here.
	 */

	return (find_SPropValue_data(aRow, proptag));
}

gconstpointer
e_mapi_util_find_propertyrow_propval (struct PropertyRow_r *rRow,
				      uint32_t proptag)
{
	if (((proptag & 0xFFFF) == PT_STRING8) ||
	    ((proptag & 0xFFFF) == PT_UNICODE)) {
		gconstpointer str = NULL;

		proptag = (proptag & 0xFFFF0000) | PT_UNICODE;
		str = find_PropertyValue_data (rRow, proptag);
		if (str)
			return str;

		proptag = (proptag & 0xFFFF0000) | PT_STRING8;
		str = find_PropertyValue_data (rRow, proptag);
		if (str)
			return str;

		return NULL;
	}

	return find_PropertyValue_data (rRow, proptag);
}

/*
 * Retrieve the property value for a given mapi_SPropValue_array and property tag.
 *
 * If the property type is a string: fetch PT_STRING8 then PT_UNICODE
 * in case the desired property is not available in first choice.
 *
 * Fetch property normally for any others properties
 */
/* NOTE: For now, since this function has special significance only for
 * 'string' type properties, callers should (preferably) use it for fetching
 * such properties alone. If callers are sure that proptag would, for instance,
 * return an 'int' or a 'systime', they should prefer find_mapi_SPropValue_data.
 */
gconstpointer
e_mapi_util_find_array_propval (struct mapi_SPropValue_array *properties, uint32_t proptag)
{
	if (((proptag & 0xFFFF) == PT_STRING8) ||
	    ((proptag & 0xFFFF) == PT_UNICODE)) {
		const void	*str = NULL;

		proptag = (proptag & 0xFFFF0000) | PT_UNICODE;
		str = find_mapi_SPropValue_data(properties, proptag);
		if (str)
			return str;

		proptag = (proptag & 0xFFFF0000) | PT_STRING8;
		str = find_mapi_SPropValue_data(properties, proptag);
		if (str)
			return str;

		return NULL;
	}

	/* NOTE: Similar generalizations (if any) for other property types
	 * can be made here.
	 */

	return (find_mapi_SPropValue_data(properties, proptag));
}

uint32_t
e_mapi_util_find_array_proptag (struct mapi_SPropValue_array *properties, uint32_t proptag)
{
	g_return_val_if_fail (properties != NULL, proptag);

	if ((proptag & 0xFFFF) == PT_STRING8 ||
	    (proptag & 0xFFFF) == PT_UNICODE) {
		gint ii;
		uint32_t tag1, tag2;

		tag1 = (proptag & 0xFFFF0000) | PT_STRING8;
		tag2 = (proptag & 0xFFFF0000) | PT_UNICODE;

		for (ii = 0; ii < properties->cValues; ii++) {
			uint32_t tag = properties->lpProps[ii].ulPropTag;
			if (tag == tag1 || tag == tag2) {
				proptag = tag;
				break;
			}
		}
	}

	return 0;
}

enum MAPISTATUS
e_mapi_util_find_array_datetime_propval (struct timeval *tv, struct mapi_SPropValue_array *properties, uint32_t proptag)
{
	g_return_val_if_fail (tv != NULL, MAPI_E_INVALID_PARAMETER);
	g_return_val_if_fail (properties != NULL, MAPI_E_INVALID_PARAMETER);

	return get_mapi_SPropValue_array_date_timeval (tv, properties, proptag);
}

static void
e_mapi_util_bin_append_uint16 (TALLOC_CTX *mem_ctx, struct Binary_r *bin, const uint16_t val)
{
	uint8_t *ptr = NULL;

	bin->lpb = talloc_realloc (mem_ctx, bin->lpb, uint8_t, bin->cb + 2);
	bin->cb += 2;

	ptr = bin->lpb + bin->cb - 2;

	*ptr++ = ( val        & 0xFF);
	*ptr++ = ((val >>  8) & 0xFF);
}

static void
e_mapi_util_bin_append_uint32 (TALLOC_CTX *mem_ctx, struct Binary_r *bin, const uint32_t val)
{
	uint8_t *ptr = NULL;

	bin->lpb = talloc_realloc (mem_ctx, bin->lpb, uint8_t, bin->cb + 4);
	bin->cb += 4;

	ptr = bin->lpb + bin->cb - 4;

	*ptr++ = ( val        & 0xFF);
	*ptr++ = ((val >>  8) & 0xFF);
	*ptr++ = ((val >> 16) & 0xFF);
	*ptr++ = ((val >> 24) & 0xFF);
}

/* returns how many bytes read, 0 means an error */
static uint32_t
bin_decode_uint16 (const uint8_t *ptr, uint32_t ptr_cb, uint16_t *res)
{
	g_return_val_if_fail (res != NULL, 0);
	g_return_val_if_fail (ptr != NULL, 0);

	if (ptr_cb < 2)
		return 0;

	*res = ((ptr[0] & 0xFF)     ) |
	       ((ptr[1] & 0xFF) << 8);

	return 2;
}

/* returns how many bytes read, 0 means an error */
static uint32_t
bin_decode_uint32 (const uint8_t *ptr, uint32_t ptr_cb, uint32_t *res)
{
	g_return_val_if_fail (res != NULL, 0);
	g_return_val_if_fail (ptr != NULL, 0);

	if (ptr_cb < 4)
		return 0;

	*res = ((ptr[0] & 0xFF)      ) |
	       ((ptr[1] & 0xFF) <<  8) |
	       ((ptr[2] & 0xFF) << 16) |
	       ((ptr[3] & 0xFF) << 24);

	return 4;
}

static uint32_t
bin_decode_string (const uint8_t *ptr, uint32_t sz, gchar **str, gboolean is_unicode)
{
	uint32_t len;

	g_return_val_if_fail (ptr != NULL, 0);
	g_return_val_if_fail (str != NULL, 0);

	for (len = 0; len < sz; len += (is_unicode ? 2 : 1)) {
		if (ptr[len] == 0x00 && (!is_unicode || (len + 1 < sz && ptr[len + 1] == 0x00)))
			break;
	}

	if (len >= sz || ptr[len] != 0x00 || (is_unicode && (len + 1 >= sz || ptr[len + 1] != 0x00)))
		return 0;

	if (is_unicode) {
		*str = g_utf16_to_utf8 ((const gunichar2 *) ptr, len / 2, NULL, NULL, NULL);
	} else {
		*str = g_malloc0 (sizeof(gchar) * (1 + len));
		strncpy (*str, (const gchar *) ptr, len);
	}

	return len + 1 + (is_unicode ? 1 : 0);
}

static void
e_mapi_util_bin_append_string (TALLOC_CTX *mem_ctx, struct Binary_r *bin, const gchar *val)
{
	gsize len = strlen (val);
	gchar *ptr = NULL;

	bin->lpb = talloc_realloc (mem_ctx, bin->lpb, uint8_t, bin->cb + (len + 1));
	bin->cb += (len + 1);

	ptr = (gchar *) bin->lpb + bin->cb - (len + 1);

	strcpy (ptr, val);
}

static void
e_mapi_util_bin_append_val (TALLOC_CTX *mem_ctx, struct Binary_r *bin, const uint8_t *val, gsize len)
{
	uint8_t *ptr = NULL;

	bin->lpb = talloc_realloc (mem_ctx, bin->lpb, uint8_t, bin->cb + len);
	bin->cb += len;

	ptr = bin->lpb + bin->cb - len;

	memcpy (ptr, val, len);
}

static void
e_mapi_util_bin_append_unicode (TALLOC_CTX *mem_ctx, struct Binary_r *bin, const gchar *val)
{
	gunichar2 *utf16;
	glong written = 0;

	utf16 = g_utf8_to_utf16 (val, -1, NULL, &written, NULL);
	g_return_if_fail (utf16 != NULL);

	e_mapi_util_bin_append_val (mem_ctx, bin, (uint8_t *)utf16, (written + 1) * 2);

	g_free (utf16);
}

static const uint8_t MAPI_ONE_OFF_UID[] = {
	0x81, 0x2b, 0x1f, 0xa4, 0xbe, 0xa3, 0x10, 0x19,
	0x9d, 0x6e, 0x00, 0xdd, 0x01, 0x0f, 0x54, 0x02
};

#define MAPI_ONE_OFF_UNICODE	  0x8000
#define MAPI_ONE_OFF_NO_RICH_INFO 0x0001
#define MAPI_ONE_OFF_MYSTERY_FLAG 0x1000

/**
 * e_mapi_util_recip_entryid_generate_smtp:
 * @entryid: entry ID to be filled
 * @display_name: the display name of the user
 * @email: the email address
 *
 * Constructs a "one-off" ENTRYID value that can be used as a MAPI
 * recipient (eg, for a message forwarding server-side rule),
 * corresponding to @display_name and @email.
 *
 * Return value: the recipient ENTRYID
 **/
void
e_mapi_util_recip_entryid_generate_smtp (TALLOC_CTX *mem_ctx, struct Binary_r *entryid, const gchar *display_name, const gchar *email)
{
	g_return_if_fail (entryid != NULL);

	e_mapi_util_bin_append_uint32 (mem_ctx, entryid, 0);
	e_mapi_util_bin_append_val (mem_ctx, entryid, MAPI_ONE_OFF_UID, sizeof(MAPI_ONE_OFF_UID));
	e_mapi_util_bin_append_uint16 (mem_ctx, entryid, 0);
	e_mapi_util_bin_append_uint16 (mem_ctx, entryid, MAPI_ONE_OFF_NO_RICH_INFO | MAPI_ONE_OFF_MYSTERY_FLAG | MAPI_ONE_OFF_UNICODE);
	e_mapi_util_bin_append_unicode (mem_ctx, entryid, display_name);
	e_mapi_util_bin_append_unicode (mem_ctx, entryid, "SMTP");
	e_mapi_util_bin_append_unicode (mem_ctx, entryid, email);
}

static const uint8_t MAPI_LOCAL_UID[] = {
	0xdc, 0xa7, 0x40, 0xc8, 0xc0, 0x42, 0x10, 0x1a,
	0xb4, 0xb9, 0x08, 0x00, 0x2b, 0x2f, 0xe1, 0x82
};

/**
 * e_mapi_util_recip_entryid_generate_ex:
 * @exchange_dn: the Exchange 5.5-style DN of the local user
 *
 * Constructs an ENTRYID value that can be used as a MAPI
 * recipient (eg, for a message forwarding server-side rule),
 * corresponding to the local user identified by @exchange_dn.
 **/
void
e_mapi_util_recip_entryid_generate_ex (TALLOC_CTX *mem_ctx, struct Binary_r *entryid, const gchar *exchange_dn)
{
	e_mapi_util_bin_append_uint32 (mem_ctx, entryid, 0);
	e_mapi_util_bin_append_val (mem_ctx, entryid, MAPI_LOCAL_UID, sizeof(MAPI_LOCAL_UID));
	e_mapi_util_bin_append_uint16 (mem_ctx, entryid, 1);
	e_mapi_util_bin_append_uint16 (mem_ctx, entryid, 0);
	e_mapi_util_bin_append_string (mem_ctx, entryid, exchange_dn);
}

static gboolean
recip_entryid_decode_smtp (const struct Binary_r *entryid, gchar **display_name, gchar **email)
{
	uint32_t u32, sz, r;
	uint16_t u16, flags;
	uint8_t *ptr;
	gchar *smtp;

	g_return_val_if_fail (entryid != NULL, FALSE);
	g_return_val_if_fail (entryid->lpb != NULL, FALSE);
	g_return_val_if_fail (display_name != NULL, FALSE);
	g_return_val_if_fail (email != NULL, FALSE);

	*display_name = NULL;
	*email = NULL;

	ptr = entryid->lpb;
	sz = entryid->cb;

	u32 = 1;
	r = bin_decode_uint32 (ptr, sz, &u32);
	if (!r || u32 != 0)
		return FALSE;

	ptr += r;
	sz -= r;

	for (r = 0; r < G_N_ELEMENTS (MAPI_ONE_OFF_UID) && r < sz; r++) {
		if (ptr[r] != MAPI_ONE_OFF_UID[r])
			return FALSE;
	}

	if (r != G_N_ELEMENTS (MAPI_ONE_OFF_UID))
		return FALSE;

	ptr += r;
	sz -= r;

	u16 = 1;
	r = bin_decode_uint16 (ptr, sz, &u16);
	if (!r || u16 != 0)
		return FALSE;
	ptr += r;
	sz -= r;

	flags = 0;
	r = bin_decode_uint16 (ptr, sz, &flags);
	if (!r)
		return FALSE;
	ptr += r;
	sz -= r;

	r = bin_decode_string (ptr, sz, display_name, (flags & MAPI_ONE_OFF_UNICODE) != 0);
	if (!r || !*display_name)
		return FALSE;
	ptr += r;
	sz -= r;

	smtp = NULL;
	r = bin_decode_string (ptr, sz, &smtp, (flags & MAPI_ONE_OFF_UNICODE) != 0);
	if (!r || !smtp || !g_str_equal (smtp, "SMTP")) {
		g_free (smtp);
		g_free (*display_name);
		*display_name = NULL;

		return FALSE;
	}
	g_free (smtp);
	ptr += r;
	sz -= r;

	r = bin_decode_string (ptr, sz, email, (flags & MAPI_ONE_OFF_UNICODE) != 0);
	if (!r || !*email) {
		g_free (*display_name);
		*display_name = NULL;

		return FALSE;
	}

	return TRUE;
}

static gboolean
recip_entryid_decode_ex (const struct Binary_r *entryid, gchar **exchange_dn)
{
	uint32_t u32, sz, r;
	uint8_t *ptr;

	g_return_val_if_fail (entryid != NULL, FALSE);
	g_return_val_if_fail (entryid->lpb != NULL, FALSE);
	g_return_val_if_fail (exchange_dn != NULL, FALSE);

	*exchange_dn = NULL;

	ptr = entryid->lpb;
	sz = entryid->cb;

	u32 = 1;
	r = bin_decode_uint32 (ptr, sz, &u32);
	if (!r || u32 != 0)
		return FALSE;

	ptr += r;
	sz -= r;

	for (r = 0; r < G_N_ELEMENTS (MAPI_LOCAL_UID) && r < sz; r++) {
		if (ptr[r] != MAPI_LOCAL_UID[r])
			return FALSE;
	}

	if (r != G_N_ELEMENTS (MAPI_LOCAL_UID))
		return FALSE;

	ptr += r;
	sz -= r;

	/* version */
	u32 = 0;
	r = bin_decode_uint32 (ptr, sz, &u32);
	if (!r)
		return FALSE;
	ptr += r;
	sz -= r;

	/* type */
	u32 = 0;
	r = bin_decode_uint32 (ptr, sz, &u32);
	if (!r)
		return FALSE;
	ptr += r;
	sz -= r;

	r = bin_decode_string (ptr, sz, exchange_dn, FALSE);
	if (!r || !*exchange_dn)
		return FALSE;

	return TRUE;
}

/**
 * e_mapi_util_recip_entryid_decode:
 * @conn: ExchangeMapiCOnnection to resolve names, if required
 * @entryid: recipient's ENTRYID to decode
 * @display_name: (out): stored display name, if any; can be NULL
 * @email: (out): email or exchange DN; cannot be NULL
 *
 * Returns: Whether was able to decode recipient information from the @entryid.
 **/
gboolean
e_mapi_util_recip_entryid_decode (EMapiConnection *conn, const struct Binary_r *entryid, gchar **display_name, gchar **email)
{
	gchar *dispnm = NULL, *exchange_dn = NULL;

	g_return_val_if_fail (conn != NULL, FALSE);
	g_return_val_if_fail (entryid != NULL, FALSE);
	g_return_val_if_fail (email != NULL, FALSE);

	*email = NULL;
	if (display_name)
		*display_name = NULL;

	if (recip_entryid_decode_smtp (entryid, &dispnm, email)) {
		if (display_name)
			*display_name = dispnm;
		else
			g_free (dispnm);

		return TRUE;
	}

	if (recip_entryid_decode_ex (entryid, &exchange_dn)) {
		*email = e_mapi_connection_ex_to_smtp (conn, exchange_dn, display_name, NULL, NULL);
		g_free (exchange_dn);

		return *email != NULL;
	}

	return FALSE;
}

gboolean
e_mapi_util_recip_entryid_decode_dn (const struct SBinary_short *entryid,
				     gchar **exchange_dn)
{
	struct Binary_r ei;

	if (!entryid)
		return FALSE;

	ei.cb = entryid->cb;
	ei.lpb = entryid->lpb;

	return recip_entryid_decode_ex (&ei, exchange_dn);
}

gboolean
e_mapi_util_recip_entryid_equal (const struct SBinary_short *entryid1,
				 const struct SBinary_short *entryid2)
{
	gchar *dn1 = NULL, *dn2 = NULL;
	gboolean same = FALSE;

	if (!entryid1 && !entryid2)
		return TRUE;

	if (!entryid1 || !entryid2 || !entryid1->lpb || !entryid2->lpb || entryid1->cb != entryid2->cb)
		return FALSE;

	same = e_mapi_util_recip_entryid_decode_dn (entryid1, &dn1) &&
	       e_mapi_util_recip_entryid_decode_dn (entryid2, &dn2) &&
	       dn1 && dn2 && g_ascii_strcasecmp (dn1, dn2) == 0;

	g_free (dn1);
	g_free (dn2);

	return same;
}

/**
 * e_mapi_util_profiledata_from_settings:
 * @empd: destination for profile settings
 * @settings: a #CamelMapiSettings
 *
 * Sets the members of an EMapiProfileData instance to
 * reflect the account settings in @settings.
 *
 * @note: no allocation is done, so do not finalize @settings and the
 *        respective underlying pointers until you no longer need the
 *        profile data.
 **/
void
e_mapi_util_profiledata_from_settings (EMapiProfileData *empd, CamelMapiSettings *settings)
{
	CamelNetworkSettings *network_settings;
	CamelNetworkSecurityMethod security_method;

	network_settings = CAMEL_NETWORK_SETTINGS (settings);
	security_method = camel_network_settings_get_security_method (network_settings);

	empd->use_ssl = (security_method != CAMEL_NETWORK_SECURITY_METHOD_NONE);
	empd->domain = camel_mapi_settings_get_domain (settings);
	empd->krb_sso = camel_mapi_settings_get_kerberos (settings);
	empd->krb_realm = camel_mapi_settings_get_realm (settings);
}

gboolean
e_mapi_util_trigger_krb_auth (const EMapiProfileData *empd,
			      GError **error)
{
	gint success = FALSE;
	GError *local_error = NULL;
	GDBusConnection *connection;
	GDBusMessage *message, *reply;
	gchar *name;

	connection = g_bus_get_sync (G_BUS_TYPE_SESSION, NULL, &local_error);
	if (local_error) {
		g_warning ("could not get system bus: %s\n",
			   local_error->message);
		g_propagate_error (error, local_error);
		return FALSE;
	}

	g_dbus_connection_set_exit_on_close (connection, FALSE);
	/* Create a new message on the KRB_DBUS_INTERFACE */
	message = g_dbus_message_new_method_call (KRB_DBUS_INTERFACE,
						  KRB_DBUS_PATH,
						  KRB_DBUS_INTERFACE,
						  "acquireTgt");
	if (!message) {
		g_object_unref (connection);
		return FALSE;
	}

	/* Appends the data as an argument to the message */
	name = g_strdup_printf ("%s@%s", empd->username, empd->krb_realm);
	g_dbus_message_set_body (message, g_variant_new ("(s)", name));

	/* Sends the message: Have a 300 sec wait timeout  */
	reply = g_dbus_connection_send_message_with_reply_sync (connection, message, G_DBUS_SEND_MESSAGE_FLAGS_NONE, 300 * 1000, NULL, NULL, &local_error);
	g_free (name);

	if (!local_error && reply) {
		if (g_dbus_message_to_gerror (reply, &local_error)) {
			g_object_unref (reply);
			reply = NULL;
		}
	}

	if (local_error) {
		g_dbus_error_strip_remote_error (local_error);
		g_propagate_error (error, local_error);
	}

	if (reply) {
		GVariant *body = g_dbus_message_get_body (reply);
		if (body) {
			g_variant_get (body, "(b)", &success);
		}
		g_object_unref (reply);
	}

	/* Free the message */
	g_object_unref (message);
	g_object_unref (connection);

	return success && !local_error;
}

gboolean
e_mapi_util_trigger_krb_auth_from_settings (CamelMapiSettings *mapi_settings,
					    GError **error)
{
	EMapiProfileData empd = { 0 };
	CamelNetworkSettings *network_settings;

	g_return_val_if_fail (CAMEL_IS_MAPI_SETTINGS (mapi_settings), FALSE);

	network_settings = CAMEL_NETWORK_SETTINGS (mapi_settings);

	empd.server = camel_network_settings_get_host (network_settings);
	empd.username = camel_network_settings_get_user (network_settings);

	e_mapi_util_profiledata_from_settings (&empd, mapi_settings);

	return e_mapi_util_trigger_krb_auth (&empd, error);
}

/**
 * e_mapi_util_profile_name:
 * @mapi_ctx: a mapi context; can be NULL if @migrate is FALSE
 * @empd: profile information used to construct the name
 * @migrate: whether migrate old profile name to a new one
 *
 * Constructs profile name from given parameters and
 * returns it as a newly allocated string. It can also
 * rename old profile name string to a new name, if requested.
 **/
gchar *
e_mapi_util_profile_name (struct mapi_context *mapi_ctx, const EMapiProfileData *empd, gboolean migrate)
{
	gchar *res;

	res = g_strdup_printf ("%s@%s@%s", empd->username, empd->domain, empd->server);
	res = g_strcanon (res, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@.-", '_');

	if (migrate) {
		/* expects MAPIInitialize already called! */
		gchar *old_name;

		g_return_val_if_fail (mapi_ctx != NULL, res);

		old_name = g_strdup_printf ("%s@%s", empd->username, empd->domain);
		old_name = g_strcanon (old_name, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@", '_');

		e_mapi_rename_profile (mapi_ctx, old_name, res, NULL);

		g_free (old_name);
	}

	return res;
}

/**
 * Adds a new SPropValue at the end of values_array, allocating its memory in the mem_ctx.
 * *n_values holds number of items stored in the array, and will be increased by one.
 **/
gboolean
e_mapi_utils_add_spropvalue (TALLOC_CTX *mem_ctx,
			     struct SPropValue **values_array,
			     uint32_t *n_values,
			     uint32_t prop_tag,
			     gconstpointer prop_value)
{
	g_return_val_if_fail (mem_ctx != NULL, FALSE);
	g_return_val_if_fail (values_array != NULL, FALSE);
	g_return_val_if_fail (n_values != NULL, FALSE);

	*values_array = add_SPropValue (mem_ctx, *values_array, n_values, prop_tag, prop_value);

	return TRUE;
}

gboolean
e_mapi_utils_add_property (struct mapi_SPropValue_array *properties,
			   uint32_t proptag,
			   gconstpointer propvalue,
			   TALLOC_CTX *mem_ctx)
{
	uint32_t ii;
	struct SPropValue sprop = { 0 };

	g_return_val_if_fail (properties != NULL, FALSE);
	g_return_val_if_fail (proptag != 0, FALSE);
	g_return_val_if_fail (propvalue != NULL, FALSE);
	g_return_val_if_fail (mem_ctx != NULL, FALSE);

	/* make copy of string properties */
	if ((proptag & 0xFFFF) == PT_STRING8 ||
	    (proptag & 0xFFFF) == PT_UNICODE)
		propvalue = talloc_strdup (mem_ctx, (const gchar *) propvalue);

	sprop.ulPropTag = proptag;
	g_return_val_if_fail (set_SPropValue (&sprop, propvalue), FALSE);

	for (ii = 0; ii < properties->cValues; ii++) {
		if (properties->lpProps[ii].ulPropTag == proptag) {
			cast_mapi_SPropValue (mem_ctx, &(properties->lpProps[ii]), &sprop);
			break;
		}
	}

	if (ii == properties->cValues) {
		properties->cValues++;
		properties->lpProps = talloc_realloc (mem_ctx,
			properties->lpProps,
			struct mapi_SPropValue,
			properties->cValues + 1);
		cast_mapi_SPropValue (mem_ctx, &(properties->lpProps[properties->cValues - 1]), &sprop);
		properties->lpProps[properties->cValues].ulPropTag = 0;
	}

	return TRUE;
}

/* the first call should be with crc32 set to 0 */
uint32_t
e_mapi_utils_push_crc32 (uint32_t crc32, uint8_t *bytes, uint32_t n_bytes)
{
	static uint32_t crc_32_tab[] = { /* CRC polynomial 0xedb88320 */
		0x00000000, 0x77073096, 0xee0e612c, 0x990951ba, 0x076dc419, 0x706af48f,
		0xe963a535, 0x9e6495a3, 0x0edb8832, 0x79dcb8a4, 0xe0d5e91e, 0x97d2d988,
		0x09b64c2b, 0x7eb17cbd, 0xe7b82d07, 0x90bf1d91, 0x1db71064, 0x6ab020f2,
		0xf3b97148, 0x84be41de, 0x1adad47d, 0x6ddde4eb, 0xf4d4b551, 0x83d385c7,
		0x136c9856, 0x646ba8c0, 0xfd62f97a, 0x8a65c9ec, 0x14015c4f, 0x63066cd9,
		0xfa0f3d63, 0x8d080df5, 0x3b6e20c8, 0x4c69105e, 0xd56041e4, 0xa2677172,
		0x3c03e4d1, 0x4b04d447, 0xd20d85fd, 0xa50ab56b, 0x35b5a8fa, 0x42b2986c,
		0xdbbbc9d6, 0xacbcf940, 0x32d86ce3, 0x45df5c75, 0xdcd60dcf, 0xabd13d59,
		0x26d930ac, 0x51de003a, 0xc8d75180, 0xbfd06116, 0x21b4f4b5, 0x56b3c423,
		0xcfba9599, 0xb8bda50f, 0x2802b89e, 0x5f058808, 0xc60cd9b2, 0xb10be924,
		0x2f6f7c87, 0x58684c11, 0xc1611dab, 0xb6662d3d, 0x76dc4190, 0x01db7106,
		0x98d220bc, 0xefd5102a, 0x71b18589, 0x06b6b51f, 0x9fbfe4a5, 0xe8b8d433,
		0x7807c9a2, 0x0f00f934, 0x9609a88e, 0xe10e9818, 0x7f6a0dbb, 0x086d3d2d,
		0x91646c97, 0xe6635c01, 0x6b6b51f4, 0x1c6c6162, 0x856530d8, 0xf262004e,
		0x6c0695ed, 0x1b01a57b, 0x8208f4c1, 0xf50fc457, 0x65b0d9c6, 0x12b7e950,
		0x8bbeb8ea, 0xfcb9887c, 0x62dd1ddf, 0x15da2d49, 0x8cd37cf3, 0xfbd44c65,
		0x4db26158, 0x3ab551ce, 0xa3bc0074, 0xd4bb30e2, 0x4adfa541, 0x3dd895d7,
		0xa4d1c46d, 0xd3d6f4fb, 0x4369e96a, 0x346ed9fc, 0xad678846, 0xda60b8d0,
		0x44042d73, 0x33031de5, 0xaa0a4c5f, 0xdd0d7cc9, 0x5005713c, 0x270241aa,
		0xbe0b1010, 0xc90c2086, 0x5768b525, 0x206f85b3, 0xb966d409, 0xce61e49f,
		0x5edef90e, 0x29d9c998, 0xb0d09822, 0xc7d7a8b4, 0x59b33d17, 0x2eb40d81,
		0xb7bd5c3b, 0xc0ba6cad, 0xedb88320, 0x9abfb3b6, 0x03b6e20c, 0x74b1d29a,
		0xead54739, 0x9dd277af, 0x04db2615, 0x73dc1683, 0xe3630b12, 0x94643b84,
		0x0d6d6a3e, 0x7a6a5aa8, 0xe40ecf0b, 0x9309ff9d, 0x0a00ae27, 0x7d079eb1,
		0xf00f9344, 0x8708a3d2, 0x1e01f268, 0x6906c2fe, 0xf762575d, 0x806567cb,
		0x196c3671, 0x6e6b06e7, 0xfed41b76, 0x89d32be0, 0x10da7a5a, 0x67dd4acc,
		0xf9b9df6f, 0x8ebeeff9, 0x17b7be43, 0x60b08ed5, 0xd6d6a3e8, 0xa1d1937e,
		0x38d8c2c4, 0x4fdff252, 0xd1bb67f1, 0xa6bc5767, 0x3fb506dd, 0x48b2364b,
		0xd80d2bda, 0xaf0a1b4c, 0x36034af6, 0x41047a60, 0xdf60efc3, 0xa867df55,
		0x316e8eef, 0x4669be79, 0xcb61b38c, 0xbc66831a, 0x256fd2a0, 0x5268e236,
		0xcc0c7795, 0xbb0b4703, 0x220216b9, 0x5505262f, 0xc5ba3bbe, 0xb2bd0b28,
		0x2bb45a92, 0x5cb36a04, 0xc2d7ffa7, 0xb5d0cf31, 0x2cd99e8b, 0x5bdeae1d,
		0x9b64c2b0, 0xec63f226, 0x756aa39c, 0x026d930a, 0x9c0906a9, 0xeb0e363f,
		0x72076785, 0x05005713, 0x95bf4a82, 0xe2b87a14, 0x7bb12bae, 0x0cb61b38,
		0x92d28e9b, 0xe5d5be0d, 0x7cdcefb7, 0x0bdbdf21, 0x86d3d2d4, 0xf1d4e242,
		0x68ddb3f8, 0x1fda836e, 0x81be16cd, 0xf6b9265b, 0x6fb077e1, 0x18b74777,
		0x88085ae6, 0xff0f6a70, 0x66063bca, 0x11010b5c, 0x8f659eff, 0xf862ae69,
		0x616bffd3, 0x166ccf45, 0xa00ae278, 0xd70dd2ee, 0x4e048354, 0x3903b3c2,
		0xa7672661, 0xd06016f7, 0x4969474d, 0x3e6e77db, 0xaed16a4a, 0xd9d65adc,
		0x40df0b66, 0x37d83bf0, 0xa9bcae53, 0xdebb9ec5, 0x47b2cf7f, 0x30b5ffe9,
		0xbdbdf21c, 0xcabac28a, 0x53b39330, 0x24b4a3a6, 0xbad03605, 0xcdd70693,
		0x54de5729, 0x23d967bf, 0xb3667a2e, 0xc4614ab8, 0x5d681b02, 0x2a6f2b94,
		0xb40bbe37, 0xc30c8ea1, 0x5a05df1b, 0x2d02ef8d
	};

	g_return_val_if_fail (bytes != NULL, crc32);

	while (n_bytes > 0) {
		#define UPDC32(octet,crc) (crc_32_tab[((crc) ^ ((uint8_t)octet)) & 0xff] ^ ((crc) >> 8))

		crc32 = UPDC32 (*bytes, crc32);

		n_bytes--;
		bytes++;
	}

	return crc32;
}

/* copies an SBinary_short, which should be freed with e_mapi_util_free_sbinary_short() */
struct SBinary_short *
e_mapi_util_copy_sbinary_short (const struct SBinary_short *bin)
{
	struct SBinary_short *res;

	if (!bin || !bin->cb)
		return NULL;

	res = g_new0 (struct SBinary_short, 1);
	res->cb = bin->cb;
	res->lpb = g_new (uint8_t, res->cb);
	memcpy (res->lpb, bin->lpb, res->cb);

	return res;
}

/* frees SBinary_short previously allocated by e_mapi_util_copy_sbinary_short() */
void
e_mapi_util_free_sbinary_short (struct SBinary_short *bin)
{
	if (!bin)
		return;

	g_free (bin->lpb);
	g_free (bin);
}

time_t
e_mapi_util_filetime_to_time_t (const struct FILETIME *filetime)
{
	NTTIME nt;

	if (!filetime)
		return (time_t) 0;

	nt = filetime->dwHighDateTime;
	nt = nt << 32;
	nt |= filetime->dwLowDateTime;

	nt /=  10 * 1000 * 1000;
	nt -= 11644473600LL;

	return (time_t) nt;
}

void
e_mapi_util_time_t_to_filetime (const time_t tt, struct FILETIME *filetime)
{
	NTTIME nt;

	g_return_if_fail (filetime != NULL);

	nt = tt;
	nt += 11644473600LL;
	nt *=  10 * 1000 * 1000;

	filetime->dwLowDateTime = nt & 0xFFFFFFFF;
	nt = nt >> 32;
	filetime->dwHighDateTime = nt & 0xFFFFFFFF;
}

gboolean
e_mapi_utils_propagate_cancelled_error (const GError *mapi_error,
					GError **error)
{
	if (!g_error_matches (mapi_error, G_IO_ERROR, G_IO_ERROR_CANCELLED) &&
	    !g_error_matches (mapi_error, E_MAPI_ERROR, MAPI_E_USER_CANCEL))
		return FALSE;

	g_set_error_literal (error, G_IO_ERROR, G_IO_ERROR_CANCELLED, mapi_error->message);

	return TRUE;
}

gboolean
e_mapi_utils_create_mapi_context (struct mapi_context **mapi_ctx, GError **perror)
{
	const gchar *user_data_dir;
	gchar *profpath;
	enum MAPISTATUS ms;

	g_return_val_if_fail (mapi_ctx != NULL, FALSE);

	if (!e_mapi_utils_global_lock (NULL, perror))
		return FALSE;

	*mapi_ctx = NULL;
	user_data_dir = e_get_user_data_dir ();
	profpath = g_build_filename (user_data_dir, DEFAULT_PROF_NAME, NULL);

	if (!g_file_test (profpath, G_FILE_TEST_EXISTS | G_FILE_TEST_IS_REGULAR)) {
		/* Create a ProfileStore */
		ms = CreateProfileStore (profpath, LIBMAPI_LDIF_DIR);
		if (ms != MAPI_E_SUCCESS && (ms != MAPI_E_NO_ACCESS || !g_file_test (profpath, G_FILE_TEST_EXISTS | G_FILE_TEST_IS_REGULAR))) {
			make_mapi_error (perror, "CreateProfileStore", ms);
			g_free (profpath);

			e_mapi_utils_global_unlock ();
			return FALSE;
		}
	}

	ms = MAPIInitialize (mapi_ctx, profpath);
	if (ms != MAPI_E_SUCCESS) {
		make_mapi_error (perror, "MAPIInitialize", ms);
		g_free (profpath);

		e_mapi_utils_global_unlock ();
		return FALSE;
	}

	g_free (profpath);

	/* Initialize libmapi logger */
	if (*mapi_ctx && g_getenv ("LIBMAPI_DEBUG")) {
		guint32 debug_log_level = atoi (g_getenv ("LIBMAPI_DEBUG"));
		SetMAPIDumpData (*mapi_ctx, TRUE);
		SetMAPIDebugLevel (*mapi_ctx, debug_log_level);
	}

	e_mapi_utils_global_unlock ();

	return TRUE;
}

void
e_mapi_utils_destroy_mapi_context (struct mapi_context *mapi_ctx)
{
	if (!mapi_ctx)
		return;

	if (!e_mapi_utils_global_lock (NULL, NULL))
		return;

	MAPIUninitialize (mapi_ctx);
	e_mapi_utils_global_unlock ();
}

gboolean
e_mapi_utils_ensure_utf8_string (uint32_t proptag,
				 const uint32_t *cpid,
				 const guint8 *buf_data,
				 guint32 buf_len,
				 gchar **out_utf8)
{
	g_return_val_if_fail (buf_data != NULL, FALSE);
	g_return_val_if_fail (out_utf8 != NULL, FALSE);

	if (proptag != PidTagHtml && (proptag & 0xFFFF) != PT_UNICODE)
		return FALSE;

	*out_utf8 = NULL;

	if ((cpid && (*cpid == 1200 || *cpid == 1201)) || (buf_len > 5 && buf_data[3] == '\0')) {
		/* this is special, get the CPID and transform to utf8 when it's utf16 */
		gsize written = 0;
		gchar *in_utf8;

		/* skip Unicode marker, if there */
		if (buf_len >= 2 && buf_data[0] == 0xFF && buf_data[1] == 0xFE)
			in_utf8 = g_convert ((const gchar *) buf_data + 2, buf_len - 2, "UTF-8", "UTF-16", NULL, &written, NULL);
		else
			in_utf8 = g_convert ((const gchar *) buf_data, buf_len, "UTF-8", "UTF-16", NULL, &written, NULL);

		if (in_utf8 && written > 0) {
			*out_utf8 = g_strndup (in_utf8, written);
			g_free (in_utf8);
		}
	}

	if (!*out_utf8)
		*out_utf8 = g_strndup ((const gchar *) buf_data, buf_len);

	return TRUE;
}

/* takes pointer to a time_t and populates restrictions
   with a restriction on PidTagLastModificationTime
*/
gboolean
e_mapi_utils_build_last_modify_restriction (EMapiConnection *conn,
					    TALLOC_CTX *mem_ctx,
					    struct mapi_SRestriction **restrictions,
					    gpointer user_data,
					    GCancellable *cancellable,
					    GError **perror)
{
	const time_t *latest_last_modify = user_data;
	struct mapi_SRestriction *restriction = NULL;

	g_return_val_if_fail (restrictions != NULL, FALSE);

	if (latest_last_modify && *latest_last_modify > 0) {
		struct SPropValue sprop;
		struct timeval t;

		restriction = talloc_zero (mem_ctx, struct mapi_SRestriction);
		g_return_val_if_fail (restriction != NULL, FALSE);

		restriction->rt = RES_PROPERTY;
		restriction->res.resProperty.relop = RELOP_GT;
		restriction->res.resProperty.ulPropTag = PidTagLastModificationTime;

		t.tv_sec = *latest_last_modify;
		t.tv_usec = 0;

		set_SPropValue_proptag_date_timeval (&sprop, PidTagLastModificationTime, &t);
		cast_mapi_SPropValue (mem_ctx, &(restriction->res.resProperty.lpProp), &sprop);
	}

	*restrictions = restriction;

	return TRUE;
}

gboolean
e_mapi_utils_get_folder_basic_properties_cb (EMapiConnection *conn,
					     TALLOC_CTX *mem_ctx,
					     /* const */ struct mapi_SPropValue_array *properties,
					     gpointer user_data,
					     GCancellable *cancellable,
					     GError **perror)
{
	struct FolderBasicPropertiesData *fbp = user_data;
	const mapi_id_t *pfid;
	const struct FILETIME *plast_modified;
	const uint32_t *pcontent_count;

	g_return_val_if_fail (properties != NULL, FALSE);
	g_return_val_if_fail (user_data != NULL, FALSE);

	pfid = e_mapi_util_find_array_propval (properties, PidTagFolderId);
	plast_modified = e_mapi_util_find_array_propval (properties, PidTagLastModificationTime);
	pcontent_count = e_mapi_util_find_array_propval (properties, PidTagContentCount);

	if (pfid)
		fbp->fid = *pfid;
	else
		fbp->fid = 0;

	if (pcontent_count)
		fbp->obj_total = *pcontent_count;
	else
		fbp->obj_total = 0;

	if (plast_modified)
		fbp->last_modified = e_mapi_util_filetime_to_time_t (plast_modified);
	else
		fbp->last_modified = 0;

	return TRUE;
}

gboolean
e_mapi_utils_copy_to_mapi_SPropValue (TALLOC_CTX *mem_ctx,
				      struct mapi_SPropValue *mapi_sprop, 
				      struct SPropValue *sprop)
{
	mapi_sprop->ulPropTag = sprop->ulPropTag;

	switch (sprop->ulPropTag & 0xFFFF) {
	case PT_BOOLEAN:
		mapi_sprop->value.b = sprop->value.b;
		return TRUE;
	case PT_I2:
		mapi_sprop->value.i = sprop->value.i;
		return TRUE;
	case PT_LONG:
		mapi_sprop->value.l = sprop->value.l;
		return TRUE;
	case PT_DOUBLE:
		memcpy (&mapi_sprop->value.dbl, (uint8_t *) &sprop->value.dbl, 8);
		return TRUE;
	case PT_I8:
		mapi_sprop->value.d = sprop->value.d;
		return TRUE;
	case PT_STRING8:
		mapi_sprop->value.lpszA = talloc_strdup (mem_ctx, sprop->value.lpszA);
		return TRUE;
	case PT_UNICODE:
		mapi_sprop->value.lpszW = talloc_strdup (mem_ctx, sprop->value.lpszW);
		return TRUE;
	case PT_SYSTIME:
		mapi_sprop->value.ft.dwLowDateTime = sprop->value.ft.dwLowDateTime;
		mapi_sprop->value.ft.dwHighDateTime = sprop->value.ft.dwHighDateTime;
		return TRUE;
	case PT_BINARY:
		mapi_sprop->value.bin.cb = sprop->value.bin.cb;
		mapi_sprop->value.bin.lpb = talloc_memdup (mem_ctx, sprop->value.bin.lpb, sprop->value.bin.cb);
		return TRUE;
        case PT_ERROR:
                mapi_sprop->value.err = sprop->value.err;
                return TRUE;
	case PT_CLSID:
	{
		DATA_BLOB	b;

		b.data = sprop->value.lpguid->ab;
		b.length = 16;

		GUID_from_ndr_blob (&b, &mapi_sprop->value.lpguid);

		return TRUE;
	}
	case PT_SVREID:
		mapi_sprop->value.bin.cb = sprop->value.bin.cb;
		mapi_sprop->value.bin.lpb = talloc_memdup (mem_ctx, sprop->value.bin.lpb, sprop->value.bin.cb);
		return TRUE;
	case PT_MV_STRING8:
	{
		uint32_t i;

		mapi_sprop->value.MVszA.cValues = sprop->value.MVszA.cValues;
		mapi_sprop->value.MVszA.strings = talloc_array (mem_ctx, struct mapi_LPSTR, mapi_sprop->value.MVszA.cValues);
		for (i = 0; i < mapi_sprop->value.MVszA.cValues; i++) {
			mapi_sprop->value.MVszA.strings[i].lppszA = talloc_strdup (mem_ctx, sprop->value.MVszA.lppszA[i]);
		}
		return TRUE;
	}
	case PT_MV_UNICODE:
	{
		uint32_t i;

		mapi_sprop->value.MVszW.cValues = sprop->value.MVszW.cValues;
		mapi_sprop->value.MVszW.strings = talloc_array (mem_ctx, struct mapi_LPWSTR, mapi_sprop->value.MVszW.cValues);
		for (i = 0; i < mapi_sprop->value.MVszW.cValues; i++) {
			mapi_sprop->value.MVszW.strings[i].lppszW = talloc_strdup (mem_ctx, sprop->value.MVszW.lppszW[i]);
		}
		return TRUE;
	}
	case PT_MV_BINARY:
	{
		uint32_t i;

		mapi_sprop->value.MVbin.cValues = sprop->value.MVbin.cValues;
		mapi_sprop->value.MVbin.bin = talloc_array (mem_ctx, struct SBinary_short, mapi_sprop->value.MVbin.cValues);
		for (i = 0; i < mapi_sprop->value.MVbin.cValues; i++) {
			mapi_sprop->value.MVbin.bin[i].cb = sprop->value.MVbin.lpbin[i].cb;
			mapi_sprop->value.MVbin.bin[i].lpb = talloc_memdup (mem_ctx, sprop->value.MVbin.lpbin[i].lpb, sprop->value.MVbin.lpbin[i].cb);
		}
		return TRUE;
	}
	case PT_MV_LONG:
	{
		uint32_t i;

		mapi_sprop->value.MVl.cValues = sprop->value.MVl.cValues;
		mapi_sprop->value.MVl.lpl = talloc_array (mem_ctx, uint32_t, mapi_sprop->value.MVl.cValues);
		for (i = 0; i < mapi_sprop->value.MVl.cValues; i++) {
			mapi_sprop->value.MVl.lpl[i] = sprop->value.MVl.lpl[i];
		}
		return TRUE;
	}
        default:
		break;
	}

	return FALSE;
}

static gpointer
unref_object_in_thread (gpointer ptr)
{
	GObject *object = ptr;

	g_return_val_if_fail (object != NULL, NULL);

	g_object_unref (object);

	return NULL;
}

void
e_mapi_utils_unref_in_thread (GObject *object)
{
	GThread *thread;
	GError *error = NULL;

	if (!object)
		return;

	g_return_if_fail (G_IS_OBJECT (object));

	thread = g_thread_try_new (NULL, unref_object_in_thread, object, &error);
	if (thread) {
		g_thread_unref (thread);
	} else {
		g_warning ("%s: Failed to run thread: %s", G_STRFUNC, error ? error->message : "Unknown error");
		g_object_unref (object);
	}
}

static gboolean
is_for_profile (ESource *source,
		const gchar *profile)
{
	ESourceCamel *extension;
	CamelMapiSettings *settings;
	const gchar *extension_name;

	if (!source)
		return FALSE;

	if (!profile)
		return TRUE;

	extension_name = e_source_camel_get_extension_name ("mapi");
	if (!e_source_has_extension (source, extension_name))
		return FALSE;

	extension = e_source_get_extension (source, extension_name);
	settings = CAMEL_MAPI_SETTINGS (e_source_camel_get_settings (extension));

	return settings && g_strcmp0 (camel_mapi_settings_get_profile (settings), profile) == 0;
}

/* filters @esources thus the resulting list will contain ESource-s only for @profile;
   free returned list with g_list_free_full (list, g_object_unref); */
GList *
e_mapi_utils_filter_sources_for_profile (const GList *esources,
					 const gchar *profile)
{
	GList *found = NULL;
	const GList *iter;
	ESource *master_source;

	master_source = e_mapi_utils_get_master_source (esources, profile);
	if (!master_source)
		return NULL;

	for (iter = esources; iter; iter = iter->next) {
		ESource *source = iter->data;

		if (is_for_profile (source, profile) ||
		    g_strcmp0 (e_source_get_uid (master_source), e_source_get_parent (source)) == 0)
			found = g_list_prepend (found, g_object_ref (source));
	}

	return g_list_reverse (found);
}

/* returns (not-reffed) member of @esources, which is for @profile and @folder_id */
ESource *
e_mapi_utils_get_source_for_folder (const GList *esources,
				    const gchar *profile,
				    mapi_id_t folder_id)
{
	ESource *master_source;
	const GList *iter;
	
	master_source = e_mapi_utils_get_master_source (esources, profile);
	if (!master_source)
		return NULL;

	for (iter = esources; iter; iter = iter->next) {
		ESource *source = iter->data;

		if ((is_for_profile (source, profile) ||
		    g_strcmp0 (e_source_get_uid (master_source), e_source_get_parent (source)) == 0) &&
		    e_source_has_extension (source, E_SOURCE_EXTENSION_MAPI_FOLDER)) {
			ESourceMapiFolder *folder_ext = e_source_get_extension (source, E_SOURCE_EXTENSION_MAPI_FOLDER);

			g_return_val_if_fail (folder_ext != NULL, NULL);

			if (e_source_mapi_folder_get_id (folder_ext) == folder_id)
				return source;
		}
	}

	return NULL;
}

/* returns (not-reffed) member of @esources, which is master (with no parent) source for @profile */
ESource *
e_mapi_utils_get_master_source (const GList *esources,
				const gchar *profile)
{
	const GList *iter;

	for (iter = esources; iter; iter = iter->next) {
		ESource *source = iter->data;

		if (!e_source_get_parent (source) &&
		    is_for_profile (source, profile))
			return source;
	}

	return NULL;
}
