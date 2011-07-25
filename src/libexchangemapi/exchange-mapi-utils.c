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

#include "exchange-mapi-utils.h"
#include "exchange-mapi-mail-utils.h"

#ifdef G_OS_WIN32
/* Undef the similar macro from pthread.h, it doesn't check if
 * gmtime() returns NULL.
 */
#undef gmtime_r

/* The gmtime() in Microsoft's C library is MT-safe */
#define gmtime_r(tp,tmp) (gmtime(tp)?(*(tmp)=*gmtime(tp),(tmp)):0)
#endif

inline gchar *
exchange_mapi_util_mapi_id_to_string (mapi_id_t id)
{
	return g_strdup_printf ("%016" G_GINT64_MODIFIER "X", id);
}

inline gboolean
exchange_mapi_util_mapi_id_from_string (const gchar *str, mapi_id_t *id)
{
	gint n = 0;

	if (str && *str)
		n = sscanf (str, "%016" G_GINT64_MODIFIER "X", id);

	return (n == 1);
}

/* NOTE: We use the UID as a combination of the folder-id and the message-id.
 * Specifically, it is in this format: ("%016" G_GINT64_MODIFIER "X%016" G_GINT64_MODIFIER "X", fid, mid).
 */
inline gchar *
exchange_mapi_util_mapi_ids_to_uid (mapi_id_t fid, mapi_id_t mid)
{
	return g_strdup_printf ("%016" G_GINT64_MODIFIER "X%016" G_GINT64_MODIFIER "X", fid, mid);
}

inline gboolean
exchange_mapi_util_mapi_ids_from_uid (const gchar *str, mapi_id_t *fid, mapi_id_t *mid)
{
	gint n = 0;

	if (str && *str)
		n = sscanf (str, "%016" G_GINT64_MODIFIER "X%016" G_GINT64_MODIFIER "X", fid, mid);

	return (n == 2);
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
exchange_mapi_util_find_SPropVal_array_propval (struct SPropValue *values, uint32_t proptag)
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

gconstpointer
exchange_mapi_util_find_SPropVal_array_namedid (struct SPropValue *values, ExchangeMapiConnection *conn, mapi_id_t fid, uint32_t namedid)
{
	uint32_t proptag;
	gconstpointer res = NULL;

	g_return_val_if_fail (values != NULL, NULL);
	g_return_val_if_fail (conn != NULL, NULL);

	proptag = exchange_mapi_connection_resolve_named_prop (conn, fid, namedid, NULL);
	if (proptag != MAPI_E_RESERVED)
		res = exchange_mapi_util_find_SPropVal_array_propval (values, proptag);

	if (!res)
		res = exchange_mapi_util_find_SPropVal_array_propval (values, namedid);

	return res;
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
exchange_mapi_util_find_row_propval (struct SRow *aRow, uint32_t proptag)
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
exchange_mapi_util_find_row_namedid (struct SRow *aRow, ExchangeMapiConnection *conn, mapi_id_t fid, uint32_t namedid)
{
	uint32_t proptag;
	gconstpointer res = NULL;

	g_return_val_if_fail (aRow != NULL, NULL);
	g_return_val_if_fail (conn != NULL, NULL);

	proptag = exchange_mapi_connection_resolve_named_prop (conn, fid, namedid, NULL);
	if (proptag != MAPI_E_RESERVED)
		res = exchange_mapi_util_find_row_propval (aRow, proptag);

	if (!res)
		res = exchange_mapi_util_find_row_propval (aRow, namedid);

	return res;
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
exchange_mapi_util_find_array_propval (struct mapi_SPropValue_array *properties, uint32_t proptag)
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

gconstpointer
exchange_mapi_util_find_array_namedid (struct mapi_SPropValue_array *properties, ExchangeMapiConnection *conn, mapi_id_t fid, uint32_t namedid)
{
	uint32_t proptag;
	gconstpointer res = NULL;

	g_return_val_if_fail (properties != NULL, NULL);
	g_return_val_if_fail (conn != NULL, NULL);

	proptag = exchange_mapi_connection_resolve_named_prop (conn, fid, namedid, NULL);
	if (proptag != MAPI_E_RESERVED)
		res = exchange_mapi_util_find_array_propval (properties, proptag);

	if (!res)
		res = exchange_mapi_util_find_array_propval (properties, namedid);

	return res;
}

ExchangeMAPIStream *
exchange_mapi_util_find_stream (GSList *stream_list, uint32_t proptag)
{
	GSList *l = stream_list;

	for (; l != NULL; l = l->next) {
		ExchangeMAPIStream *stream = (ExchangeMAPIStream *) (l->data);
		if (stream->proptag == proptag)
			return stream;
	}

	return NULL;
}

void
exchange_mapi_util_free_attachment_list (GSList **attach_list)
{
	GSList *l = *attach_list;

	if (!l)
		return;

	for (; l != NULL; l = l->next) {
		ExchangeMAPIAttachment *attachment = (ExchangeMAPIAttachment *) (l->data);

		if (attachment->mail) {
			mail_item_free (attachment->mail);
		} else {
			g_free (attachment->lpProps);
			exchange_mapi_util_free_stream_list (&(attachment->streams));
		}

		g_free (attachment);
		l->data = NULL;
	}
	g_slist_free (*attach_list);
	*attach_list = NULL;
}

void
exchange_mapi_util_free_recipient_list (GSList **recip_list)
{
	GSList *l = *recip_list;

	if (!l)
		return;

	for (; l != NULL; l = l->next) {
		ExchangeMAPIRecipient *recipient = (ExchangeMAPIRecipient *) (l->data);

		talloc_free (recipient->mem_ctx);
		if (recipient->in.ext_cValues)
			g_free (recipient->in.ext_lpProps);
		if (recipient->in.req_cValues)
			g_free (recipient->in.req_lpProps);
/*		if (recipient->out_SRow.cValues)
			g_free (recipient->out_SRow.lpProps);
*/		g_free (recipient);
	}
	g_slist_free (*recip_list);
	*recip_list = NULL;
}

void
exchange_mapi_util_free_stream_list (GSList **stream_list)
{
	GSList *l = *stream_list;

	if (!l)
		return;

	for (; l != NULL; l = l->next) {
		ExchangeMAPIStream *stream = (ExchangeMAPIStream *) (l->data);
		g_byte_array_free (stream->value, TRUE);
		stream->value = NULL;
		g_free (stream);
		stream = NULL;
	}
	g_slist_free (*stream_list);
	*stream_list = NULL;
}

static void
dump_bin (const uint8_t *bin, uint32_t bin_sz, const gchar *line_prefix)
{
	gint k, l, last;

	if (!bin) {
		g_print ("NULL");
		return;
	}

	g_print ("%s", line_prefix);

	last = 0;
	for (k = 0; k < bin_sz; k++) {
		if ((k > 0 && (k % 16) == 0)) {
			g_print ("  ");
			for (l = last; l < k; l++) {
				uint8_t u8 = bin[l];

				if ((l % 8) == 0)
					g_print (" ");
				if (u8 <= 32 || u8 >= 128)
					g_print (".");
				else
					g_print ("%c", u8);
			}

			last = l;
			g_print ("\n%s", line_prefix);
		} else if (k > 0 && (k % 8) == 0) {
			g_print ("  ");
		}
		g_print (" %02X", bin[k]);
	}

	if (last < k) {
		l = k;

		while ((l % 16) != 0) {
			g_print ("   ");
			if (l > 0 && (l % 8) == 0)
				g_print ("  ");
			l++;
		}

		g_print ("  ");
		for (l = last; l < k; l++) {
			uint8_t u8 = bin[l];

			if ((l % 8) == 0)
				g_print (" ");
			if (u8 <= 32 || u8 >= 128)
				g_print (".");
			else
				g_print ("%c", u8);
		}
	}
}

void
exchange_mapi_debug_property_dump (struct mapi_SPropValue_array *properties)
{
	gint i = 0;

	for (i = 0; i < properties->cValues; i++) {
		for (i = 0; i < properties->cValues; i++) {
			struct mapi_SPropValue *lpProp = &properties->lpProps[i];
			const gchar *tmp =  get_proptag_name (lpProp->ulPropTag);
			gchar t_str[26];
			gint j = 0;
			if (tmp && *tmp)
				g_print("\n%s \t",tmp);
			else
				g_print("\n0x%08X \t", lpProp->ulPropTag);
			switch (lpProp->ulPropTag & 0xFFFF) {
			case PT_UNSPECIFIED:
				g_print (" PT_UNSPECIFIED");
				break;
			case PT_NULL:
				g_print (" PT_NULL");
				break;
			case PT_BOOLEAN:
				g_print(" (bool) - %d", (bool) lpProp->value.b);
				break;
			case PT_I2:
				g_print(" (uint16_t) - %d", lpProp->value.i);
				break;
			case PT_LONG:
				g_print(" (long) - %u", lpProp->value.l);
				break;
			case PT_FLOAT:
				g_print (" PT_FLOAT");
				break;
			case PT_DOUBLE:
				g_print (" (double) -  %lf", (double)lpProp->value.dbl);
				break;
			case PT_CURRENCY:
				g_print (" PT_CURRENCY");
				break;
			case PT_APPTIME:
				g_print (" PT_APPTIME");
			case PT_I8:
				g_print (" (gint) - 0x%016" G_GINT64_MODIFIER "X", lpProp->value.d);
				break;
			case PT_SYSTIME: {
					struct timeval t;
					struct tm tm;
					if (get_mapi_SPropValue_array_date_timeval (&t, properties, lpProp->ulPropTag) == MAPI_E_SUCCESS) {
						gmtime_r (&(t.tv_sec), &tm);
						strftime (t_str, 26, "%Y-%m-%dT%H:%M:%SZ", &tm);
						g_print (" (struct FILETIME *) - %p\t (struct timeval) %s\t", &lpProp->value.ft, t_str);
					}
				}
				break;
			case PT_ERROR:
				g_print (" (error) - "/* , lpProp->value.err */);
				break;
			case PT_STRING8:
				g_print(" (string) - %s", lpProp->value.lpszA ? lpProp->value.lpszA : "null" );
				break;
			case PT_UNICODE:
				if (lpProp)
					g_print(" (unicodestring) - %s", lpProp->value.lpszW ? lpProp->value.lpszW : lpProp->value.lpszA ? lpProp->value.lpszA : "null");
				break;
			case PT_OBJECT:
				g_print (" PT_OBJECT");
				break;
			case PT_CLSID:
				g_print (" PT_CLSID");
				break;
			case PT_SVREID:
				g_print (" PT_SVREID");
				break;
			case PT_SRESTRICT:
				g_print (" PT_SRESTRICT");
				break;
			case PT_ACTIONS:
				g_print (" PT_ACTIONS");
				break;
			case PT_BINARY:
				g_print(" (struct SBinary_short *) - %p Binary data follows (size %d): \n", &lpProp->value.bin, lpProp->value.bin.cb);
				dump_bin (lpProp->value.bin.lpb, lpProp->value.bin.cb, "     ");
				break;
			case PT_MV_STRING8:
				g_print(" (struct mapi_SLPSTRArray *) (%d items)", lpProp->value.MVszA.cValues);
				for (j = 0; j < lpProp->value.MVszA.cValues; j++) {
					g_print ("\n   item[%d] = '%s'", j, lpProp->value.MVszA.strings[j].lppszA ? lpProp->value.MVszA.strings[j].lppszA : "[NULL]");
				}
				break;
			case PT_MV_SHORT:
				g_print (" PT_MV_SHORT");
				break;
			case PT_MV_LONG:
				g_print (" PT_MV_LONG");
				break;
			case PT_MV_FLOAT:
				g_print (" PT_MV_FLOAT");
				break;
			case PT_MV_DOUBLE:
				g_print (" PT_MV_DOUBLE");
				break;
			case PT_MV_CURRENCY:
				g_print (" PT_MV_CURRENCY");
				break;
			case PT_MV_APPTIME:
				g_print (" PT_MV_APPTIME");
				break;
			case PT_MV_I8:
				g_print (" PT_MV_I8");
				break;
			case PT_MV_UNICODE:
				g_print (" PT_MV_UNICODE (%d items)", lpProp->value.MVszW.cValues);
				for (j = 0; j < lpProp->value.MVszW.cValues; j++) {
					g_print ("\n   item[%d] = '%s'", j, lpProp->value.MVszW.strings[j].lppszW ? lpProp->value.MVszW.strings[j].lppszW : "[NULL]");
				}
				break;
			case PT_MV_SYSTIME:
				g_print (" PT_MV_SYSTIME");
				break;
			case PT_MV_CLSID:
				g_print (" PT_MV_CLSID");
				break;
			case PT_MV_BINARY:
				g_print (" PT_MV_BINARY (%d items)", lpProp->value.MVbin.cValues);
				for (j = 0; j < lpProp->value.MVbin.cValues; j++) {
					g_print ("\n   item[%d] (size %d)\n", j, lpProp->value.MVbin.bin[j].cb);
					dump_bin (lpProp->value.MVbin.bin[j].lpb, lpProp->value.MVbin.bin[j].cb, "     ");
				}
				g_print ("\n---");
				break;
			default:
				g_print (" - Unknown type 0x%04X", lpProp->ulPropTag & 0xFFFF);
			}
		}
	}
	g_print ("\n");
}

/* Attention: Devs at work;-) */

static void
exchange_mapi_util_bin_append_uint16 (TALLOC_CTX *mem_ctx, struct Binary_r *bin, const uint16_t val)
{
	uint8_t *ptr = NULL;

	bin->lpb = talloc_realloc (mem_ctx, bin->lpb, uint8_t, bin->cb + 2);
	bin->cb += 2;

	ptr = bin->lpb + bin->cb - 2;

	*ptr++ = ( val        & 0xFF);
	*ptr++ = ((val >>  8) & 0xFF);
}

static void
exchange_mapi_util_bin_append_uint32 (TALLOC_CTX *mem_ctx, struct Binary_r *bin, const uint32_t val)
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
exchange_mapi_util_bin_append_string (TALLOC_CTX *mem_ctx, struct Binary_r *bin, const gchar *val)
{
	gsize len = strlen (val);
	gchar *ptr = NULL;

	bin->lpb = talloc_realloc (mem_ctx, bin->lpb, uint8_t, bin->cb + (len + 1));
	bin->cb += (len + 1);

	ptr = (gchar *) bin->lpb + bin->cb - (len + 1);

	strcpy (ptr, val);
}

static void
exchange_mapi_util_bin_append_val (TALLOC_CTX *mem_ctx, struct Binary_r *bin, const uint8_t *val, gsize len)
{
	uint8_t *ptr = NULL;

	bin->lpb = talloc_realloc (mem_ctx, bin->lpb, uint8_t, bin->cb + len);
	bin->cb += len;

	ptr = bin->lpb + bin->cb - len;

	memcpy (ptr, val, len);
}

static void
exchange_mapi_util_bin_append_unicode (TALLOC_CTX *mem_ctx, struct Binary_r *bin, const gchar *val)
{
	gunichar2 *utf16;
	glong written = 0;

	utf16 = g_utf8_to_utf16 (val, -1, NULL, &written, NULL);
	g_return_if_fail (utf16 != NULL);

	exchange_mapi_util_bin_append_val (mem_ctx, bin, (uint8_t *)utf16, (written + 1) * 2);

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
 * exchange_mapi_util_recip_entryid_generate_smtp:
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
exchange_mapi_util_recip_entryid_generate_smtp (TALLOC_CTX *mem_ctx, struct Binary_r *entryid, const gchar *display_name, const gchar *email)
{
	g_return_if_fail (entryid != NULL);

	exchange_mapi_util_bin_append_uint32 (mem_ctx, entryid, 0);
	exchange_mapi_util_bin_append_val (mem_ctx, entryid, MAPI_ONE_OFF_UID, sizeof(MAPI_ONE_OFF_UID));
	exchange_mapi_util_bin_append_uint16 (mem_ctx, entryid, 0);
	exchange_mapi_util_bin_append_uint16 (mem_ctx, entryid, MAPI_ONE_OFF_NO_RICH_INFO | MAPI_ONE_OFF_MYSTERY_FLAG | MAPI_ONE_OFF_UNICODE);
	exchange_mapi_util_bin_append_unicode (mem_ctx, entryid, display_name);
	exchange_mapi_util_bin_append_unicode (mem_ctx, entryid, "SMTP");
	exchange_mapi_util_bin_append_unicode (mem_ctx, entryid, email);
}

static const uint8_t MAPI_LOCAL_UID[] = {
	0xdc, 0xa7, 0x40, 0xc8, 0xc0, 0x42, 0x10, 0x1a,
	0xb4, 0xb9, 0x08, 0x00, 0x2b, 0x2f, 0xe1, 0x82
};

/**
 * exchange_mapi_util_recip_entryid_generate_ex:
 * @exchange_dn: the Exchange 5.5-style DN of the local user
 *
 * Constructs an ENTRYID value that can be used as a MAPI
 * recipient (eg, for a message forwarding server-side rule),
 * corresponding to the local user identified by @exchange_dn.
 **/
void
exchange_mapi_util_recip_entryid_generate_ex (TALLOC_CTX *mem_ctx, struct Binary_r *entryid, const gchar *exchange_dn)
{
	exchange_mapi_util_bin_append_uint32 (mem_ctx, entryid, 0);
	exchange_mapi_util_bin_append_val (mem_ctx, entryid, MAPI_LOCAL_UID, sizeof(MAPI_LOCAL_UID));
	exchange_mapi_util_bin_append_uint16 (mem_ctx, entryid, 1);
	exchange_mapi_util_bin_append_uint16 (mem_ctx, entryid, 0);
	exchange_mapi_util_bin_append_string (mem_ctx, entryid, exchange_dn);
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
 * exchange_mapi_util_recip_entryid_decode:
 * @conn: ExchangeMapiCOnnection to resolve names, if required
 * @entryid: recipient's ENTRYID to decode
 * @display_name: (out): stored display name, if any; can be NULL
 * @email: (out): email or exchange DN; cannot be NULL
 *
 * Returns: Whether was able to decode recipient information from the @entryid.
 **/
gboolean
exchange_mapi_util_recip_entryid_decode (ExchangeMapiConnection *conn, const struct Binary_r *entryid, gchar **display_name, gchar **email)
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
		*email = exchange_mapi_connection_ex_to_smtp (conn, exchange_dn, display_name, NULL);
		g_free (exchange_dn);

		return *email != NULL;
	}

	return FALSE;
}

/**
 * exchange_lf_to_crlf:
 * @in: input text in UNIX ("\n") format
 *
 * Creates a copy of @in with all LFs converted to CRLFs.
 *
 * Return value: the converted text, which the caller must free.
 **/
gchar *
exchange_lf_to_crlf (const gchar *in)
{
	gint len;
	const gchar *s;
	gchar *out, *d;

	g_return_val_if_fail (in != NULL, NULL);

	len = strlen (in);
	for (s = strchr (in, '\n'); s; s = strchr (s + 1, '\n'))
		len++;

	out = g_malloc (len + 1);
	for (s = in, d = out; *s; s++) {
		if (*s == '\n')
			*d++ = '\r';
		*d++ = *s;
	}
	*d = '\0';

	return out;
}

/**
 * exchange_crlf_to_lf:
 * @in: input text in network ("\r\n") format
 *
 * Creates a copy of @in with all CRLFs converted to LFs. (Actually,
 * it just strips CRs, so any raw CRs will be removed.)
 *
 * Return value: the converted text, which the caller must free.
 **/
gchar *
exchange_crlf_to_lf (const gchar *in)
{
	const gchar *s;
	gchar *out;
	GString *str;

	g_return_val_if_fail (in != NULL, NULL);

	str = g_string_new ("");

	for (s = in; *s; s++) {
		if (*s != '\r')
			str = g_string_append_c (str, *s);
	}

	out = str->str;
	g_string_free (str, FALSE);

	return out;
}

/**
 * exchange_mapi_util_profile_name:
 * @username: User name of the profile
 * @domain: Domain name of the profile
 * @hostname: Server host name
 * @migrate: whether migrate old profile name to a new one
 *
 * Constructs profile name from given parameters and
 * returns it as a newly allocated string. It can also
 * rename old profile name string to a new name, if requested.
 **/
gchar *
exchange_mapi_util_profile_name (const gchar *username, const gchar *domain, const gchar *hostname, gboolean migrate)
{
	gchar *res;

	res = g_strdup_printf ("%s@%s@%s", username, domain, hostname);
	res = g_strcanon (res, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@.-", '_');

	if (migrate) {
		/* expects MAPIInitialize already called! */
		gchar *old_name;

		old_name = g_strdup_printf ("%s@%s", username, domain);
		old_name = g_strcanon (old_name, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789@", '_');

		exchange_mapi_rename_profile (old_name, res);

		g_free (old_name);
	}

	return res;
}

/**
 * Adds prop_ids to props array. props should be created within the given mem_ctx.
 **/
gboolean
exchange_mapi_utils_add_props_to_props_array (TALLOC_CTX *mem_ctx, struct SPropTagArray *props, const uint32_t *prop_ids, guint prop_ids_n_elems)
{
	guint i;

	g_return_val_if_fail (mem_ctx != NULL, FALSE);
	g_return_val_if_fail (props != NULL, FALSE);
	g_return_val_if_fail (prop_ids != NULL, FALSE);
	g_return_val_if_fail (prop_ids_n_elems > 0, FALSE);

	for (i = 0; i < prop_ids_n_elems; i++) {
		SPropTagArray_add (mem_ctx, props, prop_ids[i]);
	}

	return TRUE;
}

/* Beware, the named_ids_list array is modified */
gboolean
exchange_mapi_utils_add_named_ids_to_props_array (ExchangeMapiConnection *conn, mapi_id_t fid, TALLOC_CTX *mem_ctx, struct SPropTagArray *props, ResolveNamedIDsData *named_ids_list, guint named_ids_n_elems)
{
	guint i;

	g_return_val_if_fail (conn != NULL, FALSE);
	g_return_val_if_fail (mem_ctx != NULL, FALSE);
	g_return_val_if_fail (props != NULL, FALSE);
	g_return_val_if_fail (fid > 0, FALSE);
	g_return_val_if_fail (named_ids_list != NULL, FALSE);
	g_return_val_if_fail (named_ids_n_elems > 0, FALSE);

	if (!exchange_mapi_connection_resolve_named_props (conn, fid, named_ids_list, named_ids_n_elems, NULL))
		return FALSE;

	for (i = 0; i < named_ids_n_elems; i++) {
		if (named_ids_list[i].propid != MAPI_E_RESERVED)
			SPropTagArray_add (mem_ctx, props, named_ids_list[i].propid);
	}

	return TRUE;
}

/**
 * Adds a new SPropValue at the end of values_array, allocating its memory in the mem_ctx.
 * *n_values holds number of items stored in the array, and will be increased by one.
 **/
gboolean
exchange_mapi_utils_add_spropvalue (TALLOC_CTX *mem_ctx, struct SPropValue **values_array, uint32_t *n_values, uint32_t prop_tag, gconstpointer prop_value)
{
	g_return_val_if_fail (mem_ctx != NULL, FALSE);
	g_return_val_if_fail (values_array != NULL, FALSE);
	g_return_val_if_fail (n_values != NULL, FALSE);

	if ((prop_tag & 0xFFFF) == PT_DOUBLE) {
		uint64_t zero = 0;

		/* add an empty fake value and rewrite it */
		*values_array = add_SPropValue (mem_ctx, *values_array, n_values, PROP_TAG(PT_LONG, 0x0001), &zero);

		((*values_array)[(*n_values) - 1]).ulPropTag = prop_tag;
		((*values_array)[(*n_values) - 1]).dwAlignPad = 0;
		memcpy (&((*values_array)[(*n_values) - 1]).value.dbl, prop_value, 8);
	} else {
		*values_array = add_SPropValue (mem_ctx, *values_array, n_values, prop_tag, prop_value);
	}

	return TRUE;
}

/* similar as exchange_mapi_utils_add_spropvalue, just here is not used prop_tag, but named id */
gboolean
exchange_mapi_utils_add_spropvalue_named_id (ExchangeMapiConnection *conn, mapi_id_t fid, TALLOC_CTX *mem_ctx, struct SPropValue **values_array, uint32_t *n_values, uint32_t named_id, gconstpointer prop_value)
{
	uint32_t prop_tag;

	g_return_val_if_fail (conn != NULL, FALSE);
	g_return_val_if_fail (fid != 0, FALSE);
	g_return_val_if_fail (mem_ctx != NULL, FALSE);
	g_return_val_if_fail (values_array != NULL, FALSE);
	g_return_val_if_fail (n_values != NULL, FALSE);

	prop_tag = exchange_mapi_connection_resolve_named_prop (conn, fid, named_id, NULL);
	if (prop_tag == MAPI_E_RESERVED)
		return FALSE;

	return exchange_mapi_utils_add_spropvalue (mem_ctx, values_array, n_values, prop_tag, prop_value);
}

/* the first call should be with crc32 set to 0 */
uint32_t
exchange_mapi_utils_push_crc32 (uint32_t crc32, uint8_t *bytes, uint32_t n_bytes)
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

/* copies a Binary_r, which should be freed with exchange_mapi_util_free_binary_r() */
struct Binary_r *
exchange_mapi_util_copy_binary_r (const struct Binary_r *bin)
{
	struct Binary_r *res;

	if (!bin || !bin->cb)
		return NULL;

	res = g_new0 (struct Binary_r, 1);
	res->cb = bin->cb;
	res->lpb = g_new (uint8_t, res->cb);
	memcpy (res->lpb, bin->lpb, res->cb);

	return res;
}

/* frees Binary_r previously allocated by exchange_mapi_util_copy_binary_r() */
void
exchange_mapi_util_free_binary_r (struct Binary_r *bin)
{
	if (!bin)
		return;

	g_free (bin->lpb);
	g_free (bin);
}

time_t
exchange_mapi_util_filetime_to_time_t (const struct FILETIME *filetime)
{
	NTTIME nt;

	if (!filetime)
		return (time_t) -1;

	nt = filetime->dwHighDateTime;
	nt = nt << 32;
	nt |= filetime->dwLowDateTime;

	nt /=  10 * 1000 * 1000;
	nt -= 11644473600LL;

	return (time_t) nt;
}

void
exchange_mapi_util_time_t_to_filetime (const time_t tt, struct FILETIME *filetime)
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
