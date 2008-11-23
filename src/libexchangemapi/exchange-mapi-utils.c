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

#include "exchange-mapi-utils.h"

#ifdef G_OS_WIN32
/* Undef the similar macro from pthread.h, it doesn't check if
 * gmtime() returns NULL.
 */
#undef gmtime_r

/* The gmtime() in Microsoft's C library is MT-safe */
#define gmtime_r(tp,tmp) (gmtime(tp)?(*(tmp)=*gmtime(tp),(tmp)):0)
#endif

/* Converts a string from Windows-UTF8 to classic-UTF8.
 * NOTE: If the returned value is non-NULL, the caller has to free the newly
 * allocated string using g_free()
 */
gchar *
utf8tolinux (const char *wstring)
{
	TALLOC_CTX 	*mem_ctx;
	gchar		*newstr, *retval = NULL;

	g_return_val_if_fail (wstring != NULL, NULL);

	mem_ctx = talloc_init ("ExchangeMAPI_utf8tolinux");

	newstr = windows_to_utf8(mem_ctx, wstring);

	if (g_utf8_validate (newstr, -1, NULL)) 
		retval = g_strdup (newstr);

	talloc_free (mem_ctx);

	return retval;
}

inline gchar *
exchange_mapi_util_mapi_id_to_string (mapi_id_t id)
{
	return g_strdup_printf ("%016llX", id);
}

inline gboolean 
exchange_mapi_util_mapi_id_from_string (const char *str, mapi_id_t *id)
{
	gint n = 0;

	if (str && *str)
		n = sscanf (str, "%016llX", id);

	return (n == 1);
}

/* NOTE: We use the UID as a combination of the folder-id and the message-id. 
 * Specifically, it is in this format: ("%016llX%016llX", fid, mid).
 */
inline gchar *
exchange_mapi_util_mapi_ids_to_uid (mapi_id_t fid, mapi_id_t mid)
{
	return g_strdup_printf ("%016llX%016llX", fid, mid);
}

inline gboolean 
exchange_mapi_util_mapi_ids_from_uid (const char *str, mapi_id_t *fid, mapi_id_t *mid)
{
	gint n = 0;

	if (str && *str)
		n = sscanf (str, "%016llX%016llX", fid, mid);

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
const void *
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
const void *
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
const void *
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

	if(!l)
		return;

	for (; l != NULL; l = l->next) {
		ExchangeMAPIAttachment *attachment = (ExchangeMAPIAttachment *) (l->data);
		/* FIXME: more stuff here */
		g_free (attachment->lpProps);
		exchange_mapi_util_free_stream_list (&(attachment->streams)); 
		g_free (attachment);
		attachment = NULL;
	}
	g_slist_free (l);
	l = NULL;
}

void 
exchange_mapi_util_free_recipient_list (GSList **recip_list)
{
	GSList *l = *recip_list;

	if(!l)
		return;

	for (; l != NULL; l = l->next) {
		ExchangeMAPIRecipient *recipient = (ExchangeMAPIRecipient *) (l->data);
		if (recipient->in.ext_cValues)
			g_free (recipient->in.ext_lpProps);
		if (recipient->in.req_cValues)
			g_free (recipient->in.req_lpProps);
/*		if (recipient->out.all_cValues)
			g_free (recipient->out.all_lpProps);
*/		g_free (recipient);
	}
	g_slist_free (l);
	l = NULL;
}

void 
exchange_mapi_util_free_stream_list (GSList **stream_list)
{
	GSList *l = *stream_list;

	if(!l)
		return;

	for (; l != NULL; l = l->next) {
		ExchangeMAPIStream *stream = (ExchangeMAPIStream *) (l->data);
		g_byte_array_free (stream->value, TRUE);
		stream->value = NULL;
		g_free (stream);
		stream = NULL;
	}
	g_slist_free (l);
	l = NULL;
}


void
exchange_mapi_debug_property_dump (struct mapi_SPropValue_array *properties)
{
	gint i = 0;

	for (i = 0; i < properties->cValues; i++) { 
		for (i = 0; i < properties->cValues; i++) {
			struct mapi_SPropValue *lpProp = &properties->lpProps[i];
			const char *tmp =  get_proptag_name (lpProp->ulPropTag);
			char t_str[26];
			gint j = 0;
			if (tmp && *tmp)
				g_print("\n%s \t",tmp);
			else
				g_print("\n0x%08X \t", lpProp->ulPropTag);
			switch(lpProp->ulPropTag & 0xFFFF) {
			case PT_BOOLEAN:
				g_print(" (bool) - %d", (bool) lpProp->value.b);
				break;
			case PT_I2:
				g_print(" (uint16_t) - %d", lpProp->value.i);
				break;
			case PT_LONG:
				g_print(" (long) - %u", lpProp->value.l);
				break;
			case PT_DOUBLE:
				g_print (" (double) -  %lf", (double)lpProp->value.dbl);
				break;
			case PT_I8:
				g_print (" (int) - 0x%016llX", lpProp->value.d);
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
			case PT_BINARY:
				g_print(" (struct SBinary_short *) - %p Binary data follows: \n", &lpProp->value.bin);
				for (j = 0; j < lpProp->value.bin.cb; j++)
					g_print("0x%02X ", lpProp->value.bin.lpb[j]);
				break;
			case PT_MV_STRING8:
 				g_print(" (struct mapi_SLPSTRArray *) - %p", &lpProp->value.MVszA);
				break;
			default:
				g_print(" - NONE NULL");
			}
		}
	}
}


/* Attention: Devs at work ;-) */

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

static void 
exchange_mapi_util_bin_append_string (TALLOC_CTX *mem_ctx, struct Binary_r *bin, const char *val)
{
	size_t len = strlen (val);
	char *ptr = NULL;

	bin->lpb = talloc_realloc (mem_ctx, bin->lpb, uint8_t, bin->cb + (len + 1));
	bin->cb += (len + 1);

	ptr = (char *) bin->lpb + bin->cb - (len + 1);

	strcpy (ptr, val);
}

static void 
exchange_mapi_util_bin_append_unicode (TALLOC_CTX *mem_ctx, struct Binary_r *bin, const char *val)
{
	/* WRITE ME */
}

static void 
exchange_mapi_util_bin_append_val (TALLOC_CTX *mem_ctx, struct Binary_r *bin, const uint8_t *val, size_t len)
{
	uint8_t *ptr = NULL;

	bin->lpb = talloc_realloc (mem_ctx, bin->lpb, uint8_t, bin->cb + len);
	bin->cb += len;

	ptr = bin->lpb + bin->cb - len;

	memcpy (ptr, val, len);
}

static const uint8_t MAPI_ONE_OFF_UID[] = {
	0x81, 0x2b, 0x1f, 0xa4, 0xbe, 0xa3, 0x10, 0x19,
	0x9d, 0x6e, 0x00, 0xdd, 0x01, 0x0f, 0x54, 0x02
};

#define MAPI_ONE_OFF_UNICODE	  0x8000
#define MAPI_ONE_OFF_NO_RICH_INFO 0x0001
#define MAPI_ONE_OFF_MYSTERY_FLAG 0x1000

/**
 * e2k_entryid_generate_oneoff:
 * @display_name: the display name of the user
 * @email: the email address
 * @unicode: %TRUE to generate a Unicode ENTRYID (in which case
 * @display_name should be UTF-8), %FALSE for an ASCII ENTRYID.
 *
 * Constructs a "one-off" ENTRYID value that can be used as a MAPI
 * recipient (eg, for a message forwarding server-side rule),
 * corresponding to @display_name and @email.
 *
 * Return value: the recipient ENTRYID
 **/
struct Binary_r *
exchange_mapi_util_entryid_generate_oneoff (TALLOC_CTX *mem_ctx, const char *display_name, const char *email, gboolean unicode)
{
	struct Binary_r *entryid;

	entryid = talloc_zero (mem_ctx, struct Binary_r);

	exchange_mapi_util_bin_append_uint32 (mem_ctx, entryid, 0);
	exchange_mapi_util_bin_append_val (mem_ctx, entryid, MAPI_ONE_OFF_UID, sizeof(MAPI_ONE_OFF_UID));
	exchange_mapi_util_bin_append_uint16 (mem_ctx, entryid, 0);
	exchange_mapi_util_bin_append_uint16 (mem_ctx, entryid,
		MAPI_ONE_OFF_NO_RICH_INFO |
		MAPI_ONE_OFF_MYSTERY_FLAG |
		(unicode ? MAPI_ONE_OFF_UNICODE : 0));

	if (unicode) {
		exchange_mapi_util_bin_append_unicode (mem_ctx, entryid, display_name);
		exchange_mapi_util_bin_append_unicode (mem_ctx, entryid, "SMTP");
		exchange_mapi_util_bin_append_unicode (mem_ctx, entryid, email);
	} else {
		exchange_mapi_util_bin_append_string (mem_ctx, entryid, display_name);
		exchange_mapi_util_bin_append_string (mem_ctx, entryid, "SMTP");
		exchange_mapi_util_bin_append_string (mem_ctx, entryid, email);
	}

	return entryid;
}

static const uint8_t MAPI_LOCAL_UID[] = {
	0xdc, 0xa7, 0x40, 0xc8, 0xc0, 0x42, 0x10, 0x1a,
	0xb4, 0xb9, 0x08, 0x00, 0x2b, 0x2f, 0xe1, 0x82
};

/**
 * e2k_entryid_generate_local:
 * @exchange_dn: the Exchange 5.5-style DN of the local user
 *
 * Constructs an ENTRYID value that can be used as a MAPI
 * recipient (eg, for a message forwarding server-side rule),
 * corresponding to the local user identified by @exchange_dn.
 *
 * Return value: the recipient ENTRYID
 **/
struct Binary_r *
exchange_mapi_util_entryid_generate_local (TALLOC_CTX *mem_ctx, const char *exchange_dn)
{
	struct Binary_r *entryid;

	entryid = talloc_zero (mem_ctx, struct Binary_r);

	exchange_mapi_util_bin_append_uint32 (mem_ctx, entryid, 0);
	exchange_mapi_util_bin_append_val (mem_ctx, entryid, MAPI_LOCAL_UID, sizeof(MAPI_LOCAL_UID));
	exchange_mapi_util_bin_append_uint16 (mem_ctx, entryid, 1);
	exchange_mapi_util_bin_append_uint16 (mem_ctx, entryid, 0);
	exchange_mapi_util_bin_append_string (mem_ctx, entryid, exchange_dn);

	return entryid;
}

/**
 * exchange_lf_to_crlf:
 * @in: input text in UNIX ("\n") format
 *
 * Creates a copy of @in with all LFs converted to CRLFs.
 *
 * Return value: the converted text, which the caller must free.
 **/
char *
exchange_lf_to_crlf (const char *in)
{
	int len;
	const char *s;
	char *out, *d;

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
char *
exchange_crlf_to_lf (const char *in)
{
	int len;
	const char *s;
	char *out;
	GString *str;

	g_return_val_if_fail (in != NULL, NULL);

	str = g_string_new ("");

	len = strlen (in);
	for (s = in; *s; s++) {
		if (*s != '\r')
			str = g_string_append_c (str, *s);
	}

	out = str->str;
	g_string_free (str, FALSE);

	return out;
}

