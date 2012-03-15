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

#include <stdarg.h>

#include "e-mapi-debug.h"

gboolean
e_mapi_debug_is_enabled (void)
{
	static gchar enabled = -1;

	if (enabled == -1)
		enabled = g_getenv ("MAPI_DEBUG") != NULL ? 1 : 0;

	return enabled == 1;
}

void
e_mapi_debug_print (const gchar *format, ...)
{
	va_list args;

	g_return_if_fail (format != NULL);

	if (!e_mapi_debug_is_enabled ())
		return;

	va_start (args, format);
	vfprintf (stdout, format, args);
	va_end (args);

	fprintf (stdout, "\n");
	fflush (stdout);
}

void
e_mapi_debug_dump_bin (const uint8_t *bin,
		       uint32_t bin_sz,
		       gint indent)
{
	gint k, l, last;

	g_print ("%*s", indent, "");

	if (!bin) {
		g_print ("NULL");
		return;
	}

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
			g_print ("\n%*s", indent, "");
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
e_mapi_debug_dump_properties (struct mapi_SPropValue_array *properties,
			      gint indent)
{
	gint i = 0;

	g_return_if_fail (properties != NULL);

	for (i = 0; i < properties->cValues; i++) {
		struct mapi_SPropValue *lpProp = &properties->lpProps[i];
		const gchar *tmp;
		gchar t_str[26];
		gint j = 0;

		tmp = get_proptag_name (lpProp->ulPropTag);
		if (!tmp || !*tmp)
			tmp = get_namedid_name (lpProp->ulPropTag);

		if (tmp && *tmp)
			g_print ("%*s%s ", indent, "", tmp);
		else
			g_print ("%*s0x%08X   ", indent, "", lpProp->ulPropTag);
		switch (lpProp->ulPropTag & 0xFFFF) {
		case PT_UNSPECIFIED:
			g_print (" PT_UNSPECIFIED");
			break;
		case PT_NULL:
			g_print (" PT_NULL");
			break;
		case PT_BOOLEAN:
			g_print (" (bool) - %d", lpProp->value.b);
			break;
		case PT_I2:
			g_print (" (uint16_t) - %d", lpProp->value.i);
			break;
		case PT_LONG:
			g_print (" (long) - %u", lpProp->value.l);
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
			break;
		case PT_I8:
			g_print (" (gint) - 0x%016" G_GINT64_MODIFIER "X", lpProp->value.d);
			break;
		case PT_SYSTIME: {
				struct timeval t;
				struct tm tm;
				if (get_mapi_SPropValue_array_date_timeval (&t, properties, lpProp->ulPropTag) == MAPI_E_SUCCESS) {
					gmtime_r (&(t.tv_sec), &tm);
					strftime (t_str, 26, "%Y-%m-%dT%H:%M:%SZ", &tm);
					g_print (" (struct FILETIME *) - %p   (struct timeval) %s", &lpProp->value.ft, t_str);
				}
			}
			break;
		case PT_ERROR:
			g_print (" (error) - "/* , lpProp->value.err */);
			break;
		case PT_STRING8:
			g_print (" (string) - '%s'", lpProp->value.lpszA ? lpProp->value.lpszA : "null");
			break;
		case PT_UNICODE:
			g_print (" (unicodestring) - '%s'", lpProp->value.lpszW ? lpProp->value.lpszW : lpProp->value.lpszA ? lpProp->value.lpszA : "null");
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
			g_print (" (struct SBinary_short *) - %p Binary data follows (size %d): %s", &lpProp->value.bin, lpProp->value.bin.cb, lpProp->value.bin.cb > 0 ? "\n" : "");
			e_mapi_debug_dump_bin (lpProp->value.bin.lpb, lpProp->value.bin.cb, indent + 3);
			break;
		case PT_MV_STRING8:
			g_print (" (struct mapi_SLPSTRArray *) (%d items)", lpProp->value.MVszA.cValues);
			for (j = 0; j < lpProp->value.MVszA.cValues; j++) {
				g_print ("\n%*sitem[%d] = '%s'", indent + 2, "", j, lpProp->value.MVszA.strings[j].lppszA ? lpProp->value.MVszA.strings[j].lppszA : "[NULL]");
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
				g_print ("\n%*sitem[%d] = '%s'", indent + 2, "", j, lpProp->value.MVszW.strings[j].lppszW ? lpProp->value.MVszW.strings[j].lppszW : "[NULL]");
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
				g_print ("\n%*sitem[%d] (size %d)\n", indent + 2, "", j, lpProp->value.MVbin.bin[j].cb);
				e_mapi_debug_dump_bin (lpProp->value.MVbin.bin[j].lpb, lpProp->value.MVbin.bin[j].cb, indent + 3);
			}
			break;
		default:
			g_print (" - Unknown type 0x%04X", lpProp->ulPropTag & 0xFFFF);
			break;
		}

		g_print ("\n");
	}
}

static void
e_mapi_debug_dump_streamed_properties (guint32 streamed_properties_count,
				       const EMapiStreamedProp *streamed_properties,
				       gint indent)
{
	guint32 ii;

	if (!streamed_properties || streamed_properties_count <= 0)
		return;

	for (ii = 0; ii < streamed_properties_count; ii++) {
		const gchar *tmp;

		tmp = get_proptag_name (streamed_properties[ii].proptag);
		if (!tmp || !*tmp)
			tmp = get_namedid_name (streamed_properties[ii].proptag);

		if (tmp && *tmp)
			g_print ("%*s%s ", indent, "", tmp);
		else
			g_print ("%*s0x%08X   ", indent, "", streamed_properties[ii].proptag);

		switch (streamed_properties[ii].proptag & 0xFFFF) {
		case PT_STRING8:
			g_print (" (streamed string) - '%s'", streamed_properties[ii].cb == 0 ? "" : streamed_properties[ii].lpb ? (const gchar *) streamed_properties[ii].lpb : "null");
			break;
		case PT_UNICODE:
			g_print (" (streamed unicodestring) - '%s'", streamed_properties[ii].cb == 0 ? "" : streamed_properties[ii].lpb ? (const gchar *) streamed_properties[ii].lpb : "null");
			break;
		case PT_BINARY:
			g_print (" (streamed Binary %p, size %" G_GINT64_MODIFIER "d): %s", streamed_properties[ii].lpb, streamed_properties[ii].cb, streamed_properties[ii].cb > 0 ? "\n" : "");
			e_mapi_debug_dump_bin (streamed_properties[ii].lpb, streamed_properties[ii].cb, indent + 3);
			break;
		default:
			g_print (" (other streamed type %p, size %" G_GINT64_MODIFIER "d): %s", streamed_properties[ii].lpb, streamed_properties[ii].cb, streamed_properties[ii].cb > 0 ? "\n" : "");
			e_mapi_debug_dump_bin (streamed_properties[ii].lpb, streamed_properties[ii].cb, indent + 3);
			break;
		}

		g_print ("\n");
	}
}

void
e_mapi_debug_dump_object (EMapiObject *object, gboolean with_properties, gint indent)
{
	EMapiRecipient *recipient;
	EMapiAttachment *attachment;
	gint index;

	g_print ("%*sEMapiObject: %p (parent:%p)\n", indent, "", object, object ? object->parent : NULL);

	if (!object)
		return;

	if (with_properties) {
		e_mapi_debug_dump_properties (&object->properties, indent + 3);
		e_mapi_debug_dump_streamed_properties (object->streamed_properties_count, object->streamed_properties, indent + 3);
	}

	for (index = 0, recipient = object->recipients; recipient; index++, recipient = recipient->next) {
		g_print ("%*sRecipient[%d]:\n", indent + 2, "", index);
		if (with_properties)
			e_mapi_debug_dump_properties (&recipient->properties, indent + 5);
	}

	for (index = 0, attachment = object->attachments; attachment; index++, attachment = attachment->next) {
		g_print ("%*sAttachment[%d]:\n", indent + 2, "", index);
		if (with_properties) {
			e_mapi_debug_dump_properties (&attachment->properties, indent + 3);
			e_mapi_debug_dump_streamed_properties (attachment->streamed_properties_count, attachment->streamed_properties, indent + 3);
		}

		if (attachment->embedded_object) {
			g_print ("%*sEmbedded object:\n", indent + 3, "");
			e_mapi_debug_dump_object (attachment->embedded_object, with_properties, indent + 5);
		}
	}
}
