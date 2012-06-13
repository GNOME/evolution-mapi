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
 * Copyright (C) 1999-2008 Novell, Inc. (www.novell.com)
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <libedataserver/e-sexp.h>

#include "e-mapi-book-utils.h"

#define ELEMENT_TYPE_MASK   0xF /* mask where the real type of the element is stored */

#define ELEMENT_TYPE_SKIP_SET	0x00
#define ELEMENT_TYPE_SIMPLE	0x01
#define ELEMENT_TYPE_COMPLEX	0x02

static const struct field_element_mapping {
	EContactField field_id;
	uint32_t mapi_id;
	gint element_type;
} mappings [] = {
	{ E_CONTACT_UID,		PidTagMid,			ELEMENT_TYPE_SKIP_SET },
	{ E_CONTACT_REV,		PidTagLastModificationTime,	ELEMENT_TYPE_SIMPLE },

	{ E_CONTACT_FILE_AS,		PidLidFileUnder,		ELEMENT_TYPE_SIMPLE },
	{ E_CONTACT_FULL_NAME,		PidTagDisplayName,		ELEMENT_TYPE_SIMPLE },
	{ E_CONTACT_GIVEN_NAME,		PidTagGivenName,		ELEMENT_TYPE_SIMPLE },
	{ E_CONTACT_FAMILY_NAME,	PidTagSurname,			ELEMENT_TYPE_SIMPLE },
	{ E_CONTACT_NICKNAME,		PidTagNickname,			ELEMENT_TYPE_SIMPLE },

	{ E_CONTACT_EMAIL_1,		PidLidEmail1OriginalDisplayName,ELEMENT_TYPE_SIMPLE },
	{ E_CONTACT_EMAIL_2,		PidLidEmail2EmailAddress,	ELEMENT_TYPE_SIMPLE },
	{ E_CONTACT_EMAIL_3,		PidLidEmail3EmailAddress,	ELEMENT_TYPE_SIMPLE },
	{ E_CONTACT_IM_AIM,		PidLidInstantMessagingAddress,	ELEMENT_TYPE_COMPLEX },

	{ E_CONTACT_PHONE_BUSINESS,	PidTagBusinessTelephoneNumber,	ELEMENT_TYPE_SIMPLE },
	{ E_CONTACT_PHONE_HOME,		PidTagHomeTelephoneNumber,	ELEMENT_TYPE_SIMPLE },
	{ E_CONTACT_PHONE_MOBILE,	PidTagMobileTelephoneNumber,	ELEMENT_TYPE_SIMPLE },
	{ E_CONTACT_PHONE_HOME_FAX,	PidTagHomeFaxNumber,		ELEMENT_TYPE_SIMPLE },
	{ E_CONTACT_PHONE_BUSINESS_FAX,	PidTagBusinessFaxNumber,	ELEMENT_TYPE_SIMPLE },
	{ E_CONTACT_PHONE_PAGER,	PidTagPagerTelephoneNumber,	ELEMENT_TYPE_SIMPLE },
	{ E_CONTACT_PHONE_ASSISTANT,	PidTagAssistantTelephoneNumber,	ELEMENT_TYPE_SIMPLE },
	{ E_CONTACT_PHONE_COMPANY,	PidTagCompanyMainTelephoneNumber,ELEMENT_TYPE_SIMPLE },

	{ E_CONTACT_HOMEPAGE_URL,	PidLidHtml,			ELEMENT_TYPE_SIMPLE },
	{ E_CONTACT_FREEBUSY_URL,	PidLidFreeBusyLocation,		ELEMENT_TYPE_SIMPLE },

	{ E_CONTACT_ROLE,		PidTagProfession,		ELEMENT_TYPE_SIMPLE },
	{ E_CONTACT_TITLE,		PidTagTitle,			ELEMENT_TYPE_SIMPLE },
	{ E_CONTACT_ORG,		PidTagCompanyName,		ELEMENT_TYPE_SIMPLE },
	{ E_CONTACT_ORG_UNIT,		PidTagDepartmentName,		ELEMENT_TYPE_SIMPLE },
	{ E_CONTACT_MANAGER,		PidTagManagerName,		ELEMENT_TYPE_SIMPLE },
	{ E_CONTACT_ASSISTANT,		PidTagAssistant,		ELEMENT_TYPE_SIMPLE },

	{ E_CONTACT_OFFICE,		PidTagOfficeLocation,		ELEMENT_TYPE_SIMPLE },
	{ E_CONTACT_SPOUSE,		PidTagSpouseName,		ELEMENT_TYPE_SIMPLE },

	{ E_CONTACT_BIRTH_DATE,		PidTagBirthday,			ELEMENT_TYPE_COMPLEX },
	{ E_CONTACT_ANNIVERSARY,	PidTagWeddingAnniversary,	ELEMENT_TYPE_COMPLEX },

	{ E_CONTACT_NOTE,		PidTagBody,			ELEMENT_TYPE_SIMPLE },

	{ E_CONTACT_ADDRESS_HOME,	PidLidHomeAddress,		ELEMENT_TYPE_COMPLEX },
	{ E_CONTACT_ADDRESS_WORK,	PidLidOtherAddress,		ELEMENT_TYPE_COMPLEX }
};

/* extra properties used in ELEMENT_TYPE_COMPLEX types and some other etra properties */
static const uint32_t extra_proptags[] = {
	PidTagHomeAddressPostOfficeBox,
	PidTagHomeAddressCity,
	PidTagHomeAddressStateOrProvince,
	PidTagHomeAddressPostalCode,
	PidTagHomeAddressCountry,
	PidTagPostOfficeBox,
	PidTagLocality,
	PidTagStateOrProvince,
	PidTagPostalCode,
	PidTagCountry,
	PidTagPrimarySmtpAddress,
	PidTagFolderId
};

static gchar *
bin_to_string (const uint8_t *lpb, uint32_t cb)
{
	gchar *res, *p;
	uint32_t i;

	g_return_val_if_fail (lpb != NULL, NULL);
	g_return_val_if_fail (cb > 0, NULL);

	res = g_new0 (gchar, cb * 2 + 1);
	for (i = 0, p = res; i < cb; i++, p += 2) {
		sprintf (p, "%02x", lpb[i] & 0xFF);
	}

	return res;
}

static const gchar *
not_null (gconstpointer ptr)
{
	return ptr ? (const gchar *) ptr : "";
}

EContact *
e_mapi_book_utils_contact_from_object (EMapiConnection *conn,
				       EMapiObject *object,
				       const gchar *book_uri)
{
	EContact *contact;
	gchar *email_1;
	const mapi_id_t *pmid;
	gint i;

	g_return_val_if_fail (object != NULL, NULL);

	if (e_mapi_debug_is_enabled ()) {
		printf ("%s:\n", G_STRFUNC);
		e_mapi_debug_dump_object (object, TRUE, 3);
	}

	contact = e_contact_new ();
	if (book_uri)
		e_contact_set (contact, E_CONTACT_BOOK_URI, book_uri);

	#define get_proptag(proptag) e_mapi_util_find_array_propval (&object->properties, proptag)
	#define get_str_proptag(proptag) not_null (get_proptag (proptag))

	pmid = get_proptag (PidTagMid);
	if (pmid) {
		gchar *suid = e_mapi_util_mapi_id_to_string (*pmid);

		e_contact_set (contact, E_CONTACT_UID, suid);

		g_free (suid);
	}

	if (g_str_equal (get_str_proptag (PidTagMessageClass), IPM_DISTLIST)) {
		const struct mapi_SBinaryArray *members, *members_dlist;
		const struct FILETIME *last_modification;
		GSList *attrs = NULL, *a;
		gint i;

		last_modification = get_proptag (PidTagLastModificationTime);
		if (last_modification) {
			gchar *buff = NULL;

			buff = e_mapi_book_utils_timet_to_string (e_mapi_util_filetime_to_time_t (last_modification));
			if (buff)
				e_contact_set (contact, E_CONTACT_REV, buff);

			g_free (buff);
		}

		/* it's a contact list/distribution list, fetch members and return it */
		e_contact_set (contact, E_CONTACT_IS_LIST, GINT_TO_POINTER (TRUE));
		/* we do not support this option, same as GroupWise */
		e_contact_set (contact, E_CONTACT_LIST_SHOW_ADDRESSES, GINT_TO_POINTER (TRUE));

		e_contact_set (contact, E_CONTACT_FILE_AS, get_str_proptag (PidLidDistributionListName));

		members = get_proptag (PidLidDistributionListOneOffMembers);
		members_dlist = get_proptag (PidLidDistributionListMembers);

		g_return_val_if_fail (members != NULL, NULL);
		g_return_val_if_fail (members_dlist != NULL, NULL);

		/* these two lists should be in sync */
		g_return_val_if_fail (members_dlist->cValues == members->cValues, NULL);

		for (i = 0; i < members->cValues; i++) {
			struct Binary_r br;
			gchar *display_name = NULL, *email = NULL;
			gchar *str;

			br.lpb = members->bin[i].lpb;
			br.cb = members->bin[i].cb;
			if (e_mapi_util_recip_entryid_decode (conn, &br, &display_name, &email)) {
				EVCardAttribute *attr;
				gchar *value;
				CamelInternetAddress *addr;

				addr = camel_internet_address_new ();
				attr = e_vcard_attribute_new (NULL, EVC_EMAIL);

				camel_internet_address_add (addr, display_name, email);

				value = camel_address_encode (CAMEL_ADDRESS (addr));

				if (value)
					e_vcard_attribute_add_value (attr, value);

				g_free (value);
				g_object_unref (addr);

				str = g_strdup_printf ("%d", i + 1);
				e_vcard_attribute_add_param_with_value (attr,
						e_vcard_attribute_param_new (EMA_X_MEMBERID),
						str);
				g_free (str);

				/* keep the value from ListMembers with the email, to not need to generate it on list changes;
				   new values added in evolution-mapi will be always SMTP addresses anyway */
				str = bin_to_string (members_dlist->bin[i].lpb, members_dlist->bin[i].cb);
				if (str) {
					e_vcard_attribute_add_param_with_value (attr,
						e_vcard_attribute_param_new (EMA_X_MEMBERVALUE),
						str);
					g_free (str);
				}

				attrs = g_slist_prepend (attrs, attr);
			}

			g_free (display_name);
			g_free (email);
		}

		for (a = attrs; a; a = a->next) {
			e_vcard_add_attribute (E_VCARD (contact), a->data);
		}

		g_slist_free (attrs);

		return contact;
	}

	for (i = 0; i < G_N_ELEMENTS (mappings); i++) {
		gpointer value;
		gint element_type;

		/* can cast value, no writing to the value; and it'll be freed not before the end of this function */
		value = (gpointer) get_proptag (mappings[i].mapi_id);
		element_type = mappings[i].element_type & ELEMENT_TYPE_MASK;
		if (element_type == ELEMENT_TYPE_SKIP_SET) {
			/* skip, when asked for */
		} else if (element_type == ELEMENT_TYPE_SIMPLE) {
			switch (mappings[i].mapi_id & 0xFFFF) {
				case PT_UNICODE: {
					const gchar *str = value;
					if (str && *str)
						e_contact_set (contact, mappings[i].field_id, str);
				} break;
				case PT_SYSTIME: {
					const struct FILETIME *t = value;
					gchar *buff = NULL;

					buff = e_mapi_book_utils_timet_to_string (e_mapi_util_filetime_to_time_t (t));
					if (buff)
						e_contact_set (contact, mappings[i].field_id, buff);

					g_free (buff);
				} break;
				default:
					/* ignore everything else */
					break;
			}
		} else if (element_type == ELEMENT_TYPE_COMPLEX) {
			if (mappings[i].field_id == E_CONTACT_IM_AIM) {
				const gchar *str = value;
				if (str && *str) {
					GList *list = g_list_append (NULL, (gpointer) str);

					e_contact_set (contact, mappings[i].field_id, list);

					g_list_free (list);
				}
			} else if (mappings[i].field_id == E_CONTACT_BIRTH_DATE
				   || mappings[i].field_id == E_CONTACT_ANNIVERSARY) {
				const struct FILETIME *t = value;
				time_t time;
				struct tm * tmtime;
				if (value) {
					EContactDate date = {0};

					time = e_mapi_util_filetime_to_time_t (t);
					tmtime = gmtime (&time);

					date.day = tmtime->tm_mday;
					date.month = tmtime->tm_mon + 1;
					date.year = tmtime->tm_year + 1900;
					e_contact_set (contact, mappings[i].field_id, &date);
				}

			} else if (mappings[i].field_id == E_CONTACT_ADDRESS_WORK
				   || mappings[i].field_id == E_CONTACT_ADDRESS_HOME) {
				EContactAddress contact_addr = { 0 };

				/* type-casting below to not allocate memory twice; e_contact_set will copy values itself. */
				if (mappings[i].field_id == E_CONTACT_ADDRESS_HOME) {
					contact_addr.address_format = NULL;
					contact_addr.po = NULL;
					contact_addr.street = (gchar *) value;
					contact_addr.ext = (gchar *) get_str_proptag (PidTagHomeAddressPostOfficeBox);
					contact_addr.locality = (gchar *) get_str_proptag (PidTagHomeAddressCity);
					contact_addr.region = (gchar *) get_str_proptag (PidTagHomeAddressStateOrProvince);
					contact_addr.code = (gchar *) get_str_proptag (PidTagHomeAddressPostalCode);
					contact_addr.country = (gchar *) get_str_proptag (PidTagHomeAddressCountry);
				} else {
					contact_addr.address_format = NULL;
					contact_addr.po = NULL;
					contact_addr.street = (gchar *) value;
					contact_addr.ext = (gchar *) get_str_proptag (PidTagPostOfficeBox);
					contact_addr.locality = (gchar *) get_str_proptag (PidTagLocality);
					contact_addr.region = (gchar *) get_str_proptag (PidTagStateOrProvince);
					contact_addr.code = (gchar *) get_str_proptag (PidTagPostalCode);
					contact_addr.country = (gchar *) get_str_proptag (PidTagCountry);
				}

				#define is_set(x) ((x) && *(x))
				if (is_set (contact_addr.address_format) ||
				    is_set (contact_addr.po) ||
				    is_set (contact_addr.street) ||
				    is_set (contact_addr.ext) ||
				    is_set (contact_addr.locality) ||
				    is_set (contact_addr.region) ||
				    is_set (contact_addr.code) ||
				    is_set (contact_addr.country)) {
					e_contact_set (contact, mappings[i].field_id, &contact_addr);
				}
				#undef is_set
			}
		}
	}

	email_1 = e_contact_get (contact, E_CONTACT_EMAIL_1);
	if (!email_1) {
		gconstpointer value = get_proptag (PidTagPrimarySmtpAddress);

		if (value)
			e_contact_set (contact, E_CONTACT_EMAIL_1, value);
	}

	g_free (email_1);

	#undef get_proptag
	#undef get_str_proptag

	return contact;
}

static uint32_t
string_to_bin (TALLOC_CTX *mem_ctx, const gchar *str, uint8_t **lpb)
{
	uint32_t len, i;

	g_return_val_if_fail (str != NULL, 0);
	g_return_val_if_fail (lpb != NULL, 0);

	len = strlen (str);
	g_return_val_if_fail ((len & 1) == 0, 0);

	len = len / 2;
	*lpb = talloc_zero_array (mem_ctx, uint8_t, len);

	i = 0;
	while (*str && i < len) {
		gchar c1 = str[0], c2 = str[1];
		str += 2;

		g_return_val_if_fail ((c1 >= '0' && c1 <= '9') || (c1 >= 'a' && c1 <= 'f') || (c1 >= 'A' && c1 <= 'F'), 0);
		g_return_val_if_fail ((c2 >= '0' && c2 <= '9') || (c2 >= 'a' && c2 <= 'f') || (c2 >= 'A' && c2 <= 'F'), 0);

		#define deHex(x) (((x) >= '0' && (x) <= '9') ? ((x) - '0') : (((x) >= 'a' && (x) <= 'f') ? (x) - 'a' + 10 : (x) - 'A' + 10))
		(*lpb)[i] = (deHex (c1) << 4) | (deHex (c2));
		#undef deHex
		i++;
	}

	return len;
}

static gint
cmp_member_id (gconstpointer a, gconstpointer b, gpointer ht)
{
	gchar *va, *vb;
	gint res;

	if (!a)
		return b ? -1 : 0;
	if (!b)
		return 1;

	va = e_vcard_attribute_get_value ((EVCardAttribute *) a);
	vb = e_vcard_attribute_get_value ((EVCardAttribute *) b);

	res = GPOINTER_TO_INT (g_hash_table_lookup (ht, va)) - GPOINTER_TO_INT (g_hash_table_lookup (ht, vb));

	g_free (va);
	g_free (vb);

	return res;
}

gboolean
e_mapi_book_utils_contact_to_object (EContact *contact,
				     EContact *old_contact, /* can be NULL */
				     EMapiObject **pobject,
				     TALLOC_CTX *mem_ctx,
				     GCancellable *cancellable,
				     GError **perror)
{
	EMapiObject *object;

	#define set_value(hex, val) G_STMT_START { \
		if (!e_mapi_utils_add_property (&object->properties, hex, val, object)) \
			return FALSE;	\
		} G_STMT_END

	#define set_con_value(hex, field_id) G_STMT_START { \
		if (e_contact_get (contact, field_id)) { \
			set_value (hex, e_contact_get (contact, field_id)); \
		} } G_STMT_END

	g_return_val_if_fail (contact != NULL, FALSE);
	g_return_val_if_fail (mem_ctx != NULL, FALSE);
	g_return_val_if_fail (pobject != NULL, FALSE);

	object = e_mapi_object_new (mem_ctx);
	*pobject = object;

	if (GPOINTER_TO_INT (e_contact_get (contact, E_CONTACT_IS_LIST))) {
		GList *local, *l;
		struct BinaryArray_r *members, *oneoff_members;
		uint32_t u32, crc32 = 0;
		GHashTable *member_values = NULL, *member_ids = NULL;

		if (old_contact) {
			member_values = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);
			member_ids = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, NULL);

			local = e_contact_get_attributes (old_contact, E_CONTACT_EMAIL);
			for (l = local; l; l = l->next) {
				EVCardAttribute *attr = l->data;
				GList *param;

				if (!attr)
					continue;

				param = e_vcard_attribute_get_param (attr, EMA_X_MEMBERVALUE);
				if (param && param->data && !param->next) {
					g_hash_table_insert (member_values, e_vcard_attribute_get_value (attr), g_strdup (param->data));
				}

				param = e_vcard_attribute_get_param (attr, EMA_X_MEMBERID);
				if (param && param->data && !param->next) {
					g_hash_table_insert (member_ids, e_vcard_attribute_get_value (attr), GINT_TO_POINTER (atoi (param->data)));
				}
			}

			g_list_free_full (local, (GDestroyNotify) e_vcard_attribute_free);
		}

		set_value (PidTagMessageClass, IPM_DISTLIST);
		u32 = 0xFFFFFFFF;
		set_value (PidLidFileUnderId, &u32);
		set_con_value (PidLidFileUnder, E_CONTACT_FILE_AS);
		set_con_value (PidLidDistributionListName, E_CONTACT_FILE_AS);
		set_con_value (PidTagDisplayName, E_CONTACT_FILE_AS);
		set_con_value (PidTagNormalizedSubject, E_CONTACT_FILE_AS);

		local = e_contact_get_attributes (contact, E_CONTACT_EMAIL);
		if (member_ids)
			local = g_list_sort_with_data (local, cmp_member_id, member_ids);

		members = talloc_zero (mem_ctx, struct BinaryArray_r);
		members->cValues = 0;
		members->lpbin = talloc_zero_array (mem_ctx, struct Binary_r, g_list_length (local));

		oneoff_members = talloc_zero (mem_ctx, struct BinaryArray_r);
		oneoff_members->cValues = 0;
		oneoff_members->lpbin = talloc_zero_array (mem_ctx, struct Binary_r, g_list_length (local));

		for (l = local; l; l = l->next) {
			EVCardAttribute *attr = (EVCardAttribute *) l->data;
			gchar *raw;
			CamelInternetAddress *addr;

			if (!attr)
				continue;

			raw = e_vcard_attribute_get_value (attr);
			if (!raw)
				continue;

			addr = camel_internet_address_new ();
			if (camel_address_decode (CAMEL_ADDRESS (addr), raw) > 0) {
				const gchar *nm = NULL, *eml = NULL;

				if (camel_internet_address_get (addr, 0, &nm, &eml) && eml) {
					/* keep both lists in sync */
					if (member_values && g_hash_table_lookup (member_values, raw)) {
						/* stored ListMembers values when contact's value didn't change */
						members->lpbin[members->cValues].cb = string_to_bin (mem_ctx, g_hash_table_lookup (member_values, raw), &members->lpbin[members->cValues].lpb);
						members->cValues++;
					} else {
						e_mapi_util_recip_entryid_generate_smtp (mem_ctx, &members->lpbin[members->cValues], nm ? nm : "", eml);
						members->cValues++;
					}

					e_mapi_util_recip_entryid_generate_smtp (mem_ctx, &oneoff_members->lpbin[oneoff_members->cValues], nm ? nm : "", eml);
					oneoff_members->cValues++;

					crc32 = e_mapi_utils_push_crc32 (crc32, members->lpbin[members->cValues - 1].lpb, members->lpbin[members->cValues - 1].cb);
				}
			}

			g_object_unref (addr);
			g_free (raw);
		}

		if (member_values)
			g_hash_table_destroy (member_values);
		if (member_ids)
			g_hash_table_destroy (member_ids);
		g_list_foreach (local, (GFunc)e_vcard_attribute_free, NULL);
		g_list_free (local);

		set_value (PidLidDistributionListOneOffMembers, oneoff_members);
		set_value (PidLidDistributionListMembers, members);
		set_value (PidLidDistributionListChecksum, &crc32);

		if (e_mapi_debug_is_enabled ()) {
			printf ("%s:\n", G_STRFUNC);
			e_mapi_debug_dump_object (object, TRUE, 3);
		}

		return TRUE;
	}

	set_value (PidTagMessageClass, IPM_CONTACT);
	set_con_value (PidLidFileUnder, E_CONTACT_FILE_AS);

	set_con_value (PidTagDisplayName, E_CONTACT_FULL_NAME);
	set_con_value (PidTagNormalizedSubject, E_CONTACT_FILE_AS);
	set_con_value (PidLidEmail1OriginalDisplayName, E_CONTACT_EMAIL_1);
	/*set_con_value (PidLidEmail1EmailAddress, E_CONTACT_EMAIL_1);*/

	/*set_con_value (0x8083001e, E_CONTACT_EMAIL_1);*/
	set_con_value (PidLidEmail2EmailAddress, E_CONTACT_EMAIL_2);

	set_con_value (PidLidEmail3EmailAddress, E_CONTACT_EMAIL_3);
	/*set_con_value (PidLidEmail3OriginalDisplayName, E_CONTACT_EMAIL_3);*/

	set_con_value (PidLidHtml, E_CONTACT_HOMEPAGE_URL);
	set_con_value (PidLidFreeBusyLocation, E_CONTACT_FREEBUSY_URL);

	set_con_value (PidTagBusinessTelephoneNumber, E_CONTACT_PHONE_BUSINESS);
	set_con_value (PidTagHomeTelephoneNumber, E_CONTACT_PHONE_HOME);
	set_con_value (PidTagMobileTelephoneNumber, E_CONTACT_PHONE_MOBILE);
	set_con_value (PidTagHomeFaxNumber, E_CONTACT_PHONE_HOME_FAX);
	set_con_value (PidTagBusinessFaxNumber, E_CONTACT_PHONE_BUSINESS_FAX);
	set_con_value (PidTagPagerTelephoneNumber, E_CONTACT_PHONE_PAGER);
	set_con_value (PidTagAssistantTelephoneNumber, E_CONTACT_PHONE_ASSISTANT);
	set_con_value (PidTagCompanyMainTelephoneNumber, E_CONTACT_PHONE_COMPANY);

	set_con_value (PidTagManagerName, E_CONTACT_MANAGER);
	set_con_value (PidTagAssistant, E_CONTACT_ASSISTANT);
	set_con_value (PidTagCompanyName, E_CONTACT_ORG);
	set_con_value (PidTagDepartmentName, E_CONTACT_ORG_UNIT);
	set_con_value (PidTagProfession, E_CONTACT_ROLE);
	set_con_value (PidTagTitle, E_CONTACT_TITLE);

	set_con_value (PidTagOfficeLocation, E_CONTACT_OFFICE);
	set_con_value (PidTagSpouseName, E_CONTACT_SPOUSE);

	set_con_value (PidTagBody, E_CONTACT_NOTE);
	set_con_value (PidTagNickname, E_CONTACT_NICKNAME);

	/* BDAY AND ANNV */
	if (e_contact_get (contact, E_CONTACT_BIRTH_DATE)) {
		EContactDate *date = e_contact_get (contact, E_CONTACT_BIRTH_DATE);
		struct tm tmtime = { 0 };
		struct FILETIME t;

		tmtime.tm_mday = date->day;
		tmtime.tm_mon = date->month - 1;
		tmtime.tm_year = date->year - 1900;

		e_mapi_util_time_t_to_filetime (mktime (&tmtime) + (24 * 60 * 60), &t);

		set_value (PidTagBirthday, &t);
	}

	if (e_contact_get (contact, E_CONTACT_ANNIVERSARY)) {
		EContactDate *date = e_contact_get (contact, E_CONTACT_ANNIVERSARY);
		struct tm tmtime = { 0 };
		struct FILETIME t;

		tmtime.tm_mday = date->day;
		tmtime.tm_mon = date->month - 1;
		tmtime.tm_year = date->year - 1900;

		e_mapi_util_time_t_to_filetime (mktime (&tmtime) + (24 * 60 * 60), &t);

		set_value (PidTagWeddingAnniversary, &t);
	}

	/* Home and Office address */
	if (e_contact_get (contact, E_CONTACT_ADDRESS_HOME)) {
		EContactAddress *contact_addr = e_contact_get (contact, E_CONTACT_ADDRESS_HOME);

		set_value (PidLidHomeAddress, contact_addr->street);
		set_value (PidTagHomeAddressPostOfficeBox, contact_addr->ext);
		set_value (PidTagHomeAddressCity, contact_addr->locality);
		set_value (PidTagHomeAddressStateOrProvince, contact_addr->region);
		set_value (PidTagHomeAddressPostalCode, contact_addr->code);
		set_value (PidTagHomeAddressCountry, contact_addr->country);
	}

	if (e_contact_get (contact, E_CONTACT_ADDRESS_WORK)) {
		EContactAddress *contact_addr = e_contact_get (contact, E_CONTACT_ADDRESS_WORK);

		set_value (PidLidWorkAddress, contact_addr->street);
		set_value (PidTagPostOfficeBox, contact_addr->ext);
		set_value (PidTagLocality, contact_addr->locality);
		set_value (PidTagStateOrProvince, contact_addr->region);
		set_value (PidTagPostalCode, contact_addr->code);
		set_value (PidTagCountry, contact_addr->country);
	}

	if (e_contact_get (contact, E_CONTACT_IM_AIM)) {
		GList *l = e_contact_get (contact, E_CONTACT_IM_AIM);
		set_value (PidLidInstantMessagingAddress, l->data);
	}

	#undef set_value

	if (e_mapi_debug_is_enabled ()) {
		printf ("%s:\n", G_STRFUNC);
		e_mapi_debug_dump_object (object, TRUE, 3);
	}

	return TRUE;
}

gchar *
e_mapi_book_utils_timet_to_string (time_t tt)
{
	GTimeVal tv;

	tv.tv_sec = tt;
	tv.tv_usec = 0;

	return g_time_val_to_iso8601 (&tv);
}

struct EMapiSExpParserData
{
	TALLOC_CTX *mem_ctx;
	/* parser results in ints, indexes to res_parts */
	GPtrArray *res_parts;
};

static ESExpResult *
term_eval_and (struct _ESExp *f,
	       gint argc,
	       struct _ESExpResult **argv,
	       gpointer user_data)
{
	struct EMapiSExpParserData *esp = user_data;
	ESExpResult *r;
	gint ii, jj, valid = 0;

	r = e_sexp_result_new (f, ESEXP_RES_INT);
	r->value.number = -1;

	for (ii = 0; ii < argc; ii++) {
		if (argv[ii]->type == ESEXP_RES_INT &&
		    argv[ii]->value.number >= 0 && 
		    argv[ii]->value.number < esp->res_parts->len) {
			struct mapi_SRestriction *subres = g_ptr_array_index (esp->res_parts, argv[ii]->value.number);

			jj = argv[ii]->value.number;
			valid++;

			/* join two consecutive AND-s into one */
			if (subres->rt == RES_AND)
				valid += subres->res.resAnd.cRes - 1;
		}
	}

	if (valid == 1) {
		r->value.number = jj;
	} else if (valid > 0) {
		struct mapi_SRestriction *res = talloc_zero (esp->mem_ctx, struct mapi_SRestriction);
		g_return_val_if_fail (res != NULL, NULL);

		res->rt = RES_AND;
		res->res.resAnd.cRes = valid;
		res->res.resAnd.res = talloc_zero_array (esp->mem_ctx, struct mapi_SRestriction_and, res->res.resAnd.cRes + 1);

		jj = 0;

		for (ii = 0; ii < argc; ii++) {
			if (argv[ii]->type == ESEXP_RES_INT &&
			    argv[ii]->value.number >= 0 && 
			    argv[ii]->value.number < esp->res_parts->len) {
				struct mapi_SRestriction *subres = g_ptr_array_index (esp->res_parts, argv[ii]->value.number);

				/* join two consecutive AND-s into one */
				if (subres->rt == RES_AND) {
					gint xx;

					for (xx = 0; xx < subres->res.resAnd.cRes; xx++, jj++) {
						res->res.resAnd.res[jj].rt = subres->res.resAnd.res[xx].rt;
						res->res.resAnd.res[jj].res = subres->res.resAnd.res[xx].res;
					}
				} else {
					res->res.resAnd.res[jj].rt = subres->rt;
					res->res.resAnd.res[jj].res = subres->res;

					jj++;
				}
			}
		}

		g_ptr_array_add (esp->res_parts, res);
		r->value.number = esp->res_parts->len - 1;
	}

	return r;
}

static ESExpResult *
term_eval_or (struct _ESExp *f,
	      gint argc,
	      struct _ESExpResult **argv,
	      gpointer user_data)
{
	struct EMapiSExpParserData *esp = user_data;
	ESExpResult *r;
	gint ii, jj = -1, valid = 0;

	r = e_sexp_result_new (f, ESEXP_RES_INT);
	r->value.number = -1;

	for (ii = 0; ii < argc; ii++) {
		if (argv[ii]->type == ESEXP_RES_INT &&
		    argv[ii]->value.number >= 0 && 
		    argv[ii]->value.number < esp->res_parts->len) {
			struct mapi_SRestriction *subres = g_ptr_array_index (esp->res_parts, argv[ii]->value.number);

			jj = argv[ii]->value.number;
			valid++;

			/* join two consecutive OR-s into one */
			if (subres->rt == RES_OR)
				valid += subres->res.resOr.cRes - 1;
		    }
	}

	if (valid == 1) {
		r->value.number = jj;
	} else if (valid > 0) {
		struct mapi_SRestriction *res = talloc_zero (esp->mem_ctx, struct mapi_SRestriction);
		g_return_val_if_fail (res != NULL, NULL);

		res->rt = RES_OR;
		res->res.resOr.cRes = valid;
		res->res.resOr.res = talloc_zero_array (esp->mem_ctx, struct mapi_SRestriction_or, res->res.resOr.cRes + 1);

		jj = 0;

		for (ii = 0; ii < argc; ii++) {
			if (argv[ii]->type == ESEXP_RES_INT &&
			    argv[ii]->value.number >= 0 && 
			    argv[ii]->value.number < esp->res_parts->len) {
				struct mapi_SRestriction *subres = g_ptr_array_index (esp->res_parts, argv[ii]->value.number);

				/* join two consecutive OR-s into one */
				if (subres->rt == RES_OR) {
					gint xx;

					for (xx = 0; xx < subres->res.resOr.cRes; xx++, jj++) {
						res->res.resOr.res[jj].rt = subres->res.resOr.res[xx].rt;
						res->res.resOr.res[jj].res = subres->res.resOr.res[xx].res;
					}
				} else {
					res->res.resOr.res[jj].rt = subres->rt;
					res->res.resOr.res[jj].res = subres->res;

					jj++;
				}
			}
		}

		g_ptr_array_add (esp->res_parts, res);
		r->value.number = esp->res_parts->len - 1;
	}

	return r;
}

static ESExpResult *
term_eval_not (struct _ESExp *f,
	       gint argc,
	       struct _ESExpResult **argv,
	       gpointer user_data)
{
	ESExpResult *r;

	r = e_sexp_result_new (f, ESEXP_RES_INT);
	r->value.number = -1;

	#ifdef HAVE_RES_NOT_SUPPORTED
	if (argc == 1 && argv[0]->type == ESEXP_RES_INT) {
		struct EMapiSExpParserData *esp = user_data;
		gint idx = argv[0]->value.number;

		if (esp && idx >= 0 && idx < esp->res_parts->len) {
			struct mapi_SRestriction *res = talloc_zero (esp->mem_ctx, struct mapi_SRestriction);
			g_return_val_if_fail (res != NULL, NULL);

			res->rt = RES_NOT;
			res->res.resNot.res = g_ptr_array_index (esp->res_parts, idx);

			g_ptr_array_add (esp->res_parts, res);
			r->value.number = esp->res_parts->len - 1;
		}
	}
	#endif

	return r;
}

static uint32_t
get_proptag_from_field_name (const gchar *field_name, gboolean is_contact_field)
{
	EContactField cfid;
	gint ii;

	if (is_contact_field)
		cfid = e_contact_field_id (field_name);
	else
		cfid = e_contact_field_id_from_vcard (field_name);

	for (ii = 0; ii < G_N_ELEMENTS (mappings); ii++) {
		if (mappings[ii].field_id == cfid) {
			return mappings[ii].mapi_id;
		}
	}

	return MAPI_E_RESERVED;
}

static ESExpResult *
func_eval_text_compare (struct _ESExp *f,
			gint argc,
			struct _ESExpResult **argv,
			gpointer user_data,
			uint32_t fuzzy)
{
	struct EMapiSExpParserData *esp = user_data;
	ESExpResult *r;

	r = e_sexp_result_new (f, ESEXP_RES_INT);
	r->value.number = -1;

	if (argc == 2
	    && argv[0]->type == ESEXP_RES_STRING
	    && argv[1]->type == ESEXP_RES_STRING) {
		const gchar *propname = argv[0]->value.string;
		const gchar *propvalue = argv[1]->value.string;

		if (propname && propvalue && g_ascii_strcasecmp (propname, "x-evolution-any-field") != 0) {
			uint32_t proptag = get_proptag_from_field_name (propname, TRUE);

			if (proptag != MAPI_E_RESERVED && ((proptag & 0xFFFF) == PT_UNICODE || (proptag & 0xFFFF) == PT_STRING8)) {
				struct mapi_SRestriction *res = talloc_zero (esp->mem_ctx, struct mapi_SRestriction);
				g_return_val_if_fail (res != NULL, NULL);

				res->rt = RES_CONTENT;
				res->res.resContent.fuzzy = fuzzy | FL_IGNORECASE;
				res->res.resContent.ulPropTag = proptag;
				res->res.resContent.lpProp.ulPropTag = proptag;
				res->res.resContent.lpProp.value.lpszW = talloc_strdup (esp->mem_ctx, propvalue);

				g_ptr_array_add (esp->res_parts, res);
				r->value.number = esp->res_parts->len - 1;
			} else if (g_ascii_strcasecmp (propname, "email") == 0) {
				uint32_t ii, jj;
				const gchar *emails[] = {"email_1", "email_2", "email_3", NULL};
				struct mapi_SRestriction *res = talloc_zero (esp->mem_ctx, struct mapi_SRestriction);
				g_return_val_if_fail (res != NULL, NULL);

				res->rt = RES_OR;
				res->res.resOr.cRes = 4;
				res->res.resOr.res = talloc_zero_array (esp->mem_ctx, struct mapi_SRestriction_or, res->res.resOr.cRes + 1);

				proptag = PidTagPrimarySmtpAddress;
				res->res.resOr.res[0].rt = RES_CONTENT;
				res->res.resOr.res[0].res.resContent.fuzzy = fuzzy | FL_IGNORECASE;
				res->res.resOr.res[0].res.resContent.ulPropTag = proptag;
				res->res.resOr.res[0].res.resContent.lpProp.ulPropTag = proptag;
				res->res.resOr.res[0].res.resContent.lpProp.value.lpszW = talloc_strdup (esp->mem_ctx, propvalue);

				for (ii = 1, jj = 0; emails[jj]; jj++) {
					proptag = get_proptag_from_field_name (emails[jj], TRUE);
					if (proptag == MAPI_E_RESERVED)
						continue;

					res->res.resOr.res[ii].rt = RES_CONTENT;
					res->res.resOr.res[ii].res.resContent.fuzzy = fuzzy | FL_IGNORECASE;
					res->res.resOr.res[ii].res.resContent.ulPropTag = proptag;
					res->res.resOr.res[ii].res.resContent.lpProp.ulPropTag = proptag;
					res->res.resOr.res[ii].res.resContent.lpProp.value.lpszW = talloc_strdup (esp->mem_ctx, propvalue);

					ii++;
				}

				res->res.resOr.cRes = ii;

				g_ptr_array_add (esp->res_parts, res);
				r->value.number = esp->res_parts->len - 1;
			}
		}
	}

	return r;
}

static ESExpResult *
func_eval_contains (struct _ESExp *f,
		    gint argc,
		    struct _ESExpResult **argv,
		    gpointer user_data)
{
	return func_eval_text_compare (f, argc, argv, user_data, FL_SUBSTRING);
}

static ESExpResult *
func_eval_is (struct _ESExp *f,
	      gint argc,
	      struct _ESExpResult **argv,
	      gpointer user_data)
{
	return func_eval_text_compare (f, argc, argv, user_data, FL_FULLSTRING);
}

static ESExpResult *
func_eval_beginswith (struct _ESExp *f,
		      gint argc,
		      struct _ESExpResult **argv,
		      gpointer user_data)
{
	return func_eval_text_compare (f, argc, argv, user_data, FL_PREFIX);
}

static ESExpResult *
func_eval_endswith (struct _ESExp *f,
		    gint argc,
		    struct _ESExpResult **argv,
		    gpointer user_data)
{
	/* no suffix, thus at least substring is used */
	return func_eval_text_compare (f, argc, argv, user_data, FL_SUBSTRING);
}

static ESExpResult *
func_eval_field_exists (struct _ESExp *f,
			gint argc,
			struct _ESExpResult **argv,
			gpointer user_data,
			gboolean is_contact_field)
{
	struct EMapiSExpParserData *esp = user_data;
	ESExpResult *r;

	r = e_sexp_result_new (f, ESEXP_RES_INT);
	r->value.number = -1;

	if (argc == 1 && argv[0]->type == ESEXP_RES_STRING) {
		const gchar *propname = argv[0]->value.string;
		uint32_t proptag = get_proptag_from_field_name (propname, is_contact_field);

		if (proptag != MAPI_E_RESERVED) {
			struct mapi_SRestriction *res = talloc_zero (esp->mem_ctx, struct mapi_SRestriction);
			g_return_val_if_fail (res != NULL, NULL);

			res->rt = RES_EXIST;
			res->res.resExist.ulPropTag = proptag;

			g_ptr_array_add (esp->res_parts, res);
			r->value.number = esp->res_parts->len - 1;
		} else if (g_ascii_strcasecmp (propname, "email") == 0) {
			uint32_t ii, jj;
			const gchar *emails[] = { "email_1", "email_2", "email_3", NULL };
			struct mapi_SRestriction *res = talloc_zero (esp->mem_ctx, struct mapi_SRestriction);
			g_return_val_if_fail (res != NULL, NULL);

			res->rt = RES_OR;
			res->res.resOr.cRes = 4;
			res->res.resOr.res = talloc_zero_array (esp->mem_ctx, struct mapi_SRestriction_or, res->res.resOr.cRes + 1);

			res->res.resOr.res[0].rt = RES_EXIST;
			res->res.resOr.res[0].res.resExist.ulPropTag = PidTagPrimarySmtpAddress;

			for (ii = 1, jj = 0; emails[jj]; jj++) {
				proptag = get_proptag_from_field_name (emails[jj], TRUE);

				if (proptag == MAPI_E_RESERVED)
					continue;

				res->res.resOr.res[ii].rt = RES_EXIST;
				res->res.resOr.res[ii].res.resExist.ulPropTag = proptag;

				ii++;
			}

			res->res.resOr.cRes = ii;

			g_ptr_array_add (esp->res_parts, res);
			r->value.number = esp->res_parts->len - 1;
		}
	}

	return r;
}

static ESExpResult *
func_eval_exists (struct _ESExp *f,
		  gint argc,
		  struct _ESExpResult **argv,
		  gpointer user_data)
{
	return func_eval_field_exists (f, argc, argv, user_data, TRUE);
}

static ESExpResult *
func_eval_exists_vcard (struct _ESExp *f,
			gint argc,
			struct _ESExpResult **argv,
			gpointer user_data)
{
	return func_eval_field_exists (f, argc, argv, user_data, FALSE);
}

static struct mapi_SRestriction *
mapi_book_utils_sexp_to_restriction (TALLOC_CTX *mem_ctx, const gchar *sexp_query)
{
	/* 'builtin' functions */
	static const struct {
		const gchar *name;
		ESExpFunc *func;
		gint type;		/* set to 1 if a function can perform shortcut evaluation, or
					   doesn't execute everything, 0 otherwise */
	} check_symbols[] = {
		{ "and", 		term_eval_and,		0 },
		{ "or", 		term_eval_or,		0 },
		{ "not", 		term_eval_not,		0 },

		{ "contains",		func_eval_contains,	0 },
		{ "is",			func_eval_is,		0 },
		{ "beginswith",		func_eval_beginswith,	0 },
		{ "endswith",		func_eval_endswith,	0 },
		{ "exists",		func_eval_exists,	0 },
		{ "exists_vcard",	func_eval_exists_vcard,	0 }
	};

	gint i;
	ESExp *sexp;
	ESExpResult *r;
	struct EMapiSExpParserData esp;
	struct mapi_SRestriction *restriction;

	g_return_val_if_fail (sexp_query != NULL, NULL);

	esp.mem_ctx = mem_ctx;
	sexp = e_sexp_new ();

	for (i = 0; i < G_N_ELEMENTS (check_symbols); i++) {
		if (check_symbols[i].type == 1) {
			e_sexp_add_ifunction (sexp, 0, check_symbols[i].name,
					      (ESExpIFunc *) check_symbols[i].func, &esp);
		} else {
			e_sexp_add_function (sexp, 0, check_symbols[i].name,
					     check_symbols[i].func, &esp);
		}
	}

	e_sexp_input_text (sexp, sexp_query, strlen (sexp_query));
	if (e_sexp_parse (sexp) == -1) {
		e_sexp_unref (sexp);
		return NULL;
	}

	esp.res_parts = g_ptr_array_new ();
	r = e_sexp_eval (sexp);

	restriction = NULL;
	if (r && r->type == ESEXP_RES_INT && r->value.number >= 0 && r->value.number < esp.res_parts->len)
		restriction = g_ptr_array_index (esp.res_parts, r->value.number);

	e_sexp_result_free (sexp, r);

	e_sexp_unref (sexp);
	g_ptr_array_free (esp.res_parts, TRUE);

	return restriction;
}

gboolean
e_mapi_book_utils_build_sexp_restriction (EMapiConnection *conn,
					  TALLOC_CTX *mem_ctx,
					  struct mapi_SRestriction **restrictions,
					  gpointer user_data, /* const gchar *sexp */
					  GCancellable *cancellable,
					  GError **perror)
{
	const gchar *sexp = user_data;

	g_return_val_if_fail (conn != NULL, FALSE);
	g_return_val_if_fail (mem_ctx != NULL, FALSE);
	g_return_val_if_fail (restrictions != NULL, FALSE);

	if (!sexp || !*sexp)
		*restrictions = NULL;
	else
		*restrictions = mapi_book_utils_sexp_to_restriction (mem_ctx, sexp);

	return TRUE;
}

/* return with g_slist_free(), 'data' pointers (strings) are not newly allocated */
GSList *
e_mapi_book_utils_get_supported_contact_fields (void)
{
	gint ii;
	GSList *fields = NULL;

	for (ii = 0; ii < G_N_ELEMENTS (mappings); ii++) {
		fields = g_slist_append (fields, (gpointer) e_contact_field_name (mappings[ii].field_id));
	}

	fields = g_slist_append (fields, (gpointer) e_contact_field_name (E_CONTACT_BOOK_URI));

	return fields;
}

gboolean
e_mapi_book_utils_get_supported_mapi_proptags (TALLOC_CTX *mem_ctx,
					       struct SPropTagArray **propTagArray)
{
	gint ii;

	g_return_val_if_fail (mem_ctx != NULL, FALSE);
	g_return_val_if_fail (propTagArray != NULL, FALSE);

	*propTagArray = set_SPropTagArray (mem_ctx, 1, PidTagObjectType);

	for (ii = 0; ii < G_N_ELEMENTS (mappings); ii++) {
		SPropTagArray_add (mem_ctx, *propTagArray, mappings[ii].mapi_id);
	}

	for (ii = 0; ii < G_N_ELEMENTS (extra_proptags); ii++) {
		SPropTagArray_add (mem_ctx, *propTagArray, extra_proptags[ii]);
	}

	return TRUE;
}
