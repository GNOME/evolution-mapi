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
 *    Srinivasa Ragavan <sragavan@novell.com>
 *
 * Copyright (C) 1999-2008 Novell, Inc. (www.novell.com)
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <glib.h>
#include <glib/gstdio.h>

#include <libebook/e-contact.h>
#include <camel/camel.h>

#include "exchange-mapi-utils.h"
#include "exchange-mapi-defs.h"

#include "e-book-backend-mapi-utils.h"

#define ELEMENT_TYPE_MASK   0xF /* mask where the real type of the element is stored */

#define ELEMENT_TYPE_SIMPLE 0x01
#define ELEMENT_TYPE_COMPLEX 0x02

#define ELEMENT_TYPE_NAMEDID 0x10

static const struct field_element_mapping {
		EContactField field_id;
		gint element_type;
		gint mapi_id;
		gint contact_type;
//		gchar *element_name;
//		void (*populate_contact_func)(EContact *contact,    gpointer data);
//		void (*set_value_in_gw_item) (EGwItem *item, gpointer data);
//		void (*set_changes) (EGwItem *new_item, EGwItem *old_item);

	} mappings [] = {

	{ E_CONTACT_UID, PT_UNICODE, 0, ELEMENT_TYPE_SIMPLE},
	{ E_CONTACT_REV, PT_SYSTIME, PR_LAST_MODIFICATION_TIME, ELEMENT_TYPE_SIMPLE},

	{ E_CONTACT_FILE_AS, PT_UNICODE, PR_EMS_AB_MANAGER_T_UNICODE, ELEMENT_TYPE_SIMPLE},
	{ E_CONTACT_FULL_NAME, PT_UNICODE, PR_DISPLAY_NAME_UNICODE, ELEMENT_TYPE_SIMPLE },
	{ E_CONTACT_GIVEN_NAME, PT_UNICODE, PR_GIVEN_NAME_UNICODE, ELEMENT_TYPE_SIMPLE},
	{ E_CONTACT_FAMILY_NAME, PT_UNICODE, PR_SURNAME_UNICODE, ELEMENT_TYPE_SIMPLE},
	{ E_CONTACT_NICKNAME, PT_UNICODE, PR_NICKNAME_UNICODE, ELEMENT_TYPE_SIMPLE },

	{ E_CONTACT_EMAIL_1, PT_UNICODE, PidLidEmail1OriginalDisplayName, ELEMENT_TYPE_SIMPLE | ELEMENT_TYPE_NAMEDID},
	{ E_CONTACT_EMAIL_2, PT_UNICODE, PidLidEmail2EmailAddress, ELEMENT_TYPE_SIMPLE | ELEMENT_TYPE_NAMEDID},
	{ E_CONTACT_EMAIL_3, PT_UNICODE, PidLidEmail3EmailAddress, ELEMENT_TYPE_SIMPLE | ELEMENT_TYPE_NAMEDID},
	{ E_CONTACT_IM_AIM,  PT_UNICODE, PidLidInstantMessagingAddress, ELEMENT_TYPE_COMPLEX | ELEMENT_TYPE_NAMEDID},

	{ E_CONTACT_PHONE_BUSINESS, PT_UNICODE, PR_OFFICE_TELEPHONE_NUMBER_UNICODE, ELEMENT_TYPE_SIMPLE},
	{ E_CONTACT_PHONE_HOME, PT_UNICODE, PR_HOME_TELEPHONE_NUMBER_UNICODE, ELEMENT_TYPE_SIMPLE},
	{ E_CONTACT_PHONE_MOBILE, PT_UNICODE, PR_MOBILE_TELEPHONE_NUMBER_UNICODE, ELEMENT_TYPE_SIMPLE},
	{ E_CONTACT_PHONE_HOME_FAX, PT_UNICODE, PR_HOME_FAX_NUMBER_UNICODE, ELEMENT_TYPE_SIMPLE},
	{ E_CONTACT_PHONE_BUSINESS_FAX, PT_UNICODE, PR_BUSINESS_FAX_NUMBER_UNICODE, ELEMENT_TYPE_SIMPLE},
	{ E_CONTACT_PHONE_PAGER, PT_UNICODE, PR_PAGER_TELEPHONE_NUMBER_UNICODE, ELEMENT_TYPE_SIMPLE},
	{ E_CONTACT_PHONE_ASSISTANT, PT_UNICODE, PR_ASSISTANT_TELEPHONE_NUMBER_UNICODE, ELEMENT_TYPE_SIMPLE},
	{ E_CONTACT_PHONE_COMPANY, PT_UNICODE, PR_COMPANY_MAIN_PHONE_NUMBER_UNICODE, ELEMENT_TYPE_SIMPLE},

	{ E_CONTACT_HOMEPAGE_URL, PT_UNICODE, PidLidHtml, ELEMENT_TYPE_SIMPLE | ELEMENT_TYPE_NAMEDID},
	{ E_CONTACT_FREEBUSY_URL, PT_UNICODE, PidLidFreeBusyLocation, ELEMENT_TYPE_SIMPLE | ELEMENT_TYPE_NAMEDID},

	{ E_CONTACT_ROLE, PT_UNICODE, PR_PROFESSION_UNICODE, ELEMENT_TYPE_SIMPLE},
	{ E_CONTACT_TITLE, PT_UNICODE, PR_TITLE_UNICODE, ELEMENT_TYPE_SIMPLE},
	{ E_CONTACT_ORG, PT_UNICODE, PR_COMPANY_NAME_UNICODE, ELEMENT_TYPE_SIMPLE},
	{ E_CONTACT_ORG_UNIT, PT_UNICODE, PR_DEPARTMENT_NAME_UNICODE, ELEMENT_TYPE_SIMPLE},
	{ E_CONTACT_MANAGER, PT_UNICODE, PR_MANAGER_NAME_UNICODE, ELEMENT_TYPE_SIMPLE},
	{ E_CONTACT_ASSISTANT, PT_UNICODE, PR_ASSISTANT_UNICODE, ELEMENT_TYPE_SIMPLE},

	{ E_CONTACT_OFFICE, PT_UNICODE, PR_OFFICE_LOCATION_UNICODE, ELEMENT_TYPE_SIMPLE},
	{ E_CONTACT_SPOUSE, PT_UNICODE, PR_SPOUSE_NAME_UNICODE, ELEMENT_TYPE_SIMPLE},

	{ E_CONTACT_BIRTH_DATE,  PT_SYSTIME, PR_BIRTHDAY, ELEMENT_TYPE_COMPLEX},
	{ E_CONTACT_ANNIVERSARY, PT_SYSTIME, PR_WEDDING_ANNIVERSARY, ELEMENT_TYPE_COMPLEX},

	{ E_CONTACT_NOTE, PT_UNICODE, PR_BODY_UNICODE, ELEMENT_TYPE_SIMPLE},

	{ E_CONTACT_ADDRESS_HOME, PT_UNICODE, PidLidHomeAddress, ELEMENT_TYPE_COMPLEX | ELEMENT_TYPE_NAMEDID},
	{ E_CONTACT_ADDRESS_WORK, PT_UNICODE, PidLidOtherAddress, ELEMENT_TYPE_COMPLEX | ELEMENT_TYPE_NAMEDID},
//		{ E_CONTACT_BOOK_URI, ELEMENT_TYPE_SIMPLE, "book_uri"}
//		{ E_CONTACT_CATEGORIES, },
	};


/* free it with g_list_free when done with it */
GList *
mapi_book_utils_get_supported_fields (void)
{
	gint i;
	GList *fields = NULL;

	for (i = 0; i < G_N_ELEMENTS (mappings); i++) {
		fields = g_list_append (fields, (gchar *)e_contact_field_name (mappings[i].field_id));
	}

	fields = g_list_append (fields, g_strdup (e_contact_field_name (E_CONTACT_BOOK_URI)));
	return fields;
}

/* 'data' is one of GET_ALL_KNOWN_IDS or GET_SHORT_SUMMARY */
gboolean
mapi_book_utils_get_prop_list (ExchangeMapiConnection *conn, mapi_id_t fid, TALLOC_CTX *mem_ctx, struct SPropTagArray *props, gpointer data)
{
	/* this is a list of all known book MAPI tag IDs;
	   if you add new add it here too, otherwise it may not be fetched */
	static uint32_t known_book_mapi_ids[] = {
		PR_ASSISTANT_TELEPHONE_NUMBER_UNICODE,
		PR_ASSISTANT_UNICODE,
		PR_BIRTHDAY,
		PR_BODY,
		PR_BODY_UNICODE,
		PR_BUSINESS_FAX_NUMBER_UNICODE,
		PR_COMPANY_MAIN_PHONE_NUMBER_UNICODE,
		PR_COMPANY_NAME_UNICODE,
		PR_COUNTRY_UNICODE,
		PR_DEPARTMENT_NAME_UNICODE,
		PR_DISPLAY_NAME_UNICODE,
		PR_SMTP_ADDRESS_UNICODE, /* used in GAL */
		PR_EMS_AB_MANAGER_T_UNICODE,
		PR_FID,
		PR_GIVEN_NAME_UNICODE,
		PR_HASATTACH,
		PR_HOME_ADDRESS_CITY_UNICODE,
		PR_HOME_ADDRESS_COUNTRY_UNICODE,
		PR_HOME_ADDRESS_POSTAL_CODE_UNICODE,
		PR_HOME_ADDRESS_POST_OFFICE_BOX_UNICODE,
		PR_HOME_ADDRESS_STATE_OR_PROVINCE_UNICODE,
		PR_HOME_FAX_NUMBER_UNICODE,
		PR_HOME_TELEPHONE_NUMBER_UNICODE,
		PR_INSTANCE_NUM,
		PR_INST_ID,
		PR_LAST_MODIFICATION_TIME,
		PR_LOCALITY_UNICODE,
		PR_MANAGER_NAME_UNICODE,
		PR_MESSAGE_CLASS,
		PR_MID,
		PR_MOBILE_TELEPHONE_NUMBER_UNICODE,
		PR_NICKNAME_UNICODE,
		PR_NORMALIZED_SUBJECT_UNICODE,
		PR_OFFICE_LOCATION_UNICODE,
		PR_OFFICE_TELEPHONE_NUMBER_UNICODE,
		PR_PAGER_TELEPHONE_NUMBER_UNICODE,
		PR_POSTAL_CODE_UNICODE,
		PR_POST_OFFICE_BOX_UNICODE,
		PR_PROFESSION_UNICODE,
		PR_RULE_MSG_NAME,
		PR_RULE_MSG_PROVIDER,
		PR_SPOUSE_NAME_UNICODE,
		PR_STATE_OR_PROVINCE_UNICODE,
		PR_SUBJECT_UNICODE,
		PR_SURNAME_UNICODE,
		PR_TITLE_UNICODE,
		PR_WEDDING_ANNIVERSARY,
		PROP_TAG(PT_UNICODE, 0x801f)
	};

	static uint32_t short_summary_ids[] = {
		PR_FID,
		PR_MID,
		PR_INST_ID,
		PR_INSTANCE_NUM,
		PR_SUBJECT_UNICODE,
		PR_MESSAGE_CLASS,
		PR_HASATTACH,
		/* FIXME: is this tag fit to check if a recipient table exists or not? */
		/* PR_DISCLOSURE_OF_RECIPIENTS, */
		PR_RULE_MSG_PROVIDER,
		PR_RULE_MSG_NAME
	};
	
	/* do not make this array static, the function modifies it on run */
	ResolveNamedIDsData nids[] = {
		{ PidLidDistributionListName, 0 },
		{ PidLidDistributionListOneOffMembers, 0 },
		{ PidLidDistributionListMembers, 0 },
		{ PidLidDistributionListChecksum, 0 },

		{ PidLidEmail1OriginalDisplayName, 0 },
		{ PidLidEmail2OriginalDisplayName, 0 },
		{ PidLidEmail3OriginalDisplayName, 0 },
		{ PidLidInstantMessagingAddress, 0 },
		{ PidLidHtml, 0 },
		{ PidLidFreeBusyLocation, 0 }
	};

	g_return_val_if_fail (props != NULL, FALSE);

	if (data == GET_ALL_KNOWN_IDS && !exchange_mapi_utils_add_props_to_props_array (mem_ctx, props, known_book_mapi_ids, G_N_ELEMENTS (known_book_mapi_ids)))
		return FALSE;

	if (data == GET_SHORT_SUMMARY && !exchange_mapi_utils_add_props_to_props_array (mem_ctx, props, short_summary_ids, G_N_ELEMENTS (short_summary_ids)))
		return FALSE;

	/* called with fid = 0 from GAL */
	if (!fid)
		fid = exchange_mapi_connection_get_default_folder_id (conn, olFolderContacts);

	return exchange_mapi_utils_add_named_ids_to_props_array (conn, fid, mem_ctx, props, nids, G_N_ELEMENTS (nids));
}

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

/* This is not setting E_CONTACT_UID */
EContact *
mapi_book_utils_contact_from_props (ExchangeMapiConnection *conn, mapi_id_t fid, struct mapi_SPropValue_array *mapi_properties, struct SRow *aRow)
{
	EContact *contact = e_contact_new ();
	gint i;

	#define get_proptag(proptag) (aRow ? exchange_mapi_util_find_row_propval (aRow, proptag) : exchange_mapi_util_find_array_propval (mapi_properties, proptag))
	#define get_str_proptag(proptag) not_null (get_proptag (proptag))
	#define get_namedid(nid) (aRow ? exchange_mapi_util_find_row_namedid (aRow, conn, fid, nid) : exchange_mapi_util_find_array_namedid (mapi_properties, conn, fid, nid))
	#define get_str_namedid(nid) not_null (get_namedid (nid))

	if (g_str_equal (get_str_proptag (PR_MESSAGE_CLASS), IPM_DISTLIST)) {
		const struct mapi_SBinaryArray *members, *members_dlist;
		GSList *attrs = NULL, *a;
		gint i;

		/* it's a contact list/distribution list, fetch members and return it */
		e_contact_set (contact, E_CONTACT_IS_LIST, GINT_TO_POINTER (TRUE));
		/* we do not support this option, same as GroupWise */
		e_contact_set (contact, E_CONTACT_LIST_SHOW_ADDRESSES, GINT_TO_POINTER (TRUE));

		e_contact_set (contact, E_CONTACT_FILE_AS, get_str_namedid (PidLidDistributionListName));

		members = get_namedid (PidLidDistributionListOneOffMembers);
		members_dlist = get_namedid (PidLidDistributionListMembers);

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
			if (exchange_mapi_util_entryid_decode_oneoff (&br, &display_name, &email)) {
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

	for (i = 1; i < G_N_ELEMENTS (mappings); i++) {
		gpointer value;
		gint contact_type;

		/* can cast value, no writing to the value; and it'll be freed not before the end of this function */
		if (mappings[i].contact_type & ELEMENT_TYPE_NAMEDID)
			value = (gpointer) get_namedid (mappings[i].mapi_id);
		else
			value = (gpointer) get_proptag (mappings[i].mapi_id);
		contact_type = mappings[i].contact_type & ELEMENT_TYPE_MASK;
		if (mappings[i].element_type == PT_UNICODE && contact_type == ELEMENT_TYPE_SIMPLE) {
			if (value)
				e_contact_set (contact, mappings[i].field_id, value);
		} else if (contact_type == ELEMENT_TYPE_SIMPLE) {
			if (value && mappings[i].element_type == PT_SYSTIME) {
				struct FILETIME *t = value;
				time_t time;
				NTTIME nt;
				gchar buff[129];

				nt = t->dwHighDateTime;
				nt = nt << 32;
				nt |= t->dwLowDateTime;
				time = nt_time_to_unix (nt);
				e_contact_set (contact, mappings[i].field_id, ctime_r (&time, buff));
			}
		} else if (contact_type == ELEMENT_TYPE_COMPLEX) {
			if (mappings[i].field_id == E_CONTACT_IM_AIM) {
				GList *list = g_list_append (NULL, value);

				e_contact_set (contact, mappings[i].field_id, list);

				g_list_free (list);
			} else if (mappings[i].field_id == E_CONTACT_BIRTH_DATE
				   || mappings[i].field_id == E_CONTACT_ANNIVERSARY) {
				struct FILETIME *t = value;
				time_t time;
				NTTIME nt;
				struct tm * tmtime;
				if (value) {
					EContactDate date = {0};
					nt = t->dwHighDateTime;
					nt = nt << 32;
					nt |= t->dwLowDateTime;
					time = nt_time_to_unix (nt);
					tmtime = gmtime (&time);
					//FIXME: Move to new libmapi api to get string dates.
					date.day = tmtime->tm_mday + 1;
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
					contact_addr.street = (gchar *)value;
					contact_addr.ext = (gchar *) get_str_proptag (PR_HOME_ADDRESS_POST_OFFICE_BOX_UNICODE);
					contact_addr.locality = (gchar *) get_str_proptag (PR_HOME_ADDRESS_CITY_UNICODE);
					contact_addr.region = (gchar *) get_str_proptag (PR_HOME_ADDRESS_STATE_OR_PROVINCE_UNICODE);
					contact_addr.code = (gchar *) get_str_proptag (PR_HOME_ADDRESS_POSTAL_CODE_UNICODE);
					contact_addr.country = (gchar *) get_str_proptag (PR_HOME_ADDRESS_COUNTRY_UNICODE);
				} else {
					contact_addr.address_format = NULL;
					contact_addr.po = NULL;
					contact_addr.street = (gchar *)value;
					contact_addr.ext = (gchar *) get_str_proptag (PR_POST_OFFICE_BOX_UNICODE);
					contact_addr.locality = (gchar *) get_str_proptag (PR_LOCALITY_UNICODE);
					contact_addr.region = (gchar *) get_str_proptag (PR_STATE_OR_PROVINCE_UNICODE);
					contact_addr.code = (gchar *) get_str_proptag (PR_POSTAL_CODE_UNICODE);
					contact_addr.country = (gchar *) get_str_proptag (PR_COUNTRY_UNICODE);
				}
				e_contact_set (contact, mappings[i].field_id, &contact_addr);
			}
		}
	}

	if (!e_contact_get (contact, E_CONTACT_EMAIL_1)) {
		gconstpointer value = get_proptag (PR_SMTP_ADDRESS_UNICODE);

		if (value)
			e_contact_set (contact, E_CONTACT_EMAIL_1, value);
	}

	#undef get_proptag
	#undef get_str_proptag
	#undef get_namedid
	#undef get_str_namedid

	return contact;
}
