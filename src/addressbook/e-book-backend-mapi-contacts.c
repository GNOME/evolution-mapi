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
#include <glib/gi18n-lib.h>

#include <sys/time.h>
/*
** #include <glib/gi18n-lib.h>
*/

#include <libedataserver/e-sexp.h>
#include "libedataserver/e-flag.h"
#include <libebook/e-contact.h>
#include <camel/camel.h>

#include <libedata-book/e-book-backend-sexp.h>
#include <libedata-book/e-data-book.h>
#include <libedata-book/e-data-book-view.h>
#include <libedata-book/e-book-backend-cache.h>
#include <libedata-book/e-book-backend-summary.h>

#include "e-book-backend-mapi-contacts.h"

G_DEFINE_TYPE (EBookBackendMAPIContacts, e_book_backend_mapi_contacts, E_TYPE_BOOK_BACKEND_MAPI)

struct _EBookBackendMAPIContactsPrivate
{
	mapi_id_t fid;
	gboolean is_public_folder;
};

static gboolean
build_restriction_emails_contains (struct mapi_SRestriction *res, const gchar *query)
{
	gchar *email=NULL, *tmp, *tmp1;

	/* This currently supports "email foo@bar.soo" */
	tmp = strdup (query);

	tmp = strstr (tmp, "email");
	if (tmp ) {
		tmp = strchr (tmp, '\"');
		if (tmp && ++tmp) {
			tmp = strchr (tmp, '\"');
			if (tmp && ++tmp) {
				tmp1 = tmp;
				tmp1 = strchr (tmp1, '\"');
				if (tmp1) {
					*tmp1 = 0;
					email = tmp;
				}
			}
		}
	}

	if (email==NULL || !strchr (email, '@'))
		return FALSE;

	res->rt = RES_PROPERTY;
	res->res.resProperty.relop = RES_PROPERTY;
	res->res.resProperty.ulPropTag = PROP_TAG(PT_UNICODE, 0x801f); /* EMAIL */
	res->res.resProperty.lpProp.ulPropTag = PROP_TAG(PT_UNICODE, 0x801f); /* EMAIL*/
	res->res.resProperty.lpProp.value.lpszA = email;

	return TRUE;
}

#if 0
static gboolean
build_multiple_restriction_emails_contains (ExchangeMapiConnection *conn, mapi_id_t fid, struct mapi_SRestriction *res,
					    struct mapi_SRestriction_or *or_res,
					    const gchar *query, gchar **to_free)
{
	gchar *email=NULL, *tmp, *tmp1;
	//Number of restriction to apply
	guint res_count = 6;

	g_return_val_if_fail (to_free != NULL, FALSE);

	/* This currently supports "email foo@bar.soo" */
	*to_free = strdup (query);

	tmp = strstr (*to_free, "email");
	if (tmp ) {
		tmp = strchr (tmp, '\"');
		if (tmp && ++tmp) {
			tmp = strchr (tmp, '\"');
			if (tmp && ++tmp) {
				tmp1 = tmp;
				tmp1 = strchr (tmp1, '\"');
				if (tmp1) {
					*tmp1 = 0;
					email = tmp;
				}
			}
		}
	}

	if (email==NULL || !strchr (email, '@')) {
		g_free (*to_free);
		*to_free = NULL;

		return FALSE;
	}

	or_res[0].rt = RES_CONTENT;
	or_res[0].res.resContent.fuzzy = FL_FULLSTRING | FL_IGNORECASE;
	or_res[0].res.resContent.ulPropTag = PR_EMS_AB_MANAGER_T_UNICODE;
	or_res[0].res.resContent.lpProp.value.lpszA = email;

	or_res[1].rt = RES_CONTENT;
	or_res[1].res.resContent.fuzzy = FL_FULLSTRING | FL_IGNORECASE;
	or_res[1].res.resContent.ulPropTag = PR_DISPLAY_NAME_UNICODE;
	or_res[1].res.resContent.lpProp.value.lpszA = email;

	or_res[2].rt = RES_CONTENT;
	or_res[2].res.resContent.fuzzy = FL_FULLSTRING | FL_IGNORECASE;
	or_res[2].res.resContent.ulPropTag = PR_GIVEN_NAME_UNICODE;
	or_res[2].res.resContent.lpProp.value.lpszA = email;

	or_res[3].rt = RES_CONTENT;
	or_res[3].res.resContent.fuzzy = FL_FULLSTRING | FL_IGNORECASE;
	or_res[3].res.resContent.ulPropTag = exchange_mapi_connection_resolve_named_prop (conn, fid, PidLidEmail1OriginalDisplayName, NULL);
	or_res[3].res.resContent.lpProp.value.lpszA = email;

	or_res[4].rt = RES_CONTENT;
	or_res[4].res.resContent.fuzzy = FL_FULLSTRING | FL_IGNORECASE;
	or_res[4].res.resContent.ulPropTag = exchange_mapi_connection_resolve_named_prop (conn, fid, PidLidEmail2OriginalDisplayName, NULL);
	or_res[4].res.resContent.lpProp.value.lpszA = email;

	or_res[5].rt = RES_CONTENT;
	or_res[5].res.resContent.fuzzy = FL_FULLSTRING | FL_IGNORECASE;
	or_res[5].res.resContent.ulPropTag = exchange_mapi_connection_resolve_named_prop (conn, fid, PidLidEmail3OriginalDisplayName, NULL);
	or_res[5].res.resContent.lpProp.value.lpszA = email;

	res = g_new0 (struct mapi_SRestriction, 1);

	res->rt = RES_OR;
	res->res.resOr.cRes = res_count;
	res->res.resOr.res = or_res;

	return TRUE;
}
#endif

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

typedef struct {
	EContact *contact;
	EBookBackendCache *cache;
} MapiCreateitemData;

static gboolean
mapi_book_write_props (ExchangeMapiConnection *conn, mapi_id_t fid, TALLOC_CTX *mem_ctx, struct SPropValue **values, uint32_t *n_values, gpointer data)
{
	/* Do not make this array static, below function modifies it.
	   The array is used to just ensure named ids are known later. */
	ResolveNamedIDsData nids[] = {
		{ PidLidDistributionListName, 0 },
		{ PidLidDistributionListOneOffMembers, 0 },
		{ PidLidDistributionListMembers, 0 },
		{ PidLidDistributionListChecksum, 0 },
		{ PidLidFileUnder, 0 },
		{ PidLidFileUnderId, 0 },
		{ PidLidEmail1OriginalDisplayName, 0 },
		{ PidLidEmail1EmailAddress, 0 },
		{ PidLidEmail2EmailAddress, 0 },
		{ PidLidEmail3EmailAddress, 0 },
		{ PidLidHtml, 0 },
		{ PidLidInstantMessagingAddress, 0 },
		{ PidLidHomeAddress, 0 },
		{ PidLidWorkAddress, 0 },
		{ PidLidEmail2OriginalDisplayName, 0 },
		{ PidLidEmail3OriginalDisplayName, 0 }
	};

	MapiCreateitemData *mcd = data;

	#define set_str_value(hex, val) G_STMT_START { \
		if (!exchange_mapi_utils_add_spropvalue (mem_ctx, values, n_values, hex, val ? val : "")) \
			return FALSE;	\
		} G_STMT_END

	#define set_str_named_value(named_id, val) G_STMT_START { \
		if (!exchange_mapi_utils_add_spropvalue_named_id (conn, fid, mem_ctx, values, n_values, named_id, val ? val : "")) \
			return FALSE;	\
		} G_STMT_END

	#define set_str_con_value(hex, field_id) G_STMT_START { \
		if (e_contact_get (mcd->contact, field_id)) { \
			set_str_value (hex, e_contact_get (mcd->contact, field_id)); \
		} } G_STMT_END

	#define set_str_named_con_value(named_id, field_id) G_STMT_START { \
		if (e_contact_get (mcd->contact, field_id)) { \
			set_str_named_value (named_id, e_contact_get (mcd->contact, field_id)); \
		} } G_STMT_END

	g_return_val_if_fail (mcd != NULL, FALSE);
	g_return_val_if_fail (mcd->contact != NULL, FALSE);
	g_return_val_if_fail (conn != NULL, FALSE);
	g_return_val_if_fail (mem_ctx != NULL, FALSE);
	g_return_val_if_fail (values != NULL, FALSE);
	g_return_val_if_fail (n_values != NULL, FALSE);

	if (!exchange_mapi_connection_resolve_named_props (conn, fid, nids, G_N_ELEMENTS (nids), NULL))
		return FALSE;

	if (GPOINTER_TO_INT (e_contact_get (mcd->contact, E_CONTACT_IS_LIST))) {
		EContact *old_contact;
		GList *local, *l;
		struct BinaryArray_r *members, *oneoff_members;
		uint32_t list_size = 0, u32, crc32 = 0;
		GHashTable *member_values = NULL, *member_ids = NULL;

		old_contact = e_contact_get_const (mcd->contact, E_CONTACT_UID) ? e_book_backend_cache_get_contact (mcd->cache, e_contact_get_const (mcd->contact, E_CONTACT_UID)) : NULL;
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

			g_object_unref (old_contact);
			g_list_foreach (local, (GFunc)e_vcard_attribute_free, NULL);
			g_list_free (local);
		}

		set_str_value (PR_MESSAGE_CLASS, IPM_DISTLIST);
		u32 = 0xFFFFFFFF;
		if (!exchange_mapi_utils_add_spropvalue_named_id (conn, fid, mem_ctx, values, n_values, PidLidFileUnderId, &u32))
			return FALSE;
		set_str_named_con_value (PidLidFileUnder, E_CONTACT_FILE_AS);
		set_str_named_con_value (PidLidDistributionListName, E_CONTACT_FILE_AS);
		set_str_con_value (PR_DISPLAY_NAME_UNICODE, E_CONTACT_FILE_AS);
		set_str_con_value (PR_NORMALIZED_SUBJECT_UNICODE, E_CONTACT_FILE_AS);

		local = e_contact_get_attributes (mcd->contact, E_CONTACT_EMAIL);
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

				camel_internet_address_get (addr, 0, &nm, &eml);
				if (eml) {
					/* keep both lists in sync */
					if (member_values && g_hash_table_lookup (member_values, raw)) {
						/* stored ListMembers values when contact's value didn't change */
						members->lpbin[members->cValues].cb = string_to_bin (mem_ctx, g_hash_table_lookup (member_values, raw), &members->lpbin[members->cValues].lpb);
						members->cValues++;
					} else {
						exchange_mapi_util_entryid_generate_oneoff (mem_ctx, &members->lpbin[members->cValues], nm ? nm : "", eml);
						members->cValues++;
					}

					exchange_mapi_util_entryid_generate_oneoff (mem_ctx, &oneoff_members->lpbin[oneoff_members->cValues], nm ? nm : "", eml);
					oneoff_members->cValues++;

					list_size += MAX (oneoff_members->lpbin[oneoff_members->cValues - 1].cb, members->lpbin[members->cValues - 1].cb);
					crc32 = exchange_mapi_utils_push_crc32 (crc32, members->lpbin[members->cValues - 1].lpb, members->lpbin[members->cValues - 1].cb);
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

		if (!exchange_mapi_utils_add_spropvalue_named_id (conn, fid, mem_ctx, values, n_values,
			PidLidDistributionListOneOffMembers, oneoff_members))
			return FALSE;

		if (!exchange_mapi_utils_add_spropvalue_named_id (conn, fid, mem_ctx, values, n_values,
			PidLidDistributionListMembers, members))
			return FALSE;

		if (!exchange_mapi_utils_add_spropvalue_named_id (conn, fid, mem_ctx, values, n_values,
			PidLidDistributionListChecksum, &crc32))
			return FALSE;

		/* list_size shouldn't exceed 15000 bytes, is so, use a stream instead of those properties above, but for now... */
		if (list_size > 15000)
			return FALSE;

		return TRUE;
	}

	set_str_value (PR_MESSAGE_CLASS, IPM_CONTACT);
	set_str_named_con_value (PidLidFileUnder, E_CONTACT_FILE_AS);

	set_str_con_value (PR_DISPLAY_NAME_UNICODE, E_CONTACT_FULL_NAME);
	set_str_con_value (PR_NORMALIZED_SUBJECT_UNICODE, E_CONTACT_FILE_AS);
	set_str_named_con_value (PidLidEmail1OriginalDisplayName, E_CONTACT_EMAIL_1);
	/*set_str_named_con_value (PidLidEmail1EmailAddress, E_CONTACT_EMAIL_1);*/

	/*set_str_con_value (0x8083001e, E_CONTACT_EMAIL_1);*/
	set_str_named_con_value (PidLidEmail2EmailAddress, E_CONTACT_EMAIL_2);

	set_str_named_con_value (PidLidEmail3EmailAddress, E_CONTACT_EMAIL_3);
	/*set_str_named_con_value (PidLidEmail3OriginalDisplayName, E_CONTACT_EMAIL_3);*/

	set_str_named_con_value (PidLidHtml, E_CONTACT_HOMEPAGE_URL);
	set_str_named_con_value (PidLidFreeBusyLocation, E_CONTACT_FREEBUSY_URL);

	set_str_con_value (PR_OFFICE_TELEPHONE_NUMBER_UNICODE, E_CONTACT_PHONE_BUSINESS);
	set_str_con_value (PR_HOME_TELEPHONE_NUMBER_UNICODE, E_CONTACT_PHONE_HOME);
	set_str_con_value (PR_MOBILE_TELEPHONE_NUMBER_UNICODE, E_CONTACT_PHONE_MOBILE);
	set_str_con_value (PR_HOME_FAX_NUMBER_UNICODE, E_CONTACT_PHONE_HOME_FAX);
	set_str_con_value (PR_BUSINESS_FAX_NUMBER_UNICODE, E_CONTACT_PHONE_BUSINESS_FAX);
	set_str_con_value (PR_PAGER_TELEPHONE_NUMBER_UNICODE, E_CONTACT_PHONE_PAGER);
	set_str_con_value (PR_ASSISTANT_TELEPHONE_NUMBER_UNICODE, E_CONTACT_PHONE_ASSISTANT);
	set_str_con_value (PR_COMPANY_MAIN_PHONE_NUMBER_UNICODE, E_CONTACT_PHONE_COMPANY);

	set_str_con_value (PR_MANAGER_NAME_UNICODE, E_CONTACT_MANAGER);
	set_str_con_value (PR_ASSISTANT_UNICODE, E_CONTACT_ASSISTANT);
	set_str_con_value (PR_COMPANY_NAME_UNICODE, E_CONTACT_ORG);
	set_str_con_value (PR_DEPARTMENT_NAME_UNICODE, E_CONTACT_ORG_UNIT);
	set_str_con_value (PR_PROFESSION_UNICODE, E_CONTACT_ROLE);
	set_str_con_value (PR_TITLE_UNICODE, E_CONTACT_TITLE);

	set_str_con_value (PR_OFFICE_LOCATION_UNICODE, E_CONTACT_OFFICE);
	set_str_con_value (PR_SPOUSE_NAME_UNICODE, E_CONTACT_SPOUSE);

	set_str_con_value (PR_BODY_UNICODE, E_CONTACT_NOTE);
	set_str_con_value (PR_NICKNAME_UNICODE, E_CONTACT_NICKNAME);

	/* BDAY AND ANNV */
	if (e_contact_get (mcd->contact, E_CONTACT_BIRTH_DATE)) {
		EContactDate *date = e_contact_get (mcd->contact, E_CONTACT_BIRTH_DATE);
		struct tm tmtime = { 0 };
		struct FILETIME t;

		tmtime.tm_mday = date->day;
		tmtime.tm_mon = date->month - 1;
		tmtime.tm_year = date->year - 1900;

		exchange_mapi_util_time_t_to_filetime (mktime (&tmtime) + (24 * 60 * 60), &t);

		if (!exchange_mapi_utils_add_spropvalue (mem_ctx, values, n_values, PR_BIRTHDAY, &t))
			return FALSE;
	}

	if (e_contact_get (mcd->contact, E_CONTACT_ANNIVERSARY)) {
		EContactDate *date = e_contact_get (mcd->contact, E_CONTACT_ANNIVERSARY);
		struct tm tmtime = { 0 };
		struct FILETIME t;

		tmtime.tm_mday = date->day;
		tmtime.tm_mon = date->month - 1;
		tmtime.tm_year = date->year - 1900;

		exchange_mapi_util_time_t_to_filetime (mktime (&tmtime) + (24 * 60 * 60), &t);

		if (!exchange_mapi_utils_add_spropvalue (mem_ctx, values, n_values, PR_WEDDING_ANNIVERSARY, &t))
			return FALSE;
	}

	/* Home and Office address */
	if (e_contact_get (mcd->contact, E_CONTACT_ADDRESS_HOME)) {
		EContactAddress *contact_addr = e_contact_get (mcd->contact, E_CONTACT_ADDRESS_HOME);

		set_str_named_value (PidLidHomeAddress, contact_addr->street);
		set_str_value (PR_HOME_ADDRESS_POST_OFFICE_BOX_UNICODE, contact_addr->ext);
		set_str_value (PR_HOME_ADDRESS_CITY_UNICODE, contact_addr->locality);
		set_str_value (PR_HOME_ADDRESS_STATE_OR_PROVINCE_UNICODE, contact_addr->region);
		set_str_value (PR_HOME_ADDRESS_POSTAL_CODE_UNICODE, contact_addr->code);
		set_str_value (PR_HOME_ADDRESS_COUNTRY_UNICODE, contact_addr->country);
	}

	if (e_contact_get (mcd->contact, E_CONTACT_ADDRESS_WORK)) {
		EContactAddress *contact_addr = e_contact_get (mcd->contact, E_CONTACT_ADDRESS_WORK);

		set_str_named_value (PidLidWorkAddress, contact_addr->street);
		set_str_value (PR_POST_OFFICE_BOX_UNICODE, contact_addr->ext);
		set_str_value (PR_LOCALITY_UNICODE, contact_addr->locality);
		set_str_value (PR_STATE_OR_PROVINCE_UNICODE, contact_addr->region);
		set_str_value (PR_POSTAL_CODE_UNICODE, contact_addr->code);
		set_str_value (PR_COUNTRY_UNICODE, contact_addr->country);
	}

	if (e_contact_get (mcd->contact, E_CONTACT_IM_AIM)) {
		GList *l = e_contact_get (mcd->contact, E_CONTACT_IM_AIM);
		set_str_named_value (PidLidInstantMessagingAddress, l->data);
	}

	return TRUE;
}

struct FetchContactItemData
{
	EBookBackendMAPI *ebma;
	EContact *contact; /* out */
};

static gboolean
fetch_contact_item_cb (FetchItemsCallbackData *item_data, gpointer data)
{
	struct FetchContactItemData *fcid = data;

	g_return_val_if_fail (data != NULL, FALSE);
	g_return_val_if_fail (fcid->ebma != NULL, FALSE);

	fcid->contact = mapi_book_utils_contact_from_props (item_data->conn, item_data->fid, e_book_backend_mapi_get_book_uri (fcid->ebma), item_data->properties, NULL);

	if (fcid->contact) {
		gchar *suid = exchange_mapi_util_mapi_ids_to_uid (item_data->fid, item_data->mid);

		/* UID of the contact is nothing but the concatenated string of hex id of folder and the message.*/
		e_contact_set (fcid->contact, E_CONTACT_UID, suid);

		if (!e_book_backend_mapi_notify_contact_update (fcid->ebma, NULL, fcid->contact, NULL, item_data->index, item_data->total, NULL)) {
			g_free (suid);
			return FALSE;
		}

		g_free (suid);
	}

	return TRUE;
}

struct CreateContactListData
{
	EBookBackendMAPI *ebma;
	GList **vCards;
};

static gboolean
create_contact_list_cb (FetchItemsCallbackData *item_data, gpointer data)
{
	struct CreateContactListData *ccld = data;
	EContact *contact;

	g_return_val_if_fail (data != NULL, FALSE);
	g_return_val_if_fail (ccld->ebma != NULL, FALSE);
	g_return_val_if_fail (ccld->vCards != NULL, FALSE);

	contact = mapi_book_utils_contact_from_props (item_data->conn, item_data->fid, e_book_backend_mapi_get_book_uri (ccld->ebma), item_data->properties, NULL);
	if (contact) {
		gchar *suid = exchange_mapi_util_mapi_ids_to_uid (item_data->fid, item_data->mid);

		e_contact_set (contact, E_CONTACT_UID, suid);

		*ccld->vCards = g_list_prepend (*ccld->vCards, e_vcard_to_string (E_VCARD (contact), EVC_FORMAT_VCARD_30));

		e_book_backend_mapi_notify_contact_update (ccld->ebma, NULL, contact, NULL, -1, -1, NULL);

		g_object_unref (contact);
		g_free (suid);
	}

	return TRUE;
}

struct FetchContactsData
{
	EBookBackendMAPI *ebma;
	EDataBookView *book_view;
	gpointer notify_contact_data;
};

static gboolean
fetch_contacts_cb (FetchItemsCallbackData *item_data, gpointer data)
{
	struct FetchContactsData *fcd = data;
	EContact *contact;

	g_return_val_if_fail (data != NULL, FALSE);
	g_return_val_if_fail (fcd->ebma != NULL, FALSE);
	g_return_val_if_fail (fcd->ebma->priv != NULL, FALSE);

	contact = mapi_book_utils_contact_from_props (item_data->conn, item_data->fid, e_book_backend_mapi_get_book_uri (fcd->ebma), item_data->properties, NULL);

	if (contact) {
		gchar *suid;
		struct timeval *last_modification = NULL, tv = { 0 };

		suid = exchange_mapi_util_mapi_ids_to_uid (item_data->fid, item_data->mid);
		e_contact_set (contact, E_CONTACT_UID, suid);
		g_free (suid);

		if (get_mapi_SPropValue_array_date_timeval (&tv, item_data->properties, PR_LAST_MODIFICATION_TIME) == MAPI_E_SUCCESS)
			last_modification = &tv;

		if (!e_book_backend_mapi_notify_contact_update (fcd->ebma, fcd->book_view, contact, last_modification, item_data->index, item_data->total, fcd->notify_contact_data)) {
			g_object_unref (contact);
			return FALSE;
		}

		g_object_unref (contact);
	}

	return TRUE;
}

struct FetchContactsUidsData
{
	GCancellable *cancelled;
	GHashTable *uids;
};

static gboolean
fetch_contacts_uids_cb (FetchItemsCallbackData *item_data, gpointer data)
{
	struct FetchContactsUidsData *fcud = data;
	gchar *suid;

	g_return_val_if_fail (data != NULL, FALSE);

	suid = exchange_mapi_util_mapi_ids_to_uid (item_data->fid, item_data->mid);
	if (suid)
		g_hash_table_insert (fcud->uids, suid, GINT_TO_POINTER (1));

	return !g_cancellable_is_cancelled (fcud->cancelled);
}

static void
ebbm_contacts_load_source (EBookBackendMAPI *ebma, ESource *source, gboolean only_if_exists, GError **perror)
{
	EBookBackendMAPIContactsPrivate *priv = ((EBookBackendMAPIContacts *) ebma)->priv;
	GError *err = NULL;

	if (e_book_backend_is_loaded (E_BOOK_BACKEND (ebma)))
		return /* Success */;

	priv->fid = 0;
	priv->is_public_folder = g_strcmp0 (e_source_get_property (source, "public"), "yes") == 0;

	exchange_mapi_util_mapi_id_from_string (e_source_get_property (source, "folder-id"), &priv->fid);

	/* Chain up to parent's op_load_source() method. */
	if (E_BOOK_BACKEND_MAPI_CLASS (e_book_backend_mapi_contacts_parent_class)->op_load_source)
		E_BOOK_BACKEND_MAPI_CLASS (e_book_backend_mapi_contacts_parent_class)->op_load_source (ebma, source, only_if_exists, &err);

	if (err)
		g_propagate_error (perror, err);
}

static void
ebbm_contacts_connection_status_changed (EBookBackendMAPI *ebma, gboolean is_online)
{
	e_book_backend_set_is_writable (E_BOOK_BACKEND (ebma), is_online);
	e_book_backend_notify_writable (E_BOOK_BACKEND (ebma), is_online);
}

static void
ebbm_contacts_remove (EBookBackendMAPI *ebma, GError **error)
{
	EBookBackendMAPIContactsPrivate *priv;
	GError *mapi_error = NULL;

	e_return_data_book_error_if_fail (ebma != NULL, E_DATA_BOOK_STATUS_INVALID_ARG);
	e_return_data_book_error_if_fail (E_IS_BOOK_BACKEND_MAPI_CONTACTS (ebma), E_DATA_BOOK_STATUS_INVALID_ARG);

	priv = E_BOOK_BACKEND_MAPI_CONTACTS (ebma)->priv;
	e_return_data_book_error_if_fail (priv != NULL, E_DATA_BOOK_STATUS_INVALID_ARG);

	if (E_BOOK_BACKEND_MAPI_CLASS (e_book_backend_mapi_contacts_parent_class)->op_remove)
		E_BOOK_BACKEND_MAPI_CLASS (e_book_backend_mapi_contacts_parent_class)->op_remove (ebma, &mapi_error);

	if (mapi_error) {
		mapi_error_to_edb_error (error, mapi_error, E_DATA_BOOK_STATUS_OTHER_ERROR, NULL);
		g_error_free (mapi_error);
		return;
	}

	if (!priv->is_public_folder) {
		ExchangeMapiConnection *conn;

		e_book_backend_mapi_lock_connection (ebma);

		conn = e_book_backend_mapi_get_connection (ebma);
		if (!conn) {
			g_propagate_error (error, EDB_ERROR (OFFLINE_UNAVAILABLE));
		} else {
			exchange_mapi_connection_remove_folder (conn, priv->fid, 0, &mapi_error);

			if (mapi_error) {
				mapi_error_to_edb_error (error, mapi_error, E_DATA_BOOK_STATUS_OTHER_ERROR, _("Failed to remove public folder"));
				g_error_free (mapi_error);
			}
		}

		e_book_backend_mapi_unlock_connection (ebma);
	}
}

static void
ebbm_contacts_create_contact (EBookBackendMAPI *ebma, const gchar *vcard, EContact **contact, GError **error)
{
	EBookBackendMAPIContacts *ebmac;
	EBookBackendMAPIContactsPrivate *priv;
	ExchangeMapiConnection *conn;
	MapiCreateitemData mcd;
	GError *mapi_error = NULL;
	mapi_id_t mid;
	gchar *id;

	e_return_data_book_error_if_fail (ebma != NULL, E_DATA_BOOK_STATUS_INVALID_ARG);
	e_return_data_book_error_if_fail (E_IS_BOOK_BACKEND_MAPI_CONTACTS (ebma), E_DATA_BOOK_STATUS_INVALID_ARG);
	e_return_data_book_error_if_fail (vcard != NULL, E_DATA_BOOK_STATUS_INVALID_ARG);
	e_return_data_book_error_if_fail (contact != NULL, E_DATA_BOOK_STATUS_INVALID_ARG);

	ebmac = E_BOOK_BACKEND_MAPI_CONTACTS (ebma);
	e_return_data_book_error_if_fail (ebmac != NULL, E_DATA_BOOK_STATUS_INVALID_ARG);

	priv = ebmac->priv;
	e_return_data_book_error_if_fail (priv != NULL, E_DATA_BOOK_STATUS_INVALID_ARG);

	e_book_backend_mapi_lock_connection (ebma);

	conn = e_book_backend_mapi_get_connection (ebma);
	if (!conn) {
		g_propagate_error (error, EDB_ERROR (REPOSITORY_OFFLINE));
		e_book_backend_mapi_unlock_connection (ebma);
		return;
	}

	*contact = e_contact_new_from_vcard (vcard);
	if (!*contact) {
		g_propagate_error (error, EDB_ERROR (REPOSITORY_OFFLINE));
		e_book_backend_mapi_unlock_connection (ebma);
		return;
	}

	e_book_backend_mapi_get_summary_and_cache (ebma, NULL, &mcd.cache);
	mcd.contact = *contact;

	mid = exchange_mapi_connection_create_item (conn, olFolderContacts, priv->fid,
		mapi_book_write_props, &mcd,
		NULL, NULL, NULL, MAPI_OPTIONS_DONT_SUBMIT | (priv->is_public_folder ? MAPI_OPTIONS_USE_PFSTORE : 0), &mapi_error);

	e_book_backend_mapi_unlock_connection (ebma);

	if (!mid) {
		mapi_error_to_edb_error (error, mapi_error, E_DATA_BOOK_STATUS_OTHER_ERROR, _("Failed to create item on a server"));

		if (mapi_error)
			g_error_free (mapi_error);

		g_object_unref (*contact);
		*contact = NULL;
		return;
	}

	id = exchange_mapi_util_mapi_ids_to_uid (priv->fid, mid);

	/* UID of the contact is nothing but the concatenated string of hex id of folder and the message.*/
	e_contact_set (*contact, E_CONTACT_UID, id);
	e_contact_set (*contact, E_CONTACT_BOOK_URI, e_book_backend_mapi_get_book_uri (ebma));

	g_free (id);
}

static void
ebbm_contacts_remove_contacts (EBookBackendMAPI *ebma, const GList *id_list, GList **removed_ids, GError **error)
{
	EBookBackendMAPIContacts *ebmac;
	EBookBackendMAPIContactsPrivate *priv;
	ExchangeMapiConnection *conn;
	GError *mapi_error = NULL;
	GSList *to_remove;
	const GList *l;

	e_return_data_book_error_if_fail (ebma != NULL, E_DATA_BOOK_STATUS_INVALID_ARG);
	e_return_data_book_error_if_fail (E_IS_BOOK_BACKEND_MAPI_CONTACTS (ebma), E_DATA_BOOK_STATUS_INVALID_ARG);
	e_return_data_book_error_if_fail (id_list != NULL, E_DATA_BOOK_STATUS_INVALID_ARG);
	e_return_data_book_error_if_fail (removed_ids != NULL, E_DATA_BOOK_STATUS_INVALID_ARG);

	ebmac = E_BOOK_BACKEND_MAPI_CONTACTS (ebma);
	e_return_data_book_error_if_fail (ebmac != NULL, E_DATA_BOOK_STATUS_INVALID_ARG);

	priv = ebmac->priv;
	e_return_data_book_error_if_fail (priv != NULL, E_DATA_BOOK_STATUS_INVALID_ARG);

	e_book_backend_mapi_lock_connection (ebma);

	conn = e_book_backend_mapi_get_connection (ebma);
	if (!conn) {
		g_propagate_error (error, EDB_ERROR (REPOSITORY_OFFLINE));
		e_book_backend_mapi_unlock_connection (ebma);
		return;
	}

	to_remove = NULL;
	for (l = id_list; l; l = l->next) {
		mapi_id_t mid, fid;
		const gchar *uid = l->data;
		struct id_list *idl = g_new0 (struct id_list, 1);

		exchange_mapi_util_mapi_ids_from_uid (uid, &fid, &mid);

		idl->id = mid;
		to_remove = g_slist_prepend (to_remove, idl);

		*removed_ids = g_list_prepend (*removed_ids, g_strdup (uid));
	}

	exchange_mapi_connection_remove_items (conn, olFolderContacts, priv->fid, priv->is_public_folder ? MAPI_OPTIONS_USE_PFSTORE : 0, to_remove, &mapi_error);

	e_book_backend_mapi_unlock_connection (ebma);

	if (mapi_error) {
		mapi_error_to_edb_error (error, mapi_error, E_DATA_BOOK_STATUS_OTHER_ERROR, NULL);

		g_error_free (mapi_error);

		g_list_foreach (*removed_ids, (GFunc) g_free, NULL);
		g_list_free (*removed_ids);
		*removed_ids = NULL;
	}

	g_slist_foreach (to_remove, (GFunc) g_free, NULL);
	g_slist_free (to_remove);
}

static void
ebbm_contacts_modify_contact (EBookBackendMAPI *ebma, const gchar *vcard, EContact **contact, GError **error)
{
	EBookBackendMAPIContacts *ebmac;
	EBookBackendMAPIContactsPrivate *priv;
	ExchangeMapiConnection *conn;
	MapiCreateitemData mcd;
	GError *mapi_error = NULL;
	mapi_id_t fid, mid;

	e_return_data_book_error_if_fail (ebma != NULL, E_DATA_BOOK_STATUS_INVALID_ARG);
	e_return_data_book_error_if_fail (E_IS_BOOK_BACKEND_MAPI_CONTACTS (ebma), E_DATA_BOOK_STATUS_INVALID_ARG);
	e_return_data_book_error_if_fail (vcard != NULL, E_DATA_BOOK_STATUS_INVALID_ARG);
	e_return_data_book_error_if_fail (contact != NULL, E_DATA_BOOK_STATUS_INVALID_ARG);

	ebmac = E_BOOK_BACKEND_MAPI_CONTACTS (ebma);
	e_return_data_book_error_if_fail (ebmac != NULL, E_DATA_BOOK_STATUS_INVALID_ARG);

	priv = ebmac->priv;
	e_return_data_book_error_if_fail (priv != NULL, E_DATA_BOOK_STATUS_INVALID_ARG);

	e_book_backend_mapi_lock_connection (ebma);

	conn = e_book_backend_mapi_get_connection (ebma);
	if (!conn) {
		g_propagate_error (error, EDB_ERROR (REPOSITORY_OFFLINE));
		e_book_backend_mapi_unlock_connection (ebma);
		return;
	}

	*contact = e_contact_new_from_vcard (vcard);
	if (!*contact) {
		g_propagate_error (error, EDB_ERROR (REPOSITORY_OFFLINE));
		e_book_backend_mapi_unlock_connection (ebma);
		return;
	}

	e_book_backend_mapi_get_summary_and_cache (ebma, NULL, &mcd.cache);
	mcd.contact = *contact;

	exchange_mapi_util_mapi_ids_from_uid (e_contact_get_const (*contact, E_CONTACT_UID), &fid, &mid);

	if (!exchange_mapi_connection_modify_item (conn, olFolderContacts, priv->fid, mid,
		mapi_book_write_props, &mcd, NULL, NULL, NULL, priv->is_public_folder ? MAPI_OPTIONS_USE_PFSTORE : 0, &mapi_error)) {

		mapi_error_to_edb_error (error, mapi_error, E_DATA_BOOK_STATUS_OTHER_ERROR, _("Failed to modify item on a server"));
		if (mapi_error)
			g_error_free (mapi_error);

		g_object_unref (*contact);
		*contact = NULL;
	}

	e_book_backend_mapi_unlock_connection (ebma);
}

static void
ebbm_contacts_get_contact (EBookBackendMAPI *ebma, const gchar *id, gchar **vcard, GError **error)
{
	EBookBackendMAPIContacts *ebmac;
	EBookBackendMAPIContactsPrivate *priv;
	ExchangeMapiConnection *conn;
	mapi_id_t fid, mid;
	guint32 options;
	struct FetchContactItemData fcid = { 0 };
	GError *mapi_error = NULL;

	e_return_data_book_error_if_fail (ebma != NULL, E_DATA_BOOK_STATUS_INVALID_ARG);
	e_return_data_book_error_if_fail (E_IS_BOOK_BACKEND_MAPI_CONTACTS (ebma), E_DATA_BOOK_STATUS_INVALID_ARG);
	e_return_data_book_error_if_fail (id != NULL, E_DATA_BOOK_STATUS_INVALID_ARG);
	e_return_data_book_error_if_fail (vcard != NULL, E_DATA_BOOK_STATUS_INVALID_ARG);

	ebmac = E_BOOK_BACKEND_MAPI_CONTACTS (ebma);
	e_return_data_book_error_if_fail (ebmac != NULL, E_DATA_BOOK_STATUS_INVALID_ARG);

	priv = ebmac->priv;
	e_return_data_book_error_if_fail (priv != NULL, E_DATA_BOOK_STATUS_INVALID_ARG);

	if (E_BOOK_BACKEND_MAPI_CLASS (e_book_backend_mapi_contacts_parent_class)->op_get_contact)
		E_BOOK_BACKEND_MAPI_CLASS (e_book_backend_mapi_contacts_parent_class)->op_get_contact (ebma, id, vcard, &mapi_error);

	if (mapi_error) {
		g_propagate_error (error, mapi_error);
		return;
	}

	/* found in a cache */
	if (*vcard)
		return;

	e_book_backend_mapi_lock_connection (ebma);

	conn = e_book_backend_mapi_get_connection (ebma);
	if (!conn) {
		g_propagate_error (error, EDB_ERROR (REPOSITORY_OFFLINE));
		e_book_backend_mapi_unlock_connection (ebma);
		return;
	}

	options = MAPI_OPTIONS_FETCH_ALL;
	if (priv->is_public_folder)
		options |= MAPI_OPTIONS_USE_PFSTORE;

	fcid.ebma = ebma;
	fcid.contact = NULL;
	exchange_mapi_util_mapi_ids_from_uid (id, &fid, &mid);

	exchange_mapi_connection_fetch_item (conn, priv->fid, mid,
		priv->is_public_folder ? NULL : mapi_book_utils_get_prop_list, GET_ALL_KNOWN_IDS,
		fetch_contact_item_cb, &fcid,
		options, &mapi_error);

	if (fcid.contact) {
		*vcard =  e_vcard_to_string (E_VCARD (fcid.contact), EVC_FORMAT_VCARD_30);
		g_object_unref (fcid.contact);
	} else {
		if (!mapi_error || mapi_error->code == MAPI_E_NOT_FOUND) {
			g_propagate_error (error, EDB_ERROR (CONTACT_NOT_FOUND));
		} else {
			mapi_error_to_edb_error (error, mapi_error, E_DATA_BOOK_STATUS_CONTACT_NOT_FOUND, NULL);
		}

		if (mapi_error)
			g_error_free (mapi_error);
	}

	e_book_backend_mapi_unlock_connection (ebma);
}

static void
ebbm_contacts_get_contact_list (EBookBackendMAPI *ebma, const gchar *query, GList **vCards, GError **error)
{
	EBookBackendMAPIContacts *ebmac;
	EBookBackendMAPIContactsPrivate *priv;
	ExchangeMapiConnection *conn;
	guint32 options;
	struct CreateContactListData ccld = { 0 };
	GError *mapi_error = NULL;
	struct mapi_SRestriction res;
	gboolean get_all;

	e_return_data_book_error_if_fail (ebma != NULL, E_DATA_BOOK_STATUS_INVALID_ARG);
	e_return_data_book_error_if_fail (E_IS_BOOK_BACKEND_MAPI_CONTACTS (ebma), E_DATA_BOOK_STATUS_INVALID_ARG);
	e_return_data_book_error_if_fail (query != NULL, E_DATA_BOOK_STATUS_INVALID_ARG);
	e_return_data_book_error_if_fail (vCards != NULL, E_DATA_BOOK_STATUS_INVALID_ARG);

	ebmac = E_BOOK_BACKEND_MAPI_CONTACTS (ebma);
	e_return_data_book_error_if_fail (ebmac != NULL, E_DATA_BOOK_STATUS_INVALID_ARG);

	priv = ebmac->priv;
	e_return_data_book_error_if_fail (priv != NULL, E_DATA_BOOK_STATUS_INVALID_ARG);

	if (E_BOOK_BACKEND_MAPI_CLASS (e_book_backend_mapi_contacts_parent_class)->op_get_contact_list)
		E_BOOK_BACKEND_MAPI_CLASS (e_book_backend_mapi_contacts_parent_class)->op_get_contact_list (ebma, query, vCards, &mapi_error);

	if (mapi_error) {
		g_propagate_error (error, mapi_error);
		return;
	}

	/* found some in cache, thus use them */
	if (*vCards)
		return;

	options = MAPI_OPTIONS_FETCH_ALL;
	if (priv->is_public_folder)
		options |= MAPI_OPTIONS_USE_PFSTORE;

	e_book_backend_mapi_lock_connection (ebma);

	conn = e_book_backend_mapi_get_connection (ebma);
	if (!conn) {
		e_book_backend_mapi_unlock_connection (ebma);
		g_propagate_error (error, EDB_ERROR (REPOSITORY_OFFLINE));

		return;
	}

	ccld.ebma = ebma;
	ccld.vCards = vCards;

	get_all = g_ascii_strcasecmp (query, "(contains \"x-evolution-any-field\" \"\")") == 0;
	if (!get_all && !build_restriction_emails_contains (&res, query)) {
		e_book_backend_mapi_unlock_connection (ebma);
		g_propagate_error (error, EDB_ERROR (OTHER_ERROR));

		return;
	}

	if (!exchange_mapi_connection_fetch_items (conn, priv->fid, get_all ? NULL : &res, NULL,
		priv->is_public_folder ? NULL : mapi_book_utils_get_prop_list, GET_ALL_KNOWN_IDS,
		create_contact_list_cb, &ccld, options, &mapi_error)) {
		mapi_error_to_edb_error (error, mapi_error, E_DATA_BOOK_STATUS_OTHER_ERROR, _("Failed to fetch items from a server"));
		if (mapi_error)
			g_error_free (mapi_error);
	}

	e_book_backend_mapi_unlock_connection (ebma);
}

static gchar *
ebbm_contacts_get_status_message (EBookBackendMAPI *ebma, gint index, gint total)
{
	if (index <= 0)
		return NULL;

	return g_strdup_printf (
		total <= 0 ?
			/* Translators : This is used to cache the downloaded contacts from a server.
			   %d is an index of the contact. */
			_("Caching contact %d") :
			/* Translators : This is used to cache the downloaded contacts from a server.
			   The first %d is an index of the contact,
			   the second %d is total count of conacts on the server. */
			_("Caching contact %d/%d"),
		index, total);
}

static void
ebbm_contacts_fetch_contacts (EBookBackendMAPI *ebma, struct mapi_SRestriction *restriction, EDataBookView *book_view, gpointer notify_contact_data, GError **error)
{
	EBookBackendMAPIContacts *ebmac;
	EBookBackendMAPIContactsPrivate *priv;
	ExchangeMapiConnection *conn;
	guint32 options;
	struct FetchContactsData fcd = { 0 };
	GError *mapi_error = NULL;

	e_return_data_book_error_if_fail (ebma != NULL, E_DATA_BOOK_STATUS_INVALID_ARG);
	e_return_data_book_error_if_fail (E_IS_BOOK_BACKEND_MAPI_CONTACTS (ebma), E_DATA_BOOK_STATUS_INVALID_ARG);

	ebmac = E_BOOK_BACKEND_MAPI_CONTACTS (ebma);
	e_return_data_book_error_if_fail (ebmac != NULL, E_DATA_BOOK_STATUS_INVALID_ARG);

	priv = ebmac->priv;
	e_return_data_book_error_if_fail (priv != NULL, E_DATA_BOOK_STATUS_INVALID_ARG);

	e_book_backend_mapi_lock_connection (ebma);

	conn = e_book_backend_mapi_get_connection (ebma);
	if (!conn) {
		e_book_backend_mapi_unlock_connection (ebma);
		g_propagate_error (error, EDB_ERROR (REPOSITORY_OFFLINE));

		return;
	}

	fcd.ebma = ebma;
	fcd.book_view = book_view;
	fcd.notify_contact_data = notify_contact_data;

	options = MAPI_OPTIONS_FETCH_ALL;
	if (priv->is_public_folder)
		options |= MAPI_OPTIONS_USE_PFSTORE;

	if (!exchange_mapi_connection_fetch_items (conn, priv->fid, restriction, NULL,
		mapi_book_utils_get_prop_list, GET_ALL_KNOWN_IDS,
		fetch_contacts_cb, &fcd, options, &mapi_error)) {
		mapi_error_to_edb_error (error, mapi_error, E_DATA_BOOK_STATUS_OTHER_ERROR, _("Failed to fetch items from a server"));

		if (mapi_error)
			g_error_free (mapi_error);
	}

	e_book_backend_mapi_unlock_connection (ebma);
}

static void
ebbm_contacts_fetch_known_uids (EBookBackendMAPI *ebma, GCancellable *cancelled, GHashTable *uids, GError **error)
{
	EBookBackendMAPIContacts *ebmac;
	EBookBackendMAPIContactsPrivate *priv;
	ExchangeMapiConnection *conn;
	GError *mapi_error = NULL;
	struct FetchContactsUidsData fcud = { 0 };
	guint32 options;

	e_return_data_book_error_if_fail (ebma != NULL, E_DATA_BOOK_STATUS_INVALID_ARG);
	e_return_data_book_error_if_fail (E_IS_BOOK_BACKEND_MAPI_CONTACTS (ebma), E_DATA_BOOK_STATUS_INVALID_ARG);
	e_return_data_book_error_if_fail (cancelled != NULL, E_DATA_BOOK_STATUS_INVALID_ARG);
	e_return_data_book_error_if_fail (uids != NULL, E_DATA_BOOK_STATUS_INVALID_ARG);

	ebmac = E_BOOK_BACKEND_MAPI_CONTACTS (ebma);
	e_return_data_book_error_if_fail (ebmac != NULL, E_DATA_BOOK_STATUS_INVALID_ARG);
	e_return_data_book_error_if_fail (ebmac->priv != NULL, E_DATA_BOOK_STATUS_INVALID_ARG);

	priv = ebmac->priv;

	e_book_backend_mapi_lock_connection (ebma);

	conn = e_book_backend_mapi_get_connection (ebma);
	if (!conn) {
		e_book_backend_mapi_unlock_connection (ebma);
		g_propagate_error (error, EDB_ERROR (REPOSITORY_OFFLINE));
		return;
	}

	options = MAPI_OPTIONS_DONT_OPEN_MESSAGE;
	if (priv->is_public_folder)
		options |= MAPI_OPTIONS_USE_PFSTORE;

	fcud.cancelled = cancelled;
	fcud.uids = uids;

	exchange_mapi_connection_fetch_items (conn, priv->fid, NULL, NULL,
		mapi_book_utils_get_prop_list, GET_UIDS_ONLY,
		fetch_contacts_uids_cb, &fcud, options, &mapi_error);

	if (mapi_error) {
		mapi_error_to_edb_error (error, mapi_error, E_DATA_BOOK_STATUS_OTHER_ERROR, _("Failed to fetch items from a server"));
		g_error_free (mapi_error);
	}

	e_book_backend_mapi_unlock_connection (ebma);
}

static void
e_book_backend_mapi_contacts_init (EBookBackendMAPIContacts *backend)
{
	backend->priv = G_TYPE_INSTANCE_GET_PRIVATE (backend, E_TYPE_BOOK_BACKEND_MAPI_CONTACTS, EBookBackendMAPIContactsPrivate);
}

static void
e_book_backend_mapi_contacts_class_init (EBookBackendMAPIContactsClass *klass)
{
	EBookBackendMAPIClass *parent_class;

	g_type_class_add_private (klass, sizeof (EBookBackendMAPIContactsPrivate));

	parent_class = E_BOOK_BACKEND_MAPI_CLASS (klass);

	/* Set the virtual methods. */
	parent_class->op_load_source			= ebbm_contacts_load_source;
	parent_class->op_remove				= ebbm_contacts_remove;
	parent_class->op_create_contact			= ebbm_contacts_create_contact;
	parent_class->op_remove_contacts		= ebbm_contacts_remove_contacts;
	parent_class->op_modify_contact			= ebbm_contacts_modify_contact;
	parent_class->op_get_contact			= ebbm_contacts_get_contact;
	parent_class->op_get_contact_list		= ebbm_contacts_get_contact_list;

	parent_class->op_connection_status_changed	= ebbm_contacts_connection_status_changed;
	parent_class->op_get_status_message		= ebbm_contacts_get_status_message;
	parent_class->op_fetch_contacts			= ebbm_contacts_fetch_contacts;
	parent_class->op_fetch_known_uids		= ebbm_contacts_fetch_known_uids;
}

EBookBackend *
e_book_backend_mapi_contacts_new (void)
{
	return g_object_new (E_TYPE_BOOK_BACKEND_MAPI_CONTACTS, NULL);
}
