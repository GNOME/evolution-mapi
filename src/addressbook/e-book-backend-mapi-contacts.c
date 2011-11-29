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

#include "e-book-backend-mapi-contacts.h"

G_DEFINE_TYPE (EBookBackendMAPIContacts, e_book_backend_mapi_contacts, E_TYPE_BOOK_BACKEND_MAPI)

struct _EBookBackendMAPIContactsPrivate
{
	mapi_id_t fid;
	gboolean is_public_folder;
};

static gboolean
build_restriction_from_sexp_query (EMapiConnection *conn,
				   mapi_id_t fid,
				   TALLOC_CTX *mem_ctx,
				   struct mapi_SRestriction **restrictions,
				   gpointer user_data,
				   GCancellable *cancellable,
				   GError **perror)
{
	const gchar *sexp_query = user_data;

	g_return_val_if_fail (sexp_query != NULL, FALSE);

	*restrictions = mapi_book_utils_sexp_to_restriction (mem_ctx, sexp_query);

	return TRUE;
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

typedef struct {
	EContact *contact;
	EBookBackendSqliteDB *db;
} MapiCreateitemData;

static gboolean
mapi_book_write_props (EMapiConnection *conn,
		       mapi_id_t fid,
		       TALLOC_CTX *mem_ctx,
		       struct SPropValue **values,
		       uint32_t *n_values,
		       gpointer data,
		       GCancellable *cancellable,
		       GError **perror)
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
		if (!e_mapi_utils_add_spropvalue (mem_ctx, values, n_values, hex, val ? val : "")) \
			return FALSE;	\
		} G_STMT_END

	#define set_str_named_value(named_id, val) G_STMT_START { \
		if (!e_mapi_utils_add_spropvalue_namedid (conn, fid, mem_ctx, values, n_values, named_id, val ? val : "", cancellable, perror)) \
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
	g_return_val_if_fail (mcd->db != NULL, FALSE);
	g_return_val_if_fail (conn != NULL, FALSE);
	g_return_val_if_fail (mem_ctx != NULL, FALSE);
	g_return_val_if_fail (values != NULL, FALSE);
	g_return_val_if_fail (n_values != NULL, FALSE);

	if (!e_mapi_connection_resolve_named_props (conn, fid, nids, G_N_ELEMENTS (nids), cancellable, perror))
		return FALSE;

	if (GPOINTER_TO_INT (e_contact_get (mcd->contact, E_CONTACT_IS_LIST))) {
		const gchar *uid = NULL;
		EContact *old_contact = NULL;
		GList *local, *l;
		struct BinaryArray_r *members, *oneoff_members;
		uint32_t list_size = 0, u32, crc32 = 0;
		GHashTable *member_values = NULL, *member_ids = NULL;
		GError *error = NULL;

		uid = e_contact_get_const (mcd->contact, E_CONTACT_UID);
		if (uid)
			old_contact = e_book_backend_sqlitedb_get_contact (mcd->db, EMA_EBB_CACHE_FOLDERID, uid, NULL, NULL, &error);

		if (!error && old_contact) {
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

		if (error)
			g_error_free (error);

		set_str_value (PR_MESSAGE_CLASS, IPM_DISTLIST);
		u32 = 0xFFFFFFFF;
		if (!e_mapi_utils_add_spropvalue_namedid (conn, fid, mem_ctx, values, n_values, PidLidFileUnderId, &u32, cancellable, perror))
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
						e_mapi_util_recip_entryid_generate_smtp (mem_ctx, &members->lpbin[members->cValues], nm ? nm : "", eml);
						members->cValues++;
					}

					e_mapi_util_recip_entryid_generate_smtp (mem_ctx, &oneoff_members->lpbin[oneoff_members->cValues], nm ? nm : "", eml);
					oneoff_members->cValues++;

					list_size += MAX (oneoff_members->lpbin[oneoff_members->cValues - 1].cb, members->lpbin[members->cValues - 1].cb);
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

		if (!e_mapi_utils_add_spropvalue_namedid (conn, fid, mem_ctx, values, n_values,
			PidLidDistributionListOneOffMembers, oneoff_members, cancellable, perror))
			return FALSE;

		if (!e_mapi_utils_add_spropvalue_namedid (conn, fid, mem_ctx, values, n_values,
			PidLidDistributionListMembers, members, cancellable, perror))
			return FALSE;

		if (!e_mapi_utils_add_spropvalue_namedid (conn, fid, mem_ctx, values, n_values,
			PidLidDistributionListChecksum, &crc32, cancellable, perror))
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

		e_mapi_util_time_t_to_filetime (mktime (&tmtime) + (24 * 60 * 60), &t);

		if (!e_mapi_utils_add_spropvalue (mem_ctx, values, n_values, PR_BIRTHDAY, &t))
			return FALSE;
	}

	if (e_contact_get (mcd->contact, E_CONTACT_ANNIVERSARY)) {
		EContactDate *date = e_contact_get (mcd->contact, E_CONTACT_ANNIVERSARY);
		struct tm tmtime = { 0 };
		struct FILETIME t;

		tmtime.tm_mday = date->day;
		tmtime.tm_mon = date->month - 1;
		tmtime.tm_year = date->year - 1900;

		e_mapi_util_time_t_to_filetime (mktime (&tmtime) + (24 * 60 * 60), &t);

		if (!e_mapi_utils_add_spropvalue (mem_ctx, values, n_values, PR_WEDDING_ANNIVERSARY, &t))
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
transfer_contact_cb (EMapiConnection *conn,
		     TALLOC_CTX *mem_ctx,
		     /* const */ EMapiObject *object,
		     guint32 obj_index,
		     guint32 obj_total,
		     gpointer user_data,
		     GCancellable *cancellable,
		     GError **perror)
{
	struct FetchContactItemData *fcid = user_data;

	g_return_val_if_fail (fcid != NULL, FALSE);
	g_return_val_if_fail (fcid->ebma != NULL, FALSE);
	g_return_val_if_fail (object != NULL, FALSE);

	fcid->contact = mapi_book_utils_contact_from_props (conn, E_BOOK_BACKEND_MAPI_CONTACTS (fcid->ebma)->priv->fid, e_book_backend_mapi_get_book_uri (fcid->ebma), &object->properties, NULL);

	if (fcid->contact) {
		const mapi_id_t *pmid;

		pmid = e_mapi_util_find_array_propval (&object->properties, PidTagMid);
		if (pmid) {
			gchar *suid = e_mapi_util_mapi_id_to_string (*pmid);

			/* UID of the contact is nothing but the concatenated string of hex id of folder and the message.*/
			e_contact_set (fcid->contact, E_CONTACT_UID, suid);

			if (!e_book_backend_mapi_notify_contact_update (fcid->ebma, NULL, fcid->contact, obj_index, obj_total, NULL)) {
				g_free (suid);
				return FALSE;
			}

			g_free (suid);
		} else {
			g_debug ("%s: No PidTagMid found", G_STRFUNC);
		}
	}

	return TRUE;
}

static gboolean
gather_contact_mids_cb (EMapiConnection *conn,
			mapi_id_t fid,
			TALLOC_CTX *mem_ctx,
			const ListObjectsData *object_data,
			guint32 obj_index,
			guint32 obj_total,
			gpointer user_data,
			GCancellable *cancellable,
			GError **perror)
{
	GSList *pmids = user_data;
	mapi_id_t *pmid;

	g_return_val_if_fail (object_data != NULL, FALSE);
	g_return_val_if_fail (pmids != NULL, FALSE);

	pmid = g_new0 (mapi_id_t, 1);
	*pmid = object_data->mid;

	pmids = g_slist_prepend (pmids, pmid);

	return TRUE;
}

struct TransferContactsData
{
	EBookBackendMAPI *ebma;
	EDataBookView *book_view;
	gpointer notify_contact_data;
	GSList **cards;
};

static gboolean
transfer_contacts_cb (EMapiConnection *conn,
		      TALLOC_CTX *mem_ctx,
		      /* const */ EMapiObject *object,
		      guint32 obj_index,
		      guint32 obj_total,
		      gpointer user_data,
		      GCancellable *cancellable,
		      GError **perror)
{
	struct TransferContactsData *tcd = user_data;
	EContact *contact;

	g_return_val_if_fail (tcd != NULL, FALSE);
	g_return_val_if_fail (object != NULL, FALSE);
	g_return_val_if_fail (tcd->ebma != NULL, FALSE);

	contact = mapi_book_utils_contact_from_props (conn, E_BOOK_BACKEND_MAPI_CONTACTS (tcd->ebma)->priv->fid, e_book_backend_mapi_get_book_uri (tcd->ebma), &object->properties, NULL);
	if (contact) {
		const mapi_id_t *pmid;

		pmid = e_mapi_util_find_array_propval (&object->properties, PidTagMid);
		if (pmid) {
			gchar *suid = e_mapi_util_mapi_id_to_string (*pmid);

			e_contact_set (contact, E_CONTACT_UID, suid);
			g_free (suid);

			if (tcd->cards)
				*tcd->cards = g_slist_prepend (*tcd->cards, e_vcard_to_string (E_VCARD (contact), EVC_FORMAT_VCARD_30));

			if (!e_book_backend_mapi_notify_contact_update (tcd->ebma, tcd->book_view, contact, obj_index, obj_total, tcd->notify_contact_data)) {
				g_object_unref (contact);
				return FALSE;
			}

			g_object_unref (contact);
		} else {
			g_debug ("%s: No PidTagMid found", G_STRFUNC);
		}
	} else {
		g_debug ("%s: [%d/%d] Failed to transform to contact", G_STRFUNC, obj_index, obj_total);
	}

	return TRUE;
}

static gboolean
gather_known_uids_cb (EMapiConnection *conn,
		      mapi_id_t fid,
		      TALLOC_CTX *mem_ctx,
		      const ListObjectsData *object_data,
		      guint32 obj_index,
		      guint32 obj_total,
		      gpointer user_data,
		      GCancellable *cancellable,
		      GError **perror)
{
	struct ListKnownUidsData *lku = user_data;
	gchar *suid;

	g_return_val_if_fail (lku != NULL, FALSE);
	g_return_val_if_fail (lku->uid_to_rev != NULL, FALSE);

	suid = e_mapi_util_mapi_id_to_string (object_data->mid);
	if (suid) {
		g_hash_table_insert (lku->uid_to_rev, suid, mapi_book_utils_timet_to_string (object_data->last_modified));
		if (lku->latest_last_modify < object_data->last_modified)
			lku->latest_last_modify = object_data->last_modified;
	}

	return TRUE;
}

static void
ebbm_contacts_open (EBookBackendMAPI *ebma, GCancellable *cancellable, gboolean only_if_exists, GError **perror)
{
	ESource *source = e_backend_get_source (E_BACKEND (ebma));
	EBookBackendMAPIContactsPrivate *priv = ((EBookBackendMAPIContacts *) ebma)->priv;
	GError *err = NULL;

	if (e_book_backend_is_opened (E_BOOK_BACKEND (ebma))) {
		if (E_BOOK_BACKEND_MAPI_CLASS (e_book_backend_mapi_contacts_parent_class)->op_open)
			E_BOOK_BACKEND_MAPI_CLASS (e_book_backend_mapi_contacts_parent_class)->op_open (ebma, cancellable, only_if_exists, perror);
		return;
	}

	priv->fid = 0;
	priv->is_public_folder = g_strcmp0 (e_source_get_property (source, "public"), "yes") == 0;

	e_mapi_util_mapi_id_from_string (e_source_get_property (source, "folder-id"), &priv->fid);

	/* Chain up to parent's op_load_source() method. */
	if (E_BOOK_BACKEND_MAPI_CLASS (e_book_backend_mapi_contacts_parent_class)->op_open)
		E_BOOK_BACKEND_MAPI_CLASS (e_book_backend_mapi_contacts_parent_class)->op_open (ebma, cancellable, only_if_exists, &err);

	if (err)
		g_propagate_error (perror, err);
}

static void
ebbm_contacts_connection_status_changed (EBookBackendMAPI *ebma, gboolean is_online)
{
	e_book_backend_notify_readonly (E_BOOK_BACKEND (ebma), !is_online);
}

static void
ebbm_contacts_remove (EBookBackendMAPI *ebma, GCancellable *cancellable, GError **error)
{
	EBookBackendMAPIContactsPrivate *priv;
	GError *mapi_error = NULL;

	e_return_data_book_error_if_fail (ebma != NULL, E_DATA_BOOK_STATUS_INVALID_ARG);
	e_return_data_book_error_if_fail (E_IS_BOOK_BACKEND_MAPI_CONTACTS (ebma), E_DATA_BOOK_STATUS_INVALID_ARG);

	priv = E_BOOK_BACKEND_MAPI_CONTACTS (ebma)->priv;
	e_return_data_book_error_if_fail (priv != NULL, E_DATA_BOOK_STATUS_INVALID_ARG);

	if (E_BOOK_BACKEND_MAPI_CLASS (e_book_backend_mapi_contacts_parent_class)->op_remove)
		E_BOOK_BACKEND_MAPI_CLASS (e_book_backend_mapi_contacts_parent_class)->op_remove (ebma, cancellable, &mapi_error);

	if (mapi_error) {
		mapi_error_to_edb_error (error, mapi_error, E_DATA_BOOK_STATUS_OTHER_ERROR, NULL);
		g_error_free (mapi_error);
		return;
	}

	if (!priv->is_public_folder) {
		EMapiConnection *conn;

		e_book_backend_mapi_lock_connection (ebma);

		conn = e_book_backend_mapi_get_connection (ebma);
		if (!conn) {
			g_propagate_error (error, EDB_ERROR (OFFLINE_UNAVAILABLE));
		} else {
			e_mapi_connection_remove_folder (conn, priv->fid, 0, cancellable, &mapi_error);

			if (mapi_error) {
				mapi_error_to_edb_error (error, mapi_error, E_DATA_BOOK_STATUS_OTHER_ERROR, _("Failed to remove public folder"));
				g_error_free (mapi_error);
			}
		}

		e_book_backend_mapi_unlock_connection (ebma);
	}
}

static void
ebbm_contacts_create_contacts (EBookBackendMAPI *ebma, GCancellable *cancellable, const GSList *vcards, GSList **added_contacts, GError **error)
{
	EBookBackendMAPIContacts *ebmac;
	EBookBackendMAPIContactsPrivate *priv;
	EMapiConnection *conn;
	MapiCreateitemData mcd;
	GError *mapi_error = NULL;
	mapi_id_t mid;
	gchar *id;
	EContact *contact;

	e_return_data_book_error_if_fail (ebma != NULL, E_DATA_BOOK_STATUS_INVALID_ARG);
	e_return_data_book_error_if_fail (E_IS_BOOK_BACKEND_MAPI_CONTACTS (ebma), E_DATA_BOOK_STATUS_INVALID_ARG);
	e_return_data_book_error_if_fail (vcards != NULL, E_DATA_BOOK_STATUS_INVALID_ARG);
	e_return_data_book_error_if_fail (added_contacts != NULL, E_DATA_BOOK_STATUS_INVALID_ARG);

	ebmac = E_BOOK_BACKEND_MAPI_CONTACTS (ebma);
	e_return_data_book_error_if_fail (ebmac != NULL, E_DATA_BOOK_STATUS_INVALID_ARG);

	priv = ebmac->priv;
	e_return_data_book_error_if_fail (priv != NULL, E_DATA_BOOK_STATUS_INVALID_ARG);

	if (vcards->next) {
		g_propagate_error (error, EDB_ERROR_EX (NOT_SUPPORTED, _("The backend does not support bulk additions")));
		return;
	}

	e_book_backend_mapi_lock_connection (ebma);

	conn = e_book_backend_mapi_get_connection (ebma);
	if (!conn) {
		g_propagate_error (error, EDB_ERROR (REPOSITORY_OFFLINE));
		e_book_backend_mapi_unlock_connection (ebma);
		return;
	}

	contact = e_contact_new_from_vcard (vcards->data);
	if (!contact) {
		g_propagate_error (error, EDB_ERROR (REPOSITORY_OFFLINE));
		e_book_backend_mapi_unlock_connection (ebma);
		return;
	}

	e_book_backend_mapi_get_db (ebma, &mcd.db);
	mcd.contact = contact;

	mid = e_mapi_connection_create_item (conn, olFolderContacts, priv->fid,
		mapi_book_write_props, &mcd,
		NULL, NULL, NULL, MAPI_OPTIONS_DONT_SUBMIT | (priv->is_public_folder ? MAPI_OPTIONS_USE_PFSTORE : 0), cancellable, &mapi_error);

	e_book_backend_mapi_unlock_connection (ebma);

	if (!mid) {
		mapi_error_to_edb_error (error, mapi_error, E_DATA_BOOK_STATUS_OTHER_ERROR, _("Failed to create item on a server"));

		if (mapi_error)
			g_error_free (mapi_error);

		g_object_unref (contact);
		return;
	}

	id = e_mapi_util_mapi_id_to_string (mid);

	/* UID of the contact is nothing but the concatenated string of hex id of folder and the message.*/
	e_contact_set (contact, E_CONTACT_UID, id);
	e_contact_set (contact, E_CONTACT_BOOK_URI, e_book_backend_mapi_get_book_uri (ebma));

	g_free (id);

	*added_contacts = g_slist_append (NULL, contact);
}

static void
ebbm_contacts_remove_contacts (EBookBackendMAPI *ebma, GCancellable *cancellable, const GSList *id_list, GSList **removed_ids, GError **error)
{
	EBookBackendMAPIContacts *ebmac;
	EBookBackendMAPIContactsPrivate *priv;
	EMapiConnection *conn;
	GError *mapi_error = NULL;
	GSList *to_remove;
	const GSList *l;

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
		mapi_id_t mid;
		const gchar *uid = l->data;
		struct id_list *idl = g_new0 (struct id_list, 1);

		if (e_mapi_util_mapi_id_from_string (uid, &mid)) {
			idl->id = mid;
			to_remove = g_slist_prepend (to_remove, idl);

			*removed_ids = g_slist_prepend (*removed_ids, g_strdup (uid));
		} else {
			g_debug ("%s: Failed to decode MID from '%s'", G_STRFUNC, uid);
		}
	}

	e_mapi_connection_remove_items (conn, olFolderContacts, priv->fid, priv->is_public_folder ? MAPI_OPTIONS_USE_PFSTORE : 0, to_remove, cancellable, &mapi_error);

	e_book_backend_mapi_unlock_connection (ebma);

	if (mapi_error) {
		mapi_error_to_edb_error (error, mapi_error, E_DATA_BOOK_STATUS_OTHER_ERROR, NULL);

		g_error_free (mapi_error);

		g_slist_foreach (*removed_ids, (GFunc) g_free, NULL);
		g_slist_free (*removed_ids);
		*removed_ids = NULL;
	}

	g_slist_foreach (to_remove, (GFunc) g_free, NULL);
	g_slist_free (to_remove);
}

static void
ebbm_contacts_modify_contacts (EBookBackendMAPI *ebma, GCancellable *cancellable, const GSList *vcards, GSList **modified_contacts, GError **error)
{
	EBookBackendMAPIContacts *ebmac;
	EBookBackendMAPIContactsPrivate *priv;
	EMapiConnection *conn;
	MapiCreateitemData mcd;
	EContact *contact;
	GError *mapi_error = NULL;
	mapi_id_t mid;

	e_return_data_book_error_if_fail (ebma != NULL, E_DATA_BOOK_STATUS_INVALID_ARG);
	e_return_data_book_error_if_fail (E_IS_BOOK_BACKEND_MAPI_CONTACTS (ebma), E_DATA_BOOK_STATUS_INVALID_ARG);
	e_return_data_book_error_if_fail (vcards != NULL, E_DATA_BOOK_STATUS_INVALID_ARG);
	e_return_data_book_error_if_fail (modified_contacts != NULL, E_DATA_BOOK_STATUS_INVALID_ARG);

	ebmac = E_BOOK_BACKEND_MAPI_CONTACTS (ebma);
	e_return_data_book_error_if_fail (ebmac != NULL, E_DATA_BOOK_STATUS_INVALID_ARG);

	priv = ebmac->priv;
	e_return_data_book_error_if_fail (priv != NULL, E_DATA_BOOK_STATUS_INVALID_ARG);

	if (vcards->next != NULL) {
		g_propagate_error (error, EDB_ERROR_EX (NOT_SUPPORTED, _("The backend does not support bulk modifications")));
		return;
	}

	e_book_backend_mapi_lock_connection (ebma);

	conn = e_book_backend_mapi_get_connection (ebma);
	if (!conn) {
		g_propagate_error (error, EDB_ERROR (REPOSITORY_OFFLINE));
		e_book_backend_mapi_unlock_connection (ebma);
		return;
	}

	contact = e_contact_new_from_vcard (vcards->data);
	if (!contact) {
		g_propagate_error (error, EDB_ERROR (REPOSITORY_OFFLINE));
		e_book_backend_mapi_unlock_connection (ebma);
		return;
	}

	e_book_backend_mapi_get_db (ebma, &mcd.db);
	mcd.contact = contact;

	if (e_mapi_util_mapi_id_from_string (e_contact_get_const (contact, E_CONTACT_UID), &mid)) {
		if (!e_mapi_connection_modify_item (conn, olFolderContacts, priv->fid, mid,
			mapi_book_write_props, &mcd, NULL, NULL, NULL, priv->is_public_folder ? MAPI_OPTIONS_USE_PFSTORE : 0, cancellable, &mapi_error)) {

			mapi_error_to_edb_error (error, mapi_error, E_DATA_BOOK_STATUS_OTHER_ERROR, _("Failed to modify item on a server"));
			if (mapi_error)
				g_error_free (mapi_error);

			g_object_unref (contact);
		} else {
			*modified_contacts = g_slist_append (NULL, contact);
		}
	} else {
		g_debug ("%s: Failed to decode MID from '%s'", G_STRFUNC, (const gchar *) e_contact_get_const (contact, E_CONTACT_UID));
	}

	e_book_backend_mapi_unlock_connection (ebma);
}

static void
ebbm_contacts_get_contact (EBookBackendMAPI *ebma, GCancellable *cancellable, const gchar *id, gchar **vcard, GError **error)
{
	EBookBackendMAPIContacts *ebmac;
	EBookBackendMAPIContactsPrivate *priv;
	EMapiConnection *conn;
	mapi_id_t mid;
	mapi_object_t obj_folder;
	struct FetchContactItemData fcid = { 0 };
	gboolean status;
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
		E_BOOK_BACKEND_MAPI_CLASS (e_book_backend_mapi_contacts_parent_class)->op_get_contact (ebma, cancellable, id, vcard, &mapi_error);

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

	if (priv->is_public_folder)
		status = e_mapi_connection_open_public_folder (conn, priv->fid, &obj_folder, cancellable, &mapi_error);
	else
		status = e_mapi_connection_open_personal_folder (conn, priv->fid, &obj_folder, cancellable, &mapi_error);

	if (status) {
		status = e_mapi_util_mapi_id_from_string (id, &mid);
		if (!status) {
			g_debug ("%s: Failed to decode MID from '%s'", G_STRFUNC, id);
		}
	}

	if (status) {
		fcid.ebma = ebma;
		fcid.contact = NULL;

		e_mapi_connection_transfer_object (conn, &obj_folder, mid, transfer_contact_cb, &fcid, cancellable, &mapi_error);
	}

	e_mapi_connection_close_folder (conn, &obj_folder, cancellable, &mapi_error);

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
ebbm_contacts_get_contact_list (EBookBackendMAPI *ebma, GCancellable *cancellable, const gchar *query, GSList **vCards, GError **error)
{
	EBookBackendMAPIContacts *ebmac;
	EBookBackendMAPIContactsPrivate *priv;
	EMapiConnection *conn;
	GError *mapi_error = NULL;
	gboolean status;
	mapi_object_t obj_folder;
	GSList *mids = NULL;
	struct TransferContactsData tcd = { 0 };

	e_return_data_book_error_if_fail (ebma != NULL, E_DATA_BOOK_STATUS_INVALID_ARG);
	e_return_data_book_error_if_fail (E_IS_BOOK_BACKEND_MAPI_CONTACTS (ebma), E_DATA_BOOK_STATUS_INVALID_ARG);
	e_return_data_book_error_if_fail (query != NULL, E_DATA_BOOK_STATUS_INVALID_ARG);
	e_return_data_book_error_if_fail (vCards != NULL, E_DATA_BOOK_STATUS_INVALID_ARG);

	ebmac = E_BOOK_BACKEND_MAPI_CONTACTS (ebma);
	e_return_data_book_error_if_fail (ebmac != NULL, E_DATA_BOOK_STATUS_INVALID_ARG);

	priv = ebmac->priv;
	e_return_data_book_error_if_fail (priv != NULL, E_DATA_BOOK_STATUS_INVALID_ARG);

	if (E_BOOK_BACKEND_MAPI_CLASS (e_book_backend_mapi_contacts_parent_class)->op_get_contact_list)
		E_BOOK_BACKEND_MAPI_CLASS (e_book_backend_mapi_contacts_parent_class)->op_get_contact_list (ebma, cancellable, query, vCards, &mapi_error);

	if (mapi_error) {
		g_propagate_error (error, mapi_error);
		return;
	}

	/* found some in cache, thus use them */
	if (*vCards)
		return;

	e_book_backend_mapi_lock_connection (ebma);

	conn = e_book_backend_mapi_get_connection (ebma);
	if (!conn) {
		e_book_backend_mapi_unlock_connection (ebma);
		g_propagate_error (error, EDB_ERROR (REPOSITORY_OFFLINE));

		return;
	}

	tcd.ebma = ebma;
	tcd.cards = vCards;

	if (priv->is_public_folder)
		status = e_mapi_connection_open_public_folder (conn, priv->fid, &obj_folder, cancellable, &mapi_error);
	else
		status = e_mapi_connection_open_personal_folder (conn, priv->fid, &obj_folder, cancellable, &mapi_error);

	if (status) {
		status = e_mapi_connection_list_objects (conn, &obj_folder,
							 build_restriction_from_sexp_query, (gpointer) query,
							 gather_contact_mids_cb, &mids,
							 cancellable, &mapi_error);

		if (mids)
			status = e_mapi_connection_transfer_objects (conn, &obj_folder, mids, transfer_contacts_cb, &tcd, cancellable, &mapi_error);

		e_mapi_connection_close_folder (conn, &obj_folder, cancellable, &mapi_error);

		g_slist_free_full (mids, g_free);
	}

	if (!status) {
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
ebbm_contacts_get_contacts_count (EBookBackendMAPI *ebma,
				  guint32 *obj_total,
				  GCancellable *cancellable,
				  GError **error)
{
	EBookBackendMAPIContacts *ebmac;
	EBookBackendMAPIContactsPrivate *priv;
	EMapiConnection *conn;
	gboolean status;
	mapi_object_t obj_folder;
	GError *mapi_error = NULL;

	e_return_data_book_error_if_fail (ebma != NULL, E_DATA_BOOK_STATUS_INVALID_ARG);
	e_return_data_book_error_if_fail (obj_total != NULL, E_DATA_BOOK_STATUS_INVALID_ARG);

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

	if (priv->is_public_folder)
		status = e_mapi_connection_open_public_folder (conn, priv->fid, &obj_folder, cancellable, &mapi_error);
	else
		status = e_mapi_connection_open_personal_folder (conn, priv->fid, &obj_folder, cancellable, &mapi_error);

	if (status) {
		struct FolderBasicPropertiesData fbp = { 0 };

		status = e_mapi_connection_get_folder_properties (conn, &obj_folder, NULL, NULL,
			e_mapi_utils_get_folder_basic_properties_cb, &fbp,
			cancellable, &mapi_error);
		if (status)
			*obj_total = fbp.obj_total;
		
		e_mapi_connection_close_folder (conn, &obj_folder, cancellable, &mapi_error);
	}

	if (mapi_error) {
		mapi_error_to_edb_error (error, mapi_error, E_DATA_BOOK_STATUS_OTHER_ERROR, _("Failed to count server contacts"));
		g_error_free (mapi_error);
	}

	e_book_backend_mapi_unlock_connection (ebma);
}

static void
ebbm_contacts_list_known_uids (EBookBackendMAPI *ebma,
			       BuildRestrictionsCB build_rs_cb,
			       gpointer build_rs_cb_data,
			       struct ListKnownUidsData *lku,
			       GCancellable *cancellable,
			       GError **error)
{
	EBookBackendMAPIContacts *ebmac;
	EBookBackendMAPIContactsPrivate *priv;
	EMapiConnection *conn;
	gboolean status;
	mapi_object_t obj_folder;
	GError *mapi_error = NULL;

	e_return_data_book_error_if_fail (ebma != NULL, E_DATA_BOOK_STATUS_INVALID_ARG);
	e_return_data_book_error_if_fail (E_IS_BOOK_BACKEND_MAPI_CONTACTS (ebma), E_DATA_BOOK_STATUS_INVALID_ARG);
	e_return_data_book_error_if_fail (lku != NULL, E_DATA_BOOK_STATUS_INVALID_ARG);
	e_return_data_book_error_if_fail (lku->uid_to_rev != NULL, E_DATA_BOOK_STATUS_INVALID_ARG);

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

	if (priv->is_public_folder)
		status = e_mapi_connection_open_public_folder (conn, priv->fid, &obj_folder, cancellable, &mapi_error);
	else
		status = e_mapi_connection_open_personal_folder (conn, priv->fid, &obj_folder, cancellable, &mapi_error);

	if (status) {
		status = e_mapi_connection_list_objects (conn, &obj_folder, build_rs_cb, build_rs_cb_data,
							 gather_known_uids_cb, lku,
							 cancellable, &mapi_error);

		e_mapi_connection_close_folder (conn, &obj_folder, cancellable, &mapi_error);
	}

	if (mapi_error) {
		mapi_error_to_edb_error (error, mapi_error, E_DATA_BOOK_STATUS_OTHER_ERROR, _("Failed to list items from a server"));
		g_error_free (mapi_error);
	}

	e_book_backend_mapi_unlock_connection (ebma);
}

static void
ebbm_contacts_transfer_contacts (EBookBackendMAPI *ebma,
				 const GSList *uids,
				 EDataBookView *book_view,
				 gpointer notify_contact_data,
				 GCancellable *cancellable,
				 GError **error)
{
	EBookBackendMAPIContacts *ebmac;
	EBookBackendMAPIContactsPrivate *priv;
	EMapiConnection *conn;
	struct TransferContactsData tcd = { 0 };
	mapi_object_t obj_folder;
	gboolean status;
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

	tcd.ebma = ebma;
	tcd.book_view = book_view;
	tcd.notify_contact_data = notify_contact_data;

	if (priv->is_public_folder)
		status = e_mapi_connection_open_public_folder (conn, priv->fid, &obj_folder, cancellable, &mapi_error);
	else
		status = e_mapi_connection_open_personal_folder (conn, priv->fid, &obj_folder, cancellable, &mapi_error);

	if (status) {
		GSList *mids = NULL;
		const GSList *iter;

		for (iter = uids; iter; iter = iter->next) {
			const gchar *uid_str = iter->data;
			mapi_id_t mid, *pmid;

			if (!uid_str || !e_mapi_util_mapi_id_from_string (uid_str, &mid))
				continue;

			pmid = g_new0 (mapi_id_t, 1);
			*pmid = mid;

			mids = g_slist_prepend (mids, pmid);
		}

		if (mids)
			status = e_mapi_connection_transfer_objects (conn, &obj_folder, mids, transfer_contacts_cb, &tcd, cancellable, &mapi_error);

		e_mapi_connection_close_folder (conn, &obj_folder, cancellable, &mapi_error);

		g_slist_free_full (mids, g_free);
	}

	if (!status) {
		mapi_error_to_edb_error (error, mapi_error, E_DATA_BOOK_STATUS_OTHER_ERROR, _("Failed to transfer contacts from a server"));

		if (mapi_error)
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
	parent_class->op_open				= ebbm_contacts_open;
	parent_class->op_remove				= ebbm_contacts_remove;
	parent_class->op_create_contacts		= ebbm_contacts_create_contacts;
	parent_class->op_remove_contacts		= ebbm_contacts_remove_contacts;
	parent_class->op_modify_contacts		= ebbm_contacts_modify_contacts;
	parent_class->op_get_contact			= ebbm_contacts_get_contact;
	parent_class->op_get_contact_list		= ebbm_contacts_get_contact_list;

	parent_class->op_connection_status_changed	= ebbm_contacts_connection_status_changed;
	parent_class->op_get_status_message		= ebbm_contacts_get_status_message;
	parent_class->op_get_contacts_count		= ebbm_contacts_get_contacts_count;
	parent_class->op_list_known_uids		= ebbm_contacts_list_known_uids;
	parent_class->op_transfer_contacts		= ebbm_contacts_transfer_contacts;
}

EBookBackend *
e_book_backend_mapi_contacts_new (void)
{
	return g_object_new (E_TYPE_BOOK_BACKEND_MAPI_CONTACTS, NULL);
}
