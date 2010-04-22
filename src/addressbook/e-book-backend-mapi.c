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
#include "e-book-backend-mapi.h"

/* vCard parameter name in contact list */
#define EMA_X_MEMBERID "X-EMA-MEMBER-ID"
#define EMA_X_MEMBERVALUE "X-EMA-MEMBER-VALUE"

G_DEFINE_TYPE (EBookBackendMAPI, e_book_backend_mapi, E_TYPE_BOOK_BACKEND)

static gboolean enable_debug = TRUE;

struct _EBookBackendMAPIPrivate
{
	gchar *profile;
	ExchangeMapiConnection *conn;

	mapi_id_t fid;
	gint mode;
	gboolean marked_for_offline;
	gboolean is_cache_ready;
	gboolean is_summary_ready;
	gboolean is_writable;
	gchar *uri;
	gchar *book_name;

	GMutex *lock;
	gchar *summary_file_name;
	EBookBackendSummary *summary;
	EBookBackendCache *cache;

};

#define LOCK() g_mutex_lock (priv->lock)
#define UNLOCK() g_mutex_unlock (priv->lock)

#define GET_ALL_KNOWN_IDS (GINT_TO_POINTER(1))
#define GET_SHORT_SUMMARY (GINT_TO_POINTER(2))

/* 'data' is one of GET_ALL_KNOWN_IDS or GET_SHORT_SUMMARY */
static gboolean
mapi_book_get_prop_list (ExchangeMapiConnection *conn, mapi_id_t fid, TALLOC_CTX *mem_ctx, struct SPropTagArray *props, gpointer data)
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
		PROP_TAG(PT_UNICODE, 0x801a),
		PROP_TAG(PT_UNICODE, 0x801c),
		PROP_TAG(PT_UNICODE, 0x801f),
		PROP_TAG(PT_UNICODE, 0x802b),
		PROP_TAG(PT_UNICODE, 0x8062),
		PROP_TAG(PT_UNICODE, 0x8084),
		PROP_TAG(PT_UNICODE, 0x8093),
		PROP_TAG(PT_UNICODE, 0x8094),
		PROP_TAG(PT_UNICODE, 0x80a3),
		PROP_TAG(PT_UNICODE, 0x80a4),
		PROP_TAG(PT_UNICODE, 0x80d8),
		PROP_TAG(PT_UNICODE, 0x812c)
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
		{ PidLidEmail3OriginalDisplayName, 0 }
	};

	g_return_val_if_fail (props != NULL, FALSE);

	if (data == GET_ALL_KNOWN_IDS && !exchange_mapi_utils_add_props_to_props_array (mem_ctx, props, known_book_mapi_ids, G_N_ELEMENTS (known_book_mapi_ids)))
		return FALSE;

	if (data == GET_SHORT_SUMMARY && !exchange_mapi_utils_add_props_to_props_array (mem_ctx, props, short_summary_ids, G_N_ELEMENTS (short_summary_ids)))
		return FALSE;

	return exchange_mapi_utils_add_named_ids_to_props_array (conn, fid, mem_ctx, props, nids, G_N_ELEMENTS (nids));
}

#define ELEMENT_TYPE_SIMPLE 0x01
#define ELEMENT_TYPE_COMPLEX 0x02 /* fields which require explicit functions to set values into EContact and EGwItem */

#define SUMMARY_FLUSH_TIMEOUT 5000
#define ELEMENT_TYPE_SIMPLE 0x01
#define ELEMENT_TYPE_COMPLEX 0x02

static EContact * emapidump_contact (ExchangeMapiConnection *conn, mapi_id_t fid, struct mapi_SPropValue_array *properties);

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

	{ E_CONTACT_EMAIL_1, PT_UNICODE, PROP_TAG(PT_UNICODE, 0x8084), ELEMENT_TYPE_SIMPLE},
	{ E_CONTACT_EMAIL_2, PT_UNICODE, PROP_TAG(PT_UNICODE, 0x8093), ELEMENT_TYPE_SIMPLE},
	{ E_CONTACT_EMAIL_3, PT_UNICODE, PROP_TAG(PT_UNICODE, 0x80a3), ELEMENT_TYPE_SIMPLE},
	{ E_CONTACT_IM_AIM,  PT_UNICODE, PROP_TAG(PT_UNICODE, 0x8062), ELEMENT_TYPE_COMPLEX},

	{ E_CONTACT_PHONE_BUSINESS, PT_UNICODE, PR_OFFICE_TELEPHONE_NUMBER_UNICODE, ELEMENT_TYPE_SIMPLE},
	{ E_CONTACT_PHONE_HOME, PT_UNICODE, PR_HOME_TELEPHONE_NUMBER_UNICODE, ELEMENT_TYPE_SIMPLE},
	{ E_CONTACT_PHONE_MOBILE, PT_UNICODE, PR_MOBILE_TELEPHONE_NUMBER_UNICODE, ELEMENT_TYPE_SIMPLE},
	{ E_CONTACT_PHONE_HOME_FAX, PT_UNICODE, PR_HOME_FAX_NUMBER_UNICODE, ELEMENT_TYPE_SIMPLE},
	{ E_CONTACT_PHONE_BUSINESS_FAX, PT_UNICODE, PR_BUSINESS_FAX_NUMBER_UNICODE, ELEMENT_TYPE_SIMPLE},
	{ E_CONTACT_PHONE_PAGER, PT_UNICODE, PR_PAGER_TELEPHONE_NUMBER_UNICODE, ELEMENT_TYPE_SIMPLE},
	{ E_CONTACT_PHONE_ASSISTANT, PT_UNICODE, PR_ASSISTANT_TELEPHONE_NUMBER_UNICODE, ELEMENT_TYPE_SIMPLE},
	{ E_CONTACT_PHONE_COMPANY, PT_UNICODE, PR_COMPANY_MAIN_PHONE_NUMBER_UNICODE, ELEMENT_TYPE_SIMPLE},

	{ E_CONTACT_HOMEPAGE_URL, PT_UNICODE, PROP_TAG(PT_UNICODE, 0x802b), ELEMENT_TYPE_SIMPLE},
	{ E_CONTACT_FREEBUSY_URL, PT_UNICODE, PROP_TAG(PT_UNICODE, 0x80d8), ELEMENT_TYPE_SIMPLE},

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

	{ E_CONTACT_ADDRESS_HOME, PT_UNICODE, PROP_TAG(PT_UNICODE, 0x801a), ELEMENT_TYPE_COMPLEX},
	{ E_CONTACT_ADDRESS_WORK, PT_UNICODE, PROP_TAG(PT_UNICODE, 0x801c), ELEMENT_TYPE_COMPLEX},
//		{ E_CONTACT_BOOK_URI, ELEMENT_TYPE_SIMPLE, "book_uri"}
//		{ E_CONTACT_CATEGORIES, },
	};

static gint maplen = G_N_ELEMENTS(mappings);

#if 0
static EDataBookView *
find_book_view (EBookBackendMAPI *ebmapi)
{
	EList *views = e_book_backend_get_book_views (E_BOOK_BACKEND (ebmapi));
	EIterator *iter;
	EDataBookView *rv = NULL;

	if (!views)
		return NULL;

	iter = e_list_get_iterator (views);

	if (!iter) {
		g_object_unref (views);
		return NULL;
	}

	if (e_iterator_is_valid (iter)) {
		/* just always use the first book view */
		EDataBookView *v = (EDataBookView*)e_iterator_get(iter);
		if (v)
			rv = v;
	}

	g_object_unref (iter);
	g_object_unref (views);

	return rv;
}
#endif

static gboolean
build_restriction_emails_contains (struct mapi_SRestriction *res,
				   const gchar *query)
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

static gboolean
build_multiple_restriction_emails_contains (struct mapi_SRestriction *res,
					    struct mapi_SRestriction_or *or_res,
					    const gchar *query)
{
	gchar *email=NULL, *tmp, *tmp1;
	//Number of restriction to apply
	guint res_count = 6;

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
	or_res[3].res.resContent.ulPropTag = PROP_TAG(PT_UNICODE, 0x8084);
	or_res[3].res.resContent.lpProp.value.lpszA = email;

	or_res[4].rt = RES_CONTENT;
	or_res[4].res.resContent.fuzzy = FL_FULLSTRING | FL_IGNORECASE;
	or_res[4].res.resContent.ulPropTag = PROP_TAG(PT_UNICODE, 0x8094);
	or_res[4].res.resContent.lpProp.value.lpszA = email;

	or_res[5].rt = RES_CONTENT;
	or_res[5].res.resContent.fuzzy = FL_FULLSTRING | FL_IGNORECASE;
	or_res[5].res.resContent.ulPropTag = PROP_TAG(PT_UNICODE, 0x80a4);
	or_res[5].res.resContent.lpProp.value.lpszA = email;

	res = g_new0 (struct mapi_SRestriction, 1);

	res->rt = RES_OR;
	res->res.resOr.cRes = res_count;
	res->res.resOr.res = or_res;

	return TRUE;
}

static gchar *
get_filename_from_uri (const gchar *uri, const gchar *file)
{
	gchar *mangled_uri, *filename;
	gint i;

	/* mangle the URI to not contain invalid characters */
	mangled_uri = g_strdup (uri);
	for (i = 0; i < strlen (mangled_uri); i++) {
		switch (mangled_uri[i]) {
		case ':' :
		case '/' :
			mangled_uri[i] = '_';
		}
	}

	/* generate the file name */
	filename = g_build_filename (g_get_home_dir (), ".evolution/cache/addressbook",
				     mangled_uri, file, NULL);

	/* free memory */
	g_free (mangled_uri);

	return filename;
}

static GNOME_Evolution_Addressbook_CallStatus
e_book_backend_mapi_load_source (EBookBackend *backend,
				 ESource      *source,
				 gboolean     only_if_exists)
{
	EBookBackendMAPIPrivate *priv = ((EBookBackendMAPI *) backend)->priv;
	const gchar *offline, *tmp;
	gchar **tokens;
	gchar *uri = NULL;
	if (enable_debug)
		printf("MAPI load source\n");
	offline = e_source_get_property (source, "offline_sync");
	if (offline  && g_str_equal (offline, "1"))
		priv->marked_for_offline = TRUE;

	/* Either we are in Online mode or this is marked for offline */

	priv->uri = g_strdup (e_source_get_uri (source));

	tokens = g_strsplit (priv->uri, ";", 2);
	if (tokens[0])
		uri = g_strdup (tokens [0]);
	priv->book_name  = g_strdup (tokens[1]);
	if (priv->book_name == NULL) {
		g_warning ("Bookname is null for %s\n", uri);
		return GNOME_Evolution_Addressbook_OtherError;
	}
	g_strfreev (tokens);

	if (priv->mode ==  GNOME_Evolution_Addressbook_MODE_LOCAL &&
	    !priv->marked_for_offline ) {
		return GNOME_Evolution_Addressbook_OfflineUnavailable;
	}

	if (priv->marked_for_offline) {
		priv->summary_file_name = get_filename_from_uri (priv->uri, "cache.summary");
		if (g_file_test (priv->summary_file_name, G_FILE_TEST_EXISTS)) {
			printf("Loading the summary\n");
			priv->summary = e_book_backend_summary_new (priv->summary_file_name,
								    SUMMARY_FLUSH_TIMEOUT);
			e_book_backend_summary_load (priv->summary);
			priv->is_summary_ready = TRUE;
		}

		/* Load the cache as well.*/
		if (e_book_backend_cache_exists (priv->uri)) {
			printf("Loading the cache\n");
			priv->cache = e_book_backend_cache_new (priv->uri);
			priv->is_cache_ready = TRUE;
		}
		//FIXME: We may have to do a time based reload. Or deltas should upload.
	} else {
		priv->summary = e_book_backend_summary_new (NULL,SUMMARY_FLUSH_TIMEOUT);
		priv->cache = e_book_backend_cache_new (priv->uri);
	}

	g_free (uri);
	e_book_backend_set_is_loaded (E_BOOK_BACKEND (backend), TRUE);
	e_book_backend_set_is_writable (backend, TRUE);
	if (priv->mode ==  GNOME_Evolution_Addressbook_MODE_LOCAL) {
		e_book_backend_set_is_writable (backend, FALSE);
		e_book_backend_notify_writable (backend, FALSE);
		e_book_backend_notify_connection_status (backend, FALSE);
		if (!priv->cache) {
			printf("Unfortunately the cache is not yet created\n");
			return GNOME_Evolution_Addressbook_OfflineUnavailable;
		}
	} else {
		e_book_backend_notify_connection_status (backend, TRUE);
	}

	priv->profile = g_strdup (e_source_get_property (source, "profile"));
	exchange_mapi_util_mapi_id_from_string (e_source_get_property (source, "folder-id"), &priv->fid);

	tmp = e_source_get_property (source, "folder-id");
	printf("Folder is %s %016" G_GINT64_MODIFIER "X\n", tmp, priv->fid);

	/* Once aunthentication in address book works this can be removed */
	if (priv->mode == GNOME_Evolution_Addressbook_MODE_LOCAL) {
		return GNOME_Evolution_Addressbook_Success;
	}

	// writable property will be set in authenticate_user callback
	e_book_backend_set_is_loaded (E_BOOK_BACKEND (backend), TRUE);
	e_book_backend_notify_connection_status (E_BOOK_BACKEND (backend), TRUE);

	if (enable_debug)
		printf("For profile %s and folder %s - %016" G_GINT64_MODIFIER "X\n", priv->profile, tmp, priv->fid);

	return GNOME_Evolution_Addressbook_Success;
}

static gchar *
e_book_backend_mapi_get_static_capabilities (EBookBackend *backend)
{
	if (enable_debug)
		printf("mapi get_static_capabilities\n");
	//FIXME: Implement this.

	return g_strdup ("net,bulk-removes,do-initial-query,contact-lists");
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

	if (!exchange_mapi_connection_resolve_named_props (conn, fid, nids, G_N_ELEMENTS (nids)))
		return FALSE;

	if (GPOINTER_TO_INT (e_contact_get (mcd->contact, E_CONTACT_IS_LIST))) {
		EContact *old_contact;
		GList *local, *l;
		struct BinaryArray_r *members, *oneoff_members;
		uint32_t list_size = 0, u32, crc32 = 0;
		GHashTable *member_values = NULL, *member_ids = NULL;

		old_contact = e_contact_get (mcd->contact, E_CONTACT_UID) ? e_book_backend_cache_get_contact (mcd->cache, e_contact_get (mcd->contact, E_CONTACT_UID)) : NULL;
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

			camel_object_unref (addr);
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
	set_str_con_value (PROP_TAG(PT_UNICODE, 0x812c), E_CONTACT_FREEBUSY_URL);

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
		struct tm tmtime;
		time_t lt;
		NTTIME nt;
		struct FILETIME t;

		tmtime.tm_mday = date->day - 1;
		tmtime.tm_mon = date->month - 1;
		tmtime.tm_year = date->year - 1900;

		lt = mktime (&tmtime);
		unix_to_nt_time (&nt, lt);
		t.dwLowDateTime = (nt << 32) >> 32;
		t.dwHighDateTime = (nt >> 32);

		if (!exchange_mapi_utils_add_spropvalue (mem_ctx, values, n_values, PR_BIRTHDAY, &t))
			return FALSE;
	}

	if (e_contact_get (mcd->contact, E_CONTACT_ANNIVERSARY)) {
		EContactDate *date = e_contact_get (mcd->contact, E_CONTACT_ANNIVERSARY);
		struct tm tmtime;
		time_t lt;
		NTTIME nt;
		struct FILETIME t;

		tmtime.tm_mday = date->day - 1;
		tmtime.tm_mon = date->month - 1;
		tmtime.tm_year = date->year - 1900;

		lt = mktime (&tmtime);
		unix_to_nt_time (&nt, lt);
		t.dwLowDateTime = (nt << 32) >> 32;
		t.dwHighDateTime = (nt >> 32);

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

static void
e_book_backend_mapi_create_contact (EBookBackend *backend,
					  EDataBook *book,
					  guint32 opid,
					  const gchar *vcard )
{
	EContact *contact;
	gchar *id;
	mapi_id_t status;
	MapiCreateitemData mcd;
	EBookBackendMAPIPrivate *priv = ((EBookBackendMAPI *) backend)->priv;

	if (enable_debug)
		printf("mapi create_contact \n");

	switch (priv->mode) {

	case GNOME_Evolution_Addressbook_MODE_LOCAL :
		e_data_book_respond_create(book, opid, GNOME_Evolution_Addressbook_RepositoryOffline, NULL);
		return;

	case  GNOME_Evolution_Addressbook_MODE_REMOTE :
		contact = e_contact_new_from_vcard(vcard);
		mcd.contact = contact;
		mcd.cache = priv->cache;
		status = exchange_mapi_connection_create_item (priv->conn, olFolderContacts, priv->fid,
				mapi_book_write_props, &mcd,
				NULL, NULL, NULL, 0);
		if (!status) {
			e_data_book_respond_create(book, opid, GNOME_Evolution_Addressbook_OtherError, NULL);
			return;
		}
		id = exchange_mapi_util_mapi_ids_to_uid (priv->fid, status);

		/* UID of the contact is nothing but the concatenated string of hex id of folder and the message.*/
		e_contact_set (contact, E_CONTACT_UID, id);
		e_contact_set (contact, E_CONTACT_BOOK_URI, priv->uri);

		//somehow get the mid.
		//add to summary and cache.
		if (priv->marked_for_offline && priv->is_cache_ready)
			e_book_backend_cache_add_contact (priv->cache, contact);

		if (priv->marked_for_offline && priv->is_summary_ready)
			e_book_backend_summary_add_contact (priv->summary, contact);

		e_data_book_respond_create(book, opid, GNOME_Evolution_Addressbook_Success, contact);
		return;
	}

	return;
}

static void
e_book_backend_mapi_remove_contacts (EBookBackend *backend,
					   EDataBook    *book,
					   guint32 opid,
					   GList *id_list)
{
	GSList *list=NULL;
	GList *tmp = id_list;
	EBookBackendMAPIPrivate *priv = ((EBookBackendMAPI *) backend)->priv;
	mapi_id_t fid, mid;

	if (enable_debug)
		printf("mapi: remove_contacts\n");

	switch (priv->mode) {

	case GNOME_Evolution_Addressbook_MODE_LOCAL :
		e_data_book_respond_remove_contacts (book, opid, GNOME_Evolution_Addressbook_RepositoryOffline, NULL);
		return;

	case GNOME_Evolution_Addressbook_MODE_REMOTE:

		while (tmp) {
			struct id_list *data = g_new (struct id_list, 1);
			exchange_mapi_util_mapi_ids_from_uid (tmp->data, &fid, &mid);
			data->id = mid;
			list = g_slist_prepend (list, (gpointer) data);
			tmp = tmp->next;
		}

		exchange_mapi_connection_remove_items (priv->conn, olFolderContacts, priv->fid, list);
		if (priv->marked_for_offline && priv->is_cache_ready) {
			tmp = id_list;
			while (tmp) {
				e_book_backend_cache_remove_contact (priv->cache, tmp->data);
				tmp = tmp->next;
			}
		}

		if (priv->marked_for_offline && priv->is_summary_ready) {
			tmp = id_list;
			while (tmp) {
				e_book_backend_summary_remove_contact (priv->summary, tmp->data);
				tmp = tmp->next;
			}
		}

		g_slist_free (list);
		e_data_book_respond_remove_contacts (book, opid,
							     GNOME_Evolution_Addressbook_Success, id_list);
		return;
	default:
		break;
	}
}

static void
e_book_backend_mapi_modify_contact (EBookBackend *backend,
					  EDataBook    *book,
					  guint32       opid,
					  const gchar   *vcard)
{
	EBookBackendMAPIPrivate *priv = ((EBookBackendMAPI *) backend)->priv;
	MapiCreateitemData mcd;
	EContact *contact;
	mapi_id_t fid, mid;
	gboolean status;
	gchar *tmp;

	if (enable_debug)
		printf("mapi: modify_contacts\n");

	switch (priv->mode) {

	case GNOME_Evolution_Addressbook_MODE_LOCAL :
		e_data_book_respond_modify(book, opid, GNOME_Evolution_Addressbook_RepositoryOffline, NULL);
		return;
	case GNOME_Evolution_Addressbook_MODE_REMOTE :
		contact = e_contact_new_from_vcard(vcard);
		tmp = e_contact_get (contact, E_CONTACT_UID);
		exchange_mapi_util_mapi_ids_from_uid (tmp, &fid, &mid);
		printf("modify id %s\n", tmp);

		mcd.contact = contact;
		mcd.cache = priv->cache;
		status = exchange_mapi_connection_modify_item (priv->conn, olFolderContacts, priv->fid, mid,
				mapi_book_write_props, &mcd,
				NULL, NULL, NULL, 0);
		printf("getting %d\n", status);
		if (!status) {
			e_data_book_respond_modify(book, opid, GNOME_Evolution_Addressbook_OtherError, NULL);
			return;
		}

		e_contact_set (contact, E_CONTACT_BOOK_URI, priv->uri);

		//FIXME: Write it cleanly
		if (priv->marked_for_offline && priv->is_cache_ready)
			printf("delete cache %d\n", e_book_backend_cache_remove_contact (priv->cache, tmp));

		if (priv->marked_for_offline && priv->is_summary_ready)
				e_book_backend_summary_remove_contact (priv->summary, tmp);

		if (priv->marked_for_offline && priv->is_cache_ready)
			e_book_backend_cache_add_contact (priv->cache, contact);

		if (priv->marked_for_offline && priv->is_summary_ready)
			e_book_backend_summary_add_contact (priv->summary, contact);

		e_data_book_respond_modify (book, opid, GNOME_Evolution_Addressbook_Success, contact);

	}
}

static gboolean
create_contact_item (FetchItemsCallbackData *item_data, gpointer data)
{
	EContact *contact;
	gchar *suid;

	contact = emapidump_contact (item_data->conn, item_data->fid, item_data->properties);
	suid = exchange_mapi_util_mapi_ids_to_uid (item_data->fid, item_data->mid);
	printf("got contact %s\n", suid);
	if (contact) {
		/* UID of the contact is nothing but the concatenated string of hex id of folder and the message.*/
		e_contact_set (contact, E_CONTACT_UID, suid);
		data = contact;
	}

	g_free (suid);

	return TRUE;
}

static void
e_book_backend_mapi_get_contact (EBookBackend *backend,
				       EDataBook    *book,
				       guint32       opid,
				       const gchar   *id)
{
	EBookBackendMAPIPrivate *priv = ((EBookBackendMAPI *) backend)->priv;
	EContact *contact = NULL;
	gchar *vcard;

	if (enable_debug)
		printf("mapi: get_contact %s\n", id);

	switch (priv->mode) {

	case GNOME_Evolution_Addressbook_MODE_LOCAL:
		contact = e_book_backend_cache_get_contact (priv->cache,
							    id);
		if (contact) {
			vcard =  e_vcard_to_string (E_VCARD (contact),
						     EVC_FORMAT_VCARD_30);
			e_data_book_respond_get_contact (book,
							 opid,
							 GNOME_Evolution_Addressbook_Success,
							 vcard);
			g_free (vcard);
			g_object_unref (contact);
			return;
		}
		else {
			e_data_book_respond_get_contact (book, opid, GNOME_Evolution_Addressbook_ContactNotFound, "");
			return;
		}

	case GNOME_Evolution_Addressbook_MODE_REMOTE:

		if (priv->marked_for_offline && e_book_backend_cache_is_populated (priv->cache)) {
			contact = e_book_backend_cache_get_contact (priv->cache,
								    id);
			if (contact) {
				vcard =  e_vcard_to_string (E_VCARD (contact),
							     EVC_FORMAT_VCARD_30);
				e_data_book_respond_get_contact (book,
								 opid,
								 GNOME_Evolution_Addressbook_Success,
								 vcard);
				g_free (vcard);
				g_object_unref (contact);
				return;
			}
			else {
				e_data_book_respond_get_contact (book, opid, GNOME_Evolution_Addressbook_ContactNotFound, "");
				return;
			}

		} else {
			mapi_id_t fid, mid;

			exchange_mapi_util_mapi_ids_from_uid (id, &fid, &mid);
			exchange_mapi_connection_fetch_item (priv->conn, priv->fid, mid,
							mapi_book_get_prop_list, GET_ALL_KNOWN_IDS,
							create_contact_item, contact,
							MAPI_OPTIONS_FETCH_ALL);

			if (contact) {
				e_contact_set (contact, E_CONTACT_BOOK_URI, priv->uri);
				vcard =  e_vcard_to_string (E_VCARD (contact),
							     EVC_FORMAT_VCARD_30);
				e_data_book_respond_get_contact (book,
								 opid,
								 GNOME_Evolution_Addressbook_Success,
								 vcard);
				g_free (vcard);
				g_object_unref (contact);
				return;

			} else {
				e_data_book_respond_get_contact (book, opid, GNOME_Evolution_Addressbook_ContactNotFound, "");
				return;
			}
		}

	default:
		break;
	}

	return;

}

static gboolean
create_contact_list_cb (FetchItemsCallbackData *item_data, gpointer data)
{
	struct mapi_SPropValue_array *array = item_data->properties;
	const mapi_id_t fid = item_data->fid;
	const mapi_id_t mid = item_data->mid;

	GList *list = * (GList **) data;
	EContact *contact;
	gchar *suid;

	contact = emapidump_contact (item_data->conn, fid, array);
	suid = exchange_mapi_util_mapi_ids_to_uid (fid, mid);

	if (contact) {
		/* UID of the contact is nothing but the concatenated string of hex id of folder and the message.*/
		printf("Contact added %s\n", suid);
		e_contact_set (contact, E_CONTACT_UID, suid);
//		e_contact_set (contact, E_CONTACT_BOOK_URI, priv->uri);
		//FIXME: Should we set this? How can we get this first?
		list = g_list_prepend (list, e_vcard_to_string (E_VCARD (contact),
								EVC_FORMAT_VCARD_30));
		g_object_unref (contact);
		if (* (GList **)data == NULL)
			* (GList **)data = list;
	}

	g_free (suid);
	return TRUE;
}

static void
e_book_backend_mapi_get_contact_list (EBookBackend *backend,
					    EDataBook    *book,
					    guint32       opid,
					    const gchar   *query )
{
	EBookBackendMAPIPrivate *priv = ((EBookBackendMAPI *) backend)->priv;

	printf("mapi: get contact list %s\n", query);
	switch (priv->mode) {
	case GNOME_Evolution_Addressbook_MODE_LOCAL:
		if (priv->marked_for_offline && priv->cache) {
			GList *contacts;
			GList *vcard_strings = NULL;
			GList *l;

			contacts = e_book_backend_cache_get_contacts (priv->cache, query);

			for (l = contacts; l; l = g_list_next (l)) {
				EContact *contact = l->data;
				vcard_strings = g_list_prepend (vcard_strings, e_vcard_to_string (E_VCARD (contact),
								EVC_FORMAT_VCARD_30));
				g_object_unref (contact);
			}

			g_list_free (contacts);
			printf("get_contact_list in  %s returning %d contacts\n", priv->uri, g_list_length (vcard_strings));
			e_data_book_respond_get_contact_list (book, opid, GNOME_Evolution_Addressbook_Success, vcard_strings);
			return;
		}
		e_data_book_respond_get_contact_list (book, opid, GNOME_Evolution_Addressbook_RepositoryOffline,
						      NULL);
		return;

	case GNOME_Evolution_Addressbook_MODE_REMOTE:
		printf("Mode : Remote\n");
		if (priv->marked_for_offline && priv->cache) {
			GList *contacts;
			GList *vcard_strings = NULL;
			GList *l;

			contacts = e_book_backend_cache_get_contacts (priv->cache, query);

			for (l = contacts; l;l = g_list_next (l)) {
				EContact *contact = l->data;
				vcard_strings = g_list_prepend (vcard_strings, e_vcard_to_string (E_VCARD (contact),
								EVC_FORMAT_VCARD_30));
				g_object_unref (contact);
			}

			g_list_free (contacts);
			printf("get_contact_list in %s  returning %d contacts\n", priv->uri, g_list_length (vcard_strings));
			e_data_book_respond_get_contact_list (book, opid, GNOME_Evolution_Addressbook_Success, vcard_strings);
			return;
		}
		else {
			struct mapi_SRestriction res;
			GList *vcard_str = NULL;

			printf("Not marked for cache\n");

			/* Unfortunately MAPI Doesn't support searching well, we do allow only online search for emails rest all are returned as error. */
			if (!build_restriction_emails_contains (&res, query)) {
				e_data_book_respond_get_contact_list (book, opid, GNOME_Evolution_Addressbook_OtherError, NULL);
				return;
			}

			if (!exchange_mapi_connection_fetch_items (priv->conn, priv->fid, &res, NULL,
								mapi_book_get_prop_list, GET_SHORT_SUMMARY,
								create_contact_list_cb, &vcard_str,
								MAPI_OPTIONS_FETCH_ALL)) {
				e_data_book_respond_get_contact_list (book, opid, GNOME_Evolution_Addressbook_OtherError, NULL);
				return;
			}
			printf("get_contact_list in %s returning %d contacts\n", priv->uri, g_list_length (vcard_str));
			e_data_book_respond_get_contact_list (book, opid, GNOME_Evolution_Addressbook_Success, vcard_str);
			return;

		}
	}
}

typedef struct {
	EBookBackendMAPI *bg;
	GThread *thread;
	EFlag *running;
} BESearchClosure;

static void
closure_destroy (BESearchClosure *closure)
{
	e_flag_free (closure->running);
	g_free (closure);
}

static BESearchClosure*
init_closure (EDataBookView *book_view, EBookBackendMAPI *bg)
{
	BESearchClosure *closure = g_new (BESearchClosure, 1);

	closure->bg = bg;
	closure->thread = NULL;
	closure->running = e_flag_new ();

	g_object_set_data_full (G_OBJECT (book_view), "closure",
				closure, (GDestroyNotify)closure_destroy);

	return closure;
}

static BESearchClosure*
get_closure (EDataBookView *book_view)
{
	return g_object_get_data (G_OBJECT (book_view), "closure");
}

//FIXME: Be more clever in dumping contacts. Can we have a callback mechanism for each types?
static EContact *
emapidump_contact (ExchangeMapiConnection *conn, mapi_id_t fid, struct mapi_SPropValue_array *properties)
{
	EContact *contact = e_contact_new ();
	gint i;

	if (g_str_equal (exchange_mapi_util_find_array_propval (properties, PR_MESSAGE_CLASS), IPM_DISTLIST)) {
		const struct mapi_SBinaryArray *members, *members_dlist;
		GSList *attrs = NULL, *a;
		gint i;

		/* it's a contact list/distribution list, fetch members and return it */
		e_contact_set (contact, E_CONTACT_IS_LIST, GINT_TO_POINTER (TRUE));
		/* we do not support this option, same as GroupWise */
		e_contact_set (contact, E_CONTACT_LIST_SHOW_ADDRESSES, GINT_TO_POINTER (TRUE));

		e_contact_set (contact, E_CONTACT_FILE_AS, exchange_mapi_util_find_array_namedid (properties, conn, fid, PidLidDistributionListName));

		members = exchange_mapi_util_find_array_namedid (properties, conn, fid, PidLidDistributionListOneOffMembers);
		members_dlist = exchange_mapi_util_find_array_namedid (properties, conn, fid, PidLidDistributionListMembers);

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
				camel_object_unref (addr);

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

//	exchange_mapi_debug_property_dump (properties);
	for (i = 1; i < maplen; i++) {
		gpointer value;

		/* can cast it, no writing to the value; and it'll be freed not before the end of this function */
		value = (gpointer) exchange_mapi_util_find_array_propval (properties, mappings[i].mapi_id);
		if (mappings[i].element_type == PT_UNICODE && mappings[i].contact_type == ELEMENT_TYPE_SIMPLE) {
			if (value)
				e_contact_set (contact, mappings[i].field_id, value);
		} else if (mappings[i].contact_type == ELEMENT_TYPE_SIMPLE) {
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
			} else
				printf("Nothing is printed\n");
		} else if (mappings[i].contact_type == ELEMENT_TYPE_COMPLEX) {
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
					contact_addr.ext = (gchar *)exchange_mapi_util_find_array_propval (properties, PR_HOME_ADDRESS_POST_OFFICE_BOX_UNICODE);
					contact_addr.locality = (gchar *)exchange_mapi_util_find_array_propval (properties, PR_HOME_ADDRESS_CITY_UNICODE);
					contact_addr.region = (gchar *)exchange_mapi_util_find_array_propval (properties, PR_HOME_ADDRESS_STATE_OR_PROVINCE_UNICODE);
					contact_addr.code = (gchar *)exchange_mapi_util_find_array_propval (properties, PR_HOME_ADDRESS_POSTAL_CODE_UNICODE);
					contact_addr.country = (gchar *)exchange_mapi_util_find_array_propval (properties, PR_HOME_ADDRESS_COUNTRY_UNICODE);
				} else {
					contact_addr.address_format = NULL;
					contact_addr.po = NULL;
					contact_addr.street = (gchar *)value;
					contact_addr.ext = (gchar *)exchange_mapi_util_find_array_propval (properties, PR_POST_OFFICE_BOX_UNICODE);
					contact_addr.locality = (gchar *)exchange_mapi_util_find_array_propval (properties, PR_LOCALITY_UNICODE);
					contact_addr.region = (gchar *)exchange_mapi_util_find_array_propval (properties, PR_STATE_OR_PROVINCE_UNICODE);
					contact_addr.code = (gchar *)exchange_mapi_util_find_array_propval (properties, PR_POSTAL_CODE_UNICODE);
					contact_addr.country = (gchar *)exchange_mapi_util_find_array_propval (properties, PR_COUNTRY_UNICODE);
				}
				e_contact_set (contact, mappings[i].field_id, &contact_addr);
			}
		}
	}

	return contact;
}

static void
get_contacts_from_cache (EBookBackendMAPI *ebmapi,
			 const gchar *query,
			 GPtrArray *ids,
			 EDataBookView *book_view,
			 BESearchClosure *closure)
{
	gint i;

	if (enable_debug)
		printf ("\nread contacts from cache for the ids found in summary\n");
	for (i = 0; i < ids->len; i ++) {
		gchar *uid;
		EContact *contact;

                if (!e_flag_is_set (closure->running))
                        break;

		uid = g_ptr_array_index (ids, i);
		contact = e_book_backend_cache_get_contact (ebmapi->priv->cache, uid);
		if (contact) {
			e_data_book_view_notify_update (book_view, contact);
			g_object_unref (contact);
		}
	}
	if (e_flag_is_set (closure->running))
		e_data_book_view_notify_complete (book_view,
						  GNOME_Evolution_Addressbook_Success);
}

static gboolean
create_contact_cb (FetchItemsCallbackData *item_data, gpointer data)
{
	EDataBookView *book_view = data;
	BESearchClosure *closure = get_closure (book_view);
	EBookBackendMAPI *be = closure->bg;
	EContact *contact;
	EBookBackendMAPIPrivate *priv = ((EBookBackendMAPI *) be)->priv;
	gchar *suid;

	if (!e_flag_is_set (closure->running)) {
		printf("Might be that the operation is cancelled. Lets ask our parent also to do.\n");
		return FALSE;
	}

	contact = emapidump_contact (item_data->conn, item_data->fid, item_data->properties);
	suid = exchange_mapi_util_mapi_ids_to_uid (item_data->fid, item_data->mid);

	if (contact) {
		/* UID of the contact is nothing but the concatenated string of hex id of folder and the message.*/
		e_contact_set (contact, E_CONTACT_UID, suid);
		e_contact_set (contact, E_CONTACT_BOOK_URI, priv->uri);
		if (priv->cache)
			e_book_backend_cache_add_contact (priv->cache, contact);
		e_data_book_view_notify_update (book_view, contact);
		g_object_unref(contact);
	}

	g_free (suid);
	return TRUE;
}

static void
book_view_thread (gpointer data)
{
	struct mapi_SRestriction res;
	struct mapi_SRestriction_or *or_res = NULL;
	EDataBookView *book_view = data;
	BESearchClosure *closure = get_closure (book_view);
	EBookBackendMAPI *backend = closure->bg;
	EBookBackendMAPIPrivate *priv = backend->priv;
	const gchar *query = NULL;
	GPtrArray *ids = NULL;
	GList *contacts = NULL, *temp_list = NULL;
	//Number of multiple restriction to apply
	guint res_count = 6;

	if (enable_debug)
		printf("mapi: book view\n");

	g_object_ref (book_view);
	e_flag_set (closure->running);

	e_data_book_view_notify_status_message (book_view, "Searching...");
	query = e_data_book_view_get_card_query (book_view);

	switch (priv->mode) {

	case GNOME_Evolution_Addressbook_MODE_LOCAL:
		if (!priv->marked_for_offline) {
			e_data_book_view_notify_complete (book_view,
					GNOME_Evolution_Addressbook_OfflineUnavailable);
			g_object_unref (book_view);
			return;
		}
		if (!priv->cache) {
			printf("The cache is not yet built\n");
			e_data_book_view_notify_complete (book_view,
					GNOME_Evolution_Addressbook_Success);
			return;
		}

		if (priv->is_summary_ready &&
		    e_book_backend_summary_is_summary_query (priv->summary, query)) {
			if (enable_debug)
				printf ("reading the contacts from summary \n");
			ids = e_book_backend_summary_search (priv->summary, query);
			if (ids && ids->len > 0) {
				get_contacts_from_cache (backend, query, ids, book_view, closure);
				g_ptr_array_free (ids, TRUE);
			}
			g_object_unref (book_view);
			return;
		}

		/* fall back to cache */
		if (enable_debug)
			printf ("summary not found or a summary query  reading the contacts from cache %s\n", query);

		contacts = e_book_backend_cache_get_contacts (priv->cache,
							      query);
		temp_list = contacts;
		for (; contacts != NULL; contacts = g_list_next(contacts)) {
			if (!e_flag_is_set (closure->running)) {
				for (;contacts != NULL; contacts = g_list_next (contacts))
					g_object_unref (contacts->data);
				break;
			}
			e_data_book_view_notify_update (book_view,
							E_CONTACT(contacts->data));
			g_object_unref (contacts->data);
		}
		if (e_flag_is_set (closure->running))
			e_data_book_view_notify_complete (book_view,
							  GNOME_Evolution_Addressbook_Success);
		if (temp_list)
			 g_list_free (temp_list);
		g_object_unref (book_view);
		return;

	case GNOME_Evolution_Addressbook_MODE_REMOTE:

		if (!priv->conn || !exchange_mapi_connection_connected (priv->conn)) {
			e_book_backend_notify_auth_required (E_BOOK_BACKEND (backend));
			e_data_book_view_notify_complete (book_view,
						GNOME_Evolution_Addressbook_AuthenticationRequired);
			g_object_unref (book_view);
			return;
		}

		if (priv->marked_for_offline && priv->cache && priv->is_cache_ready) {
			if (priv->is_summary_ready &&
			    e_book_backend_summary_is_summary_query (priv->summary, query)) {
				if (enable_debug)
					printf ("reading the contacts from summary \n");
				ids = e_book_backend_summary_search (priv->summary, query);
				if (ids && ids->len > 0) {
					get_contacts_from_cache (backend, query, ids, book_view, closure);
					g_ptr_array_free (ids, TRUE);
				}
				g_object_unref (book_view);
				return;
			}

			printf("Summary seems to be not there or not a summary query, lets fetch from cache directly\n");

			/* We are already cached. Lets return from there. */
			contacts = e_book_backend_cache_get_contacts (priv->cache,
								      query);
			temp_list = contacts;
			for (; contacts != NULL; contacts = g_list_next(contacts)) {
				if (!e_flag_is_set (closure->running)) {
					for (;contacts != NULL; contacts = g_list_next (contacts))
						g_object_unref (contacts->data);
					break;
				}
				e_data_book_view_notify_update (book_view,
								E_CONTACT(contacts->data));
				g_object_unref (contacts->data);
			}
			if (e_flag_is_set (closure->running))
				e_data_book_view_notify_complete (book_view,
								  GNOME_Evolution_Addressbook_Success);
			if (temp_list)
				 g_list_free (temp_list);
			g_object_unref (book_view);
			return;
		}

		if (e_book_backend_summary_is_summary_query (priv->summary, query)) {
			or_res = g_new (struct mapi_SRestriction_or, res_count);

			if (!build_multiple_restriction_emails_contains (&res, or_res, query)) {
				e_data_book_view_notify_complete (book_view,
							  GNOME_Evolution_Addressbook_OtherError);
				return;
			}

			//FIXME: We need to fetch only the query from the server live and not everything.
			if (!exchange_mapi_connection_fetch_items (priv->conn, priv->fid, &res, NULL,
							   mapi_book_get_prop_list, GET_SHORT_SUMMARY,
							   create_contact_cb, book_view,
							   MAPI_OPTIONS_FETCH_ALL)) {
			if (e_flag_is_set (closure->running))
				e_data_book_view_notify_complete (book_view,
								  GNOME_Evolution_Addressbook_OtherError);
				g_object_unref (book_view);

				if (or_res)
					g_free(or_res);

				return;
			}
		} else {
			if (!exchange_mapi_connection_fetch_items (priv->conn, priv->fid, NULL, NULL,
							mapi_book_get_prop_list, GET_ALL_KNOWN_IDS,
							create_contact_cb, book_view,
							MAPI_OPTIONS_FETCH_ALL)) {
				if (e_flag_is_set (closure->running))
					e_data_book_view_notify_complete (book_view,
									  GNOME_Evolution_Addressbook_OtherError);
				g_object_unref (book_view);
				return;
			}
		}

		if (e_flag_is_set (closure->running))
			e_data_book_view_notify_complete (book_view,
							  GNOME_Evolution_Addressbook_Success);
		g_object_unref (book_view);

	default:
		break;
	}

	if (or_res)
		g_free(or_res);

	return;
}

static void
e_book_backend_mapi_start_book_view (EBookBackend  *backend,
					   EDataBookView *book_view)
{
	BESearchClosure *closure = init_closure (book_view, E_BOOK_BACKEND_MAPI (backend));

	if (enable_debug)
		printf ("mapi: start_book_view...\n");
	closure->thread = g_thread_create ((GThreadFunc) book_view_thread, book_view, FALSE, NULL);
	e_flag_wait (closure->running);

	/* at this point we know the book view thread is actually running */
}

static void
e_book_backend_mapi_stop_book_view (EBookBackend  *backend,
					  EDataBookView *book_view)
{
	if (enable_debug)
		printf("mapi: stop book view\n");
	/* FIXME : provide implmentation */
}

static void
e_book_backend_mapi_get_changes (EBookBackend *backend,
				       EDataBook    *book,
				       guint32       opid,
				       const gchar *change_id  )
{
	if (enable_debug)
		printf("mapi: get changes\n");
	/* FIXME : provide implmentation */
	e_data_book_respond_get_changes (book, opid, GNOME_Evolution_Addressbook_RepositoryOffline, NULL);
}

static gboolean
cache_contact_cb (FetchItemsCallbackData *item_data, gpointer data)
{
	EBookBackendMAPI *be = data;
	EContact *contact;
	EBookBackendMAPIPrivate *priv = ((EBookBackendMAPI *) be)->priv;
	gchar *suid;

	contact = emapidump_contact (item_data->conn, item_data->fid, item_data->properties);
	suid = exchange_mapi_util_mapi_ids_to_uid (item_data->fid, item_data->mid);

	if (contact) {
		/* UID of the contact is nothing but the concatenated string of hex id of folder and the message.*/
		e_contact_set (contact, E_CONTACT_UID, suid);
		e_contact_set (contact, E_CONTACT_BOOK_URI, priv->uri);
		e_book_backend_cache_add_contact (priv->cache, contact);
		e_book_backend_summary_add_contact (priv->summary, contact);
		g_object_unref(contact);
	}

	g_free (suid);
	return TRUE;
}

static gpointer
build_cache (EBookBackendMAPI *ebmapi)
{
	EBookBackendMAPIPrivate *priv = ((EBookBackendMAPI *) ebmapi)->priv;
	gchar *tmp;

	//FIXME: What if book view is NULL? Can it be? Check that.
	if (!priv->cache) {
		printf("Caching for the first time\n");
		priv->cache = e_book_backend_cache_new (priv->uri);
	}

	if (!priv->summary) {
		priv->summary = e_book_backend_summary_new (priv->summary_file_name,
							    SUMMARY_FLUSH_TIMEOUT);
		printf("Summary file name is %s\n", priv->summary_file_name);
	}

	e_file_cache_freeze_changes (E_FILE_CACHE (priv->cache));

	if (!exchange_mapi_connection_fetch_items (priv->conn, priv->fid, NULL, NULL,
						mapi_book_get_prop_list, GET_ALL_KNOWN_IDS,
						cache_contact_cb, ebmapi,
						MAPI_OPTIONS_FETCH_ALL)) {
		printf("Error during caching addressbook\n");
		e_file_cache_thaw_changes (E_FILE_CACHE (priv->cache));
		return NULL;
	}
	tmp = g_strdup_printf("%d", (gint)time (NULL));
	e_book_backend_cache_set_time (priv->cache, tmp);
	printf("setting time  %s\n", tmp);
	g_free (tmp);
	e_file_cache_thaw_changes (E_FILE_CACHE (priv->cache));
	e_book_backend_summary_save (priv->summary);
	priv->is_cache_ready = TRUE;
	priv->is_summary_ready = TRUE;
	return NULL;
}

#if 0
static gpointer
update_cache (EBookBackendMAPI *ebmapi)
{
	EBookBackendMAPIPrivate *priv = ((EBookBackendMAPI *) ebmapi)->priv;
	gchar *tmp = e_book_backend_cache_get_time (priv->cache);
	//FIXME: What if book view is NULL? Can it be? Check that.
	time_t t=0;
//	struct mapi_SRestriction res;

	if (tmp)
		t = atoi (tmp);

//	res.rt = RES_PROPERTY;
//	res.res.resProperty.relop = RES_PROPERTY;
//	res.res.resProperty.ulPropTag = PR_LAST_MODIFICATION_TIME;
//	res.res.resProperty.lpProp.ulPropTag = PR_LAST_MODIFICATION_TIME;
//	res.res.resProperty.lpProp.value.lpszA = email;

#if 0
	printf("time updated was %d\n", t);
	/* Assume the cache and summary are already there */

	e_file_cache_freeze_changes (E_FILE_CACHE (priv->cache));

	if (!exchange_mapi_connection_fetch_items (priv->conn, priv->fid, &res, NULL,
						mapi_book_get_prop_list, GET_ALL_KNOWN_IDS,
						cache_contact_cb, ebmapi,
						MAPI_OPTIONS_FETCH_ALL)) {
		printf("Error during caching addressbook\n");
		e_file_cache_thaw_changes (E_FILE_CACHE (priv->cache));
		return NULL;
	}
	e_file_cache_thaw_changes (E_FILE_CACHE (priv->cache));
	e_book_backend_summary_save (priv->summary);
	priv->is_cache_ready = TRUE;
	priv->is_summary_ready = TRUE;
#endif

	return NULL;
}
#endif

static void
e_book_backend_mapi_authenticate_user (EBookBackend *backend,
					    EDataBook    *book,
					    guint32       opid,
					    const gchar *user,
					    const gchar *passwd,
					    const gchar *auth_method)
{
	EBookBackendMAPIPrivate *priv = ((EBookBackendMAPI *) backend)->priv;

	if (enable_debug) {
		printf ("mapi: authenticate user\n");
	}

	switch (priv->mode) {
	case GNOME_Evolution_Addressbook_MODE_LOCAL:
		e_book_backend_notify_writable (backend, FALSE);
		e_book_backend_notify_connection_status (backend, FALSE);
		e_data_book_respond_authenticate_user (book, opid, GNOME_Evolution_Addressbook_Success);
		return;

	case GNOME_Evolution_Addressbook_MODE_REMOTE:

		priv->conn = exchange_mapi_connection_new (priv->profile, passwd);
		if (!priv->conn) {
			priv->conn = exchange_mapi_connection_find (priv->profile);
			if (priv->conn && !exchange_mapi_connection_connected (priv->conn))
				exchange_mapi_connection_reconnect (priv->conn, passwd);
		}

		if (!priv->conn)
			return e_data_book_respond_authenticate_user (book, opid,GNOME_Evolution_Addressbook_OtherError);

		if (priv->cache && priv->is_cache_ready) {
			printf("FIXME: Should check for an update in the cache\n");
//			g_thread_create ((GThreadFunc) update_cache,
	//					  backend, FALSE, backend);
		} else if (priv->marked_for_offline && !priv->is_cache_ready) {
			/* Means we dont have a cache. Lets build that first */
			printf("Preparing to build cache\n");
			g_thread_create ((GThreadFunc) build_cache, backend, FALSE, NULL);
		}
		e_book_backend_set_is_writable (backend, TRUE);
		e_data_book_respond_authenticate_user (book, opid, GNOME_Evolution_Addressbook_Success);
		return;

	default :
		break;
	}
}

static void
e_book_backend_mapi_get_required_fields (EBookBackend *backend,
					       EDataBook    *book,
					       guint32       opid)
{
	GList *fields = NULL;

	if (enable_debug)
		printf ("mapi get_required_fields...\n");

	fields = g_list_append (fields, (gchar *)e_contact_field_name (E_CONTACT_FILE_AS));
	e_data_book_respond_get_supported_fields (book, opid,
						  GNOME_Evolution_Addressbook_Success,
						  fields);
	g_list_free (fields);
}

static void
e_book_backend_mapi_get_supported_fields (EBookBackend *backend,
					       EDataBook    *book,
					       guint32       opid)
{
	GList *fields = NULL;
	gint i;

	if (enable_debug)
		printf ("mapi get_supported_fields...\n");

	for (i=0; i<maplen; i++)
	{
		fields = g_list_append (fields, (gchar *)e_contact_field_name (mappings[i].field_id));
	}
	fields = g_list_append (fields, g_strdup (e_contact_field_name (E_CONTACT_BOOK_URI)));

	e_data_book_respond_get_supported_fields (book, opid,
						  GNOME_Evolution_Addressbook_Success,
						  fields);
	g_list_free (fields);

}

static void
e_book_backend_mapi_get_supported_auth_methods (EBookBackend *backend, EDataBook *book, guint32 opid)
{
	GList *auth_methods = NULL;
	gchar *auth_method;

	if (enable_debug)
		printf ("mapi get_supported_auth_methods...\n");

	auth_method =  g_strdup_printf ("plain/password");
	auth_methods = g_list_append (auth_methods, auth_method);
	e_data_book_respond_get_supported_auth_methods (book,
							opid,
							GNOME_Evolution_Addressbook_Success,
							auth_methods);
	g_free (auth_method);
	g_list_free (auth_methods);
}

static GNOME_Evolution_Addressbook_CallStatus
e_book_backend_mapi_cancel_operation (EBookBackend *backend, EDataBook *book)
{
	if (enable_debug)
		printf ("mapi cancel_operation...\n");
	return GNOME_Evolution_Addressbook_CouldNotCancel;
}

static void
e_book_backend_mapi_remove (EBookBackend *backend,
				  EDataBook    *book,
				  guint32      opid)
{
	EBookBackendMAPIPrivate *priv = ((EBookBackendMAPI *) backend)->priv;
	gchar *cache_uri = NULL;
	gboolean status;

	if (enable_debug)
		printf("mapi: remove\n");

	switch (priv->mode) {

	case GNOME_Evolution_Addressbook_MODE_LOCAL:
		e_data_book_respond_remove (book, opid, GNOME_Evolution_Addressbook_OfflineUnavailable);
		return;

	case GNOME_Evolution_Addressbook_MODE_REMOTE:

		status = exchange_mapi_connection_remove_folder (priv->conn, priv->fid);
		if (!status) {
			e_data_book_respond_remove (book, opid, GNOME_Evolution_Addressbook_OtherError);
			return;
		}

		if (priv->marked_for_offline && priv->is_summary_ready) {
			g_object_unref (priv->summary);
			priv->summary = NULL;
		}

		if (e_book_backend_cache_exists (priv->uri)) {

			g_object_unref (priv->cache);
			priv->cache= NULL;

		}

		/* Remove the summary and cache independent of whether they are loaded or not. */
		cache_uri = get_filename_from_uri (priv->uri, "cache.summary");
		if (g_file_test (cache_uri, G_FILE_TEST_EXISTS)) {
			g_unlink (cache_uri);
		}
		g_free (cache_uri);

		cache_uri = get_filename_from_uri (priv->uri, "cache.xml");
		if (g_file_test (cache_uri, G_FILE_TEST_EXISTS)) {
			g_unlink (cache_uri);
		}
		g_free (cache_uri);

		e_data_book_respond_remove (book, opid, GNOME_Evolution_Addressbook_Success);
		return;

	default:
		break;
	}

	return;

	/* FIXME : provide implmentation */
}

static void
e_book_backend_mapi_set_mode (EBookBackend *backend, GNOME_Evolution_Addressbook_BookMode mode)
{
	EBookBackendMAPIPrivate *priv = ((EBookBackendMAPI *) backend)->priv;

	if (enable_debug)
		printf("mapi: set_mode \n");

	priv->mode = mode;
	if (e_book_backend_is_loaded (backend)) {
		if (mode == GNOME_Evolution_Addressbook_MODE_LOCAL) {
			e_book_backend_notify_writable (backend, FALSE);
			e_book_backend_notify_connection_status (backend, FALSE);
			/* FIXME: Uninitialize mapi here. may be.*/
		}
		else if (mode == GNOME_Evolution_Addressbook_MODE_REMOTE) {
			e_book_backend_notify_writable (backend, TRUE);
			e_book_backend_notify_connection_status (backend, TRUE);
			e_book_backend_notify_auth_required (backend); //FIXME: WTH is this required.
		}
	}
}

static void
e_book_backend_mapi_dispose (GObject *object)
{
	/* FIXME : provide implmentation */
	EBookBackendMAPIPrivate *priv = ((EBookBackendMAPI *) object)->priv;

	if (priv->profile) {
		g_free (priv->profile);
		priv->profile = NULL;
	}
	if (priv->conn) {
		g_object_unref (priv->conn);
		priv->conn = NULL;
	}
	if (priv->uri) {
		g_free (priv->uri);
		priv->uri = NULL;
	}

}

static void e_book_backend_mapi_class_init (EBookBackendMAPIClass *klass)
{
	GObjectClass  *object_class = G_OBJECT_CLASS (klass);
	EBookBackendClass *parent_class;

	e_book_backend_mapi_parent_class = g_type_class_peek_parent (klass);

	parent_class = E_BOOK_BACKEND_CLASS (klass);

	/* Set the virtual methods. */
	parent_class->load_source		   = e_book_backend_mapi_load_source;
	parent_class->get_static_capabilities    = e_book_backend_mapi_get_static_capabilities;
	parent_class->create_contact             = e_book_backend_mapi_create_contact;
	parent_class->remove_contacts            = e_book_backend_mapi_remove_contacts;
	parent_class->modify_contact             = e_book_backend_mapi_modify_contact;
	parent_class->get_contact                = e_book_backend_mapi_get_contact;
	parent_class->get_contact_list           = e_book_backend_mapi_get_contact_list;
	parent_class->start_book_view            = e_book_backend_mapi_start_book_view;
	parent_class->stop_book_view             = e_book_backend_mapi_stop_book_view;
	parent_class->get_changes                = e_book_backend_mapi_get_changes;
	parent_class->authenticate_user          = e_book_backend_mapi_authenticate_user;
	parent_class->get_required_fields        = e_book_backend_mapi_get_required_fields;
	parent_class->get_supported_fields       = e_book_backend_mapi_get_supported_fields;
	parent_class->get_supported_auth_methods = e_book_backend_mapi_get_supported_auth_methods;
	parent_class->cancel_operation           = e_book_backend_mapi_cancel_operation;
	parent_class->remove                     = e_book_backend_mapi_remove;
	parent_class->set_mode                   = e_book_backend_mapi_set_mode;
	object_class->dispose                    = e_book_backend_mapi_dispose;

}

EBookBackend *e_book_backend_mapi_new (void)
{
	EBookBackendMAPI *backend;

	backend = g_object_new (E_TYPE_BOOK_BACKEND_MAPI, NULL);
	return E_BOOK_BACKEND (backend);
}

static void	e_book_backend_mapi_init (EBookBackendMAPI *backend)
{
	EBookBackendMAPIPrivate *priv;

	priv= g_new0 (EBookBackendMAPIPrivate, 1);
	/* Priv Struct init */
	backend->priv = priv;

	priv->marked_for_offline = FALSE;
	priv->uri = NULL;
	priv->cache = NULL;
	priv->is_summary_ready = FALSE;
	priv->is_cache_ready = FALSE;

	if (g_getenv ("MAPI_DEBUG"))
		enable_debug = TRUE;
	else
		enable_debug = FALSE;

}
