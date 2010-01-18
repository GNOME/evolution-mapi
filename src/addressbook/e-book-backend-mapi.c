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

#include <libedata-book/e-book-backend-sexp.h>
#include <libedata-book/e-data-book.h>
#include <libedata-book/e-data-book-view.h>
#include <libedata-book/e-book-backend-cache.h>
#include <libedata-book/e-book-backend-summary.h>
#include "e-book-backend-mapi.h"

static EBookBackendClass *e_book_backend_mapi_parent_class;
static gboolean enable_debug = TRUE;

struct _EBookBackendMAPIPrivate
{
	char *profile;
	mapi_id_t fid;
	int mode;
	gboolean marked_for_offline;
	gboolean is_cache_ready;
	gboolean is_summary_ready;
	gboolean is_writable;
	char *uri;
	char *book_name;
	
	GMutex *lock;
	char *summary_file_name;
	EBookBackendSummary *summary;
	EBookBackendCache *cache;

};

#define LOCK() g_mutex_lock (priv->lock)
#define UNLOCK() g_mutex_unlock (priv->lock)

#define ELEMENT_TYPE_SIMPLE 0x01
#define ELEMENT_TYPE_COMPLEX 0x02 /* fields which require explicit functions to set values into EContact and EGwItem */

#define SUMMARY_FLUSH_TIMEOUT 5000
#define ELEMENT_TYPE_SIMPLE 0x01
#define ELEMENT_TYPE_COMPLEX 0x02

static EContact * emapidump_contact(struct mapi_SPropValue_array *properties);

static const struct field_element_mapping {
		EContactField field_id;
		int element_type;
	        int mapi_id;
	        int contact_type;
//		char *element_name;
//		void (*populate_contact_func)(EContact *contact,    gpointer data);
//		void (*set_value_in_gw_item) (EGwItem *item, gpointer data);
//		void (*set_changes) (EGwItem *new_item, EGwItem *old_item);

	} mappings [] = { 

	{ E_CONTACT_UID, PT_STRING8, 0, ELEMENT_TYPE_SIMPLE},
	{ E_CONTACT_REV, PT_SYSTIME, PR_LAST_MODIFICATION_TIME, ELEMENT_TYPE_SIMPLE},
		
	{ E_CONTACT_FILE_AS, PT_STRING8, PR_EMS_AB_MANAGER_T, ELEMENT_TYPE_SIMPLE},
	{ E_CONTACT_FULL_NAME, PT_STRING8, PR_DISPLAY_NAME, ELEMENT_TYPE_SIMPLE },
	{ E_CONTACT_GIVEN_NAME, PT_STRING8, PR_GIVEN_NAME, ELEMENT_TYPE_SIMPLE},
	{ E_CONTACT_FAMILY_NAME, PT_STRING8, PR_SURNAME , ELEMENT_TYPE_SIMPLE},
	{ E_CONTACT_NICKNAME, PT_STRING8, PR_NICKNAME, ELEMENT_TYPE_SIMPLE },

	{ E_CONTACT_EMAIL_1, PT_STRING8, PROP_TAG(PT_STRING8, 0x8084), ELEMENT_TYPE_SIMPLE},
	{ E_CONTACT_EMAIL_2, PT_STRING8, PROP_TAG(PT_STRING8, 0x8093), ELEMENT_TYPE_SIMPLE},
	{ E_CONTACT_EMAIL_3, PT_STRING8, PROP_TAG(PT_STRING8, 0x80a3), ELEMENT_TYPE_SIMPLE},
	{ E_CONTACT_IM_AIM,  PT_STRING8, PROP_TAG(PT_UNICODE, 0x8062), ELEMENT_TYPE_COMPLEX},	
		
	{ E_CONTACT_PHONE_BUSINESS, PT_STRING8, PR_OFFICE_TELEPHONE_NUMBER, ELEMENT_TYPE_SIMPLE},
	{ E_CONTACT_PHONE_HOME, PT_STRING8, PR_HOME_TELEPHONE_NUMBER, ELEMENT_TYPE_SIMPLE},
	{ E_CONTACT_PHONE_MOBILE, PT_STRING8, PR_MOBILE_TELEPHONE_NUMBER, ELEMENT_TYPE_SIMPLE},
	{ E_CONTACT_PHONE_HOME_FAX, PT_STRING8, PR_HOME_FAX_NUMBER ,ELEMENT_TYPE_SIMPLE},
	{ E_CONTACT_PHONE_BUSINESS_FAX, PT_STRING8, PR_BUSINESS_FAX_NUMBER,ELEMENT_TYPE_SIMPLE},
	{ E_CONTACT_PHONE_PAGER, PT_STRING8, PR_PAGER_TELEPHONE_NUMBER,ELEMENT_TYPE_SIMPLE},
	{ E_CONTACT_PHONE_ASSISTANT, PT_STRING8, PR_ASSISTANT_TELEPHONE_NUMBER ,ELEMENT_TYPE_SIMPLE},
	{ E_CONTACT_PHONE_COMPANY, PT_STRING8, PR_COMPANY_MAIN_PHONE_NUMBER ,ELEMENT_TYPE_SIMPLE},

	{ E_CONTACT_HOMEPAGE_URL, PT_STRING8, 0x802b001e, ELEMENT_TYPE_SIMPLE},
	{ E_CONTACT_FREEBUSY_URL, PT_STRING8, 0x80d8001e, ELEMENT_TYPE_SIMPLE},

	{ E_CONTACT_ROLE, PT_STRING8, PR_PROFESSION, ELEMENT_TYPE_SIMPLE},
	{ E_CONTACT_TITLE, PT_STRING8, PR_TITLE, ELEMENT_TYPE_SIMPLE},
	{ E_CONTACT_ORG, PT_STRING8, PR_COMPANY_NAME, ELEMENT_TYPE_SIMPLE},
	{ E_CONTACT_ORG_UNIT, PT_STRING8, PR_DEPARTMENT_NAME,ELEMENT_TYPE_SIMPLE},
	{ E_CONTACT_MANAGER, PT_STRING8, PR_MANAGER_NAME, ELEMENT_TYPE_SIMPLE},
	{ E_CONTACT_ASSISTANT, PT_STRING8, PR_ASSISTANT, ELEMENT_TYPE_SIMPLE},
		
	{ E_CONTACT_OFFICE, PT_STRING8, PR_OFFICE_LOCATION, ELEMENT_TYPE_SIMPLE},
	{ E_CONTACT_SPOUSE, PT_STRING8, PR_SPOUSE_NAME, ELEMENT_TYPE_SIMPLE},
		
	{ E_CONTACT_BIRTH_DATE,  PT_SYSTIME, PR_BIRTHDAY, ELEMENT_TYPE_COMPLEX},
	{ E_CONTACT_ANNIVERSARY, PT_SYSTIME, PR_WEDDING_ANNIVERSARY, ELEMENT_TYPE_COMPLEX},
		  
	{ E_CONTACT_NOTE, PT_STRING8, PR_BODY, ELEMENT_TYPE_SIMPLE},
		

	{ E_CONTACT_ADDRESS_HOME, PT_STRING8, 0x801a001e, ELEMENT_TYPE_COMPLEX},
	{ E_CONTACT_ADDRESS_WORK, PT_STRING8, 0x801c001e, ELEMENT_TYPE_COMPLEX},
//		{ E_CONTACT_BOOK_URI, ELEMENT_TYPE_SIMPLE, "book_uri"}
//		{ E_CONTACT_EMAIL, PT_STRING8, 0x8084001e},
//		{ E_CONTACT_CATEGORIES, },		
	};

static int maplen = G_N_ELEMENTS(mappings);
gboolean mapi_book_build_name_id (struct mapi_nameid *nameid, gpointer data);
int mapi_book_build_props (struct SPropValue ** value, struct SPropTagArray * SPropTagArray, gpointer data);
gboolean mapi_book_build_name_id_for_getprops (struct mapi_nameid *nameid, gpointer data);


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
				   const char *query)
{
	char *email=NULL, *tmp, *tmp1;

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
	res->res.resProperty.ulPropTag = 0x801f001e; /* EMAIL */
	res->res.resProperty.lpProp.ulPropTag = 0x801f001e; /* EMAIL*/
	res->res.resProperty.lpProp.value.lpszA = email;

	return TRUE;
}

static gboolean
build_multiple_restriction_emails_contains (struct mapi_SRestriction *res, 
				            struct mapi_SRestriction_or *or_res, 
					    const char *query)
{
	char *email=NULL, *tmp, *tmp1;
	//Number of restriction to apply
	unsigned int res_count = 6;

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
	or_res[0].res.resContent.ulPropTag = PR_EMS_AB_MANAGER_T;
	or_res[0].res.resContent.lpProp.value.lpszA = email;

	or_res[1].rt = RES_CONTENT;
	or_res[1].res.resContent.fuzzy = FL_FULLSTRING | FL_IGNORECASE;
	or_res[1].res.resContent.ulPropTag = PR_DISPLAY_NAME;
	or_res[1].res.resContent.lpProp.value.lpszA = email;

	or_res[2].rt = RES_CONTENT;
	or_res[2].res.resContent.fuzzy = FL_FULLSTRING | FL_IGNORECASE;
	or_res[2].res.resContent.ulPropTag = PR_GIVEN_NAME;
	or_res[2].res.resContent.lpProp.value.lpszA = email;

	or_res[3].rt = RES_CONTENT;
	or_res[3].res.resContent.fuzzy = FL_FULLSTRING | FL_IGNORECASE;
	or_res[3].res.resContent.ulPropTag = 0x8084001e;
	or_res[3].res.resContent.lpProp.value.lpszA = email;

	or_res[4].rt = RES_CONTENT;
	or_res[4].res.resContent.fuzzy = FL_FULLSTRING | FL_IGNORECASE;
	or_res[4].res.resContent.ulPropTag = 0x8094001e;
	or_res[4].res.resContent.lpProp.value.lpszA = email;

	or_res[5].rt = RES_CONTENT;
	or_res[5].res.resContent.fuzzy = FL_FULLSTRING | FL_IGNORECASE;
	or_res[5].res.resContent.ulPropTag = 0x80a4001e;
	or_res[5].res.resContent.lpProp.value.lpszA = email;

	res = g_new0 (struct mapi_SRestriction, 1);

	res->rt = RES_OR;
	res->res.resOr.cRes = res_count;
	res->res.resOr.res = or_res;

	return TRUE;
}

static char *
get_filename_from_uri (const char *uri, const char *file)
{
	char *mangled_uri, *filename;
	int i;

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
	char **tokens;
	char *uri = NULL;
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

static char *
e_book_backend_mapi_get_static_capabilities (EBookBackend *backend)
{
	if(enable_debug)
		printf("mapi get_static_capabilities\n");
	//FIXME: Implement this.
	
	return g_strdup ("net,bulk-removes,do-initial-query,contact-lists");
}

gboolean
mapi_book_build_name_id (struct mapi_nameid *nameid, gpointer data)
{
//	EContact *contact = data;
	
	mapi_nameid_lid_add(nameid, 0x8005, PSETID_Address);
	mapi_nameid_lid_add(nameid, 0x8084, PSETID_Address);
	mapi_nameid_lid_add(nameid, 0x8083, PSETID_Address);

	mapi_nameid_lid_add(nameid, 0x8093, PSETID_Address);
	mapi_nameid_lid_add(nameid, 0x80A3, PSETID_Address);
	
	mapi_nameid_string_add(nameid, "urn:schemas:contacts:fileas", PS_PUBLIC_STRINGS);

	mapi_nameid_lid_add(nameid, 0x802B, PSETID_Address);
	mapi_nameid_lid_add(nameid, 0x8062, PSETID_Address);

	mapi_nameid_lid_add(nameid, 0x801A, PSETID_Address);	
	mapi_nameid_lid_add(nameid, 0x801B, PSETID_Address);

	mapi_nameid_lid_add(nameid, 0x3A4F, PS_MAPI);

	mapi_nameid_lid_add(nameid, 0x8094, PSETID_Address);
	mapi_nameid_lid_add(nameid, 0x80A4, PSETID_Address);

	return TRUE;
}

#define set_str_value(field_id, hex) if (e_contact_get (contact, field_id)) set_SPropValue_proptag (&props[i++], hex, e_contact_get (contact, field_id));

int
mapi_book_build_props (struct SPropValue ** value, struct SPropTagArray * SPropTagArray, gpointer data)
{
	EContact *contact = data;	
	struct SPropValue *props;
	int i=0;

	for (i=0; i<13; i++)
		printf("hex %x\n", SPropTagArray->aulPropTag[i]);
	i=0;
	props = g_new (struct SPropValue, 50); //FIXME: Correct value tbd
	set_str_value ( E_CONTACT_FILE_AS, SPropTagArray->aulPropTag[0]);

	set_str_value (E_CONTACT_FULL_NAME, PR_DISPLAY_NAME);
	set_SPropValue_proptag(&props[i++], PR_MESSAGE_CLASS, (const void *)IPM_CONTACT);
	set_str_value (E_CONTACT_FILE_AS, PR_NORMALIZED_SUBJECT);
	set_str_value (E_CONTACT_EMAIL_1,  SPropTagArray->aulPropTag[1]);
//	set_str_value (E_CONTACT_EMAIL_1,  SPropTagArray->aulPropTag[2]);
	set_str_value (E_CONTACT_FILE_AS,  SPropTagArray->aulPropTag[5]);

	
//	set_str_value ( E_CONTACT_EMAIL_1, 0x8083001e);
	set_str_value ( E_CONTACT_EMAIL_2, SPropTagArray->aulPropTag[3]);
//	set_str_value ( E_CONTACT_EMAIL_2, SPropTagArray->aulPropTag[11]);
	
	set_str_value ( E_CONTACT_EMAIL_3, SPropTagArray->aulPropTag[4]);
//	set_str_value ( E_CONTACT_EMAIL_3, SPropTagArray->aulPropTag[12]);
	
	set_str_value (E_CONTACT_HOMEPAGE_URL, SPropTagArray->aulPropTag[6]);
	set_str_value (E_CONTACT_FREEBUSY_URL, 0x812C001E);
	

	set_str_value ( E_CONTACT_PHONE_BUSINESS, PR_OFFICE_TELEPHONE_NUMBER);
	set_str_value ( E_CONTACT_PHONE_HOME, PR_HOME_TELEPHONE_NUMBER);
	set_str_value ( E_CONTACT_PHONE_MOBILE, PR_MOBILE_TELEPHONE_NUMBER);
	set_str_value ( E_CONTACT_PHONE_HOME_FAX, PR_HOME_FAX_NUMBER);
	set_str_value ( E_CONTACT_PHONE_BUSINESS_FAX, PR_BUSINESS_FAX_NUMBER);
	set_str_value ( E_CONTACT_PHONE_PAGER, PR_PAGER_TELEPHONE_NUMBER);
	set_str_value ( E_CONTACT_PHONE_ASSISTANT, PR_ASSISTANT_TELEPHONE_NUMBER);
	set_str_value ( E_CONTACT_PHONE_COMPANY, PR_COMPANY_MAIN_PHONE_NUMBER);

	set_str_value (E_CONTACT_MANAGER, PR_MANAGER_NAME);
	set_str_value (E_CONTACT_ASSISTANT, PR_ASSISTANT);
	set_str_value (E_CONTACT_ORG, PR_COMPANY_NAME);
	set_str_value (E_CONTACT_ORG_UNIT, PR_DEPARTMENT_NAME);
	set_str_value (E_CONTACT_ROLE, PR_PROFESSION);
	set_str_value (E_CONTACT_TITLE, PR_TITLE);

	set_str_value (E_CONTACT_OFFICE, PR_OFFICE_LOCATION);
	set_str_value (E_CONTACT_SPOUSE, PR_SPOUSE_NAME);

	set_str_value (E_CONTACT_NOTE, PR_BODY);

	//BDAY AND ANNV
	if (e_contact_get (contact, E_CONTACT_BIRTH_DATE)) {
		EContactDate *date = e_contact_get (contact, E_CONTACT_BIRTH_DATE);
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
		printf("sending bday\n");
		set_SPropValue_proptag (&props[i++], PR_BIRTHDAY, &t);
	}

	if (e_contact_get (contact, E_CONTACT_ANNIVERSARY)) {
		EContactDate *date = e_contact_get (contact, E_CONTACT_ANNIVERSARY);
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
		printf("sending wed\n");
		set_SPropValue_proptag (&props[i++], PR_WEDDING_ANNIVERSARY, &t);
	}	
	//Home and Office address
	if (e_contact_get (contact, E_CONTACT_ADDRESS_HOME)) {
		EContactAddress *contact_addr;

		contact_addr = e_contact_get (contact, E_CONTACT_ADDRESS_HOME);
		set_SPropValue_proptag (&props[i++], SPropTagArray->aulPropTag[8], contact_addr->street);
		set_SPropValue_proptag (&props[i++], PR_HOME_ADDRESS_POST_OFFICE_BOX, contact_addr->ext);
		set_SPropValue_proptag (&props[i++], PR_HOME_ADDRESS_CITY, contact_addr->locality);
		set_SPropValue_proptag (&props[i++], PR_HOME_ADDRESS_STATE_OR_PROVINCE, contact_addr->region);
		set_SPropValue_proptag (&props[i++], PR_HOME_ADDRESS_POSTAL_CODE, contact_addr->code);
		set_SPropValue_proptag (&props[i++], PR_HOME_ADDRESS_COUNTRY, contact_addr->country);				
	}

	if (e_contact_get (contact, E_CONTACT_ADDRESS_WORK)) {
		EContactAddress *contact_addr;

		contact_addr = e_contact_get (contact, E_CONTACT_ADDRESS_WORK);
		set_SPropValue_proptag (&props[i++], SPropTagArray->aulPropTag[9], contact_addr->street);
		set_SPropValue_proptag (&props[i++], PR_POST_OFFICE_BOX, contact_addr->ext);
		set_SPropValue_proptag (&props[i++], PR_LOCALITY, contact_addr->locality);
		set_SPropValue_proptag (&props[i++], PR_STATE_OR_PROVINCE, contact_addr->region);
		set_SPropValue_proptag (&props[i++], PR_POSTAL_CODE, contact_addr->code);
		set_SPropValue_proptag (&props[i++], PR_COUNTRY, contact_addr->country);				
	}

	
// 	set_str_value (E_CONTACT_NICKNAME, SPropTagArray->aulPropTag[10]); 
	if (e_contact_get (contact, E_CONTACT_IM_AIM)) {
		GList *l = e_contact_get (contact, E_CONTACT_IM_AIM);
		set_SPropValue_proptag (&props[i++], SPropTagArray->aulPropTag[7], l->data);
	}

	if (e_contact_get (contact, E_CONTACT_NICKNAME)) {
		char *nick  = e_contact_get (contact, E_CONTACT_NICKNAME);
//		set_SPropValue_proptag (&props[i++], SPropTagArray->aulPropTag[10], nick);
		printf("nickname %s %x\n", nick,  SPropTagArray->aulPropTag[10]);
	}
	
	*value =props;
	printf("Sending %d \n", i);
	return i;
}

static void
e_book_backend_mapi_create_contact (EBookBackend *backend,
					  EDataBook *book,
					  guint32 opid,
					  const char *vcard )
{
	EContact *contact;
	char *id;
	mapi_id_t status;
	EBookBackendMAPIPrivate *priv = ((EBookBackendMAPI *) backend)->priv;

	if(enable_debug)
		printf("mapi create_contact \n");
	
	switch (priv->mode) {

	case GNOME_Evolution_Addressbook_MODE_LOCAL :
		e_data_book_respond_create(book, opid, GNOME_Evolution_Addressbook_RepositoryOffline, NULL);
		return;
	   
	case  GNOME_Evolution_Addressbook_MODE_REMOTE :
		contact = e_contact_new_from_vcard(vcard);
		status = exchange_mapi_create_item (olFolderContacts, priv->fid, mapi_book_build_name_id, contact, mapi_book_build_props, contact, NULL, NULL, NULL, 0);
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
			
	if(enable_debug)
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

		exchange_mapi_remove_items (olFolderContacts, priv->fid, list);
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
					  const char   *vcard)
{
	EBookBackendMAPIPrivate *priv = ((EBookBackendMAPI *) backend)->priv;
	EContact *contact;
	mapi_id_t fid, mid;
	gboolean status;
	char *tmp;
	
	if(enable_debug)
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
		
		status = exchange_mapi_modify_item (olFolderContacts, priv->fid, mid, mapi_book_build_name_id, contact, mapi_book_build_props, contact, NULL, NULL, NULL, 0);
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
	char *suid;
	GSList *recipients = item_data->recipients;
	
	contact = emapidump_contact (item_data->properties);
	suid = exchange_mapi_util_mapi_ids_to_uid (item_data->fid, item_data->mid);
	printf("got contact %s\n", suid);
	if (contact) {
		/* UID of the contact is nothing but the concatenated string of hex id of folder and the message.*/
		e_contact_set (contact, E_CONTACT_UID, suid);
		data = contact;
	}

	exchange_mapi_util_free_recipient_list (&recipients);

	g_free (suid);

	return TRUE;
}

static void
e_book_backend_mapi_get_contact (EBookBackend *backend,
				       EDataBook    *book,
				       guint32       opid,
				       const char   *id)
{
	EBookBackendMAPIPrivate *priv = ((EBookBackendMAPI *) backend)->priv;
	EContact *contact = NULL;
	char *vcard;
	
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
			exchange_mapi_connection_fetch_item (priv->fid, mid, 
							NULL, 0, 
							NULL, NULL, 
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
	char *suid;
	
	contact = emapidump_contact (array);
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

static const uint32_t GetPropsList[] = {
	PR_FID,
	PR_MID,
	PR_INST_ID,
	PR_INSTANCE_NUM,
	PR_SUBJECT,
	PR_MESSAGE_CLASS,
	PR_HASATTACH,
/* FIXME: is this tag fit to check if a recipient table exists or not ? */
//	PR_DISCLOSURE_OF_RECIPIENTS,
	PR_RULE_MSG_PROVIDER,
	PR_RULE_MSG_NAME
};
static const uint16_t n_GetPropsList = G_N_ELEMENTS (GetPropsList);

gboolean
mapi_book_build_name_id_for_getprops (struct mapi_nameid *nameid, gpointer data)
{
	mapi_nameid_lid_add(nameid, 0x8084, PSETID_Address); /* PT_STRING8 - EmailOriginalDisplayName */
//	mapi_nameid_lid_add(nameid, 0x8020, PSETID_Address);
//	mapi_nameid_lid_add(nameid, 0x8021, PSETID_Address);
	mapi_nameid_lid_add(nameid, 0x8094, PSETID_Address);
	mapi_nameid_lid_add(nameid, 0x80a4, PSETID_Address);

	return TRUE;
}

static void
e_book_backend_mapi_get_contact_list (EBookBackend *backend,
					    EDataBook    *book,
					    guint32       opid,
					    const char   *query )
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

			for (l = contacts; l ;l = g_list_next (l)) {
				EContact *contact = l->data;
				vcard_strings = g_list_prepend (vcard_strings, e_vcard_to_string (E_VCARD (contact),
							        EVC_FORMAT_VCARD_30));
				g_object_unref (contact);
			}

			g_list_free (contacts);
			printf("get_contact_list in %s  returning %d contacts\n", priv->uri, g_list_length (vcard_strings));			
			e_data_book_respond_get_contact_list (book, opid, GNOME_Evolution_Addressbook_Success, vcard_strings);
			return ;
		}
		else {
			struct mapi_SRestriction res;
			GList *vcard_str = NULL;

			printf("Not marked for cache\n");

			/* Unfortunately MAPI Doesn't support searching well, we do allow only online search for emails rest all are returned as error. */
			if (!build_restriction_emails_contains (&res, query)) {
				e_data_book_respond_get_contact_list (book, opid, GNOME_Evolution_Addressbook_OtherError, NULL);
				return ;				
			}

			if (!exchange_mapi_connection_fetch_items (priv->fid, &res, NULL,
								GetPropsList, n_GetPropsList, 
								mapi_book_build_name_id_for_getprops, NULL, 
								create_contact_list_cb, &vcard_str, 
								MAPI_OPTIONS_FETCH_ALL)) {
				e_data_book_respond_get_contact_list (book, opid, GNOME_Evolution_Addressbook_OtherError, NULL);
				return ;
			}
			printf("get_contact_list in %s returning %d contacts\n", priv->uri, g_list_length (vcard_str));			
			e_data_book_respond_get_contact_list (book, opid, GNOME_Evolution_Addressbook_Success, vcard_str);
			return ;
			
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
emapidump_contact(struct mapi_SPropValue_array *properties)
{
	EContact *contact = e_contact_new ();
	int i;
	
//	exchange_mapi_debug_property_dump (properties);
	for (i=1; i<maplen; i++) {
		gpointer value;

		/* can cast it, no writing to the value; and it'll be freed not before the end of this function */
		value = (gpointer) find_mapi_SPropValue_data (properties, mappings[i].mapi_id);
		if (mappings[i].element_type == PT_STRING8 && mappings[i].contact_type == ELEMENT_TYPE_SIMPLE) {
			if (value)
				e_contact_set (contact, mappings[i].field_id, value);
		} else if (mappings[i].contact_type == ELEMENT_TYPE_SIMPLE) {
			if (value && mappings[i].element_type == PT_SYSTIME) {
				struct FILETIME *t = value;
				time_t time;
				NTTIME nt;
				char buff[129];

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
					contact_addr.street = (char *)value;
					contact_addr.ext = (char *)find_mapi_SPropValue_data (properties, PR_HOME_ADDRESS_POST_OFFICE_BOX);
					contact_addr.locality = (char *)find_mapi_SPropValue_data (properties, PR_HOME_ADDRESS_CITY);
					contact_addr.region = (char *)find_mapi_SPropValue_data (properties, PR_HOME_ADDRESS_STATE_OR_PROVINCE);
					contact_addr.code = (char *)find_mapi_SPropValue_data (properties, PR_HOME_ADDRESS_POSTAL_CODE);
					contact_addr.country = (char *)find_mapi_SPropValue_data (properties, PR_HOME_ADDRESS_COUNTRY);
				} else {
					contact_addr.address_format = NULL;
					contact_addr.po = NULL;
					contact_addr.street = (char *)value;
					contact_addr.ext = (char *)find_mapi_SPropValue_data (properties, PR_POST_OFFICE_BOX);
					contact_addr.locality = (char *)find_mapi_SPropValue_data (properties, PR_LOCALITY);
					contact_addr.region = (char *)find_mapi_SPropValue_data (properties, PR_STATE_OR_PROVINCE);
					contact_addr.code = (char *)find_mapi_SPropValue_data (properties, PR_POSTAL_CODE);
					contact_addr.country = (char *)find_mapi_SPropValue_data (properties, PR_COUNTRY);
				}
				e_contact_set (contact, mappings[i].field_id, &contact_addr);
			}
		}
	}
	
	return contact;
}

static void
get_contacts_from_cache (EBookBackendMAPI *ebmapi, 
			 const char *query,
			 GPtrArray *ids,
			 EDataBookView *book_view, 
			 BESearchClosure *closure)
{
	int i;

	if (enable_debug)
		printf ("\nread contacts from cache for the ids found in summary\n");
	for (i = 0; i < ids->len; i ++) {
		char *uid;
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
	char *suid;
	
	if (!e_flag_is_set (closure->running)) {
		printf("Might be that the operation is cancelled. Lets ask our parent also to do.\n");
		return FALSE;
	}
	
	contact = emapidump_contact (item_data->properties);
	suid = exchange_mapi_util_mapi_ids_to_uid (item_data->fid, item_data->mid);
	
	if (contact) {
		/* UID of the contact is nothing but the concatenated string of hex id of folder and the message.*/
		e_contact_set (contact, E_CONTACT_UID, suid);		
		e_contact_set (contact, E_CONTACT_BOOK_URI, priv->uri);
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
	const char *query = NULL;
	GPtrArray *ids = NULL;
	GList *contacts = NULL, *temp_list = NULL;
	//Number of multiple restriction to apply
	unsigned int res_count = 6;
	
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

		if (!exchange_mapi_connection_exists ()) {
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
				return ;
			} 

			//FIXME: We need to fetch only the query from the server live and not everything.
			if (!exchange_mapi_connection_fetch_items (priv->fid, &res, NULL,
							   GetPropsList, n_GetPropsList, 
							   mapi_book_build_name_id_for_getprops, NULL, 
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
			if (!exchange_mapi_connection_fetch_items (priv->fid, NULL, NULL,
							NULL, 0, 
							NULL, NULL, 
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
	if(enable_debug)
		printf("mapi: stop book view\n");	
	/* FIXME : provide implmentation */
}

static void
e_book_backend_mapi_get_changes (EBookBackend *backend,
				       EDataBook    *book,
				       guint32       opid,
				       const char *change_id  )
{
	if(enable_debug)
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
	char *suid;

	contact = emapidump_contact (item_data->properties);
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
	char *tmp;
	
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
	
	if (!exchange_mapi_connection_fetch_items (priv->fid, NULL, NULL,
						NULL, 0, 
						NULL, NULL, 
						cache_contact_cb, ebmapi, 
						MAPI_OPTIONS_FETCH_ALL)) {
		printf("Error during caching addressbook\n");
		e_file_cache_thaw_changes (E_FILE_CACHE (priv->cache));
		return NULL;
	}
	tmp = g_strdup_printf("%d", (int)time (NULL));
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
	char *tmp = e_book_backend_cache_get_time (priv->cache);
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
	
	if (!exchange_mapi_connection_fetch_items ( priv->fid, &res, NULL,
						NULL, 0, 
						NULL, NULL, 
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
					    const char *user,
					    const char *passwd,
					    const char *auth_method)
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
		
		if (!exchange_mapi_connection_new (priv->profile, NULL))
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
  
	fields = g_list_append (fields, (char *)e_contact_field_name (E_CONTACT_FILE_AS));
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
	int i;

	if (enable_debug)
		printf ("mapi get_supported_fields...\n");

	for (i=0; i<maplen; i++)
	{
		fields = g_list_append (fields, (char *)e_contact_field_name (mappings[i].field_id));
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
	char *auth_method;
	
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
	char *cache_uri = NULL;
	gboolean status;

	if(enable_debug)
		printf("mapi: remove\n");
	
	switch (priv->mode) {
	
	case GNOME_Evolution_Addressbook_MODE_LOCAL:
		e_data_book_respond_remove (book, opid, GNOME_Evolution_Addressbook_OfflineUnavailable);
		return;
		
	case GNOME_Evolution_Addressbook_MODE_REMOTE:

		status = exchange_mapi_remove_folder (olFolderContacts, priv->fid);
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
e_book_backend_mapi_set_mode (EBookBackend *backend, int mode)
{
	EBookBackendMAPIPrivate *priv = ((EBookBackendMAPI *) backend)->priv;

	if(enable_debug)
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


GType	e_book_backend_mapi_get_type (void)
{
	static GType type = 0;
	
	if (! type) {
		GTypeInfo info = {
			sizeof (EBookBackendMAPIClass),
			NULL, /* base_class_init */
			NULL, /* base_class_finalize */
			(GClassInitFunc)  e_book_backend_mapi_class_init,
			NULL, /* class_finalize */
			NULL, /* class_data */
			sizeof (EBookBackendMAPI),
			0,    /* n_preallocs */
			(GInstanceInitFunc) e_book_backend_mapi_init
		};
		
		type = g_type_register_static (E_TYPE_BOOK_BACKEND, "EBookBackendMAPI", &info, 0);
	}
	
	return type;
}
