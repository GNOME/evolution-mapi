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
 *     Johnny Jacob <jjohnny@novell.com>
 *
 * Copyright (C) 1999-2008 Novell, Inc. (www.novell.com)
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>

#include <glib/gstdio.h>

#include <camel/camel-sasl.h>
#include <camel/camel-utf8.h>
#include <camel/camel-tcp-stream-raw.h>

#ifdef HAVE_SSL
#include <camel/camel-tcp-stream-ssl.h>
#endif

#include <camel/camel-private.h>
#include <camel/camel-session.h>
#include <camel/camel-service.h>
#include <camel/camel-store-summary.h>
#include <camel/camel-i18n.h>
#include <camel/camel-net-utils.h>

#include "camel-mapi-store.h"
#include "camel-mapi-folder.h"
#include "camel-mapi-store-summary.h"
#include "camel-mapi-summary.h"
#include "camel-mapi-notifications.h"

#include <exchange-mapi-utils.h>
//#define d(x) x


/* This definition should be in-sync with those in exchange-mapi-account-setup.c and exchange-account-listener.c */
#define E_PASSWORD_COMPONENT "ExchangeMAPI"

#define DISPLAY_NAME_FAVOURITES _("Favorites")
#define DISPLAY_NAME_ALL_PUBLIC_FOLDERS _("All Public Folders")

#include <sys/types.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <libmapi/libmapi.h>
#include <param.h>

#define d(x) printf("%s:%s:%s \n", G_STRLOC, G_STRFUNC, x)

struct _CamelMapiStorePrivate {
	char *user;
	const char *profile;
	char *base_url;
	char *storage_path;

	GHashTable *id_hash; /*get names from ids*/
	GHashTable *name_hash;/*get ids from names*/
	GHashTable *parent_hash;
	GHashTable *default_folders; /*Default Type : Folder ID*/

	gboolean folders_synced; /* whether were synced folder list already */
	gpointer notification_data; /* pointer to a notification data; can be only one */
};

static CamelOfflineStoreClass *parent_class = NULL;

static void	camel_mapi_store_class_init(CamelMapiStoreClass *);
static void	camel_mapi_store_init(CamelMapiStore *, CamelMapiStoreClass *);
static void	camel_mapi_store_finalize(CamelObject *);

/* service methods */
static void	mapi_construct(CamelService *, CamelSession *,
				     CamelProvider *, CamelURL *,
				     CamelException *);
static char	*mapi_get_name(CamelService *, gboolean );
static gboolean	mapi_connect(CamelService *, CamelException *);
static gboolean	mapi_disconnect(CamelService *, gboolean , CamelException *);
static GList	*mapi_query_auth_types(CamelService *, CamelException *);

/* store methods */
static CamelFolder	*mapi_get_folder(CamelStore *, const char *, guint32, CamelException *);
static CamelFolderInfo	*mapi_create_folder(CamelStore *, const char *, const char *, CamelException *);
static void		mapi_delete_folder(CamelStore *, const char *, CamelException *);
static void		mapi_rename_folder(CamelStore *, const char *, const char *, CamelException *);
static CamelFolderInfo	*mapi_get_folder_info(CamelStore *, const char *, guint32, CamelException *);
static void		mapi_subscribe_folder(CamelStore *, const char *, CamelException *);
static gboolean mapi_folder_subscribed (CamelStore *store, const char *folder_name);
static void		mapi_unsubscribe_folder(CamelStore *, const char *, CamelException *);
static void		mapi_noop(CamelStore *, CamelException *);
static CamelFolderInfo * mapi_build_folder_info(CamelMapiStore *mapi_store, const char *parent_name, const char *folder_name);
static gboolean mapi_fid_is_system_folder (CamelMapiStore *mapi_store, const char *fid);

static void mapi_update_folder_hash_tables (CamelMapiStore *store, const gchar *name, const gchar *fid, const gchar *parent_id);
/* static const gchar* mapi_folders_hash_table_name_lookup (CamelMapiStore *store, const gchar *fid, gboolean use_cache); */
#if 0
static const gchar* mapi_folders_hash_table_fid_lookup (CamelMapiStore *store, const gchar *name, gboolean use_cache);
#endif

#if 0
static void
dump_summary (CamelMapiStore *mstore)
{
	CamelStoreSummary *summary = (CamelStoreSummary *) mstore->summary;
	gint summary_count = camel_store_summary_count (summary);
	guint i = 0;

	printf ("%s: dumping %d items:\n", G_STRFUNC, summary_count);
	for (i = 0; i < summary_count; i++) {
		CamelStoreInfo *csi = camel_store_summary_index(summary, i);
		CamelMapiStoreInfo *si = (CamelMapiStoreInfo *) csi;

		printf ("[%2d] ", i);
		if (si == NULL) {
			printf ("NULL\n");
			continue;
		} /*else if (strstr (si->full_name, "/s3/") == NULL) {
			printf ("   '%s'\n", si->full_name);
			camel_store_summary_info_free ((CamelStoreSummary *)mstore->summary, csi);
			continue;
		}*/

		printf ("   full name: '%s'\n", si->full_name);
		printf ("   folder id: '%s'\n", si->folder_id);
		printf ("   parent id: '%s'\n", si->parent_id);
		printf ("   path: '%s'\n", csi->path);
		printf ("   uri: '%s'\n", csi->uri?csi->uri:"[null]");
		printf ("   flags:%x unread:%d total:%d\n", csi->flags, csi->unread, csi->total);
		camel_store_summary_info_free ((CamelStoreSummary *)mstore->summary, csi);
	}
	printf ("\n");
}
#endif

static guint
mapi_hash_folder_name(gconstpointer key)
{
	return g_str_hash(key);
}

static gint
mapi_compare_folder_name(gconstpointer a, gconstpointer b)
{
	gconstpointer	aname = a; 
	gconstpointer	bname = b;
  
	return g_str_equal(aname, bname);
}

static void
camel_mapi_store_class_init(CamelMapiStoreClass *klass)
{
	CamelServiceClass	*service_class = 
		CAMEL_SERVICE_CLASS (klass);
	CamelStoreClass		*store_class = (CamelStoreClass *) klass;

	parent_class = (CamelOfflineStoreClass *) camel_type_get_global_classfuncs(CAMEL_TYPE_OFFLINE_STORE);

	service_class->construct = mapi_construct;
	service_class->get_name = mapi_get_name;
	service_class->connect = mapi_connect;
	service_class->disconnect = mapi_disconnect;
	service_class->query_auth_types = mapi_query_auth_types;

	store_class->hash_folder_name = mapi_hash_folder_name;
	store_class->compare_folder_name = mapi_compare_folder_name;
	/* store_class->get_inbox = mapi_get_inbox; */
	store_class->get_folder = mapi_get_folder;
	store_class->create_folder = mapi_create_folder;
	store_class->delete_folder = mapi_delete_folder;
	store_class->rename_folder = mapi_rename_folder;
	store_class->get_folder_info = mapi_get_folder_info;
	store_class->subscribe_folder = mapi_subscribe_folder;
	store_class->folder_subscribed = mapi_folder_subscribed;
	store_class->unsubscribe_folder = mapi_unsubscribe_folder;
	store_class->noop = mapi_noop;
}

CamelType 
camel_mapi_store_get_type(void)
{
	static CamelType camel_mapi_store_type = CAMEL_INVALID_TYPE;
  
	if (camel_mapi_store_type == CAMEL_INVALID_TYPE) {
		camel_mapi_store_type = camel_type_register(camel_offline_store_get_type (),
							    "CamelMapiStores",
							    sizeof (CamelMapiStore),
							    sizeof (CamelMapiStoreClass),
							    (CamelObjectClassInitFunc) camel_mapi_store_class_init,
							    NULL,
							    (CamelObjectInitFunc) camel_mapi_store_init,
							    (CamelObjectFinalizeFunc) camel_mapi_store_finalize);
	}

	return camel_mapi_store_type;
}

/*
** store is already initilyse to NULL or 0 value
** klass already have a parent_class
** nothing must be doing here
*/
static void camel_mapi_store_init(CamelMapiStore *store, CamelMapiStoreClass *klass)
{
	CamelMapiStore *mapi_store = CAMEL_MAPI_STORE (store);
	CamelMapiStorePrivate *priv = g_new0 (CamelMapiStorePrivate, 1);

	mapi_store->summary = NULL;

	priv->storage_path = NULL;
	priv->base_url = NULL;
	priv->folders_synced = FALSE;
	priv->notification_data = NULL;

	mapi_store->priv = priv;

}

static void camel_mapi_store_finalize(CamelObject *object)
{
}

/* service methods */
static void mapi_construct(CamelService *service, CamelSession *session,
				 CamelProvider *provider, CamelURL *url,
				 CamelException *ex)
{
	CamelMapiStore	*mapi_store = CAMEL_MAPI_STORE (service);
	CamelStore *store = CAMEL_STORE (service);
	CamelMapiStorePrivate *priv = mapi_store->priv;
	char *path = NULL;
	
	CAMEL_SERVICE_CLASS (parent_class)->construct (service, session, provider, url, ex);

	if (camel_exception_is_set (ex))
		return;
	
/* 	if (!(url->host || url->user)) { */
/* 		camel_exception_set (ex, CAMEL_EXCEPTION_SERVICE_INVALID, */
/* 				     _("Host or user not available in url")); */
/* 	} */

	/*storage path*/
	priv->storage_path = camel_session_get_storage_path (session, service, ex);
	if (!priv->storage_path)
		return;
	
	/*store summary*/
	path = g_alloca (strlen (priv->storage_path) + 32);
	sprintf (path, "%s/.summary", priv->storage_path);

	mapi_store->summary = camel_mapi_store_summary_new ();
	camel_store_summary_set_filename ((CamelStoreSummary *)mapi_store->summary, path);

	camel_store_summary_touch ((CamelStoreSummary *)mapi_store->summary);
	camel_store_summary_load ((CamelStoreSummary *) mapi_store->summary);

	/*user and profile*/
	priv->user = g_strdup (url->user);
	priv->profile = g_strdup (camel_url_get_param(url, "profile"));

	/*base url*/
	priv->base_url = camel_url_to_string (service->url, (CAMEL_URL_HIDE_PASSWORD |
						       CAMEL_URL_HIDE_PARAMS   |
						       CAMEL_URL_HIDE_AUTH)  );


	/*filter*/
	if (camel_url_get_param (url, "filter"))
		store->flags |= CAMEL_STORE_FILTER_INBOX;

	/*Hash Table*/	
	priv->id_hash = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free); /* folder ID to folder Full name */
	priv->name_hash = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free); /* folder Full name to folder ID */
	/*priv->parent_hash = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free); / * folder ID to its parent folder ID */
	priv->default_folders = g_hash_table_new_full (g_int_hash, g_int_equal, g_free, g_free); /* default folder type to folder ID */

	store->flags &= ~CAMEL_STORE_VJUNK;
	store->flags &= ~CAMEL_STORE_VTRASH;

	store->flags |= CAMEL_STORE_SUBSCRIPTIONS;

}

static char
*mapi_get_name(CamelService *service, gboolean brief)
{
	if (brief) {
		return g_strdup_printf(_("Exchange MAPI server %s"), service->url->host);
	} else {
		/*To translators : Example string : Exchange MAPI service for 
		  _username_ on _server host name__*/
		return g_strdup_printf(_("Exchange MAPI service for %s on %s"),
				       service->url->user, service->url->host);
	}
}

static gboolean
check_for_connection (CamelService *service, CamelException *ex)
{
	/*Fixme : What happens when the network connection drops. 
	  will mapi subsystem handle that ?*/
	return exchange_mapi_connection_exists ();
}

static gboolean
mapi_auth_loop (CamelService *service, CamelException *ex)
{
	CamelSession *session = camel_service_get_session (service);

	char *errbuf = NULL;
	gboolean authenticated = FALSE;

	service->url->passwd = NULL;

	while (!authenticated) {
		if (errbuf) {
			/* We need to un-cache the password before prompting again */
			camel_session_forget_password (session, service, E_PASSWORD_COMPONENT, "password", ex);
			g_free (service->url->passwd);
			service->url->passwd = NULL;
		}
	
		if (!service->url->passwd ){
			char *prompt;
			
			/*To translators : First %s : is the error text or the reason
			  for prompting the user if it is available.
			 Second %s is : Username.
			 Third %s is : Server host name.*/
			prompt = g_strdup_printf (_("%s Please enter the MAPI password for %s@%s"),
						  errbuf ? errbuf : "",
						  service->url->user,
						  service->url->host);
			service->url->passwd =
				camel_session_get_password (session, service, E_PASSWORD_COMPONENT,
							    prompt, "password", CAMEL_SESSION_PASSWORD_SECRET, ex);
			g_free (prompt);
			g_free (errbuf);
			errbuf = NULL;
			
			if (!service->url->passwd) {
				camel_exception_set (ex, CAMEL_EXCEPTION_USER_CANCEL,
						     _("You did not enter a password."));
				return FALSE;
			}
		}
		
		exchange_mapi_connection_new (NULL,service->url->passwd);

		if (!exchange_mapi_connection_exists ()) {
			errbuf = g_strdup_printf (_("Unable to authenticate to Exchange MAPI server."));
						  
			camel_exception_clear (ex);
		} else 
			authenticated = TRUE;
		
	}
	return TRUE;
}


static gboolean
mapi_connect(CamelService *service, CamelException *ex)
{
	CamelMapiStore *store = CAMEL_MAPI_STORE (service);
	CamelMapiStorePrivate *priv = store->priv;
	guint16 event_mask = 0;

	if (service->status == CAMEL_SERVICE_DISCONNECTED) {
		return FALSE;
	}

	if (!priv) {
		store->priv = g_new0 (CamelMapiStorePrivate, 1);
		priv = store->priv;
		camel_service_construct (service, service->session, service->provider, service->url, ex);
	}

	CAMEL_SERVICE_REC_LOCK (service, connect_lock);
	if (check_for_connection (service, ex)) {
		CAMEL_SERVICE_REC_UNLOCK (service, connect_lock);
		return TRUE;
	}

	if (!mapi_auth_loop (service, ex)) {
		CAMEL_SERVICE_REC_UNLOCK (service, connect_lock);
		camel_service_disconnect (service, TRUE, NULL);
		return FALSE;
	}
	
	service->status = CAMEL_SERVICE_CONNECTED;
	((CamelOfflineStore *) store)->state = CAMEL_OFFLINE_STORE_NETWORK_AVAIL;

	/* Start event monitor */
	event_mask = fnevNewMail | fnevObjectCreated | fnevObjectDeleted |
		fnevObjectModified | fnevObjectMoved | fnevObjectCopied;

	CAMEL_SERVICE_REC_LOCK (store, connect_lock);

	if (!store->priv->notification_data)
		store->priv->notification_data = camel_mapi_notification_listener_start (store, event_mask, MAPI_EVENTS_USE_STORE);

	CAMEL_SERVICE_REC_UNLOCK (store, connect_lock);

	camel_store_summary_save ((CamelStoreSummary *) store->summary);

	CAMEL_SERVICE_REC_UNLOCK (service, connect_lock);

	return TRUE;
}

void
camel_mapi_store_unset_notification_data (CamelMapiStore *mstore)
{
	g_return_if_fail (mstore != NULL);
	g_return_if_fail (CAMEL_IS_MAPI_STORE (mstore));

	mstore->priv->notification_data = NULL;
}

static gboolean 
mapi_disconnect(CamelService *service, gboolean clean, CamelException *ex)
{
	CamelMapiStore *store = CAMEL_MAPI_STORE (service);

	/* Disconnect from event monitor */
	if (store->priv->notification_data) {
		camel_mapi_notification_listener_stop (store, store->priv->notification_data);
		store->priv->notification_data = NULL;
	}

	/* Close the mapi subsystem */
	exchange_mapi_connection_close ();

	store->priv->folders_synced = FALSE;

	((CamelOfflineStore *) store)->state = CAMEL_OFFLINE_STORE_NETWORK_UNAVAIL;
	service->status = CAMEL_SERVICE_DISCONNECTED;

	return TRUE;
}

static GList *mapi_query_auth_types(CamelService *service, CamelException *ex)
{
	return NULL;
}


static gboolean 
hash_check_fid_presence (gpointer key, gpointer value, gpointer folder_id)
{
	return (g_ascii_strcasecmp (value, folder_id) == 0);
}

static gboolean
mapi_fid_is_system_folder (CamelMapiStore *mapi_store, const char *fid)
{
	CamelMapiStorePrivate *priv = mapi_store->priv;

	if (!(fid && *fid)) 
		return FALSE;

	return (g_hash_table_find (priv->default_folders, hash_check_fid_presence, (gpointer) fid) != NULL);
}

static const gchar*
mapi_system_folder_fid (CamelMapiStore *mapi_store, int folder_type)
{ 
	CamelMapiStorePrivate *priv = mapi_store->priv;

	return g_hash_table_lookup (priv->default_folders, &folder_type); 
}

static CamelFolder *
mapi_get_folder(CamelStore *store, const char *folder_name, guint32 flags, CamelException *ex)
{
	CamelMapiStore *mapi_store = CAMEL_MAPI_STORE (store);
	CamelMapiStorePrivate *priv = mapi_store->priv;
	CamelMapiStoreInfo *si;
	CamelFolder *folder;
	gchar *storage_path;

	si = camel_mapi_store_summary_full_name (mapi_store->summary, folder_name);
	if (!si && (flags & CAMEL_STORE_FOLDER_CREATE) == CAMEL_STORE_FOLDER_CREATE) {
		gchar *name, *tmp;
		const gchar *parent;
		CamelFolderInfo *folder_info;

		tmp = g_strdup (folder_name);
		if (!(name = strrchr (tmp, '/'))) {
			name = tmp;
			parent = "";
		} else {
			*name++ = '\0';
			parent = tmp;
		}

		folder_info = mapi_create_folder (store, parent, name, ex);
		g_free (tmp);

		if (!folder_info)
			return NULL;

		camel_folder_info_free (folder_info);
	}

	if (si)
		camel_store_summary_info_free ((CamelStoreSummary *)mapi_store->summary, (CamelStoreInfo *)si);

	storage_path = g_strdup_printf ("%s/folders", priv->storage_path);
	folder = camel_mapi_folder_new (store, folder_name, storage_path, flags, ex);
	g_free (storage_path);

	return folder;
}

static CamelFolderInfo*
mapi_create_folder(CamelStore *store, const char *parent_name, const char *folder_name, CamelException *ex)
{
	CamelMapiStore *mapi_store = CAMEL_MAPI_STORE (store);
	CamelMapiStorePrivate  *priv = mapi_store->priv;
	CamelFolderInfo *root = NULL;
	char *parent_id;
	mapi_id_t parent_fid, new_folder_id;

	if (((CamelOfflineStore *) store)->state == CAMEL_OFFLINE_STORE_NETWORK_UNAVAIL) {
		camel_exception_set (ex, CAMEL_EXCEPTION_SYSTEM, _("Cannot create MAPI folders in offline mode."));
		return NULL;
	}

	if (mapi_fid_is_system_folder (mapi_store, camel_mapi_store_folder_id_lookup (mapi_store, folder_name))) {
		camel_exception_setv (ex, CAMEL_EXCEPTION_SYSTEM, _("Cannot create new folder `%s'"),
				      folder_name);
		return NULL;
	}

	if (parent_name && (strlen(parent_name) > 0) )
		parent_id = g_strdup (g_hash_table_lookup (priv->name_hash, parent_name));
	else
		parent_id = g_strdup ("");

	if (!mapi_connect (CAMEL_SERVICE(store), ex)) {
			camel_exception_set (ex, CAMEL_EXCEPTION_SERVICE_CANT_AUTHENTICATE, _("Authentication failed"));
			return NULL;
	}

	CAMEL_SERVICE_REC_LOCK (store, connect_lock);

	exchange_mapi_util_mapi_id_from_string (parent_id, &parent_fid);
	new_folder_id = exchange_mapi_create_folder(olFolderInbox, parent_fid, folder_name);
	if (new_folder_id != 0) {
		CamelMapiStoreInfo *si;
		gchar *fid = g_strdup_printf ("%016" G_GINT64_MODIFIER "X", new_folder_id);

		root = mapi_build_folder_info(mapi_store, parent_name, folder_name);

		si = camel_mapi_store_summary_add_from_full(mapi_store->summary, root->full_name, '/', fid, parent_id);
		camel_store_summary_save((CamelStoreSummary *)mapi_store->summary);

		mapi_update_folder_hash_tables (mapi_store, root->full_name, fid, parent_id);

		camel_object_trigger_event (CAMEL_OBJECT (store), "folder_created", root);
	}

	CAMEL_SERVICE_REC_UNLOCK (store, connect_lock);
	return root;

}

static void
mapi_forget_folder (CamelMapiStore *mapi_store, const char *folder_name, CamelException *ex)
{
	CamelMapiStorePrivate *priv = mapi_store->priv;
	char *state_file;
	char *folder_dir, *storage_path;
	CamelFolderInfo *fi;
	const char *name;

	name = folder_name;

	storage_path = g_strdup_printf ("%s/folders", priv->storage_path);

	/* Fixme Path - e_*-to_path */
	folder_dir = g_strconcat (storage_path, "/", folder_name, NULL);
	g_free (storage_path);

	if (g_access(folder_dir, F_OK) != 0) {
		g_free(folder_dir);
		return;
	}

	state_file = g_strdup_printf ("%s/cmeta", folder_dir);
	g_unlink (state_file);
	g_free (state_file);

	g_rmdir (folder_dir);
	g_free (folder_dir);

	camel_store_summary_remove_path ((CamelStoreSummary *)mapi_store->summary, folder_name);
	camel_store_summary_save ((CamelStoreSummary *)mapi_store->summary);

	fi = mapi_build_folder_info (mapi_store, NULL, folder_name);
	camel_object_trigger_event (CAMEL_OBJECT (mapi_store), "folder_deleted", fi);
	camel_folder_info_free (fi);
}

static void 
mapi_delete_folder(CamelStore *store, const char *folder_name, CamelException *ex)
{
	CamelMapiStore *mapi_store = CAMEL_MAPI_STORE (store);
	CamelMapiStorePrivate  *priv = mapi_store->priv;

	const char *folder_id; 
	mapi_id_t folder_fid;
	gboolean status = FALSE;
	
	CAMEL_SERVICE_REC_LOCK (store, connect_lock);
	
	if (!camel_mapi_store_connected ((CamelMapiStore *)store, ex)) {
		CAMEL_SERVICE_REC_UNLOCK (store, connect_lock);
		return;
	}

	folder_id = g_hash_table_lookup (priv->name_hash, folder_name);
	exchange_mapi_util_mapi_id_from_string (folder_id, &folder_fid);
	status = exchange_mapi_remove_folder (0, folder_fid);

	if (status) {
		/* Fixme ??  */
/* 		if (mapi_store->current_folder) */
/* 			camel_object_unref (mapi_store->current_folder); */
		mapi_forget_folder(mapi_store,folder_name,ex);

		/* remove from name_cache at the end, because the folder_id is from there */
		/*g_hash_table_remove (priv->parent_hash, folder_id);*/
		g_hash_table_remove (priv->id_hash, folder_id);
		g_hash_table_remove (priv->name_hash, folder_name);
	} 

	CAMEL_SERVICE_REC_UNLOCK (store, connect_lock);

}

static void 
mapi_rename_folder(CamelStore *store, const char *old_name, const char *new_name, CamelException *ex)
{
	CamelMapiStore *mapi_store = CAMEL_MAPI_STORE (store);
	CamelMapiStorePrivate  *priv = mapi_store->priv;
	CamelStoreInfo *si = NULL;
	gchar *old_parent, *new_parent, *tmp;
	gboolean move_cache = TRUE;
	const gchar *old_fid_str, *new_parent_fid_str = NULL;
	mapi_id_t old_fid;

	CAMEL_SERVICE_REC_LOCK (mapi_store, connect_lock);

	if (!camel_mapi_store_connected ((CamelMapiStore *)store, ex)) {
		CAMEL_SERVICE_REC_UNLOCK (mapi_store, connect_lock);
		return;
	}

	/* Need a full name of a folder */
	old_fid_str = camel_mapi_store_folder_id_lookup (mapi_store, old_name);
	if (!old_fid_str) {
		/*To translators : '%s' is current name of the folder */
		camel_exception_setv (ex, CAMEL_EXCEPTION_SYSTEM, 
				      _("Cannot rename MAPI folder `%s'. Folder does not exist."),
				      old_name);
		CAMEL_SERVICE_REC_UNLOCK (mapi_store, connect_lock);
		return;
	}

	/*Do not allow rename for system folders.*/
	if (mapi_fid_is_system_folder (mapi_store, old_fid_str)) {
		/*To translators : '%s to %s' is current name of the folder  and
		 new name of the folder.*/
		camel_exception_setv (ex, CAMEL_EXCEPTION_SYSTEM, 
				      _("Cannot rename MAPI default folder `%s' to `%s'."),
				      old_name, new_name);
		return;
	}

	old_parent = g_strdup (old_name);
	tmp = strrchr (old_parent, '/');
	if (tmp) {
		*tmp = '\0';
	} else {
		strcpy (old_parent, "");
	}

	new_parent = g_strdup (new_name);
	tmp = strrchr (new_parent, '/');
	if (tmp) {
		*tmp = '\0';
		tmp++; /* here's a new folder name now */
	} else {
		strcpy (new_parent, "");
		tmp = NULL;
	}

	if (!exchange_mapi_util_mapi_id_from_string (old_fid_str, &old_fid)) {
		camel_exception_setv (ex, CAMEL_EXCEPTION_SYSTEM, _("Cannot rename MAPI folder `%s' to `%s'"), old_name, new_name);
		CAMEL_SERVICE_REC_UNLOCK (mapi_store, connect_lock);
		g_free (old_parent);
		g_free (new_parent);
		return;
	}

	if (tmp == NULL || g_str_equal (old_parent, new_parent)) {
		gchar *folder_id;

		/* renaming in the same folder, thus no MoveFolder necessary */
		if (!exchange_mapi_rename_folder (old_fid, tmp ? tmp : new_name)) {
			/*To translators : '%s to %s' is current name of the folder  and
			new name of the folder.*/
			camel_exception_setv (ex, CAMEL_EXCEPTION_SYSTEM, 
						  _("Cannot rename MAPI folder `%s' to `%s'"), old_name, new_name);

			CAMEL_SERVICE_REC_UNLOCK (mapi_store, connect_lock);
			g_free (old_parent);
			g_free (new_parent);
			return;
		}

		folder_id = g_strdup (old_fid_str);

		/* this frees old_fid_str */
		g_hash_table_remove (priv->name_hash, old_name);
		g_hash_table_remove (priv->id_hash, folder_id);

		mapi_update_folder_hash_tables (mapi_store, new_name, folder_id, NULL);

		g_free (folder_id);
	} else {
		const gchar *old_parent_fid_str;
		mapi_id_t old_parent_fid, new_parent_fid;
		gchar *folder_id;

		old_parent_fid_str = camel_mapi_store_folder_id_lookup (mapi_store, old_parent);
		new_parent_fid_str = camel_mapi_store_folder_id_lookup (mapi_store, new_parent);
		if (!old_parent_fid_str && new_parent_fid_str) {
			CamelStoreInfo *new_si;

			/* Folder was in a store-summary, and is known, but the parent gone.
			   The reason might be that this is a subfolder whose parent got moved
			   a second ago. Thus just update local summary with proper paths. */
			move_cache = FALSE;

			new_si = camel_store_summary_path ((CamelStoreSummary *)mapi_store->summary, new_name);
			if (new_si) {
				si = camel_store_summary_path ((CamelStoreSummary *)mapi_store->summary, old_name);
				if (si) {
					/* for cases where folder sync realized new folders before this got updated;
					   this shouldn't duplicate the info in summary, but remove the old one */
					camel_store_summary_remove ((CamelStoreSummary *)mapi_store->summary, si);
					camel_store_summary_info_free ((CamelStoreSummary *)mapi_store->summary, si);
					si = NULL;
				}
				camel_store_summary_info_free ((CamelStoreSummary *)mapi_store->summary, new_si);
			}
		} else if (!old_parent_fid_str || !new_parent_fid_str ||
			   !exchange_mapi_util_mapi_id_from_string (old_parent_fid_str, &old_parent_fid) ||
			   !exchange_mapi_util_mapi_id_from_string (new_parent_fid_str, &new_parent_fid) ||
			   !exchange_mapi_move_folder (old_fid, old_parent_fid, new_parent_fid, tmp)) {
			CAMEL_SERVICE_REC_UNLOCK (mapi_store, connect_lock);
			camel_exception_setv (ex, CAMEL_EXCEPTION_SYSTEM, _("Cannot rename MAPI folder `%s' to `%s'"), old_name, new_name);
			g_free (old_parent);
			g_free (new_parent);
			return;
		} else {
			/* folder was moved, update all subfolders immediately, thus
			   the next get_folder_info call will know about them */
			gint sz, i;

			sz = camel_store_summary_count ((CamelStoreSummary*) mapi_store->summary);
			for (i = 0; i < sz; i++) {
				const gchar *full_name;

				si = camel_store_summary_index ((CamelStoreSummary *) mapi_store->summary, i);
				if (!si)
					continue;

				full_name = camel_mapi_store_info_full_name (mapi_store->summary, si);
				if (full_name && g_str_has_prefix (full_name, old_name) && !g_str_equal (full_name, old_name) &&
				    full_name [strlen (old_name)] == '/' && full_name [strlen (old_name) + 1] != '\0') {
					/* it's a subfolder of old_name */
					const gchar *fid = camel_mapi_store_info_folder_id (mapi_store->summary, si);

					if (fid) {
						gchar *new_full_name;

						/* do not remove it from name_hash yet, because this function
						   will be called for it again */
						/* g_hash_table_remove (priv->name_hash, full_name); */
						g_hash_table_remove (priv->id_hash, fid);

						/* parent is still the same, only the path changed */
						new_full_name = g_strconcat (new_name, full_name + strlen (old_name) + (g_str_has_suffix (new_name, "/") ? 1 : 0), NULL);

						mapi_update_folder_hash_tables (mapi_store, new_full_name, fid, NULL);

						camel_store_info_set_string ((CamelStoreSummary *)mapi_store->summary, si, CAMEL_STORE_INFO_PATH, new_full_name);
						camel_store_info_set_string ((CamelStoreSummary *)mapi_store->summary, si, CAMEL_MAPI_STORE_INFO_FULL_NAME, new_full_name);
						camel_store_summary_touch ((CamelStoreSummary *)mapi_store->summary);

						g_free (new_full_name);
					}
				}
				camel_store_summary_info_free ((CamelStoreSummary *)mapi_store->summary, si);
			}
		}

		folder_id = g_strdup (old_fid_str);

		/* this frees old_fid_str */
		g_hash_table_remove (priv->name_hash, old_name);
		g_hash_table_remove (priv->id_hash, folder_id);
		/*g_hash_table_remove (priv->parent_hash, folder_id);*/

		mapi_update_folder_hash_tables (mapi_store, new_name, folder_id, new_parent_fid_str);

		g_free (folder_id);
	}

	CAMEL_SERVICE_REC_UNLOCK (mapi_store, connect_lock);

	si = camel_store_summary_path ((CamelStoreSummary *)mapi_store->summary, old_name);
	if (si) {
		camel_store_info_set_string ((CamelStoreSummary *)mapi_store->summary, si, CAMEL_STORE_INFO_PATH, new_name);
		camel_store_info_set_string ((CamelStoreSummary *)mapi_store->summary, si, CAMEL_MAPI_STORE_INFO_FULL_NAME, new_name);
		if (new_parent_fid_str) {
			camel_store_info_set_string ((CamelStoreSummary *)mapi_store->summary, si, CAMEL_MAPI_STORE_INFO_PARENT_ID, new_parent_fid_str);
		}
		camel_store_summary_info_free ((CamelStoreSummary *)mapi_store->summary, si);
		camel_store_summary_touch ((CamelStoreSummary *)mapi_store->summary);
	}

	if (move_cache) {
		gchar *oldpath, *newpath;

		oldpath = g_build_filename (priv->storage_path, "folders", old_name, NULL);
		newpath = g_build_filename (priv->storage_path, "folders", new_name, NULL);

		if (g_file_test (oldpath, G_FILE_TEST_IS_DIR) && g_rename (oldpath, newpath) == -1) {
			g_warning ("Could not rename message cache '%s' to '%s': %s: cache reset", oldpath, newpath, g_strerror (errno));
		}

		g_free (oldpath);
		g_free (newpath);
	}

	g_free (old_parent);
	g_free (new_parent);
}

static guint32 hexnib(guint32 c)
{
	if (c >= '0' && c <= '9')
		return c-'0';
	else if (c>='A' && c <= 'Z')
		return c-'A'+10;
	else
		return 0;
}

char *
camel_mapi_store_summary_path_to_full(CamelMapiStoreSummary *s, const char *path, char dir_sep)
{
	char *full, *f;
	guint32 c, v = 0;
	const char *p;
	int state=0;
	char *subpath, *last = NULL;
	CamelStoreInfo *si;

	/* check to see if we have a subpath of path already defined */
	subpath = alloca(strlen(path)+1);
	strcpy(subpath, path);
	do {
		si = camel_store_summary_path((CamelStoreSummary *)s, subpath);
		if (si == NULL) {
			last = strrchr(subpath, '/');
			if (last)
				*last = 0;
		}
	} while (si == NULL && last);

	/* path is already present, use the raw version we have */
	if (si && strlen(subpath) == strlen(path)) {
		f = g_strdup(camel_mapi_store_info_full_name(s, si));
		camel_store_summary_info_free((CamelStoreSummary *)s, si);
		return f;
	}

	f = full = alloca(strlen(path)*2+1);
	if (si)
		p = path + strlen(subpath);
	else
		p = path;

	while ( (c = camel_utf8_getc((const unsigned char **)&p)) ) {
		switch(state) {
			case 0:
				if (c == '%')
					state = 1;
				else {
					if (c == '/')
						c = dir_sep;
					camel_utf8_putc((unsigned char **)&f, c);
				}
				break;
			case 1:
				state = 2;
				v = hexnib(c)<<4;
				break;
			case 2:
				state = 0;
				v |= hexnib(c);
				camel_utf8_putc((unsigned char **)&f, v);
				break;
		}
	}
	camel_utf8_putc((unsigned char **)&f, c);

	/* merge old path part if required */
	f = g_strdup (full);
	if (si) {
		full = g_strdup_printf("%s%s", camel_mapi_store_info_full_name(s, si), f);
		g_free(f);
		camel_store_summary_info_free((CamelStoreSummary *)s, si);
		f = full;
	} 

	return f ;
}


//do we realy need this. move to utils then ! 
static int 
match_path(const char *path, const char *name)
{
	char p, n;

	p = *path++;
	n = *name++;
	while (n && p) {
		if (n == p) {
			p = *path++;
			n = *name++;
		} else if (p == '%') {
			if (n != '/') {
				n = *name++;
			} else {
				p = *path++;
			}
		} else if (p == '*') {
			return TRUE;
		} else
			return FALSE;
	}

	return n == 0 && (p == '%' || p == 0);
}

static char *
mapi_concat ( const char *prefix, const char *suffix)
{
	size_t len;

	len = strlen (prefix);
	if (len == 0 || prefix[len - 1] == '/')
		return g_strdup_printf ("%s%s", prefix, suffix);
	else
		return g_strdup_printf ("%s%c%s", prefix, '/', suffix);
}

static CamelFolderInfo *
mapi_build_folder_info(CamelMapiStore *mapi_store, const char *parent_name, const char *folder_name)
{
	CamelURL *url;
	const char *name;
	CamelFolderInfo *fi;
	CamelMapiStorePrivate *priv = mapi_store->priv;

	fi = camel_folder_info_new ();
	
	fi->unread = -1;
	fi->total = -1;

	if (parent_name) {
		if (strlen(parent_name) > 0) 
			fi->full_name = g_strconcat(parent_name, "/", folder_name, NULL);
		else
			fi->full_name = g_strdup (folder_name);
	} else 
		fi->full_name = g_strdup(folder_name);
 
	url = camel_url_new(priv->base_url,NULL);
	g_free(url->path);

	url->path = g_strdup_printf("/%s", fi->full_name);
	fi->uri = camel_url_to_string(url,CAMEL_URL_HIDE_ALL);
	camel_url_free(url);

	name = strrchr(fi->full_name,'/');
	if(name == NULL)
		name = fi->full_name;
	else
		name++;

	/*Fixme : Mark system folders.*/

	fi->name = g_strdup(name);
	return fi;
}

static CamelFolderInfo *
mapi_get_folder_info_offline (CamelStore *store, const char *top,
			 guint32 flags, CamelException *ex)
{
	CamelMapiStore *mapi_store = CAMEL_MAPI_STORE (store);
	CamelFolderInfo *fi;
	GPtrArray *folders;
	char *path, *name;
	int i;
	gboolean subscribed, favourites = FALSE, subscription_list = FALSE;

	subscription_list = (flags & CAMEL_STORE_FOLDER_INFO_SUBSCRIPTION_LIST);
	subscribed = (flags & CAMEL_STORE_FOLDER_INFO_SUBSCRIBED);

	folders = g_ptr_array_new ();

	if (top == NULL)
		top = "";

	/* get starting point */
	if (top[0] == 0) {
			name = g_strdup("");
	} else {
		name = camel_mapi_store_summary_full_from_path(mapi_store->summary, top);
		if (name == NULL)
			name = camel_mapi_store_summary_path_to_full(mapi_store->summary, top, '/');
	}

	path = mapi_concat (name, "*");

	for (i=0;i<camel_store_summary_count((CamelStoreSummary *)mapi_store->summary);i++) {
		CamelStoreInfo *si = camel_store_summary_index((CamelStoreSummary *)mapi_store->summary, i);

		if (si == NULL) 
			continue;

		/* Allow only All Public Folders heirarchy */
		if (subscription_list && (!(si->flags & CAMEL_MAPI_FOLDER_PUBLIC))) {
			camel_store_summary_info_free ((CamelStoreSummary *)mapi_store->summary, si);
			continue;
		}

		/*Allow Mailbox and Favourites (Subscribed public folders)*/
		if (subscribed && (!(si->flags & CAMEL_STORE_INFO_FOLDER_SUBSCRIBED))) {
			camel_store_summary_info_free ((CamelStoreSummary *)mapi_store->summary, si);
			continue;
		}

		if ( !strcmp(name, camel_mapi_store_info_full_name (mapi_store->summary, si))
		     || match_path (path, camel_mapi_store_info_full_name (mapi_store->summary, si))) {

			const gchar *store_info_path = camel_store_info_path((CamelStoreSummary *)mapi_store->summary, si);
			gchar *parent_name = NULL;
			const gchar *folder_name = NULL;

			/* TODO : UTF8 / i18n*/
			if (g_str_has_prefix (store_info_path, DISPLAY_NAME_ALL_PUBLIC_FOLDERS) && subscribed) {
				parent_name = DISPLAY_NAME_FAVOURITES;

				folder_name = strrchr(store_info_path,'/');
				if(folder_name != NULL)
					store_info_path = ++folder_name;

				favourites = TRUE;
			}

			fi = mapi_build_folder_info(mapi_store, parent_name, store_info_path);
			if (favourites) {
				CamelURL *url;
				url = camel_url_new(mapi_store->priv->base_url,NULL);
				url->path = g_strdup_printf("/%s", camel_store_info_path((CamelStoreSummary *)mapi_store->summary, si));
				g_free (fi->uri);
				fi->uri = camel_url_to_string(url,CAMEL_URL_HIDE_ALL);
				camel_url_free (url);
			}
				
			fi->unread = si->unread;
			fi->total = si->total;
			fi->flags = si->flags;

			g_ptr_array_add (folders, fi);
		}
		camel_store_summary_info_free((CamelStoreSummary *)mapi_store->summary, si);
	}

	if (!(subscription_list) && top[0] == '\0') {
		fi = mapi_build_folder_info(mapi_store, NULL, DISPLAY_NAME_FAVOURITES);
		fi->flags |= CAMEL_FOLDER_NOSELECT;
		fi->flags |= CAMEL_FOLDER_SYSTEM;
		
		g_ptr_array_add (folders, fi);
	}

	g_free(name);
	g_free (path);
	fi = camel_folder_info_build (folders, top, '/', TRUE);
	g_ptr_array_free (folders, TRUE);
	return fi;
}

static CamelFolderInfo *
mapi_convert_to_folder_info (CamelMapiStore *store, ExchangeMAPIFolder *folder, const char *url, CamelException *ex)
{
	const char *name = NULL;
	gchar *parent, *id = NULL;
	mapi_id_t mapi_id_folder;

	const char *par_name = NULL;
	CamelFolderInfo *fi;

	name = exchange_mapi_folder_get_name (folder);

	id = g_strdup_printf ("%016" G_GINT64_MODIFIER "X", exchange_mapi_folder_get_fid (folder));
		
	fi = camel_folder_info_new ();

	if (folder->is_default) {
		switch (folder->default_type) {
		case olFolderTopInformationStore:
			fi->flags |= CAMEL_FOLDER_NOSELECT;
			break;
		case olFolderInbox:
			fi->flags |= CAMEL_FOLDER_TYPE_INBOX;
			break;
		case olFolderSentMail:
			fi->flags |= CAMEL_FOLDER_TYPE_SENT;
			break;
		case olFolderDeletedItems:
			fi->flags |= CAMEL_FOLDER_TYPE_TRASH;
			break;
		case olFolderOutbox:
			fi->flags |= CAMEL_FOLDER_TYPE_OUTBOX;
			break;
		case olFolderJunk:
			fi->flags |= CAMEL_FOLDER_TYPE_JUNK;
			break;
		}

		fi->flags |= CAMEL_FOLDER_SYSTEM;
	}

	if (folder->category == MAPI_PERSONAL_FOLDER) {
		fi->flags |= CAMEL_MAPI_FOLDER_PERSONAL;
		fi->flags |= CAMEL_STORE_INFO_FOLDER_SUBSCRIBED; /*Set this default for mailbox.*/
	} else if (folder->category == MAPI_FAVOURITE_FOLDER)
		fi->flags |= CAMEL_MAPI_FOLDER_PUBLIC;

	if (folder->child_count <=0)
		fi->flags |= CAMEL_FOLDER_NOCHILDREN;
	/*
	   parent_hash contains the "parent id <-> folder id" combination. So we form
	   the path for the full name in camelfolder info by looking up the hash table until
	   NULL is found
	 */

	mapi_id_folder = exchange_mapi_folder_get_parent_id (folder);
	parent = g_strdup_printf ("%016" G_GINT64_MODIFIER "X", mapi_id_folder);

	fi->name =  g_strdup (name);

	par_name = mapi_folders_hash_table_name_lookup (store, parent, TRUE);
	if (par_name != NULL) {
		gchar *str = g_strconcat (par_name, "/", name, NULL);

		fi->full_name = str; /* takes ownership of the string */
		fi->uri = g_strconcat (url, str, NULL);
	} else {
		fi->full_name = g_strdup (name);
		fi->uri = g_strconcat (url, "", name, NULL);
	}

	/*name_hash returns the container id given the name */
	mapi_update_folder_hash_tables (store, fi->full_name, id, parent);

	g_free (parent);
	g_free (id);

	fi->total = folder->total;
	fi->unread = folder->unread_count;

	return fi;
}

gboolean
camel_mapi_store_connected (CamelMapiStore *store, CamelException *ex)
{
	if (((CamelOfflineStore *) store)->state == CAMEL_OFFLINE_STORE_NETWORK_AVAIL
	    && camel_service_connect ((CamelService *)store, ex)) 

		return TRUE;

	return FALSE;
}


static void
mapi_update_folder_hash_tables (CamelMapiStore *store, const gchar *full_name, const gchar *fid, const gchar *parent_id)
{
	CamelMapiStorePrivate  *priv = store->priv;

	if (fid && full_name) {
		/*id_hash returns the name for a given container id*/
		if (!g_hash_table_lookup (priv->id_hash, fid))
			g_hash_table_insert (priv->id_hash, g_strdup (fid), g_strdup (full_name)); 

		/* name_hash : name <-> fid mapping */
		if (!g_hash_table_lookup (priv->name_hash, full_name))
			g_hash_table_insert (priv->name_hash, g_strdup (full_name), g_strdup (fid));
	}

	/*parent_hash returns the parent container id, given an id*/
	/*if (fid && parent_id && !g_hash_table_lookup (priv->parent_hash, fid))
		g_hash_table_insert (priv->parent_hash, g_strdup (fid), g_strdup (parent_id));*/

}

static void
mapi_folders_update_hash_tables_from_cache (CamelMapiStore *store)
{
	CamelStoreSummary *summary = (CamelStoreSummary *) store->summary;
	gint summary_count = camel_store_summary_count (summary);
	guint i = 0;

	for (i = 0; i < summary_count; i++) {
		CamelMapiStoreInfo *si = (CamelMapiStoreInfo *) camel_store_summary_index(summary, i);
		
		if (si == NULL) continue;

		mapi_update_folder_hash_tables (store, si->full_name, si->folder_id, si->parent_id);
		camel_store_summary_info_free (summary, (CamelStoreInfo *)si);
	}
}

/* static const gchar* */
const gchar*
mapi_folders_hash_table_name_lookup (CamelMapiStore *store, const gchar *fid,
				     gboolean use_cache)
{
	CamelMapiStorePrivate  *priv = store->priv;
	const gchar *name = g_hash_table_lookup (priv->id_hash, fid);

	if (!name && use_cache)
		mapi_folders_update_hash_tables_from_cache (store);

	name = g_hash_table_lookup (priv->id_hash, fid);

	return name;
}

#if 0
static const gchar*
mapi_folders_hash_table_fid_lookup (CamelMapiStore *store, const gchar *name,
				    gboolean use_cache)
{
	CamelMapiStorePrivate  *priv = store->priv;

	const gchar *fid = g_hash_table_lookup (priv->name_hash, name);

	if (!fid && use_cache)
		mapi_folders_update_hash_tables_from_cache (store);

	fid = g_hash_table_lookup (priv->name_hash, name);

	return fid;
}
#endif

static void
remove_path_from_store_summary (const gchar *path, gpointer value, CamelMapiStore *mstore)
{
	const gchar *folder_id;
	CamelStoreInfo *si;

	g_return_if_fail (path != NULL);
	g_return_if_fail (mstore != NULL);

	folder_id = g_hash_table_lookup (mstore->priv->name_hash, path);
	if (folder_id) {
		/* name_hash as the second, because folder_id is from there */
		g_hash_table_remove (mstore->priv->id_hash, folder_id);
		g_hash_table_remove (mstore->priv->name_hash, path);
	}

	si = camel_store_summary_path ((CamelStoreSummary *)mstore->summary, path);
	if (si) {
		CamelFolderInfo *fi;
	
		fi = camel_folder_info_new ();
		fi->unread = -1;
		fi->total = -1;
		fi->uri = g_strdup (camel_store_info_uri (mstore->summary, si));
		fi->name = g_strdup (camel_store_info_name (mstore->summary, si));
		fi->full_name = g_strdup (camel_mapi_store_info_full_name (mstore->summary, si));
		if (!fi->name && fi->full_name) {
			fi->name = strrchr (fi->full_name, '/');
			if (fi->name)
				fi->name = g_strdup (fi->name + 1);
		}

		camel_object_trigger_event (CAMEL_OBJECT (mstore), "folder_unsubscribed", fi);
		camel_object_trigger_event (CAMEL_OBJECT (mstore), "folder_deleted", fi);
		camel_folder_info_free (fi);

		camel_store_summary_info_free ((CamelStoreSummary *)mstore->summary, si);
	}

	camel_store_summary_remove_path ((CamelStoreSummary *)mstore->summary, path);
}

static void
mapi_folders_sync (CamelMapiStore *store, const char *top, guint32 flags, CamelException *ex)
{
	CamelMapiStorePrivate  *priv = store->priv;
	gboolean status;
	GSList *folder_list = NULL, *temp_list = NULL, *list = NULL;
	char *url, *temp_url;
	gboolean subscription_list = FALSE;
	CamelFolderInfo *info = NULL;
	CamelMapiStoreInfo *mapi_si = NULL;
	guint32 count, i;
	CamelStoreInfo *si = NULL;
	GHashTable *old_cache_folders;

	if (!camel_mapi_store_connected (store, ex)) {
		camel_exception_set (ex, CAMEL_EXCEPTION_SERVICE_UNAVAILABLE,
				_("Folder list not available in offline mode."));
		return;
	}

	status = exchange_mapi_get_folders_list (&folder_list);

	if (!status) {
		g_warning ("Could not get folder list..\n");
		return;
	}

	/* remember all folders in cache before update */
	old_cache_folders = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, NULL);
	count = camel_store_summary_count ((CamelStoreSummary *)store->summary);
	for (i = 0; i < count; i++) {
		si = camel_store_summary_index ((CamelStoreSummary *)store->summary, i);
		if (si == NULL)
			continue;

		g_hash_table_insert (old_cache_folders, g_strdup (camel_store_info_path (store->summary, si)), GINT_TO_POINTER (1));
		camel_store_summary_info_free ((CamelStoreSummary *)store->summary, si);
	}

	subscription_list = (flags & CAMEL_STORE_FOLDER_INFO_SUBSCRIPTION_LIST);

	if (subscription_list) {
		/*Consult the name <-> fid hash table for a FID.*/
		gchar *parent_id = NULL;
		mapi_id_t pid = 0;

		parent_id = (top) ? g_strdup (camel_mapi_store_folder_id_lookup_offline (store, top)) : NULL; 
		exchange_mapi_util_mapi_id_from_string (parent_id, &pid);

		status = exchange_mapi_get_pf_folders_list (&folder_list, pid);

		if (!status)
			g_warning ("Could not get Public folder list..\n");

		g_free (parent_id);
	}

	temp_list = folder_list;
	list = folder_list;

	url = camel_url_to_string (CAMEL_SERVICE(store)->url,
				   (CAMEL_URL_HIDE_PASSWORD|
				    CAMEL_URL_HIDE_PARAMS|
				    CAMEL_URL_HIDE_AUTH) );

	if ( url[strlen(url) - 1] != '/') {
		temp_url = g_strconcat (url, "/", NULL);
		g_free ((char *)url);
		url = temp_url;
	}
	
	/*populate the hash table for finding the mapping from container id <-> folder name*/
	for (;temp_list != NULL ; temp_list = g_slist_next (temp_list) ) {
		const char *full_name;
		gchar *fid = NULL, *parent_id = NULL, *tmp = NULL;

		fid = g_strdup_printf ("%016" G_GINT64_MODIFIER "X", exchange_mapi_folder_get_fid((ExchangeMAPIFolder *)(temp_list->data)));
		parent_id = g_strdup_printf ("%016" G_GINT64_MODIFIER "X", exchange_mapi_folder_get_parent_id ((ExchangeMAPIFolder *)(temp_list->data)));
		full_name = g_hash_table_lookup (priv->id_hash, fid);
		if (!full_name) {
			const gchar *par_full_name;

			par_full_name = g_hash_table_lookup (priv->id_hash, parent_id);
			if (par_full_name) {
				tmp = g_strconcat (par_full_name, "/", exchange_mapi_folder_get_name (temp_list->data), NULL);
				full_name = tmp;
			} else {
				full_name = exchange_mapi_folder_get_name (temp_list->data);
			}
		}

		/* remove from here; what lefts is not on the server any more */
		g_hash_table_remove (old_cache_folders, full_name);

		mapi_update_folder_hash_tables (store, full_name, fid, parent_id);

		if (((ExchangeMAPIFolder *)(temp_list->data))->is_default) {
			guint *type = g_new0 (guint, 1);
			*type = ((ExchangeMAPIFolder *)(temp_list->data))->default_type;
			g_hash_table_insert (priv->default_folders, type,
					     g_strdup(fid));
		}

		g_free (fid);
		g_free (parent_id);
		g_free (tmp);
	}

	for (;folder_list != NULL; folder_list = g_slist_next (folder_list)) {
		ExchangeMAPIFolder *folder = (ExchangeMAPIFolder *) folder_list->data;
		
		if (folder->default_type == olPublicFoldersAllPublicFolders)
			continue;

		if ( folder->container_class != MAPI_FOLDER_TYPE_MAIL) 
			continue;

		info = mapi_convert_to_folder_info (store, folder, (const char *)url, ex);
		if (!(mapi_si = (CamelMapiStoreInfo *) camel_store_summary_path ((CamelStoreSummary *)store->summary, info->full_name))){
			gchar *fid, *pfid = NULL;

			fid = g_strdup_printf ("%016" G_GINT64_MODIFIER "X", 
					       exchange_mapi_folder_get_fid((ExchangeMAPIFolder *)(folder_list->data)));
			pfid = g_strdup_printf ("%016" G_GINT64_MODIFIER "X", 
						exchange_mapi_folder_get_parent_id((ExchangeMAPIFolder *)(folder_list->data)));

			mapi_si = camel_mapi_store_summary_add_from_full (store->summary, info->full_name, '/', fid, pfid);

			g_free (fid);
			g_free (pfid);
			if (mapi_si == NULL) {
				continue;
			}

			camel_store_summary_info_ref ((CamelStoreSummary *)store->summary, (CamelStoreInfo *)mapi_si);

			if (!subscription_list) {
				camel_object_trigger_event (CAMEL_OBJECT (store), "folder_created", info);
				camel_object_trigger_event (CAMEL_OBJECT (store), "folder_subscribed", info);
			}
		}

		mapi_si->info.flags |= info->flags;
		mapi_si->info.total = info->total;
		mapi_si->info.unread = info->unread;

		camel_store_summary_info_free ((CamelStoreSummary *)store->summary, (CamelStoreInfo *)mapi_si);
		camel_folder_info_free (info);
	}

	/* Weed out deleted folders */
	g_hash_table_foreach (old_cache_folders, (GHFunc) remove_path_from_store_summary, store);
	g_hash_table_destroy (old_cache_folders);

	camel_store_summary_touch ((CamelStoreSummary *)store->summary);
	camel_store_summary_save ((CamelStoreSummary *)store->summary);

	g_free (url);

	g_slist_foreach (list, (GFunc) exchange_mapi_folder_free, NULL);
	g_slist_free (list);

	priv->folders_synced = TRUE;

	//	g_hash_table_foreach (present, get_folders_free, NULL);
	//	g_hash_table_destroy (present);

	/* FIXME : This place is not right! */
	/* Start Push Notification listener */
	/* event_mask = fnevNewMail | fnevObjectCreated | fnevObjectDeleted | */
	/* 	fnevObjectModified | fnevObjectMoved | fnevObjectCopied; */

	/* camel_mapi_notfication_listener_start (store, event_mask, MAPI_EVENTS_USE_STORE); */
}


static CamelFolderInfo*
mapi_get_folder_info(CamelStore *store, const char *top, guint32 flags, CamelException *ex)
{
	CamelMapiStore *mapi_store = CAMEL_MAPI_STORE (store);
	CamelFolderInfo *info = NULL;
	int s_count = 0;	

	/*
	 * Thanks to Michael, for his cached folders implementation in IMAP
	 * is used as is here.
	 */

	CAMEL_SERVICE_REC_LOCK (store, connect_lock);

	if (((CamelOfflineStore *) store)->state == CAMEL_OFFLINE_STORE_NETWORK_AVAIL) {
		if (((CamelService *)store)->status == CAMEL_SERVICE_DISCONNECTED){
			((CamelService *)store)->status = CAMEL_SERVICE_CONNECTING;
			mapi_connect ((CamelService *)store, ex);
		}
	}

	/* update folders from the server only when asking for the top most or the 'top' is not known;
	   otherwise believe the local cache, because folders sync is pretty slow operation to be done
	   one every single question on the folder info */
	if (((flags & CAMEL_STORE_FOLDER_INFO_SUBSCRIPTION_LIST) != 0 ||
	     (!(flags & CAMEL_STORE_FOLDER_INFO_SUBSCRIBED)) ||
	     (!mapi_store->priv->folders_synced) ||
	     (top && *top && !camel_mapi_store_folder_id_lookup (mapi_store, top))) &&
	    (check_for_connection ((CamelService *)store, ex) || ((CamelService *)store)->status == CAMEL_SERVICE_CONNECTING)) {
		mapi_folders_sync (mapi_store, top, flags, ex);

		if (camel_exception_is_set (ex)) {
			CAMEL_SERVICE_REC_UNLOCK (store, connect_lock);
			return NULL;
		}
		camel_store_summary_touch ((CamelStoreSummary *)mapi_store->summary);
		camel_store_summary_save ((CamelStoreSummary *)mapi_store->summary);
	}

	CAMEL_SERVICE_REC_UNLOCK (store, connect_lock);

	s_count = camel_store_summary_count((CamelStoreSummary *)mapi_store->summary);
	info = mapi_get_folder_info_offline (store, top, flags, ex);
	return info;
}

const gchar *
camel_mapi_store_folder_id_lookup_offline (CamelMapiStore *mapi_store, const char *folder_name)
{
	CamelMapiStoreInfo *mapi_si;
	const gchar *folder_id;

	mapi_si = (CamelMapiStoreInfo *)camel_store_summary_path ((CamelStoreSummary *)mapi_store->summary, folder_name);
	g_return_val_if_fail (mapi_si != NULL, NULL);
	folder_id = mapi_si->folder_id;

	/* shouldn't be the last reference to it, right? */
	camel_store_summary_info_free ((CamelStoreSummary *)mapi_store->summary, (CamelStoreInfo *) mapi_si);

	return folder_id;
}

const gchar *
camel_mapi_store_folder_id_lookup (CamelMapiStore *mapi_store, const char *folder_name)
{
	CamelMapiStorePrivate *priv = mapi_store->priv;

	return g_hash_table_lookup (priv->name_hash, folder_name);
}

const gchar *
camel_mapi_store_system_folder_fid (CamelMapiStore *mapi_store, guint folder_type)
{
	return mapi_system_folder_fid (mapi_store, folder_type);
}

const gchar *
camel_mapi_store_folder_lookup (CamelMapiStore *mapi_store, const char *folder_id)
{
	CamelMapiStorePrivate *priv = mapi_store->priv;

	return g_hash_table_lookup (priv->id_hash, folder_id);
}

const gchar *
camel_mapi_store_get_profile_name (CamelMapiStore *mapi_store)
{
	CamelMapiStorePrivate *priv;

	g_return_val_if_fail (CAMEL_IS_MAPI_STORE (mapi_store), NULL);

	priv = mapi_store->priv;

	return priv->profile;
}

static void
mapi_subscribe_folder(CamelStore *store, const char *folder_name, CamelException *ex)
{
	CamelMapiStore *mapi_store = CAMEL_MAPI_STORE (store);

	CamelFolderInfo *fi;
	CamelStoreInfo *si = NULL;
	gchar *parent_name = NULL;
	gchar *f_name = NULL;
	/* TODO : exchange_mapi_add_to_favorites (); */

	si = camel_store_summary_path((CamelStoreSummary *)mapi_store->summary, folder_name);
	if (si != NULL) {
		if ((si->flags & CAMEL_STORE_INFO_FOLDER_SUBSCRIBED) == 0) {
			si->flags |= CAMEL_STORE_INFO_FOLDER_SUBSCRIBED;
			si->flags |= CAMEL_FOLDER_SUBSCRIBED;
			camel_store_summary_touch((CamelStoreSummary *)mapi_store->summary);
		}
		camel_store_summary_info_free((CamelStoreSummary *)mapi_store->summary, si);
	}

	if (g_str_has_prefix (folder_name, DISPLAY_NAME_ALL_PUBLIC_FOLDERS) ) {
		parent_name = DISPLAY_NAME_FAVOURITES;

		f_name = strrchr(folder_name,'/');
		if(f_name != NULL)
			folder_name = ++f_name;
		else  //Don't process All Public Folder.
			return;
	}

	fi = mapi_build_folder_info (mapi_store, parent_name, folder_name);

	fi->flags |= CAMEL_FOLDER_SUBSCRIBED;
	fi->flags |= CAMEL_FOLDER_NOCHILDREN;
	fi->flags |= CAMEL_STORE_INFO_FOLDER_SUBSCRIBED;

	camel_object_trigger_event (CAMEL_OBJECT (store), "folder_subscribed", fi);
	camel_folder_info_free (fi);
}

static gboolean
mapi_folder_subscribed (CamelStore *store, const char *folder_name)
{
	CamelMapiStore *mapi_store = (CamelMapiStore *) store;
	CamelStoreInfo *si;
	int truth = FALSE;

	if ((si = camel_store_summary_path ((CamelStoreSummary *) mapi_store->summary, folder_name))) {
		truth = (si->flags & CAMEL_STORE_INFO_FOLDER_SUBSCRIBED) != 0;
		camel_store_summary_info_free ((CamelStoreSummary *) mapi_store->summary, si);
	}

	return truth;
}

static void 
mapi_unsubscribe_folder(CamelStore *store, const char *folder_name, CamelException *ex)
{
	CamelFolderInfo *fi;
	CamelStoreInfo *si;
	gchar *parent_name = NULL;
	gchar *f_name = NULL;

	CamelMapiStore *mapi_store = CAMEL_MAPI_STORE (store);

	si = camel_store_summary_path((CamelStoreSummary *)mapi_store->summary, folder_name);
	if (si) {
		if (si->flags & CAMEL_STORE_INFO_FOLDER_SUBSCRIBED) {
			si->flags &= ~CAMEL_STORE_INFO_FOLDER_SUBSCRIBED;
			camel_store_summary_touch((CamelStoreSummary *)mapi_store->summary);
			camel_store_summary_save((CamelStoreSummary *)mapi_store->summary);
		}
		camel_store_summary_info_free((CamelStoreSummary *)mapi_store->summary, si);
	}

	if (g_str_has_prefix (folder_name, DISPLAY_NAME_ALL_PUBLIC_FOLDERS) ) {
		parent_name = DISPLAY_NAME_FAVOURITES;

		f_name = strrchr(folder_name,'/');
		if(f_name != NULL)
			folder_name = ++f_name;
		else //Don't process All Public Folder.
			return;
	}

	fi = mapi_build_folder_info (mapi_store, parent_name, folder_name);

	camel_object_trigger_event (CAMEL_OBJECT (store), "folder_unsubscribed", fi);
	camel_folder_info_free (fi);
}

static void
mapi_noop(CamelStore *store, CamelException *ex)
{

}

