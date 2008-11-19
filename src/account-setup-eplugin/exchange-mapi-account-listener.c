/*
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) version 3.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with the program; if not, see <http://www.gnu.org/licenses/> 
 *
 *
 * Authors:
 *		Srinivasa Ragavan <sragavan@novell.com>
 *		Suman Manjunath <msuman@novell.com>
 *
 * Copyright (C) 1999-2008 Novell, Inc. (www.novell.com)
 *
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include "exchange-mapi-account-listener.h"
#include "exchange-mapi-account-setup.h"
#include <string.h>
#include <camel/camel-i18n.h>
#include <libedataserverui/e-passwords.h>
#include "e-util/e-error.h"
#include <libedataserver/e-account.h>
#include <libecal/e-cal.h>
#include <libedataserver/e-account-list.h>
#include <libedataserver/e-source.h>
#include <libedataserver/e-source-list.h>
#include <camel/camel-url.h>

#include <libmapi/libmapi.h>


/* FIXME: The mapi should not be needed in the include statement.
LIMBAPI_CFLAGS or something is going wrong */

#include <mapi/exchange-mapi-folder.h>
#include <mapi/exchange-mapi-connection.h>
#include <mapi/exchange-mapi-utils.h>

#define d(x) x

struct _ExchangeMAPIAccountListenerPrivate {
	GConfClient *gconf_client;
	/* we get notification about mail account changes from this object */
	EAccountList *account_list;
};

typedef struct _ExchangeMAPIAccountInfo ExchangeMAPIAccountInfo;

/* stores some info about all currently existing mapi accounts */
struct _ExchangeMAPIAccountInfo {
	char *uid;
	char *name;
	char *source_url;
	gboolean enabled; 
};

/* list of ExchangeMAPIAccountInfo structures */
static 	GList *mapi_accounts = NULL;

#define PARENT_TYPE G_TYPE_OBJECT

static GObjectClass *parent_class = NULL;

static void 
dispose (GObject *object)
{
	ExchangeMAPIAccountListener *config_listener = EXCHANGE_MAPI_ACCOUNT_LISTENER (object);
	
	g_object_unref (config_listener->priv->gconf_client);
	g_object_unref (config_listener->priv->account_list);

	G_OBJECT_CLASS (parent_class)->dispose (object);
}

static void 
finalize (GObject *object)
{
	ExchangeMAPIAccountListener *config_listener = EXCHANGE_MAPI_ACCOUNT_LISTENER (object);
	GList *list;

	if (config_listener->priv) {
		g_free (config_listener->priv);
	}

	for (list = g_list_first (mapi_accounts); list ; list = g_list_next (list)) {
		ExchangeMAPIAccountInfo *info = (ExchangeMAPIAccountInfo *)(list->data);
		if (info) {
			g_free (info->uid);
			g_free (info->name);
			g_free (info->source_url);
			g_free (info);
		}
	}
	
	g_list_free (mapi_accounts);

	G_OBJECT_CLASS (parent_class)->finalize (object);
}

static void 
exchange_mapi_account_listener_class_init (ExchangeMAPIAccountListenerClass *class)
{
	GObjectClass *object_class;
	
	parent_class = g_type_class_ref (PARENT_TYPE);
	object_class = G_OBJECT_CLASS (class);
	
	/* virtual method override */
	object_class->dispose = dispose;
	object_class->finalize = finalize;
}

static void 
exchange_mapi_account_listener_init (ExchangeMAPIAccountListener *config_listener, ExchangeMAPIAccountListenerClass *class)
{
	config_listener->priv = g_new0 (ExchangeMAPIAccountListenerPrivate, 1);
}


/* This is a list of folders returned by e-d-s. */
static	GSList *folders_list = NULL;

GSList *
exchange_mapi_account_listener_peek_folder_list (void)
{
	if (!folders_list)
		folders_list = exchange_mapi_peek_folder_list ();

	return folders_list;
}

void
exchange_mapi_account_listener_get_folder_list (void)
{
	if (folders_list)
		return;

	folders_list = exchange_mapi_peek_folder_list ();
}

void
exchange_mapi_account_listener_free_folder_list (void)
{
	exchange_mapi_folder_list_free ();
	folders_list = NULL;
}

/*determines whehter the passed in account is exchange or not by looking at source url */

static gboolean
is_mapi_account (EAccount *account)
{
	return (account->source->url && (g_ascii_strncasecmp (account->source->url, MAPI_URI_PREFIX, MAPI_PREFIX_LENGTH) == 0));
}

/* looks up for an existing exchange account info in the mapi_accounts list based on uid */

static ExchangeMAPIAccountInfo* 
lookup_account_info (const char *key)
{
	GList *list;

	g_return_val_if_fail (key != NULL, NULL); 

	for (list = g_list_first (mapi_accounts); list; list = g_list_next (list)) {
		ExchangeMAPIAccountInfo *info = (ExchangeMAPIAccountInfo *)(list->data);
		if (g_ascii_strcasecmp (info->uid, key) == 0)
			return info; 
	}

	return NULL;
}

#define CALENDAR_SOURCES 	"/apps/evolution/calendar/sources"
#define TASK_SOURCES 		"/apps/evolution/tasks/sources"
#define JOURNAL_SOURCES 	"/apps/evolution/memos/sources"
#define SELECTED_CALENDARS 	"/apps/evolution/calendar/display/selected_calendars"
#define SELECTED_TASKS 		"/apps/evolution/calendar/tasks/selected_tasks"
#define SELECTED_JOURNALS 	"/apps/evolution/calendar/memos/selected_memos"

#define ITIP_MESSAGE_HANDLING 	"/apps/evolution/itip/delete_processed"

static void
add_cal_esource (EAccount *account, GSList *folders, ExchangeMAPIFolderType folder_type, CamelURL *url)
{
	ESourceList *source_list = NULL;
	ESourceGroup *group = NULL;
	const gchar *conf_key = NULL, *source_selection_key = NULL;
 	GSList *temp_list = NULL;
	GConfClient* client;
	GSList *ids, *temp ;
	gchar *base_uri = NULL;

	if (folder_type == MAPI_FOLDER_TYPE_APPOINTMENT) { 
		conf_key = CALENDAR_SOURCES;
		source_selection_key = SELECTED_CALENDARS;
	} else if (folder_type == MAPI_FOLDER_TYPE_TASK) { 
		conf_key = TASK_SOURCES;
		source_selection_key = SELECTED_TASKS;
	} else if (folder_type == MAPI_FOLDER_TYPE_MEMO) {
		conf_key = JOURNAL_SOURCES;
		source_selection_key = SELECTED_JOURNALS;
	} else {
		g_warning ("%s(%d): %s: Unknown ExchangeMAPIFolderType\n", __FILE__, __LINE__, __PRETTY_FUNCTION__);
		return;
	} 

	client = gconf_client_get_default ();
	gconf_client_set_bool (client, ITIP_MESSAGE_HANDLING, TRUE, NULL);
	source_list = e_source_list_new_for_gconf (client, conf_key);
	base_uri = g_strdup_printf ("%s%s@%s/", MAPI_URI_PREFIX, url->user, url->host);
	group = e_source_group_new (account->name, base_uri);
	g_free (base_uri);
	e_source_group_set_property (group, "create_source", "yes");
	e_source_group_set_property (group, "username", url->user);
	e_source_group_set_property (group, "host", url->host);
	e_source_group_set_property (group, "profile", camel_url_get_param (url, "profile"));
	e_source_group_set_property (group, "domain", camel_url_get_param (url, "domain"));

	/* We set these because on new folder creation - these are required. */
	e_source_group_set_property (group, "acl-user-name", account->id->name);
	e_source_group_set_property (group, "acl-user-email", account->id->address);
	e_source_group_set_property (group, "acl-owner-name", account->id->name);
	e_source_group_set_property (group, "acl-owner-email", account->id->address);

	for (temp_list = folders; temp_list != NULL; temp_list = g_slist_next (temp_list)) {
 		ExchangeMAPIFolder *folder = temp_list->data;
		ESource *source = NULL;
		gchar *relative_uri = NULL, *fid = NULL;

		if (folder->container_class != folder_type)
			continue;

		fid = exchange_mapi_util_mapi_id_to_string (folder->folder_id);
		relative_uri = g_strconcat (";", fid, NULL);
		source = e_source_new (folder->folder_name, relative_uri);
		e_source_set_property (source, "auth", "1");
		e_source_set_property (source, "auth-domain", EXCHANGE_MAPI_PASSWORD_COMPONENT);
		e_source_set_property (source, "auth-type", "plain/password");
		e_source_set_property (source, "username", url->user);
		e_source_set_property (source, "host", url->host);
		e_source_set_property (source, "profile", camel_url_get_param (url, "profile"));
		e_source_set_property (source, "domain", camel_url_get_param (url, "domain"));
		e_source_set_property (source, "folder-id", fid);
		e_source_set_property (source, "offline_sync", 
					camel_url_get_param (url, "offline_sync") ? "1" : "0");

		if (folder->is_default) 
			e_source_set_property (source, "delete", "no");

		if (folder->parent_folder_id) {
			gchar *tmp = exchange_mapi_util_mapi_id_to_string (folder->parent_folder_id);
			e_source_set_property (source, "parent-fid", tmp);
			g_free (tmp);
		}

		e_source_set_property (source, "acl-user-name", account->id->name);
		e_source_set_property (source, "acl-user-email", account->id->address);
		/* FIXME: this would change after foreign folders/delegation is implemented */
		e_source_set_property (source, "acl-owner-name", account->id->name);
		e_source_set_property (source, "acl-owner-email", account->id->address);

		e_source_group_add_source (group, source, -1);

		if (source_selection_key && folder->is_default) {
			ids = gconf_client_get_list (client, source_selection_key , GCONF_VALUE_STRING, NULL);
			ids = g_slist_append (ids, g_strdup (e_source_peek_uid (source)));
			gconf_client_set_list (client, source_selection_key, GCONF_VALUE_STRING, ids, NULL);

			for (temp = ids; temp != NULL; temp = g_slist_next (temp))
				g_free (temp->data);

			g_slist_free (ids);
		}

		g_object_unref (source);
		g_free (relative_uri);
		g_free (fid);
	}

	if (!e_source_list_add_group (source_list, group, -1))
		return;

	if (!e_source_list_sync (source_list, NULL))
		return;

	g_object_unref (group);
	g_object_unref (source_list);
	g_object_unref (client);
}

static void 
remove_cal_esource (EAccount *existing_account_info, ExchangeMAPIFolderType folder_type, CamelURL *url)
{
	ESourceList *list;
	const gchar *conf_key = NULL, *source_selection_key = NULL;
	GSList *groups;
	gboolean found_group;
	GConfClient* client;
	GSList *ids;
	GSList *node_tobe_deleted;
	gchar *base_uri;

	if (folder_type == MAPI_FOLDER_TYPE_APPOINTMENT) { 
		conf_key = CALENDAR_SOURCES;
		source_selection_key = SELECTED_CALENDARS;
	} else if (folder_type == MAPI_FOLDER_TYPE_TASK) { 
		conf_key = TASK_SOURCES;
		source_selection_key = SELECTED_TASKS;
	} else if (folder_type == MAPI_FOLDER_TYPE_MEMO) {
		conf_key = JOURNAL_SOURCES;
		source_selection_key = SELECTED_JOURNALS;
	} else {
		g_warning ("%s(%d): %s: Unknown ExchangeMAPIFolderType\n", __FILE__, __LINE__, __PRETTY_FUNCTION__);
		return;
	} 

	client = gconf_client_get_default();
	gconf_client_set_bool (client, ITIP_MESSAGE_HANDLING, FALSE, NULL);
	list = e_source_list_new_for_gconf (client, conf_key);
	groups = e_source_list_peek_groups (list); 

	base_uri = g_strdup_printf ("mapi://%s@%s/", url->user, url->host);

	found_group = FALSE;

	for ( ; groups != NULL && !found_group; groups = g_slist_next (groups)) {
		ESourceGroup *group = E_SOURCE_GROUP (groups->data);

		if (strcmp (e_source_group_peek_name (group), existing_account_info->name) == 0 && 
		    strcmp (e_source_group_peek_base_uri (group), base_uri) == 0) {
			GSList *sources = e_source_group_peek_sources (group);
			
			for( ; sources != NULL; sources = g_slist_next (sources)) {
				ESource *source = E_SOURCE (sources->data);

				if (source_selection_key) {
					ids = gconf_client_get_list (client, source_selection_key , 
								     GCONF_VALUE_STRING, NULL);
					node_tobe_deleted = g_slist_find_custom (ids, e_source_peek_uid (source), (GCompareFunc) strcmp);
					if (node_tobe_deleted) {
						g_free (node_tobe_deleted->data);
						ids = g_slist_delete_link (ids, node_tobe_deleted);
					}
					gconf_client_set_list (client, source_selection_key, 
							       GCONF_VALUE_STRING, ids, NULL);
				}
			}
			e_source_list_remove_group (list, group);
			e_source_list_sync (list, NULL);	
			found_group = TRUE;
			break;
		}
	}

	g_free (base_uri);
	g_object_unref (list);
	g_object_unref (client);		
}

/* add sources for calendar and tasks if the account added is exchange account
   adds the new account info to mapi_accounts list */

static void 
add_calendar_sources (EAccount *account, GSList *folders)
{
	CamelURL *url;

	url = camel_url_new (account->source->url, NULL);

	if (url) {
		add_cal_esource (account, folders, MAPI_FOLDER_TYPE_APPOINTMENT, url);
		add_cal_esource (account, folders, MAPI_FOLDER_TYPE_TASK, url);
		add_cal_esource (account, folders, MAPI_FOLDER_TYPE_MEMO, url);
	}

	camel_url_free (url);
}

/* removes calendar and tasks sources if the account removed is exchange account 
   removes the the account info from mapi_account list */

static void 
remove_calendar_sources (EAccount *account)
{
	CamelURL *url;

	url = camel_url_new (account->source->url, NULL);

	if (url) {
		remove_cal_esource (account, MAPI_FOLDER_TYPE_APPOINTMENT, url);
		remove_cal_esource (account, MAPI_FOLDER_TYPE_TASK, url);
		remove_cal_esource (account, MAPI_FOLDER_TYPE_MEMO, url);
	}

	camel_url_free (url);
}

static gboolean
add_addressbook_sources (EAccount *account, GSList *folders)
{
	CamelURL *url;
	ESourceList *list;
	ESourceGroup *group;
	ESource *source;
	char *base_uri;
	GSList *temp_list;
	GConfClient* client;

	url = camel_url_new (account->source->url, NULL);
	if (url == NULL) {
		return FALSE;
	}

	base_uri = g_strdup_printf ("mapi://%s@%s/", url->user, url->host);
	client = gconf_client_get_default ();
	list = e_source_list_new_for_gconf (client, "/apps/evolution/addressbook/sources" );
	group = e_source_group_new (account->name, base_uri);
	e_source_group_set_property (group, "user", url->user);
	e_source_group_set_property (group, "host", url->host);
	e_source_group_set_property (group, "profile", camel_url_get_param (url, "profile"));
	e_source_group_set_property (group, "domain", camel_url_get_param (url, "domain"));

	for (temp_list = folders; temp_list != NULL; temp_list = g_slist_next (temp_list)) {
 		ExchangeMAPIFolder *folder = temp_list->data;
		char *tmp = NULL;
		if (folder->container_class != MAPI_FOLDER_TYPE_CONTACT)
			continue;

		source = e_source_new (folder->folder_name, g_strconcat (";",folder->folder_name, NULL));
		e_source_set_property (source, "auth", "plain/password");
		e_source_set_property (source, "auth-domain", EXCHANGE_MAPI_PASSWORD_COMPONENT);
		e_source_set_property(source, "user", url->user);
		e_source_set_property(source, "host", url->host);
		e_source_set_property(source, "profile", camel_url_get_param (url, "profile"));
		e_source_set_property(source, "domain", camel_url_get_param (url, "domain"));
		tmp = exchange_mapi_util_mapi_id_to_string (folder->folder_id);
		e_source_set_property(source, "folder-id", tmp);
		g_free (tmp);
		e_source_set_property (source, "offline_sync", 
					       camel_url_get_param (url, "offline_sync") ? "1" : "0");
		e_source_set_property (source, "completion", "true");
		e_source_group_add_source (group, source, -1);
		g_object_unref (source);
	}

	//Add GAL
	{
		char *uri;
		uri = g_strdup_printf("galldap://%s@%s/;Global Address List", url->user, url->host);
		source = e_source_new_with_absolute_uri ("Global Address List", uri);
//		source = e_source_new ("Global Address List", g_strconcat (";","Global Address List" , NULL));
		e_source_set_property (source, "auth", "plain/password");
		e_source_set_property (source, "auth-domain", "GALLDAP");
		e_source_set_property(source, "user", url->user);
		e_source_set_property(source, "host", camel_url_get_param (url, "ad_server"));
		e_source_set_property(source, "view-limit", camel_url_get_param (url, "ad_limit"));		
		e_source_set_property(source, "profile", camel_url_get_param (url, "profile"));
		e_source_set_property(source, "domain", camel_url_get_param (url, "domain"));
//		e_source_set_property (source, "offline_sync", 
//					       camel_url_get_param (url, "offline_sync") ? "1" : "0");
		e_source_set_property(source, "offline_sync", "1");
		e_source_set_property (source, "completion", "true");
		e_source_group_add_source (group, source, -1);
		g_object_unref (source);		
	}
	e_source_list_add_group (list, group, -1);
	e_source_list_sync (list, NULL);
	g_object_unref (group);
	g_object_unref (list);
	g_object_unref (client);
	g_free (base_uri);

	return TRUE;
}

static void 
remove_addressbook_sources (ExchangeMAPIAccountInfo *existing_account_info)
{
	ESourceList *list;
	ESourceGroup *group;
	GSList *groups;
	gboolean found_group;
	CamelURL *url;
	char *base_uri;
	GConfClient *client;

	url = camel_url_new (existing_account_info->source_url, NULL);
	if (url == NULL) {
		return;
	}

	base_uri = g_strdup_printf ("mapi://%s@%s/", url->user, url->host);
	client = gconf_client_get_default ();
	list = e_source_list_new_for_gconf (client, "/apps/evolution/addressbook/sources" );
	groups = e_source_list_peek_groups (list); 

	found_group = FALSE;

	for ( ; groups != NULL && !found_group; groups = g_slist_next (groups)) {

		group = E_SOURCE_GROUP (groups->data);
		if ( strcmp ( e_source_group_peek_base_uri (group), base_uri) == 0 && strcmp (e_source_group_peek_name (group), existing_account_info->name) == 0) {

			e_source_list_remove_group (list, group);
			e_source_list_sync (list, NULL);
			found_group = TRUE;
		}
	}

	g_object_unref (list);
	g_object_unref (client);
	g_free (base_uri);
	camel_url_free (url);
}

static void
mapi_account_added (EAccountList *account_listener, EAccount *account)
{
	ExchangeMAPIAccountInfo *info = NULL;

	if (!is_mapi_account (account))
		return;

	info = g_new0 (ExchangeMAPIAccountInfo, 1);
	info->uid = g_strdup (account->uid);
	info->name = g_strdup (account->name);
	info->source_url = g_strdup (account->source->url);
	info->enabled = account->enabled; 

	mapi_accounts = g_list_append (mapi_accounts, info);

	if (account->enabled) {
		/* Fetch the folders into a global list for future use.*/
		exchange_mapi_account_listener_get_folder_list ();

		add_addressbook_sources (account, folders_list);
		add_calendar_sources (account, folders_list);
		/*FIXME: Maybe the folders_list above should be freed */
	}
}

static void 
mapi_account_removed (EAccountList *account_listener, EAccount *account)
{
	ExchangeMAPIAccountInfo *info = NULL;
	CamelURL *url = NULL;

	if (!is_mapi_account (account))
		return;

	/* We store a complete list of MAPI accounts - both enabled and disabled */
	info = lookup_account_info (account->uid);
	g_return_if_fail (info != NULL);  

	/* Remove from the local MAPI accounts list */
	mapi_accounts = g_list_remove (mapi_accounts, info);

	/* If the account was disabled, then the corresponding ESource should have been removed
	 * when the account was disabled. We should only clean up the MAPI profile database etc. 
	 */
	if (info->enabled) {
		remove_addressbook_sources (info);
		remove_calendar_sources (account);
	}

	/* Now, clean up the profile database etc */
	url = camel_url_new (info->source_url, NULL);
	if (url != NULL) {
		const char *profile = camel_url_get_param (url, "profile");
		gchar *key = camel_url_to_string (url, CAMEL_URL_HIDE_PASSWORD | CAMEL_URL_HIDE_PARAMS);
		exchange_mapi_delete_profile (profile);
		e_passwords_forget_password (EXCHANGE_MAPI_PASSWORD_COMPONENT, key); 
		g_free (key); 
		camel_url_free (url);
	}

	/* Free up the structure */
	g_free (info->uid);
	g_free (info->name);
	g_free (info->source_url);
	g_free (info);
}

static gboolean
create_profile_entry (CamelURL *url)
{
	gboolean status = FALSE;
	guint8 attempts = 0; 

	while (!status && attempts <= 3) {
		gchar *password = NULL, *key = NULL;

		key = camel_url_to_string (url, CAMEL_URL_HIDE_PASSWORD | CAMEL_URL_HIDE_PARAMS);
		password = e_passwords_get_password (EXCHANGE_MAPI_PASSWORD_COMPONENT, key);
		if (!password) {
			gboolean remember = FALSE;
			gchar *title;

			title = g_strdup_printf (_("Enter Password for %s@%s"), url->user, url->host);
			password = e_passwords_ask_password (title, EXCHANGE_MAPI_PASSWORD_COMPONENT, key, title,
					E_PASSWORDS_REMEMBER_FOREVER|E_PASSWORDS_SECRET,
					&remember, NULL);
			g_free (title);
		} 
		g_free (key);

		if (password)
			status = exchange_mapi_create_profile (url->user, password, camel_url_get_param (url, "domain"), url->host);

		++attempts; 
	}

	return status; 
}

static gboolean
mapi_camel_url_equal (CamelURL *a, CamelURL *b)
{
	const char *params[] = { "profile", "domain", "ad_limit", "ad_server" }; 
	guint n_params = G_N_ELEMENTS (params), i; 
	gboolean retval = TRUE; 

	retval &= camel_url_equal (a, b); 

	for (i = 0; i < n_params; ++i)
		retval &= (g_ascii_strcasecmp (camel_url_get_param (a, params[i]), camel_url_get_param (b, params[i])) == 0);

	return retval; 
}

static void
mapi_account_changed (EAccountList *account_listener, EAccount *account)
{
	CamelURL *new_url = NULL, *old_url = NULL;
	gboolean isa_mapi_account = FALSE;
	ExchangeMAPIAccountInfo *existing_account_info = NULL;

	isa_mapi_account = is_mapi_account (account);

	if (isa_mapi_account)
		existing_account_info = lookup_account_info (account->uid);

	if (existing_account_info)
		old_url = camel_url_new (existing_account_info->source_url, NULL); 

	new_url = camel_url_new (account->source->url, NULL); 

	if (existing_account_info == NULL && isa_mapi_account) {
		/* some account of other type is changed to MAPI */
		if (create_profile_entry (new_url)) {
			/* Things are successful */
			gchar *profname = NULL, *uri = NULL; 
			ExchangeMAPIAccountListener *config_listener = exchange_mapi_accounts_peek_config_listener();

			profname = g_strdup_printf("%s@%s", new_url->user, camel_url_get_param (new_url, "domain"));
			camel_url_set_param(new_url, "profile", profname);
			g_free (profname);

			uri = camel_url_to_string(new_url, 0);
			/* FIXME: Find a better way to append to the Account source URL. The current
			 * method uses e_account_set_string() which initiates another signal emmission
			 * which we have to block for now. */
			g_signal_handlers_block_by_func (config_listener->priv->account_list, G_CALLBACK (mapi_account_changed), NULL); 
			e_account_set_string(account, E_ACCOUNT_SOURCE_URL, uri);
			g_signal_handlers_unblock_by_func (config_listener->priv->account_list, G_CALLBACK (mapi_account_changed), NULL); 
			g_free (uri);

			mapi_account_added (account_listener, account);
		}
	} else if (existing_account_info != NULL && !isa_mapi_account) {
		/* MAPI account is changed to some other type */
		mapi_account_removed (account_listener, account);
	} else if (existing_account_info != NULL && isa_mapi_account) {
		/* Just disabling the account requires no further action */
		if (!account->enabled) {
			remove_addressbook_sources (existing_account_info);
			remove_calendar_sources (account);
			existing_account_info->enabled = FALSE;
		} else if (!mapi_camel_url_equal (old_url, new_url) || (existing_account_info->enabled != account->enabled)) {
		/* Some or all of the account info changed OR the account has been moved from a disabled state to enabled state */
			mapi_account_removed (account_listener, account);
			if (create_profile_entry (new_url)) {
				/* Things are successful */
				gchar *profname = NULL, *uri = NULL; 
				ExchangeMAPIAccountListener *config_listener = exchange_mapi_accounts_peek_config_listener();

				profname = g_strdup_printf("%s@%s", new_url->user, camel_url_get_param (new_url, "domain"));
				camel_url_set_param(new_url, "profile", profname);
				g_free (profname);

				uri = camel_url_to_string(new_url, 0);
				/* FIXME: Find a better way to append to the Account source URL. The current
				 * method uses e_account_set_string() which initiates another signal emmission
				 * which we have to block for now. */
				g_signal_handlers_block_by_func (config_listener->priv->account_list, G_CALLBACK (mapi_account_changed), NULL); 
				e_account_set_string(account, E_ACCOUNT_SOURCE_URL, uri);
				g_signal_handlers_unblock_by_func (config_listener->priv->account_list, G_CALLBACK (mapi_account_changed), NULL); 
				g_free (uri);

				mapi_account_added (account_listener, account);
			}
		}
	}

	if (old_url)
		camel_url_free (old_url); 

	camel_url_free (new_url); 
} 

static void
exchange_mapi_account_listener_construct (ExchangeMAPIAccountListener *config_listener)
{
	EIterator *iter;

	config_listener->priv->account_list = e_account_list_new (config_listener->priv->gconf_client);

	for (iter = e_list_get_iterator (E_LIST(config_listener->priv->account_list)); e_iterator_is_valid (iter); e_iterator_next (iter)) {
		EAccount *account = E_ACCOUNT (e_iterator_get (iter));
		if (is_mapi_account (account)) {
			ExchangeMAPIAccountInfo *info = g_new0 (ExchangeMAPIAccountInfo, 1);
			info->uid = g_strdup (account->uid);
			info->name = g_strdup (account->name);
			info->source_url = g_strdup (account->source->url);
			info->enabled = account->enabled; 
			mapi_accounts = g_list_append (mapi_accounts, info);
		}
	}

	d(g_debug ("MAPI listener is constructed with %d listed MAPI accounts ", g_list_length (mapi_accounts)));

	g_signal_connect (config_listener->priv->account_list, "account_added", G_CALLBACK (mapi_account_added), NULL);
	g_signal_connect (config_listener->priv->account_list, "account_changed", G_CALLBACK (mapi_account_changed), NULL);
	g_signal_connect (config_listener->priv->account_list, "account_removed", G_CALLBACK (mapi_account_removed), NULL);
}

GType
exchange_mapi_account_listener_get_type (void)
{
	static GType exchange_mapi_account_listener_type = 0;

	if (!exchange_mapi_account_listener_type) {
		static GTypeInfo info = {
			sizeof (ExchangeMAPIAccountListenerClass),
			(GBaseInitFunc) NULL,
			(GBaseFinalizeFunc) NULL,
			(GClassInitFunc) exchange_mapi_account_listener_class_init,
			NULL, NULL,
			sizeof (ExchangeMAPIAccountListener),
			0,
			(GInstanceInitFunc) exchange_mapi_account_listener_init
		};
		exchange_mapi_account_listener_type = g_type_register_static (PARENT_TYPE, "ExchangeMAPIAccountListener", &info, 0);
	}

	return exchange_mapi_account_listener_type;
}

ExchangeMAPIAccountListener *
exchange_mapi_account_listener_new ()
{
	ExchangeMAPIAccountListener *config_listener;

	config_listener = g_object_new (EXCHANGE_MAPI_ACCOUNT_LISTENER_TYPE, NULL);
	config_listener->priv->gconf_client = gconf_client_get_default();

	exchange_mapi_account_listener_construct (config_listener);

	return config_listener;
}
