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

#include "e-mapi-account-listener.h"
#include "e-mapi-account-setup.h"
#include <string.h>
#include <glib/gi18n-lib.h>
#include <camel/camel.h>
#include <libedataserverui/e-passwords.h>
#include <libedataserver/e-account.h>
#include <libecal/e-cal-client.h>
#include <libedataserver/e-account-list.h>
#include <libedataserver/e-source.h>
#include <libedataserver/e-source-list.h>
#include <shell/e-shell.h>

#include <e-mapi-folder.h>
#include <e-mapi-connection.h>
#include <e-mapi-utils.h>
#include <e-mapi-operation-queue.h>

#define d(x)

#define SET_KRB_SSO(_esource, _krbval) \
	G_STMT_START { \
		ESource *tmp_src = (_esource); \
		const gchar *tmp_val = (_krbval); \
		e_source_set_property (tmp_src, "kerberos", tmp_val); \
		if (tmp_val && g_str_equal (tmp_val, "required")) { \
			e_source_set_property (tmp_src, "auth", NULL); \
			e_source_set_property (tmp_src, "auth-type", NULL); \
		} \
	} G_STMT_END

G_DEFINE_TYPE (EMapiAccountListener, e_mapi_account_listener, G_TYPE_OBJECT)

static gboolean create_profile_entry (CamelURL *url, EAccount *account, CamelMapiSettings *settings);

struct _EMapiAccountListenerPrivate {
	GConfClient *gconf_client;
	/* we get notification about mail account changes from this object */
	EAccountList *account_list;
};

typedef struct _EMapiAccountInfo EMapiAccountInfo;

/* stores some info about all currently existing mapi accounts */
struct _EMapiAccountInfo {
	gchar *uid;
	gchar *name;
	gchar *source_url;
	gboolean enabled;
};

static EMapiAccountInfo *
copy_mapi_account_info (const EMapiAccountInfo *src)
{
	EMapiAccountInfo *res;

	g_return_val_if_fail (src != NULL, NULL);

	res = g_new0 (EMapiAccountInfo, 1);
	res->uid = g_strdup (src->uid);
	res->name = g_strdup (src->name);
	res->source_url = g_strdup (src->source_url);
	res->enabled = src->enabled;

	return res;
}

static void
free_mapi_account_info (EMapiAccountInfo *info)
{
	g_return_if_fail (info != NULL);

	g_free (info->uid);
	g_free (info->name);
	g_free (info->source_url);
	g_free (info);
}

/* list of EMapiAccountInfo structures */
static GList *mapi_accounts = NULL;
static gpointer async_ops = NULL; /* EMapiOperationQueue * */

static GObjectClass *parent_class = NULL;

static void
dispose (GObject *object)
{
	EMapiAccountListener *config_listener = E_MAPI_ACCOUNT_LISTENER (object);

	g_object_unref (config_listener->priv->gconf_client);
	g_object_unref (config_listener->priv->account_list);

	G_OBJECT_CLASS (parent_class)->dispose (object);
}

static void
finalize (GObject *object)
{
	EMapiAccountListener *config_listener = E_MAPI_ACCOUNT_LISTENER (object);
	GList *list;

	if (config_listener->priv) {
		g_free (config_listener->priv);
	}

	for (list = g_list_first (mapi_accounts); list; list = g_list_next (list)) {
		EMapiAccountInfo *info = (EMapiAccountInfo *)(list->data);
		if (info) {
			g_free (info->uid);
			g_free (info->name);
			g_free (info->source_url);
			g_free (info);
		}
	}

	g_list_free (mapi_accounts);

	G_OBJECT_CLASS (parent_class)->finalize (object);

	if (async_ops)
		g_object_unref (async_ops);
}

static void
e_mapi_account_listener_class_init (EMapiAccountListenerClass *class)
{
	GObjectClass *object_class;

	parent_class = g_type_class_ref (G_TYPE_OBJECT);
	object_class = G_OBJECT_CLASS (class);

	/* virtual method override */
	object_class->dispose = dispose;
	object_class->finalize = finalize;
}

static void
e_mapi_account_listener_init (EMapiAccountListener *config_listener)
{
	config_listener->priv = g_new0 (EMapiAccountListenerPrivate, 1);
}

/*determines whehter the passed in account is exchange or not by looking at source url */

static gboolean
is_mapi_account (EAccount *account)
{
	return (account->source->url && (g_ascii_strncasecmp (account->source->url, MAPI_URI_PREFIX, MAPI_PREFIX_LENGTH) == 0));
}

/* looks up for an existing exchange account info in the mapi_accounts list based on uid */

static EMapiAccountInfo*
lookup_account_info (const gchar *key)
{
	GList *list;

	g_return_val_if_fail (key != NULL, NULL);

	for (list = g_list_first (mapi_accounts); list; list = g_list_next (list)) {
		EMapiAccountInfo *info = (EMapiAccountInfo *)(list->data);
		if (g_ascii_strcasecmp (info->uid, key) == 0)
			return info;
	}

	return NULL;
}

static ESource *
find_source_by_fid (GSList *sources, const gchar *fid)
{
	GSList *s;

	g_return_val_if_fail (fid != NULL, NULL);

	if (!sources)
		return NULL;

	for (s = sources; s; s = s->next) {
		ESource *source = s->data;

		if (source && E_IS_SOURCE (source)) {
			const gchar *has_fid = e_source_get_property (source, "folder-id");

			if (has_fid && g_str_equal (fid, has_fid))
				return source;
		}
	}

	return NULL;
}

#define CALENDAR_SOURCES	"/apps/evolution/calendar/sources"
#define TASK_SOURCES		"/apps/evolution/tasks/sources"
#define JOURNAL_SOURCES		"/apps/evolution/memos/sources"
#define SELECTED_CALENDARS	"/apps/evolution/calendar/display/selected_calendars"
#define SELECTED_TASKS		"/apps/evolution/calendar/tasks/selected_tasks"
#define SELECTED_JOURNALS	"/apps/evolution/calendar/memos/selected_memos"
#define ADDRESSBOOK_SOURCES     "/apps/evolution/addressbook/sources"

static void
add_cal_esource (EAccount *account, GSList *folders, EMapiFolderType folder_type, CamelURL *url, CamelSettings *settings, mapi_id_t trash_fid)
{
	CamelMapiSettings *mapi_settings;
	ESourceList *source_list = NULL;
	ESourceGroup *group = NULL;
	const gchar *conf_key = NULL, *source_selection_key = NULL;
	GConfClient* client;
	GSList *ids, *temp_list, *old_sources = NULL;
	gchar *base_uri = NULL;
	gboolean is_new_group = FALSE;
	const gchar *profile;
	const gchar *domain;
	const gchar *realm;
	const gchar *kerberos;
	gboolean stay_synchronized;

	mapi_settings = CAMEL_MAPI_SETTINGS (settings);
	profile = camel_mapi_settings_get_profile (mapi_settings);
	domain = camel_mapi_settings_get_domain (mapi_settings);
	realm = camel_mapi_settings_get_realm (mapi_settings);
	kerberos = camel_mapi_settings_get_kerberos (mapi_settings) ? "required" : NULL;
	stay_synchronized = camel_offline_settings_get_stay_synchronized (CAMEL_OFFLINE_SETTINGS (settings));

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
		g_warning ("%s: %s: Unknown EMapiFolderType\n", G_STRLOC, G_STRFUNC);
		return;
	}

	client = gconf_client_get_default ();
	source_list = e_source_list_new_for_gconf (client, conf_key);
	base_uri = g_strdup_printf ("%s%s@%s/", MAPI_URI_PREFIX, url->user, url->host);
	group = e_source_list_peek_group_by_base_uri (source_list, base_uri);
	if (group) {
		e_source_group_set_name (group, account->name);
		g_object_ref (group);
		is_new_group = FALSE;
		old_sources = NULL;
		for (temp_list = e_source_group_peek_sources (group); temp_list; temp_list = temp_list->next) {
			old_sources = g_slist_prepend (old_sources, temp_list->data);
		}
	} else {
		group = e_source_group_new (account->name, base_uri);
		is_new_group = TRUE;
		old_sources = NULL;
	}
	g_free (base_uri);
	e_source_group_set_property (group, "create_source", "yes");
	e_source_group_set_property (group, "username", url->user);
	e_source_group_set_property (group, "host", url->host);
	e_source_group_set_property (group, "profile", profile);
	e_source_group_set_property (group, "domain", domain);
	e_source_group_set_property (group, "realm", realm);
	e_source_group_set_property (group, "kerberos", kerberos);

	/* We set these because on new folder creation - these are required. */
	e_source_group_set_property (group, "acl-user-name", account->id->name);
	e_source_group_set_property (group, "acl-user-email", account->id->address);
	e_source_group_set_property (group, "acl-owner-name", account->id->name);
	e_source_group_set_property (group, "acl-owner-email", account->id->address);

	for (temp_list = folders; temp_list != NULL; temp_list = g_slist_next (temp_list)) {
		EMapiFolder *folder = temp_list->data;
		ESource *source = NULL;
		gchar *relative_uri = NULL, *fid = NULL;
		gboolean is_new_source = FALSE;

		if (folder->container_class != folder_type || trash_fid == e_mapi_folder_get_parent_id (folder))
			continue;

		fid = e_mapi_util_mapi_id_to_string (folder->folder_id);
		relative_uri = g_strconcat (";", fid, NULL);
		source = find_source_by_fid (old_sources, fid);
		if (source) {
			is_new_source = FALSE;
			g_object_ref (source);
			old_sources = g_slist_remove (old_sources, source);
			e_source_set_name (source, folder->folder_name);
			e_source_set_relative_uri (source, relative_uri);
		} else {
			source = e_source_new (folder->folder_name, relative_uri);
			is_new_source = TRUE;
		}
		e_source_set_property (source, "auth", "1");
		e_source_set_property (source, "auth-type", "plain/password");
		e_source_set_property (source, "username", url->user);
		e_source_set_property (source, "host", url->host);
		e_source_set_property (source, "profile", profile);
		e_source_set_property (source, "domain", domain);
		e_source_set_property (source, "realm", realm);
		e_source_set_property (source, "folder-id", fid);
		e_source_set_property (source, "public", "no");
		SET_KRB_SSO(source, kerberos);

		if (is_new_source)
			e_source_set_property (source, "offline_sync", stay_synchronized ? "1" : "0");

		if (folder->is_default)
			e_source_set_property (source, "delete", "no");
		else
			e_source_set_property (source, "delete", NULL);

		if (folder->parent_folder_id) {
			gchar *tmp = e_mapi_util_mapi_id_to_string (folder->parent_folder_id);
			e_source_set_property (source, "parent-fid", tmp);
			g_free (tmp);
		} else {
			e_source_set_property (source, "parent-fid", NULL);
		}

		e_source_set_property (source, "acl-user-name", account->id->name);
		e_source_set_property (source, "acl-user-email", account->id->address);
		/* FIXME: this would change after foreign folders/delegation is implemented */
		e_source_set_property (source, "acl-owner-name", account->id->name);
		e_source_set_property (source, "acl-owner-email", account->id->address);

		if (is_new_source)
			e_source_group_add_source (group, source, -1);

		if (source_selection_key && folder->is_default) {
			ids = gconf_client_get_list (client, source_selection_key , GCONF_VALUE_STRING, NULL);
			ids = g_slist_append (ids, g_strdup (e_source_peek_uid (source)));
			gconf_client_set_list (client, source_selection_key, GCONF_VALUE_STRING, ids, NULL);

			g_slist_foreach (ids, (GFunc) g_free, NULL);
			g_slist_free (ids);
		}

		g_object_unref (source);
		g_free (relative_uri);
		g_free (fid);
	}

	if (old_sources) {
		/* these were not found on the server by fid, thus remove them */
		for (temp_list = old_sources; temp_list; temp_list = temp_list->next) {
			ESource *source = temp_list->data;

			if (source && E_IS_SOURCE (source)) {
				if (g_strcmp0 (e_source_get_property (source, "public"), "yes") != 0)
					e_source_group_remove_source (group, source);
			}
		}

		g_slist_free (old_sources);
	}

	if (is_new_group && !e_source_list_add_group (source_list, group, -1))
		g_warning ("%s: Failed to add new group", G_STRFUNC);

	if (!e_source_list_sync (source_list, NULL))
		g_warning ("%s: Failed to sync source list", G_STRFUNC);

	g_object_unref (group);
	g_object_unref (source_list);
	g_object_unref (client);
}

void e_mapi_add_esource (CamelService *service, const gchar *folder_name, const gchar *fid, gint folder_type)
{
	CamelNetworkSettings *network_settings;
	CamelOfflineSettings *offline_settings;
	CamelMapiSettings *mapi_settings;
	CamelSettings *settings;
	ESourceList *source_list = NULL;
	ESourceGroup *group = NULL;
	const gchar *conf_key = NULL, *kerberos = NULL;
	GConfClient* client;
	GSList *sources;
	ESource *source = NULL;
	gchar *relative_uri = NULL;
	gchar *base_uri = NULL;
	const gchar *host;
	const gchar *user;

	g_return_if_fail (CAMEL_IS_SERVICE (service));

	if (folder_type == MAPI_FOLDER_TYPE_APPOINTMENT)
		conf_key = CALENDAR_SOURCES;
	else if (folder_type == MAPI_FOLDER_TYPE_TASK)
		conf_key = TASK_SOURCES;
	else if (folder_type == MAPI_FOLDER_TYPE_MEMO)
		conf_key = JOURNAL_SOURCES;
	else if (folder_type == MAPI_FOLDER_TYPE_JOURNAL)
		conf_key = JOURNAL_SOURCES;
	else if (folder_type == MAPI_FOLDER_TYPE_CONTACT)
		conf_key = ADDRESSBOOK_SOURCES;
	else {
		g_warning ("%s: %s: Unknown EMapiFolderType\n", G_STRLOC, G_STRFUNC);
		return;
	}

	settings = camel_service_get_settings (service);

	network_settings = CAMEL_NETWORK_SETTINGS (settings);
	host = camel_network_settings_get_host (network_settings);
	user = camel_network_settings_get_user (network_settings);

	client = gconf_client_get_default ();
	source_list = e_source_list_new_for_gconf (client, conf_key);
	base_uri = g_strdup_printf ("%s%s@%s/", MAPI_URI_PREFIX, user, host);
	group = e_source_list_peek_group_by_base_uri (source_list, base_uri);
	sources = e_source_group_peek_sources (group);
	for (; sources != NULL; sources = g_slist_next (sources)) {
		ESource *source = E_SOURCE (sources->data);
		gchar * folder_id = e_source_get_duped_property (source, "folder-id");
		if (folder_id && fid) {
			if (strcmp (fid, folder_id) != 0)
				continue;
			else {
				g_warning ("%s: %s: Esource Already exist \n", G_STRLOC, G_STRFUNC);
				return;
			}
		}
	}

	mapi_settings = CAMEL_MAPI_SETTINGS (settings);
	offline_settings = CAMEL_OFFLINE_SETTINGS (settings);

	relative_uri = g_strconcat (";", fid, NULL);
	kerberos = camel_mapi_settings_get_kerberos (mapi_settings) ? "required" : NULL;
	source = e_source_new (folder_name, relative_uri);
	e_source_set_property (source, "auth", "1");
	e_source_set_property (source, "auth-type", "plain/password");
	e_source_set_property (source, "username", user);
	e_source_set_property (source, "host", host);
	e_source_set_property (source, "profile", camel_mapi_settings_get_profile (mapi_settings));
	e_source_set_property (source, "domain", camel_mapi_settings_get_domain (mapi_settings));
	e_source_set_property (source, "realm", camel_mapi_settings_get_realm (mapi_settings));
	e_source_set_property (source, "folder-id", fid);
	e_source_set_property (source, "offline_sync", camel_offline_settings_get_stay_synchronized (offline_settings) ? "1" : "0");
	e_source_set_property (source, "public", "yes");
	e_source_set_property (source, "delete", "yes");
	SET_KRB_SSO(source, kerberos);

	e_source_group_add_source (group, source, -1);

	g_object_unref (source);
	g_free (relative_uri);

	if (!e_source_list_add_group (source_list, group, -1))
		return;

	if (!e_source_list_sync (source_list, NULL))
		return;

	g_object_unref (group);
	g_object_unref (source_list);
	g_object_unref (client);
}

void e_mapi_remove_esource (CamelService *service, const gchar * folder_name, const gchar *fid, gint folder_type)
{
	CamelNetworkSettings *network_settings;
	CamelSettings *settings;
	ESourceList *source_list = NULL;
	ESourceGroup *group = NULL;
	const gchar *conf_key = NULL;
	GConfClient* client;
	GSList *sources=NULL;
	gchar *base_uri = NULL;
	const gchar *host;
	const gchar *user;

	g_return_if_fail (CAMEL_IS_SERVICE (service));

	if (folder_type == MAPI_FOLDER_TYPE_APPOINTMENT)
		conf_key = CALENDAR_SOURCES;
	else if (folder_type == MAPI_FOLDER_TYPE_TASK)
		conf_key = TASK_SOURCES;
	else if (folder_type == MAPI_FOLDER_TYPE_MEMO)
		conf_key = JOURNAL_SOURCES;
	else if (folder_type == MAPI_FOLDER_TYPE_JOURNAL)
		conf_key = JOURNAL_SOURCES;
	else if (folder_type == MAPI_FOLDER_TYPE_CONTACT)
		conf_key = ADDRESSBOOK_SOURCES;
	else {
		g_warning ("%s: %s: Unknown EMapiFolderType\n", G_STRLOC, G_STRFUNC);
		return;
	}

	settings = camel_service_get_settings (service);

	network_settings = CAMEL_NETWORK_SETTINGS (settings);
	host = camel_network_settings_get_host (network_settings);
	user = camel_network_settings_get_user (network_settings);

	client = gconf_client_get_default ();
	source_list = e_source_list_new_for_gconf (client, conf_key);
	base_uri = g_strdup_printf ("%s%s@%s/", MAPI_URI_PREFIX, user, host);
	group = e_source_list_peek_group_by_base_uri (source_list, base_uri);
	sources = e_source_group_peek_sources (group);

	for (; sources != NULL; sources = g_slist_next (sources)) {
		ESource *source = E_SOURCE (sources->data);
		gchar * folder_id = e_source_get_duped_property (source, "folder-id");
		if (folder_id && fid)
			if (strcmp(fid, folder_id) == 0) {
				e_source_group_remove_source(group, source);
				break;
			}
	}

	g_free (base_uri);
	g_object_unref (source_list);
	g_object_unref (client);

}

static void
remove_cal_esource (EAccount *existing_account_info, EMapiFolderType folder_type, CamelURL *url)
{
	ESourceList *list;
	const gchar *conf_key = NULL, *source_selection_key = NULL;
	GSList *groups;
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
		g_warning ("%s: %s: Unknown EMapiFolderType\n", G_STRLOC, G_STRFUNC);
		return;
	}

	client = gconf_client_get_default();
	list = e_source_list_new_for_gconf (client, conf_key);

	base_uri = g_strdup_printf ("mapi://%s@%s/", url->user, url->host);

	for (groups = e_source_list_peek_groups (list); groups != NULL; groups = g_slist_next (groups)) {
		ESourceGroup *group = E_SOURCE_GROUP (groups->data);

		if (strcmp (e_source_group_peek_name (group), existing_account_info->name) == 0 &&
		    strcmp (e_source_group_peek_base_uri (group), base_uri) == 0) {
			GSList *sources = e_source_group_peek_sources (group);

			for (; sources != NULL; sources = g_slist_next (sources)) {
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
			break;
		}
	}

	g_free (base_uri);
	g_object_unref (list);
	g_object_unref (client);
}

/* add sources for calendar and tasks if the account added is exchange account
   adds the new account info to mapi_accounts list;
   it is always called in the main thread
*/
static void
add_calendar_sources (EAccount *account, GSList *folders, mapi_id_t trash_fid)
{
	CamelURL *url;

	url = camel_url_new (account->source->url, NULL);

	if (url) {
		CamelSettings *settings;

		settings = g_object_new (CAMEL_TYPE_MAPI_SETTINGS, NULL);
		camel_settings_load_from_url (settings, url);

		add_cal_esource (account, folders, MAPI_FOLDER_TYPE_APPOINTMENT, url, settings, trash_fid);
		add_cal_esource (account, folders, MAPI_FOLDER_TYPE_TASK, url, settings, trash_fid);
		add_cal_esource (account, folders, MAPI_FOLDER_TYPE_MEMO, url, settings, trash_fid);

		g_object_unref (settings);
		camel_url_free (url);
	}
}

/* removes calendar and tasks sources if the account removed is exchange account
   removes the the account info from mapi_account list;
   it is always called in the main thread
*/
static void
remove_calendar_sources_async (gpointer worker_data, gboolean cancelled, gpointer user_data)
{
	EAccount *account = worker_data;
	CamelURL *url;

	g_return_if_fail (account != NULL);

	url = camel_url_new (account->source->url, NULL);

	if (url) {
		remove_cal_esource (account, MAPI_FOLDER_TYPE_APPOINTMENT, url);
		remove_cal_esource (account, MAPI_FOLDER_TYPE_TASK, url);
		remove_cal_esource (account, MAPI_FOLDER_TYPE_MEMO, url);

		camel_url_free (url);
	}

	g_object_unref (account);
}

static void
remove_calendar_sources (EAccount *account)
{
	g_return_if_fail (account != NULL);

	g_object_ref (account);

	if (!g_main_context_get_thread_default () || g_main_context_is_owner (g_main_context_default ())) {
		e_mapi_async_queue_push (async_ops, account, NULL, NULL, remove_calendar_sources_async);
	} else {
		remove_calendar_sources_async (account, FALSE, NULL);
	}
}

static gboolean
add_addressbook_sources (EAccount *account, GSList *folders, mapi_id_t trash_fid)
{
	CamelURL *url;
	CamelMapiSettings *settings;
	ESourceList *list;
	ESourceGroup *group;
	ESource *source;
	gchar *base_uri;
	GSList *temp_list, *old_sources = NULL;
	GConfClient* client;
	gboolean is_new_group = FALSE;
	const gchar *profile;
	const gchar *domain;
	const gchar *realm;
	const gchar *kerberos;
	gboolean stay_synchronized;

	url = camel_url_new (account->source->url, NULL);
	if (url == NULL) {
		return FALSE;
	}

	settings = g_object_new (CAMEL_TYPE_MAPI_SETTINGS, NULL);
	camel_settings_load_from_url (CAMEL_SETTINGS (settings), url);

	profile = camel_mapi_settings_get_profile (settings);
	domain = camel_mapi_settings_get_domain (settings);
	realm = camel_mapi_settings_get_realm (settings);
	kerberos = camel_mapi_settings_get_kerberos (settings) ? "required" : NULL;
	stay_synchronized = camel_offline_settings_get_stay_synchronized (CAMEL_OFFLINE_SETTINGS (settings));

	base_uri = g_strdup_printf ("mapi://%s@%s/", url->user, url->host);
	client = gconf_client_get_default ();
	list = e_source_list_new_for_gconf (client, "/apps/evolution/addressbook/sources" );
	group = e_source_list_peek_group_by_base_uri (list, base_uri);
	if (group) {
		e_source_group_set_name (group, account->name);
		g_object_ref (group);
		is_new_group = FALSE;
		old_sources = NULL;
		for (temp_list = e_source_group_peek_sources (group); temp_list; temp_list = temp_list->next) {
			old_sources = g_slist_prepend (old_sources, temp_list->data);
		}
	} else {
		group = e_source_group_new (account->name, base_uri);
		is_new_group = TRUE;
		old_sources = NULL;
	}
	e_source_group_set_property (group, "user", NULL);
	e_source_group_set_property (group, "username", url->user);
	e_source_group_set_property (group, "host", url->host);
	e_source_group_set_property (group, "profile", profile);
	e_source_group_set_property (group, "domain", domain);
	e_source_group_set_property (group, "realm", realm);
	e_source_group_set_property (group, "kerberos", kerberos);

	for (temp_list = folders; temp_list != NULL; temp_list = g_slist_next (temp_list)) {
		EMapiFolder *folder = temp_list->data;
		gchar *fid, *relative_uri;
		gboolean is_new_source = FALSE;

		if (folder->container_class != MAPI_FOLDER_TYPE_CONTACT || trash_fid == e_mapi_folder_get_parent_id (folder))
			continue;

		fid = e_mapi_util_mapi_id_to_string (folder->folder_id);
		relative_uri = g_strconcat (";", folder->folder_name, NULL);
		source = find_source_by_fid (old_sources, fid);
		if (source) {
			is_new_source = FALSE;
			g_object_ref (source);
			old_sources = g_slist_remove (old_sources, source);
			e_source_set_name (source, folder->folder_name);
			e_source_set_relative_uri (source, relative_uri);
		} else {
			source = e_source_new (folder->folder_name, relative_uri);
			is_new_source = TRUE;
		}
		e_source_set_property (source, "auth", "plain/password");
		e_source_set_property(source, "user", NULL);
		e_source_set_property(source, "username", url->user);
		e_source_set_property(source, "host", url->host);
		e_source_set_property(source, "profile", profile);
		e_source_set_property(source, "domain", domain);
		e_source_set_property(source, "realm", realm);
		e_source_set_property(source, "folder-id", fid);
		e_source_set_property (source, "public", "no");
		SET_KRB_SSO(source, kerberos);

		if (is_new_source) {
			e_source_set_property (source, "offline_sync", stay_synchronized ? "1" : "0");
			e_source_set_property (source, "completion", "true");
		}

		if (folder->is_default)
			e_source_set_property (source, "delete", "no");
		else
			e_source_set_property (source, "delete", NULL);

		if (folder->parent_folder_id) {
			gchar *tmp = e_mapi_util_mapi_id_to_string (folder->parent_folder_id);
			e_source_set_property (source, "parent-fid", tmp);
			g_free (tmp);
		} else {
			e_source_set_property (source, "parent-fid", NULL);
		}

		if (is_new_source)
			e_source_group_add_source (group, source, -1);
		g_object_unref (source);
		g_free (fid);
		g_free (relative_uri);
	}

	//Add GAL
	if (!gconf_client_get_bool (client, "/apps/evolution/eplugin/mapi/disable_gal", NULL)) {
		gchar *uri;
		gboolean is_new_source = FALSE;

		source = NULL;
		uri = g_strdup_printf ("mapigal://%s@%s/;Global Address List", url->user, url->host);
		for (temp_list = old_sources; temp_list; temp_list = temp_list->next) {
			source = temp_list->data;

			if (source && E_IS_SOURCE (source)
			    && e_source_peek_absolute_uri (source)
			    && g_str_equal (e_source_peek_absolute_uri (source), uri))
				break;
		}

		if (source) {
			is_new_source = FALSE;
			g_object_ref (source);
			old_sources = g_slist_remove (old_sources, source);
			e_source_set_name (source, _("Global Address List"));
		} else {
			source = e_source_new_with_absolute_uri (_("Global Address List"), uri);
			is_new_source = TRUE;
		}
		g_free (uri);
		e_source_set_property (source, "auth", "plain/password");

		//FIXME: Offline handling
		e_source_set_property(source, "user", NULL);
		e_source_set_property(source, "username", url->user);
		e_source_set_property(source, "profile", profile);
		e_source_set_property(source, "domain", domain);
		e_source_set_property(source, "realm", realm);
		SET_KRB_SSO(source, kerberos);

		if (is_new_source) {
			e_source_set_property(source, "offline_sync", "1");
			e_source_set_property (source, "completion", "true");
		}

		e_source_set_property (source, "delete", "no");
		if (is_new_source)
			e_source_group_add_source (group, source, -1);
		g_object_unref (source);
	}

	if (old_sources) {
		/* these were not found on the server by fid, thus remove them */
		for (temp_list = old_sources; temp_list; temp_list = temp_list->next) {
			ESource *source = temp_list->data;

			if (source && E_IS_SOURCE (source)) {
				if (g_strcmp0 (e_source_get_property (source, "public"), "yes") != 0)
					e_source_group_remove_source (group, source);
			}
		}

		g_slist_free (old_sources);
	}

	if (is_new_group && !e_source_list_add_group (list, group, -1))
		g_warning ("%s: Failed to add new group", G_STRFUNC);

	if (!e_source_list_sync (list, NULL))
		g_warning ("%s: Failed to sync source list", G_STRFUNC);

	g_object_unref (settings);

	g_object_unref (group);
	g_object_unref (list);
	g_object_unref (client);
	g_free (base_uri);

	return TRUE;
}

/* this is always called in the main thread */
static void
remove_addressbook_sources_async (gpointer worker_data, gboolean cancelled, gpointer user_data)
{
	EMapiAccountInfo *existing_account_info = worker_data;
	ESourceList *list;
	ESourceGroup *group;
	GSList *groups;
	CamelURL *url;
	gchar *base_uri;
	GConfClient *client;

	g_return_if_fail (existing_account_info != NULL);

	url = camel_url_new (existing_account_info->source_url, NULL);
	if (url == NULL) {
		free_mapi_account_info (existing_account_info);
		return;
	}

	base_uri = g_strdup_printf ("mapi://%s@%s/", url->user, url->host);
	client = gconf_client_get_default ();
	list = e_source_list_new_for_gconf (client, "/apps/evolution/addressbook/sources" );

	for (groups = e_source_list_peek_groups (list); groups != NULL; groups = g_slist_next (groups)) {
		group = E_SOURCE_GROUP (groups->data);

		if (strcmp (e_source_group_peek_base_uri (group), base_uri) == 0 && strcmp (e_source_group_peek_name (group), existing_account_info->name) == 0) {
			e_source_list_remove_group (list, group);
			e_source_list_sync (list, NULL);
			break;
		}
	}

	g_object_unref (list);
	g_object_unref (client);
	g_free (base_uri);
	camel_url_free (url);
	free_mapi_account_info (existing_account_info);
}

static void
remove_addressbook_sources (EMapiAccountInfo *existing_account_info)
{
	g_return_if_fail (existing_account_info != NULL);

	if (!g_main_context_get_thread_default () || g_main_context_is_owner (g_main_context_default ())) {
		e_mapi_async_queue_push (async_ops, copy_mapi_account_info (existing_account_info), NULL, NULL, remove_addressbook_sources_async);
	} else {
		remove_addressbook_sources_async (copy_mapi_account_info (existing_account_info), FALSE, NULL);
	}
}

struct add_sources_data
{
	EAccount *account;
	GSList *folders;
	mapi_id_t trash_fid;
};

static void
add_sources_async (gpointer worker_data, gboolean cancelled, gpointer user_data)
{
	struct add_sources_data *data = worker_data;

	g_return_if_fail (data != NULL);

	add_addressbook_sources (data->account, data->folders, data->trash_fid);
	add_calendar_sources (data->account, data->folders, data->trash_fid);

	g_object_unref (data->account);
	e_mapi_folder_free_list (data->folders);
	g_free (data);
}

static void
add_sources (EAccount *account, GSList *folders, mapi_id_t trash_fid)
{
	struct add_sources_data *data;

	g_return_if_fail (account != NULL);
	g_return_if_fail (folders != NULL);

	data = g_new0 (struct add_sources_data, 1);
	data->account = g_object_ref (account);
	data->folders = e_mapi_folder_copy_list (folders);
	data->trash_fid = trash_fid;

	if (!g_main_context_get_thread_default () || g_main_context_is_owner (g_main_context_default ())) {
		e_mapi_async_queue_push (async_ops, data, NULL, NULL, add_sources_async);
	} else {
		add_sources_async (data, FALSE, NULL);
	}
}

static void
update_sources_idle_cb (gpointer data, gboolean cancelled, gpointer user_data)
{
	EMapiConnection *conn = data;
	EAccount *account;
	GSList *folders_list;

	g_return_if_fail (conn != NULL);

	account = g_object_get_data (G_OBJECT (conn), "EAccount");
	if (!account) {
		g_object_unref (conn);
		g_return_if_fail (account != NULL);
		return;
	}

	g_object_set_data (G_OBJECT (conn), "EAccount", NULL);

	if (!cancelled) {
		folders_list = e_mapi_connection_peek_folders_list (conn);

		if (account->enabled && lookup_account_info (account->uid)) {
			mapi_id_t *trash_fid = user_data;

			add_sources (account, folders_list, trash_fid ? *trash_fid : 0);
		}
	}

	g_object_unref (conn);
	g_object_unref (account);
	g_free (user_data);
}

static void
update_sources_cb (gpointer data, gboolean cancelled, gpointer user_data)
{
	EMapiConnection *conn = data;
	mapi_id_t *trash_id = user_data;

	if (cancelled)
		return;

	g_return_if_fail (conn != NULL);

	/* this fetches folder_list to the connection cache,
	   thus next call will be quick as much as possible */
	e_mapi_connection_peek_folders_list (conn);

	if (trash_id)
		*trash_id = e_mapi_connection_get_default_folder_id (conn, olFolderDeletedItems, NULL, NULL);
}

static void
run_update_sources_thread (EMapiConnection *conn, EAccount *account)
{
	g_return_if_fail (conn != NULL);
	g_return_if_fail (account != NULL);
	g_return_if_fail (async_ops != NULL);

	g_object_set_data (G_OBJECT (conn), "EAccount", g_object_ref (account));

	e_mapi_async_queue_push (async_ops, conn, g_new0 (mapi_id_t, 1), update_sources_cb, update_sources_idle_cb);
}

struct create_sources_data
{
	gchar *profile_name;
	EAccount *account;
};

static gboolean
check_for_account_conn_cb (gpointer data)
{
	struct create_sources_data *csd = data;

	g_return_val_if_fail (csd != NULL, FALSE);
	g_return_val_if_fail (csd->profile_name != NULL, FALSE);
	g_return_val_if_fail (csd->account != NULL, FALSE);

	if (csd->account->enabled && lookup_account_info (csd->account->uid)) {
		EMapiConnection *conn;

		conn = e_mapi_connection_find (csd->profile_name);
		if (!conn) {
			/* try later, it's still trying to connect */
			return TRUE;
		}

		run_update_sources_thread (conn, csd->account);
	}

	g_object_unref (csd->account);
	g_free (csd->profile_name);
	g_free (csd);

	return FALSE;
}

static void
update_account_sources_async (gpointer worker_data, gboolean cancelled, gpointer user_data)
{
	CamelURL *url;
	CamelSettings *settings;
	EMapiConnection *conn;
	EAccount *account = worker_data;
	gboolean can_create_profile = GPOINTER_TO_INT (user_data) ? TRUE : FALSE;
	const gchar *profile;

	url = camel_url_new (account->source->url, NULL);
	g_return_if_fail (url != NULL);

	settings = g_object_new (CAMEL_TYPE_MAPI_SETTINGS, NULL);
	camel_settings_load_from_url (settings, url);

	profile = camel_mapi_settings_get_profile (CAMEL_MAPI_SETTINGS (settings));

	conn = e_mapi_connection_find (profile);
	if (!conn && can_create_profile) {
		/* connect to the server when not connected yet */
		if (!create_profile_entry (url, account, CAMEL_MAPI_SETTINGS (settings))) {
			camel_url_free (url);
			g_object_unref (settings);
			g_warning ("%s: Failed to create MAPI profile for '%s'", G_STRFUNC, account->name);
			return;
		}

		conn = e_mapi_connection_find (profile);
	}

	if (conn) {
		run_update_sources_thread (conn, account);
	} else {
		struct create_sources_data *csd;

		csd = g_new0 (struct create_sources_data, 1);
		csd->profile_name = g_strdup (profile);
		csd->account = g_object_ref (account);

		g_timeout_add_seconds (1, check_for_account_conn_cb, csd);
	}

	camel_url_free (url);
	g_object_unref (account);
	g_object_unref (settings);
}

static void
update_account_sources (EAccount *account, gboolean can_create_profile)
{
	g_return_if_fail (account != NULL);

	if (!g_main_context_get_thread_default () || g_main_context_is_owner (g_main_context_default ())) {
		/* called from main thread, but we want this to be called
		   in its own thread, thus create it */
		e_mapi_async_queue_push (async_ops, g_object_ref (account), GINT_TO_POINTER (can_create_profile ? 1 : 0), update_account_sources_async, NULL);
	} else {
		update_account_sources_async (g_object_ref (account), FALSE, GINT_TO_POINTER (can_create_profile ? 1 : 0));
	}
}

static void
mapi_account_added (EAccountList *account_listener, EAccount *account)
{
	EMapiAccountInfo *info = NULL;

	if (!is_mapi_account (account))
		return;

	info = g_new0 (EMapiAccountInfo, 1);
	info->uid = g_strdup (account->uid);
	info->name = g_strdup (account->name);
	info->source_url = g_strdup (account->source->url);
	info->enabled = account->enabled;

	mapi_accounts = g_list_append (mapi_accounts, info);

	if (account->enabled)
		update_account_sources (account, TRUE);
}

static void
mapi_account_removed (EAccountList *account_listener, EAccount *account)
{
	EMapiAccountInfo *info = NULL;
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
		const gchar *profile = camel_url_get_param (url, "profile");
		gchar *key = camel_url_to_string (url, CAMEL_URL_HIDE_PARAMS);
		struct mapi_context *mapi_ctx = NULL;
		GError *error = NULL;

		if (e_mapi_utils_create_mapi_context (&mapi_ctx, &error)) {
			e_mapi_delete_profile (mapi_ctx, profile, &error);
			e_mapi_utils_destroy_mapi_context (mapi_ctx);
		}

		e_passwords_forget_password (NULL, key);

		g_free (key);
		camel_url_free (url);
		if (error) {
			g_warning ("%s: Failed to delete profile: %s", G_STRFUNC, error->message);
			g_error_free (error);
		}
	}

	/* Free up the structure */
	free_mapi_account_info (info);
}

static gboolean
create_profile_entry (CamelURL *url, EAccount *account, CamelMapiSettings *settings)
{
	gboolean status = FALSE;
	guint8 attempts = 0;
	EMapiProfileData empd = { 0 };
	struct mapi_context *mapi_ctx = NULL;
	GError *error = NULL;

	if (!e_shell_get_online (e_shell_get_default ()))
		return FALSE;

	if (!e_mapi_utils_create_mapi_context (&mapi_ctx, &error)) {
		g_warning ("%s: Failed to create mapi context: %s", G_STRFUNC, error ? error->message : "Unknown error");
		g_clear_error (&error);
		return FALSE;
	}
	
	empd.server = url->host;
	empd.username = url->user;
	e_mapi_util_profiledata_from_settings (&empd, settings);

	while (!status && attempts <= 3) {
		gchar *key = NULL;

		key = camel_url_to_string (url, CAMEL_URL_HIDE_PARAMS);
		if (!attempts && !empd.krb_sso)
			empd.password = e_passwords_get_password (NULL, key);
		if (!empd.password && !empd.krb_sso) {
			gboolean remember = account && e_account_get_bool (account, E_ACCOUNT_SOURCE_SAVE_PASSWD);
			gchar *title;

			title = g_strdup_printf (_("Enter Password for %s@%s"),
						 url->user, url->host);
			empd.password = e_passwords_ask_password (title, NULL, key, title, E_PASSWORDS_REMEMBER_FOREVER | E_PASSWORDS_SECRET | (attempts ? E_PASSWORDS_REPROMPT : 0), &remember, NULL);
			g_free (title);
		}
		g_free (key);


		if (empd.password || empd.krb_sso) {
			GError *error = NULL;

			status = e_mapi_create_profile (mapi_ctx, &empd, NULL, NULL, NULL, &error);
			if (status) {
				/* profile was created, try to connect to the server */
				EMapiConnection *conn;
				gchar *profname;

				status = FALSE;
				profname = e_mapi_util_profile_name (mapi_ctx, &empd, FALSE);

				conn = e_mapi_connection_new (profname, empd.password, NULL, &error);
				if (conn) {
					status = e_mapi_connection_connected (conn);
					g_object_unref (conn);
				}

				g_free (profname);
			}

			if (error) {
				g_warning ("%s: Failed to create profile: %s", G_STRFUNC, error->message);
				g_error_free (error);
			}
		}

		++attempts;
	}

	e_mapi_utils_destroy_mapi_context (mapi_ctx);

	return status;
}

static gboolean
check_equal (const gchar *a, const gchar *b)
{
	if (!a && a == b)
		return TRUE;

	return a && b && g_ascii_strcasecmp (a, b) == 0;
}

static gboolean
mapi_camel_url_equal (CamelURL *a, CamelURL *b)
{
	const gchar *params[] = { "profile", "domain", "realm", "kerberos" };
	guint n_params = G_N_ELEMENTS (params), i;
	gboolean retval = TRUE;

	retval = camel_url_equal (a, b);

	for (i = 0; retval && i < n_params; ++i)
		retval = retval && check_equal (camel_url_get_param (a, params[i]), camel_url_get_param (b, params[i]));

	return retval;
}

static void mapi_account_changed (EAccountList *account_listener, EAccount *account);

static void
mapi_account_changed_async (gpointer worker_data, gboolean cancelled, gpointer user_data)
{
	CamelURL *new_url = NULL, *old_url = NULL;
	gboolean isa_mapi_account = FALSE;
	EMapiAccountInfo *existing_account_info = NULL;
	EAccountList *account_listener = worker_data;
	EAccount *account = user_data;
	EMapiProfileData empd = { 0 };
	CamelSettings *settings;

	g_return_if_fail (account_listener != NULL);
	g_return_if_fail (account != NULL);

	isa_mapi_account = is_mapi_account (account);

	if (isa_mapi_account)
		existing_account_info = lookup_account_info (account->uid);

	if (existing_account_info)
		old_url = camel_url_new (existing_account_info->source_url, NULL);

	if (!isa_mapi_account && !existing_account_info)
		return;

	new_url = camel_url_new (account->source->url, NULL);

	settings = g_object_new (CAMEL_TYPE_MAPI_SETTINGS, NULL);
	camel_settings_load_from_url (settings, new_url);

	if (existing_account_info == NULL && isa_mapi_account) {
		/* some account of other type is changed to MAPI */
		if (create_profile_entry (new_url, account, CAMEL_MAPI_SETTINGS (settings))) {
			/* Things are successful */
			gchar *profname = NULL, *uri = NULL;
			EMapiAccountListener *config_listener = e_mapi_accounts_peek_config_listener();

			empd.server = new_url->host;
			empd.username = new_url->user;
			e_mapi_util_profiledata_from_settings (&empd, CAMEL_MAPI_SETTINGS (settings));
			profname = e_mapi_util_profile_name (NULL, &empd, FALSE);
			camel_mapi_settings_set_profile (CAMEL_MAPI_SETTINGS (settings), profname);
			camel_settings_save_to_url (settings, new_url);
			g_free (profname);

			uri = camel_url_to_string(new_url, 0);
			/* FIXME: Find a better way to append to the Account source URL. The current
			 * method uses e_account_set_string() which initiates another signal emmission
			 * which we have to block for now. */
			g_signal_handlers_block_by_func (config_listener->priv->account_list, G_CALLBACK (mapi_account_changed), NULL);
			e_account_set_string (account, E_ACCOUNT_SOURCE_URL, uri);
			e_account_set_string (account, E_ACCOUNT_TRANSPORT_URL, uri);
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
			if (create_profile_entry (new_url, account, CAMEL_MAPI_SETTINGS (settings))) {
				/* Things are successful */
				gchar *profname = NULL, *uri = NULL;
				EMapiAccountListener *config_listener = e_mapi_accounts_peek_config_listener();

				empd.server = new_url->host;
				empd.username = new_url->user;
				e_mapi_util_profiledata_from_settings (&empd, CAMEL_MAPI_SETTINGS (settings));
				profname = e_mapi_util_profile_name (NULL, &empd, FALSE);
				camel_mapi_settings_set_profile (CAMEL_MAPI_SETTINGS (settings), profname);
				camel_settings_save_to_url (settings, new_url);
				g_free (profname);

				uri = camel_url_to_string(new_url, 0);
				/* FIXME: Find a better way to append to the Account source URL. The current
				 * method uses e_account_set_string() which initiates another signal emmission
				 * which we have to block for now. */
				g_signal_handlers_block_by_func (config_listener->priv->account_list, G_CALLBACK (mapi_account_changed), NULL);
				e_account_set_string (account, E_ACCOUNT_SOURCE_URL, uri);
				e_account_set_string (account, E_ACCOUNT_TRANSPORT_URL, uri);
				g_signal_handlers_unblock_by_func (config_listener->priv->account_list, G_CALLBACK (mapi_account_changed), NULL);
				g_free (uri);

				mapi_account_added (account_listener, account);
			}
		}
	}

	if (old_url)
		camel_url_free (old_url);

	g_object_unref (settings);
	camel_url_free (new_url);

	g_object_unref (account_listener);
	g_object_unref (account);
}

static void
mapi_account_changed (EAccountList *account_listener, EAccount *account)
{
	g_return_if_fail (async_ops != NULL);

	e_mapi_async_queue_push (async_ops, g_object_ref (account_listener), g_object_ref (account), mapi_account_changed_async, NULL);
}

static void
e_mapi_account_listener_construct (EMapiAccountListener *config_listener)
{
	EIterator *iter;

	config_listener->priv->account_list = e_account_list_new (config_listener->priv->gconf_client);

	for (iter = e_list_get_iterator (E_LIST(config_listener->priv->account_list)); e_iterator_is_valid (iter); e_iterator_next (iter)) {
		EAccount *account = E_ACCOUNT (e_iterator_get (iter));
		if (is_mapi_account (account)) {
			EMapiAccountInfo *info = g_new0 (EMapiAccountInfo, 1);
			info->uid = g_strdup (account->uid);
			info->name = g_strdup (account->name);
			info->source_url = g_strdup (account->source->url);
			info->enabled = account->enabled;

			mapi_accounts = g_list_append (mapi_accounts, info);

			if (!account->enabled) {
				remove_addressbook_sources (info);
				remove_calendar_sources (account);
			} else {
				/* fetch new calendars/remove dropped from a server, if any */
				update_account_sources (account, FALSE);
			}
		}
	}

	d(e_mapi_debug_print ("MAPI listener is constructed with %d listed MAPI accounts ", g_list_length (mapi_accounts)));

	g_signal_connect (config_listener->priv->account_list, "account_added", G_CALLBACK (mapi_account_added), NULL);
	g_signal_connect (config_listener->priv->account_list, "account_changed", G_CALLBACK (mapi_account_changed), NULL);
	g_signal_connect (config_listener->priv->account_list, "account_removed", G_CALLBACK (mapi_account_removed), NULL);
}

EMapiAccountListener *
e_mapi_account_listener_new (void)
{
	EMapiAccountListener *config_listener;

	if (!async_ops) {
		async_ops = e_mapi_async_queue_new ();
		g_object_add_weak_pointer (G_OBJECT (async_ops), &async_ops);
	} else {
		g_object_ref (async_ops);
	}

	config_listener = g_object_new (E_MAPI_ACCOUNT_LISTENER_TYPE, NULL);
	config_listener->priv->gconf_client = gconf_client_get_default();

	e_mapi_account_listener_construct (config_listener);

	return config_listener;
}