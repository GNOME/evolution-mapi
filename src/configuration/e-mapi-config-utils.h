/*
 * e-mapi-config-utils.h
 *
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
 */

#ifndef E_MAPI_CONFIG_UTILS_H
#define E_MAPI_CONFIG_UTILS_H

#include <gtk/gtk.h>

#include <shell/e-shell-view.h>
#include <misc/e-source-config.h>
#include <misc/e-source-config-backend.h>

#include "e-mapi-connection.h"
#include "camel-mapi-settings.h"

typedef void		(* EMapiSetupFunc)					(GObject *with_object,
										 gpointer user_data,
										 GCancellable *cancellable,
										 GError **perror);

void			e_mapi_config_utils_run_in_thread_with_feedback		(GtkWindow *parent,
										 GObject *with_object,
										 const gchar *description,
										 EMapiSetupFunc thread_func,
										 EMapiSetupFunc idle_func,
										 gpointer user_data,
										 GDestroyNotify free_user_data);

void			e_mapi_config_utils_run_in_thread_with_feedback_modal	(GtkWindow *parent,
										 GObject *with_object,
										 const gchar *description,
										 EMapiSetupFunc thread_func,
										 EMapiSetupFunc idle_func,
										 gpointer user_data,
										 GDestroyNotify free_user_data);

EMapiConnection	*	e_mapi_config_utils_open_connection_for			(GtkWindow *parent,
										 ESourceRegistry *registry,
										 ESource *source,
										 CamelMapiSettings *mapi_settings,
										 GCancellable *cancellable,
										 GError **perror);

void			e_mapi_config_utils_run_folder_size_dialog		(ESourceRegistry *registry,
										 ESource *source,
										 CamelMapiSettings *mapi_settings);

void			e_mapi_config_utils_init_ui				(EShellView *shell_view,
										 const gchar *ui_manager_id,
										 gchar **ui_definition);

gboolean		e_mapi_config_utils_is_online				(void);

GtkWindow *		e_mapi_config_utils_get_widget_toplevel_window		(GtkWidget *widget);

void			e_mapi_config_utils_insert_widgets			(ESourceConfigBackend *backend,
										 ESource *scratch_source);

#endif /* E_MAPI_CONFIG_UTILS */
