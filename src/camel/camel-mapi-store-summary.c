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

#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <glib.h>

#include <libedataserver/e-memory.h>

#include "camel-mapi-store.h"
#include "camel-mapi-store-summary.h"

#define d(x) 

static gint summary_header_load(CamelStoreSummary *, FILE *);
static gint summary_header_save(CamelStoreSummary *, FILE *);

static CamelStoreInfo *store_info_load(CamelStoreSummary *s, FILE *in);
static gint store_info_save(CamelStoreSummary *s, FILE *out, CamelStoreInfo *mi);
static void store_info_free(CamelStoreSummary *s, CamelStoreInfo *mi);
static void store_info_set_string(CamelStoreSummary *s, CamelStoreInfo *mi, gint type, const gchar *str);

static const gchar *store_info_string(CamelStoreSummary *s, const CamelStoreInfo *mi, gint type);

G_DEFINE_TYPE (CamelMapiStoreSummary, camel_mapi_store_summary, CAMEL_TYPE_STORE_SUMMARY)

static void
camel_mapi_store_summary_class_init (CamelMapiStoreSummaryClass *class)
{
	CamelStoreSummaryClass *store_summary_class;

	store_summary_class = CAMEL_STORE_SUMMARY_CLASS (class);
	store_summary_class->summary_header_load = summary_header_load;
	store_summary_class->summary_header_save = summary_header_save;
	store_summary_class->store_info_load = store_info_load;
	store_summary_class->store_info_save = store_info_save;
	store_summary_class->store_info_free = store_info_free;
	store_summary_class->store_info_string = store_info_string;
	store_summary_class->store_info_set_string = store_info_set_string;
}

static void
camel_mapi_store_summary_init (CamelMapiStoreSummary *mapi_store_summary)
{
	CamelStoreSummary *store_summary;

	store_summary = CAMEL_STORE_SUMMARY (mapi_store_summary);
	store_summary->store_info_size = sizeof (CamelMapiStoreInfo);

	mapi_store_summary->version = CAMEL_MAPI_STORE_SUMMARY_VERSION;
}

CamelMapiStoreSummary *
camel_mapi_store_summary_new (void)
{
	return g_object_new (CAMEL_TYPE_MAPI_STORE_SUMMARY, NULL);
}

static gint
summary_header_load(CamelStoreSummary *s, FILE *in)
{
	CamelMapiStoreSummary *summary = (CamelMapiStoreSummary *)s;
	CamelStoreSummaryClass *store_summary_class;

	store_summary_class = CAMEL_STORE_SUMMARY_CLASS (
		camel_mapi_store_summary_parent_class);

	/* TODO */
	if (store_summary_class->summary_header_load (s, in) == -1)
			/* || camel_file_util_decode_fixed_int32(in, &version) == -1) */
		return -1;

	summary->version = 0;

	return 0;
}

static gint
summary_header_save(CamelStoreSummary *s, FILE *out)
{
	CamelStoreSummaryClass *store_summary_class;

	store_summary_class = CAMEL_STORE_SUMMARY_CLASS (
		camel_mapi_store_summary_parent_class);

	if (store_summary_class->summary_header_save (s, out) == -1)
		return -1;

	return 0;
}

static CamelStoreInfo *
store_info_load(CamelStoreSummary *s, FILE *in)
{
	CamelStoreSummaryClass *store_summary_class;
	CamelMapiStoreInfo *si;

	store_summary_class = CAMEL_STORE_SUMMARY_CLASS (
		camel_mapi_store_summary_parent_class);

	si = (CamelMapiStoreInfo *)store_summary_class->store_info_load(s, in);
	if (si) {
		if (camel_file_util_decode_string(in, &si->full_name) == -1
		    || camel_file_util_decode_string(in, &si->folder_id) == -1
		    || camel_file_util_decode_string(in, &si->parent_id) == -1) {
			camel_store_summary_info_free(s, (CamelStoreInfo *)si);
			si = NULL;
		}
	}
	return (CamelStoreInfo *)si;
}

static gint
store_info_save(CamelStoreSummary *s, FILE *out, CamelStoreInfo *mi)
{
	CamelMapiStoreInfo *summary = (CamelMapiStoreInfo *)mi;
	CamelStoreSummaryClass *store_summary_class;

	store_summary_class = CAMEL_STORE_SUMMARY_CLASS (
		camel_mapi_store_summary_parent_class);

	if (store_summary_class->store_info_save(s, out, mi) == -1
	    || camel_file_util_encode_string(out, summary->full_name) == -1
	    || camel_file_util_encode_string(out, summary->folder_id) == -1
	    || camel_file_util_encode_string(out, summary->parent_id) == -1)
		return -1;

	return 0;
}

static void
store_info_free(CamelStoreSummary *s, CamelStoreInfo *mi)
{
	CamelMapiStoreInfo *si = (CamelMapiStoreInfo *)mi;
	CamelStoreSummaryClass *store_summary_class;

	store_summary_class = CAMEL_STORE_SUMMARY_CLASS (
		camel_mapi_store_summary_parent_class);

	g_free (si->full_name);
	g_free (si->folder_id);
	g_free (si->parent_id);

	store_summary_class->store_info_free(s, mi);
}

static const gchar *
store_info_string(CamelStoreSummary *s, const CamelStoreInfo *mi, gint type)
{
	CamelMapiStoreInfo *isi = (CamelMapiStoreInfo *)mi;
	CamelStoreSummaryClass *store_summary_class;

	store_summary_class = CAMEL_STORE_SUMMARY_CLASS (
		camel_mapi_store_summary_parent_class);

	/* FIXME: Locks? */

	g_assert (mi != NULL);

	switch (type) {
		case CAMEL_MAPI_STORE_INFO_FULL_NAME:
			return isi->full_name;
		case CAMEL_MAPI_STORE_INFO_FOLDER_ID:
			return isi->folder_id;
		case CAMEL_MAPI_STORE_INFO_PARENT_ID:
			return isi->parent_id;
		default:
			return store_summary_class->store_info_string(s, mi, type);
	}
}

static void
store_info_set_string(CamelStoreSummary *s, CamelStoreInfo *mi, gint type, const gchar *str)
{
	CamelMapiStoreInfo *isi = (CamelMapiStoreInfo *)mi;
	CamelStoreSummaryClass *store_summary_class;

	g_assert(mi != NULL);

	store_summary_class = CAMEL_STORE_SUMMARY_CLASS (
		camel_mapi_store_summary_parent_class);

	switch (type) {
		case CAMEL_MAPI_STORE_INFO_FULL_NAME:
			d(printf("Set full name %s -> %s\n", isi->full_name, str));
			camel_store_summary_lock (s, CSS_SUMMARY_LOCK);
			g_free(isi->full_name);
			isi->full_name = g_strdup(str);
			camel_store_summary_unlock (s, CSS_SUMMARY_LOCK);
			break;
		case CAMEL_MAPI_STORE_INFO_FOLDER_ID:
			d(printf("Set folder id %s -> %s\n", isi->folder_id, str));
			camel_store_summary_lock (s, CSS_SUMMARY_LOCK);
			g_free(isi->folder_id);
			isi->folder_id = g_strdup(str);
			camel_store_summary_unlock (s, CSS_SUMMARY_LOCK);
			break;
		case CAMEL_MAPI_STORE_INFO_PARENT_ID:
			d(printf("Set parent id %s -> %s\n", isi->parent_id, str));
			camel_store_summary_lock (s, CSS_SUMMARY_LOCK);
			g_free(isi->parent_id);
			isi->parent_id = g_strdup(str);
			camel_store_summary_unlock (s, CSS_SUMMARY_LOCK);
			break;
		default:
			store_summary_class->store_info_set_string(s, mi, type, str);
			break;
	}
}

CamelMapiStoreInfo *
camel_mapi_store_summary_full_name(CamelMapiStoreSummary *s, const gchar *full_name)
{
	gint count, i;
	CamelMapiStoreInfo *info;

	count = camel_store_summary_count((CamelStoreSummary *)s);
	for (i=0;i<count;i++) {
		info = (CamelMapiStoreInfo *)camel_store_summary_index((CamelStoreSummary *)s, i);
		if (info) {
			if (strcmp(info->full_name, full_name) == 0)
				return info;
			camel_store_summary_info_free((CamelStoreSummary *)s, (CamelStoreInfo *)info);
		}
	}

	return NULL;

}

gchar *
camel_mapi_store_summary_full_to_path(CamelMapiStoreSummary *s, const gchar *full_name, gchar dir_sep)
{
	gchar *path, *p;
	gint c;
	const gchar *f;

	if (dir_sep != '/') {
		p = path = alloca(strlen(full_name)*3+1);
		f = full_name;
		while ((c = *f++ & 0xff)) {
			if (c == dir_sep)
				*p++ = '/';
//FIXME : why ?? :(
/*			else if (c == '/' || c == '%') */
/*				p += sprintf(p, "%%%02X", c); */
			else
				*p++ = c;
		}
		*p = 0;
	} else
		path = (gchar *)full_name;

	return g_strdup (path);
}

CamelMapiStoreInfo *
camel_mapi_store_summary_add_from_full(CamelMapiStoreSummary *s, const gchar *full,
				       gchar dir_sep, gchar *folder_id, gchar *parent_id)
{
	CamelMapiStoreInfo *info;
	gchar *pathu8;
	gint len;
	gchar *full_name;

	d(printf("adding full name '%s' '%c'\n", full, dir_sep));
	len = strlen(full);
	full_name = alloca(len+1);
	strcpy(full_name, full);

	if (full_name[len-1] == dir_sep)
		full_name[len-1] = 0;

	info = camel_mapi_store_summary_full_name(s, full_name);
	if (info) {
		camel_store_summary_info_free((CamelStoreSummary *)s, (CamelStoreInfo *)info);
		d(printf("  already there\n"));
		return info;
	}
	pathu8 = camel_mapi_store_summary_full_to_path(s, full_name, '/');
	info = (CamelMapiStoreInfo *)camel_store_summary_add_from_path((CamelStoreSummary *)s, pathu8);

	if (info) {
		camel_store_info_set_string((CamelStoreSummary *)s, (CamelStoreInfo *)info, CAMEL_MAPI_STORE_INFO_FULL_NAME, full_name);
		camel_store_info_set_string((CamelStoreSummary *)s, (CamelStoreInfo *)info, CAMEL_MAPI_STORE_INFO_FOLDER_ID, folder_id);
		camel_store_info_set_string((CamelStoreSummary *)s, (CamelStoreInfo *)info, CAMEL_MAPI_STORE_INFO_PARENT_ID, parent_id);
	}

	return info;
}

gchar *
camel_mapi_store_summary_full_from_path(CamelMapiStoreSummary *s, const gchar *path)
{
	gchar *name = NULL;

	d(printf("looking up path %s -> %s\n", path, name?name:"not found"));

	return name;
}
