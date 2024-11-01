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
 *    Suman Manjunath <msuman@novell.com>
 *
 * Copyright (C) 1999-2008 Novell, Inc. (www.novell.com)
 *
 */

#include "evolution-mapi-config.h"

#include "e-mapi-cal-utils.h"
#include "e-mapi-cal-tz-utils.h"

#define d(x) 

#define MAPPING_SEPARATOR "~~~"

static GRecMutex mutex;

static GHashTable *mapi_to_ical = NULL;
static GHashTable *ical_to_mapi = NULL;

const gchar *
e_mapi_cal_tz_util_get_mapi_equivalent (const gchar *ical_tz_location)
{
	const gchar *retval = NULL;

	g_return_val_if_fail ((ical_tz_location && *ical_tz_location), NULL);

	g_rec_mutex_lock(&mutex);
	if (!e_mapi_cal_tz_util_populate()) {
		g_rec_mutex_unlock(&mutex);
		return NULL;
	}

	d(g_message("%s: %s of '%s' ", G_STRLOC, G_STRFUNC, ical_tz_location));

	retval = g_hash_table_lookup (ical_to_mapi, ical_tz_location);

	g_rec_mutex_unlock(&mutex);

	return retval;
}

const gchar *
e_mapi_cal_tz_util_get_ical_equivalent (const gchar *mapi_tz_location)
{
	const gchar *retval = NULL;

	g_return_val_if_fail ((mapi_tz_location && *mapi_tz_location), NULL);

	g_rec_mutex_lock(&mutex);
	if (!e_mapi_cal_tz_util_populate()) {
		g_rec_mutex_unlock(&mutex);
		return NULL;
	}

	d(g_message("%s: %s of '%s' ", G_STRLOC, G_STRFUNC, mapi_tz_location));

	retval = g_hash_table_lookup (mapi_to_ical, mapi_tz_location);

	g_rec_mutex_unlock(&mutex);

	return retval;
}

static ICalTime *
e_mapi_tm_to_icaltime (struct tm *tm,
		       gboolean dst)
{
	ICalTime *itt;

	itt = i_cal_time_new_null_time ();
	i_cal_time_set_time (itt, 0, 0, 0);
	i_cal_time_set_date (itt, tm->tm_year + 1900, dst ? 6 : 1, 1);
	i_cal_time_set_timezone (itt, NULL);
	i_cal_time_set_is_date (itt, FALSE);

	return itt;
}

static gint
get_offset (ICalTimezone *zone,
	    gboolean dst)
{
	struct tm local;
	ICalTime *itt;
	gint offset;
	gint is_daylight = 0; /* Its value is ignored, but libical-glib 3.0.5 API requires it */
	time_t now = time (NULL);

	gmtime_r (&now, &local);
	itt = e_mapi_tm_to_icaltime (&local, dst);
	offset = i_cal_timezone_get_utc_offset (zone, itt, &is_daylight);
	g_clear_object (&itt);

	return offset / -60;
}

const gchar *
e_mapi_cal_tz_util_ical_from_zone_struct (const guint8 *lpb,
					  guint32 cb)
{
	GHashTableIter iter;
	gpointer key, value;
	guint32 utcBias, stdBias, dstBias;
	const gchar *res = NULL;

	g_return_val_if_fail (lpb != NULL, NULL);

	/* get the timezone by biases, which are the first 3*4 bytes */
	if (cb < 12)
		return NULL;

	memcpy (&utcBias, lpb, 4); lpb += 4;
	memcpy (&stdBias, lpb, 4); lpb += 4;
	memcpy (&dstBias, lpb, 4); lpb += 4;

	g_rec_mutex_lock (&mutex);
	if (!e_mapi_cal_tz_util_populate ()) {
		g_rec_mutex_unlock (&mutex);
		return NULL;
	}

	g_hash_table_iter_init (&iter, mapi_to_ical);
	while (g_hash_table_iter_next (&iter, &key, &value)) {
		const gchar *location = value;
		ICalTimezone *zone;
		gint offset;

		zone = i_cal_timezone_get_builtin_timezone (location);
		if (!zone)
			continue;

		offset = get_offset (zone, FALSE);
		if (offset != utcBias || offset != utcBias + stdBias)
			continue;

		offset = get_offset (zone, TRUE);
		if (offset != utcBias + dstBias)
			continue;

		/* pick shortest and alphabetically first timezone */
		if (!res ||
		    strlen (res) > strlen (location) ||
		    (strlen (res) == strlen (location) &&
		    strcmp (location, res) < 0))
			res = location;
	}

	g_rec_mutex_unlock (&mutex);

	return res;
}

void
e_mapi_cal_tz_util_destroy (void)
{
	g_rec_mutex_lock(&mutex);
	if (!(mapi_to_ical && ical_to_mapi)) {
		g_rec_mutex_unlock(&mutex);
		return;
	}

	g_hash_table_destroy (mapi_to_ical);
	g_hash_table_destroy (ical_to_mapi);

	/* Reset all the values */
	mapi_to_ical = NULL;
	ical_to_mapi = NULL;

	g_rec_mutex_unlock(&mutex);
}

static void
file_contents_to_hashtable (const gchar *contents, GHashTable *table)
{
	gchar **array = NULL;
	guint len = 0, i;

	array = g_strsplit (contents, "\n", -1);
	len = g_strv_length (array);

	for (i=0; i < len-1; ++i) {
		gchar **mapping = g_strsplit (array[i], MAPPING_SEPARATOR, -1);
		if (g_strv_length (mapping) == 2)
			g_hash_table_insert (table, g_strdup (mapping[0]), g_strdup (mapping[1]));
		g_strfreev (mapping);
	}

	g_strfreev (array);
}

gboolean
e_mapi_cal_tz_util_populate (void)
{
	gchar *mtoi_fn = NULL, *itom_fn = NULL;
	GMappedFile *mtoi_mf = NULL, *itom_mf = NULL;

	g_rec_mutex_lock(&mutex);
	if (mapi_to_ical && ical_to_mapi) {
		g_rec_mutex_unlock(&mutex);
		return TRUE;
	}

	mtoi_fn = g_build_filename (MAPI_DATADIR, "tz-mapi-to-ical", NULL);
	itom_fn = g_build_filename (MAPI_DATADIR, "tz-ical-to-mapi", NULL);

	mtoi_mf = g_mapped_file_new (mtoi_fn, FALSE, NULL);
	itom_mf = g_mapped_file_new (itom_fn, FALSE, NULL);

	g_free (mtoi_fn);
	g_free (itom_fn);

	if (!(mtoi_mf && itom_mf)) {
		g_warning ("Could not map Exchange MAPI timezone files.");

		if (mtoi_mf)
#if GLIB_CHECK_VERSION(2,21,3)
			g_mapped_file_unref (mtoi_mf);
#else
			g_mapped_file_free (mtoi_mf);
#endif
		if (itom_mf)
#if GLIB_CHECK_VERSION(2,21,3)
			g_mapped_file_unref (itom_mf);
#else
			g_mapped_file_free (itom_mf);
#endif

		g_rec_mutex_unlock(&mutex);
		return FALSE;
	}

	mapi_to_ical = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);

	file_contents_to_hashtable (g_mapped_file_get_contents (mtoi_mf), mapi_to_ical);

	ical_to_mapi = g_hash_table_new_full (g_str_hash, g_str_equal, g_free, g_free);

	file_contents_to_hashtable (g_mapped_file_get_contents (itom_mf), ical_to_mapi);

	if (!(g_hash_table_size (mapi_to_ical) && g_hash_table_size (ical_to_mapi))) {
		g_warning ("Exchange MAPI timezone files are not valid.");

		e_mapi_cal_tz_util_destroy ();

#if GLIB_CHECK_VERSION(2,21,3)
		g_mapped_file_unref (mtoi_mf);
		g_mapped_file_unref (itom_mf);
#else
		g_mapped_file_free (mtoi_mf);
		g_mapped_file_free (itom_mf);
#endif

		g_rec_mutex_unlock(&mutex);
		return FALSE;
	}

#if GLIB_CHECK_VERSION(2,21,3)
	g_mapped_file_unref (mtoi_mf);
	g_mapped_file_unref (itom_mf);
#else
	g_mapped_file_free (mtoi_mf);
	g_mapped_file_free (itom_mf);
#endif

	d(e_mapi_cal_tz_util_dump ());

	g_rec_mutex_unlock(&mutex);

	return TRUE;
}

static void
e_mapi_cal_tz_util_dump_ical_tzs (void)
{
	gint ii, nelems;
	ICalArray *zones;
	GList *l, *list_items = NULL;

	/* Get the array of builtin timezones. */
	zones = i_cal_timezone_get_builtin_timezones ();
	nelems = i_cal_array_size (zones);

	g_message("%s: %s: ", G_STRLOC, G_STRFUNC);

	for (ii = 0; ii < nelems; ii++) {
		ICalTimezone *zone;
		const gchar *tzid = NULL;

		zone = i_cal_timezone_array_element_at (zones, ii);
		if (!zone)
			continue;

		tzid = i_cal_timezone_get_tzid (zone);
		if (tzid)
			list_items = g_list_prepend (list_items, g_strdup (tzid));

		g_object_unref (zone);
	}

	list_items = g_list_sort (list_items, (GCompareFunc) g_ascii_strcasecmp);

	/* Put the "UTC" entry at the top of the combo's list. */
	list_items = g_list_prepend (list_items, g_strdup ("UTC"));

	for (l = list_items, ii = 0; l != NULL; l = l->next, ++ii) {
		g_print ("[%3d]\t%s\n", (ii + 1), (gchar *)(l->data));
	}

	/* i_cal_timezone_free_builtin_timezones (); */

	g_list_free_full (list_items, g_free);
}

void
e_mapi_cal_tz_util_dump (void)
{
	guint i;
	GList *keys, *values, *l, *m;

	g_rec_mutex_lock(&mutex);

	e_mapi_cal_tz_util_dump_ical_tzs ();

	if (!(mapi_to_ical && ical_to_mapi)) {
		g_rec_mutex_unlock(&mutex);
		return;
	}

	g_message("%s: %s: ", G_STRLOC, G_STRFUNC);

	g_message ("Dumping #table mapi_to_ical");
	keys = g_hash_table_get_keys (mapi_to_ical);
	values = g_hash_table_get_values (mapi_to_ical);
	l = g_list_first (keys);
	m = g_list_first (values);
	for (i=0; l && m; ++i, l=l->next, m=m->next)
		g_print ("[%3d]\t%s\t%s\t%s\n", (i+1), (gchar *)(l->data), MAPPING_SEPARATOR, (gchar *)(m->data));
	g_message ("Dumping differences in #tables");
	l = g_list_first (keys);
	m = g_list_first (values);
	for (i=0; l && m; ++i, l=l->next, m=m->next)
		if (g_ascii_strcasecmp ((gchar *)(l->data), (gchar *) g_hash_table_lookup (ical_to_mapi, (m->data))))
			g_print ("[%3d] Possible mis-match for %s\n", (i+1), (gchar *)(l->data));
	g_list_free (keys);
	g_list_free (values);

	g_message ("Dumping #table ical_to_mapi");
	keys = g_hash_table_get_keys (ical_to_mapi);
	values = g_hash_table_get_values (ical_to_mapi);
	l = g_list_first (keys);
	m = g_list_first (values);
	for (i=0; l && m; ++i, l=l->next, m=m->next)
		g_print ("[%3d]\t%s\t%s\t%s\n", (i+1), (gchar *)(l->data), MAPPING_SEPARATOR, (gchar *)(m->data));
	g_list_free (keys);
	g_list_free (values);

	g_rec_mutex_unlock(&mutex);
}

static void
write_icaltime_as_systemtime (GByteArray *ba,
			      ICalTime *itt)
{
	guint16 flag16;

	/* wYear */
	flag16 = i_cal_time_get_year (itt);
	g_byte_array_append (ba, (const guint8 *) &flag16, sizeof (guint16));

	/* wMonth */
	flag16 = i_cal_time_get_month (itt);
	g_byte_array_append (ba, (const guint8 *) &flag16, sizeof (guint16));

	/* wDayOfWeek */
	flag16 = i_cal_time_get_year (itt) == 0 ? 0 : i_cal_time_day_of_week (itt);
	g_byte_array_append (ba, (const guint8 *) &flag16, sizeof (guint16));

	/* wDay */
	flag16 = i_cal_time_get_day (itt);
	g_byte_array_append (ba, (const guint8 *) &flag16, sizeof (guint16));

	/* wHour */
	flag16 = i_cal_time_get_hour (itt);
	g_byte_array_append (ba, (const guint8 *) &flag16, sizeof (guint16));

	/* wMinute */
	flag16 = i_cal_time_get_minute (itt);
	g_byte_array_append (ba, (const guint8 *) &flag16, sizeof (guint16));

	/* wSecond */
	flag16 = i_cal_time_get_second (itt);
	g_byte_array_append (ba, (const guint8 *) &flag16, sizeof (guint16));

	/* wMilliseconds */
	flag16 = 0;
	g_byte_array_append (ba, (const guint8 *) &flag16, sizeof (guint16));
}

static void
write_tz_rule (GByteArray *ba,
	       gboolean is_recur,
	       guint32 bias,
	       guint32 standard_bias,
	       guint32 daylight_bias,
	       ICalTime *standard_date,
	       ICalTime *daylight_date)
{
	guint8 flag8;
	guint16 flag16;

	g_return_if_fail (ba != NULL);

	/* Major version */
	flag8 = 0x02;
	g_byte_array_append (ba, (const guint8 *) &flag8, sizeof (guint8));
	
	/* Minor version */
	flag8 = 0x01;
	g_byte_array_append (ba, (const guint8 *) &flag8, sizeof (guint8));

	/* Reserved */
	flag16 = 0x003e;
	g_byte_array_append (ba, (const guint8 *) &flag16, sizeof (guint16));

	/* TZRule flags */
	flag16 = 0;
	if (is_recur)
		flag16 |= 1;
	g_byte_array_append (ba, (const guint8 *) &flag16, sizeof (guint16));

	/* wYear */
	flag16 = i_cal_time_get_year (standard_date);
	g_byte_array_append (ba, (const guint8 *) &flag16, sizeof (guint16));

	/* X - 14 times 0x00 */
	flag8 = 0x00;
	for (flag16 = 0; flag16 < 14; flag16++) {
		g_byte_array_append (ba, (const guint8 *) &flag8, sizeof (guint8));
	}

	/* lBias */
	g_byte_array_append (ba, (const guint8 *) &bias, sizeof (guint32));

	/* lStandardBias */
	g_byte_array_append (ba, (const guint8 *) &standard_bias, sizeof (guint32));

	/* lDaylightBias */
	g_byte_array_append (ba, (const guint8 *) &daylight_bias, sizeof (guint32));

	/* stStandardDate */
	write_icaltime_as_systemtime (ba, standard_date);

	/* stDaylightDate */
	write_icaltime_as_systemtime (ba, daylight_date);
}

static void
extract_bias_and_date (ICalComponent *icomp,
		       guint32 *bias,
		       ICalTime **start)
{
	ICalProperty *prop;
	gint tzoffset;

	g_return_if_fail (icomp != NULL);
	g_return_if_fail (bias != NULL);
	g_return_if_fail (start != NULL);

	prop = i_cal_component_get_first_property (icomp, I_CAL_TZOFFSETTO_PROPERTY);
	if (prop)
		tzoffset = i_cal_property_get_tzoffsetto (prop);
	else
		tzoffset = 0;

	*bias = tzoffset / 60;
	*start = i_cal_component_get_dtstart (icomp);

	g_clear_object (&prop);
}

static void
write_tz_rule_comps (GByteArray *ba,
		     gboolean is_recur,
		     ICalComponent *standardcomp,
		     ICalComponent *daylightcomp,
		     ICalTimezone *zone)
{
	ICalTime *standard_date = NULL, *daylight_date = NULL, *current_time;
	guint32 bias, standard_bias = 0, daylight_bias = 0;

	g_return_if_fail (ba != NULL);
	g_return_if_fail (standardcomp != NULL);
	g_return_if_fail (daylightcomp != NULL);

	extract_bias_and_date (standardcomp, &standard_bias, &standard_date);
	extract_bias_and_date (daylightcomp, &daylight_bias, &daylight_date);

	current_time = i_cal_time_new_current_with_zone (zone);
	bias = i_cal_time_is_daylight (current_time) ? daylight_bias : standard_bias;

	write_tz_rule (ba, is_recur, bias, standard_bias, daylight_bias, standard_date, daylight_date);

	g_clear_object (&standard_date);
	g_clear_object (&daylight_date);
	g_clear_object (&current_time);
}

static void
add_timezone_rules (GByteArray *ba,
		    gboolean is_recur,
		    ICalComponent *vtimezone,
		    ICalTimezone *zone)
{
	gboolean any_added = FALSE;

	g_return_if_fail (ba != NULL);

	if (vtimezone) {
		ICalComponent *subcomp, *standardcomp = NULL, *daylightcomp = NULL;

		for (subcomp = i_cal_component_get_first_component (vtimezone, I_CAL_ANY_COMPONENT);
		     subcomp;
		     g_object_unref (subcomp), subcomp = i_cal_component_get_next_component (vtimezone, I_CAL_ANY_COMPONENT)) {
			if (i_cal_component_isa (subcomp) == I_CAL_XSTANDARD_COMPONENT)
				standardcomp = g_object_ref (subcomp);
			if (i_cal_component_isa (subcomp) == I_CAL_XDAYLIGHT_COMPONENT)
				daylightcomp = g_object_ref (subcomp);
			if (standardcomp && daylightcomp) {
				write_tz_rule_comps (ba, is_recur, standardcomp, daylightcomp, zone);

				any_added = TRUE;
				g_clear_object (&standardcomp);
				g_clear_object (&daylightcomp);
			}
		}

		if (standardcomp || daylightcomp) {
			if (!standardcomp)
				standardcomp = g_object_ref (daylightcomp);
			write_tz_rule_comps (ba, is_recur, standardcomp, daylightcomp, zone);
			any_added = TRUE;
		}

		g_clear_object (&standardcomp);
		g_clear_object (&daylightcomp);
	}

	/* at least one should be always added, make it UTC */
	if (!any_added) {
		ICalTime *fake_utc;

		fake_utc = i_cal_time_new_null_time ();

		write_tz_rule (ba, is_recur, 0, 0, 0, fake_utc, fake_utc);

		g_object_unref (fake_utc);
	}
}

#define TZDEFINITION_FLAG_VALID_GUID     0x0001 // the guid is valid
#define TZDEFINITION_FLAG_VALID_KEYNAME  0x0002 // the keyname is valid
#define TZ_MAX_RULES          1024 
#define TZ_BIN_VERSION_MAJOR  0x02 
#define TZ_BIN_VERSION_MINOR  0x01 

void
e_mapi_cal_util_mapi_tz_to_bin (const gchar *mapi_tzid,
				struct SBinary_short *bin,
				TALLOC_CTX *mem_ctx,
				gboolean is_recur)
{
	GByteArray *ba;
	guint8 flag8;
	guint16 flag16;
	gunichar2 *buf;
	glong items_written;
	ICalTimezone *zone = NULL;
	ICalComponent *vtimezone;
	gint rules = 0;
	const gchar *ical_location = e_mapi_cal_tz_util_get_ical_equivalent (mapi_tzid);

	if (ical_location && *ical_location)
		zone = i_cal_timezone_get_builtin_timezone (ical_location);
	if (!zone)
		zone = i_cal_timezone_get_utc_timezone ();
	vtimezone = i_cal_timezone_get_component (zone);
	if (vtimezone)
		rules = (i_cal_component_count_components (vtimezone, I_CAL_XSTANDARD_COMPONENT) +
			 i_cal_component_count_components (vtimezone, I_CAL_XDAYLIGHT_COMPONENT)) / 2;
	if (!rules)
		rules = 1;

	ba = g_byte_array_new ();

	/* UTF-8 length of the keyname */
	flag16 = g_utf8_strlen (mapi_tzid, -1);
	ba = g_byte_array_append (ba, (const guint8 *)&flag16, sizeof (guint16));
	/* Keyname */
	buf = g_utf8_to_utf16 (mapi_tzid, flag16, NULL, &items_written, NULL);
	ba = g_byte_array_append (ba, (const guint8 *)buf, (sizeof (gunichar2) * items_written));
	g_free (buf);

	/* number of rules */
	flag16 = rules;
	ba = g_byte_array_append (ba, (const guint8 *)&flag16, sizeof (guint16));

	/* wFlags: we know only keyname based names */
	flag16 = TZDEFINITION_FLAG_VALID_KEYNAME;
	ba = g_byte_array_prepend (ba, (const guint8 *)&flag16, sizeof (guint16));

	/* Length in bytes until rules info */
	flag16 = (guint16) (ba->len);
	ba = g_byte_array_prepend (ba, (const guint8 *)&flag16, sizeof (guint16));

	/* Minor version */
	flag8 = TZ_BIN_VERSION_MINOR;
	ba = g_byte_array_prepend (ba, (const guint8 *)&flag8, sizeof (guint8));

	/* Major version */
	flag8 = TZ_BIN_VERSION_MAJOR;
	ba = g_byte_array_prepend (ba, (const guint8 *)&flag8, sizeof (guint8));

	/* Rules */
	add_timezone_rules (ba, is_recur, vtimezone, zone);

	bin->cb = ba->len;
	bin->lpb = talloc_memdup (mem_ctx, ba->data, ba->len);

	d(g_message ("New timezone stream.. Length: %d bytes.. Hex-data follows:", ba->len));
	d(for (i = 0; i < ba->len; i++)
		g_print("0x%.2X ", ba->data[i]));

	g_byte_array_free (ba, TRUE);
	g_clear_object (&vtimezone);
}

gchar *
e_mapi_cal_util_bin_to_mapi_tz (const guint8 *lpb,
				guint32 cb)
{
	guint8 flag8;
	guint16 flag16, cbHeader = 0;
	const guint8 *ptr = lpb;
	gchar *buf = NULL;

	d(g_message ("New timezone stream.. Length: %d bytes.. Info follows:", ba->len));

	/* Major version */
	flag8 = *((guint8 *)ptr);
	ptr += sizeof (guint8);
	d(g_print ("Major version: %d\n", flag8));
	if (TZ_BIN_VERSION_MAJOR != flag8)
		return NULL;

	/* Minor version */
	flag8 = *((guint8 *)ptr);
	ptr += sizeof (guint8);
	d(g_print ("Minor version: %d\n", flag8));
	if (TZ_BIN_VERSION_MINOR > flag8)
		return NULL;

	/* Length in bytes until rules info */
	flag16 = *((guint16 *)ptr);
	ptr += sizeof (guint16);
	d(g_print ("Length in bytes until rules: %d\n", flag16));
	cbHeader = flag16;

	/* wFlags: we don't yet understand GUID based names */
	flag16 = *((guint16 *)ptr);
	ptr += sizeof (guint16);
	d(g_print ("wFlags: %d\n", flag16));
	cbHeader -= sizeof (guint16);
	if (TZDEFINITION_FLAG_VALID_KEYNAME != flag16)
		return NULL;

	/* UTF-8 length of the keyname */
	flag16 = *((guint16 *)ptr);
	ptr += sizeof (guint16);
	d(g_print ("UTF8 length of keyname: %d\n", flag16));
	cbHeader -= sizeof (guint16);

	/* number of rules is at the end of the header.. we'll parse and use later */
	cbHeader -= sizeof (guint16);

	/* Keyname */
	buf = g_utf16_to_utf8 ((const gunichar2 *)ptr, cbHeader/sizeof (gunichar2), NULL, NULL, NULL);
	ptr += cbHeader;
	d(g_print ("Keyname: %s\n", buf));

	/* number of rules */
	flag16 = *((guint16 *)ptr);
	ptr += sizeof (guint16);
	d(g_print ("Number of rules: %d\n", flag16));

	/* FIXME: Need to support rules */

	return buf;
}

/* Corresponds to the first table in OXOCAL 2.2.5.6.
   - has_dst is signifies whether the SDT/DST entries are relevant or "N/A"
   - utc_offset is in minutes east of UTC
 */
struct pltz_mapentry {
	gboolean has_dst;
	int utc_offset;
	int standard_wMonth;
	int standard_wDayOfWeek;
	int standard_wDay;
	int standard_wHour;
	int daylight_wMonth;
	int daylight_wDayOfWeek;
	int daylight_wDay;
	int daylight_wHour;
};

/* Table contents, current as of [MS-OXOCAL] - v20110315 */
static const struct pltz_mapentry pltz_table[] = {
	{ FALSE,  720,  0, 0, 0, 0,   0, 0, 0, 0 },
	{ TRUE,     0, 10, 0, 5, 2,   3, 0, 5, 1 },
	{ TRUE,    60,  9, 0, 5, 2,   3, 0, 5, 1 },
	{ TRUE,    60, 10, 0, 5, 3,   3, 0, 5, 2 },
	{ TRUE,    60, 10, 0, 5, 3,   3, 0, 5, 2 },
	{ TRUE,   120,  9, 0, 5, 1,   3, 0, 5, 0 },
	{ TRUE,    60,  9, 0, 5, 1,   3, 0, 5, 0 },
	{ TRUE,   120, 10, 0, 5, 4,   3, 0, 5, 3 },
	{ TRUE,  -180,  2, 0, 2, 2,  10, 0, 3, 2 },
	{ TRUE,  -240, 11, 0, 1, 2,   3, 0, 2, 2 },
	{ TRUE,  -300, 11, 0, 1, 2,   3, 0, 2, 2 },
	{ TRUE,  -360, 11, 0, 1, 2,   3, 0, 2, 2 },
	{ TRUE,  -420, 11, 0, 1, 2,   3, 0, 2, 2 },
	{ TRUE,  -480, 11, 0, 1, 2,   3, 0, 2, 2 },
	{ TRUE,  -540, 11, 0, 1, 2,   3, 0, 2, 2 },
	{ FALSE, -600,  0, 0, 0, 0,   0, 0, 0, 0 },
	{ FALSE, -660,  0, 0, 0, 0,   0, 0, 0, 0 },
	{ TRUE,   720,  4, 0, 1, 3,   9, 0, 5, 2 },
	{ TRUE,   600,  3, 0, 5, 3,  10, 0, 5, 2 },
	{ TRUE,   570,  3, 0, 5, 3,  10, 0, 5, 2 },
	{ FALSE,  540,  0, 0, 0, 0,   0, 0, 0, 0 },
	{ FALSE,  480,  0, 0, 0, 0,   0, 0, 0, 0 },
	{ FALSE,  420,  0, 0, 0, 0,   0, 0, 0, 0 },
	{ FALSE,  330,  0, 0, 0, 0,   0, 0, 0, 0 },
	{ FALSE,  240,  0, 0, 0, 0,   0, 0, 0, 0 },
	{ TRUE,   210,  9, 2, 4, 2,   3, 0, 1, 2 },
	{ FALSE,  180,  0, 0, 0, 0,   0, 0, 0, 0 },
	{ TRUE,   120,  9, 0, 3, 2,   3, 5, 5, 2 },
	{ TRUE,  -210, 11, 0, 1, 0,   3, 0, 2, 0 },
	{ TRUE,   -60, 10, 0, 5, 1,   3, 0, 5, 0 },
	{ TRUE,  -120, 10, 0, 5, 1,   3, 0, 5, 0 },
	{ FALSE,    0,  0, 0, 0, 0,   0, 0, 0, 0 },
	{ FALSE, -180,  0, 0, 0, 0,   0, 0, 0, 0 },
	{ FALSE, -240,  0, 0, 0, 0,   0, 0, 0, 0 },
	{ FALSE, -300,  0, 0, 0, 0,   0, 0, 0, 0 },
	{ FALSE, -300,  0, 0, 0, 0,   0, 0, 0, 0 },
	{ FALSE, -360,  0, 0, 0, 0,   0, 0, 0, 0 },
	{ TRUE,  -360, 10, 0, 5, 2,   4, 0, 1, 2 },
	{ FALSE, -420,  0, 0, 0, 0,   0, 0, 0, 0 },
	{ FALSE, -720,  0, 0, 0, 0,   0, 0, 0, 0 },
	{ FALSE,  720,  0, 0, 0, 0,   0, 0, 0, 0 },
	{ FALSE,  660,  0, 0, 0, 0,   0, 0, 0, 0 },
	{ TRUE,   600,  3, 0, 5, 2,  10, 0, 1, 2 },
	{ FALSE,  600,  0, 0, 0, 0,   0, 0, 0, 0 },
	{ FALSE,  570,  0, 0, 0, 0,   0, 0, 0, 0 },
	{ TRUE,   480,  9, 0, 2, 2,   4, 0, 2, 2 },
	{ FALSE,  360,  0, 0, 0, 0,   0, 0, 0, 0 },
	{ FALSE,  300,  0, 0, 0, 0,   0, 0, 0, 0 },
	{ FALSE,  270,  0, 0, 0, 0,   0, 0, 0, 0 },
	{ TRUE,   120,  9, 4, 5, 2,   5, 5, 1, 2 },
	{ FALSE,  120,  0, 0, 0, 0,   0, 0, 0, 0 },
	{ TRUE,   180, 10, 0, 5, 1,   3, 0, 5, 0 },
	{ TRUE,   600,  3, 0, 5, 2,   8, 0, 5, 2 },
	{ TRUE,   600,  4, 0, 1, 3,  10, 0, 5, 2 },
	{ TRUE,   570,  4, 0, 1, 3,  10, 0, 5, 2 },
	{ TRUE,   600,  4, 0, 1, 3,  10, 0, 1, 2 },
	{ TRUE,  -240,  3, 6, 2, 23, 10, 6, 2, 23 },
	{ TRUE,   480,  3, 0, 5, 3,  10, 0, 5, 2 },
	{ TRUE,  -420, 10, 0, 5, 2,   4, 0, 1, 2 },
	{ TRUE,  -480, 10, 0, 5, 2,   4, 0, 1, 2 }
};

/* Return the ordinal-th wday day in month as a time_t in the local time.
	@year: year in decimal form
	@month: month (1 == Jan)
	@wday: weekday (0 == Sunday)
	@ordinal: nth occurence of wday, or last occurrence if out of bounds
 */
static time_t
nth_day_of_month (int year, int month, int wday, int ordinal)
{
	struct tm stm = {0};
	time_t ts;

	/* first day of month */
	stm.tm_year = year - 1900;
	stm.tm_mon = month - 1;
	stm.tm_mday = 1;

	ts = mktime (&stm);
	/* go to first instance of wday in month */
	ts += (60 * 60 * 24) * (wday - stm.tm_wday + 7 * (wday < stm.tm_wday));
	/* go to the n weeks in the future */
	ts += (60 * 60 * 24 * 7) * (ordinal - 1);
	localtime_r (&ts, &stm);
	/* the MS spec says that the 5th such weekday of the month always
	   refers to the last such day, even if it is the 4th.  So, check to
       see if we're in the same month, and if not, rewind a week. */
	if (stm.tm_mon != month - 1)
		ts -= (60 * 60 * 24 * 7);

	return ts;
}

/* return the most-correct PidLidTimeZone value w.r.t. OXOCAL 2.2.5.6. */
int
e_mapi_cal_util_mapi_tz_pidlidtimezone (ICalTimezone *ictz)
{
	gboolean tz_dst_now = FALSE, tz_has_dst = FALSE;
	int i, utc_offset = 0, best_index = 0, best_score = -1;
	const gchar *tznames;
	ICalTime *tt;

	if (ictz == NULL)
		return 0;

	/* Simple hack to determine if our TZ has DST */
	tznames = i_cal_timezone_get_tznames (ictz);
	if (tznames && strchr (tznames, '/'))
		tz_has_dst = TRUE;

	/* Calculate minutes east of UTC, what MS uses in this spec */
	tt = i_cal_time_new_current_with_zone (ictz);
	utc_offset = i_cal_timezone_get_utc_offset (ictz, tt, &tz_dst_now) / 60;
	if (tz_dst_now)
		utc_offset -= 60;

	/* Find the PidLidTimeZone entry that matches the most closely to
	   the SDT/DST rules for the given timezone */
	for (i = 0; i < sizeof (pltz_table) / sizeof (struct pltz_mapentry); ++i) {
		const struct pltz_mapentry *pme = &pltz_table[i];
		time_t pre_sdt, sdt, post_sdt, pre_dst, dst, post_dst;
		struct tm pre_stm, stm, post_stm;
		int score = 0;

		if (pme->utc_offset == utc_offset && tz_has_dst == pme->has_dst)
			score = 1;

		if (score && tz_has_dst) {
			sdt = nth_day_of_month (i_cal_time_get_year (tt), pme->standard_wMonth,
			                        pme->standard_wDayOfWeek,
			                        pme->standard_wDay);
			/* add the transition hour and a second */
			sdt += (pme->standard_wHour * 60 * 60) + 1;
			pre_sdt = sdt - 2 * 60 * 60;
			post_sdt = sdt + 2 * 60 * 60;

			dst = nth_day_of_month (i_cal_time_get_year (tt), pme->daylight_wMonth,
			                        pme->daylight_wDayOfWeek,
			                        pme->daylight_wDay);
			dst += (pme->daylight_wHour * 60 * 60) + 1;
			pre_dst = dst - 2 * 60 * 60;
			post_dst = dst + 2 * 60 * 60;

			localtime_r (&sdt, &stm);
			localtime_r (&pre_sdt, &pre_stm);
			localtime_r (&post_sdt, &post_stm);

			if (!stm.tm_isdst)
				score++;
			if (pre_stm.tm_isdst)
				score++;
			if (!post_stm.tm_isdst)
				score++;

			localtime_r (&dst, &stm);
			localtime_r (&pre_dst, &pre_stm);
			localtime_r (&post_dst, &post_stm);

			if (stm.tm_isdst)
				score++;
			if (!pre_stm.tm_isdst)
				score++;
			if (post_stm.tm_isdst)
				score++;

			if (score > best_score) {
				best_score = score;
				best_index = i;
			}
		}
	}

	g_clear_object (&tt);

	return best_index;
}
