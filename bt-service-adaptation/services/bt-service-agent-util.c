/*
 * Bluetooth-frwk
 *
 * Copyright (c) 2015 - 2016 Samsung Electronics Co., Ltd. All rights reserved.
 *
 * Contact:  Anupam Roy <anupam.r@samsung.com>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *              http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <malloc.h>
#include <stacktrim.h>
#include <syspopup_caller.h>

#include "bt-internal-types.h"
#include "bt-service-common.h"

gboolean _bt_agent_is_hid_keyboard(unsigned int dev_class)
{
	switch ((dev_class & 0x1f00) >> 8) {
		case 0x05:
			switch ((dev_class & 0xc0) >> 6) {
				case 0x01:
					/* input-keyboard" */
					return TRUE;
			}
			break;
	}

	return FALSE;
}

static gboolean __bt_agent_find_device_by_address_exactname(char *buffer,
		const char *address)
{
	char *pch;
	char *last;

	pch = strtok_r(buffer, "= ,", &last);

	if (pch == NULL)
		return FALSE;

	while ((pch = strtok_r(NULL, ",", &last))) {
		if (0 == g_strcmp0(pch, address)) {
			BT_DBG("Match found\n");
			return TRUE;
		}
	}
	return FALSE;
}

static gboolean __bt_agent_find_device_by_partial_name(char *buffer,
		const char *partial_name)
{
	char *pch;
	char *last;

	pch = strtok_r(buffer, "= ,", &last);

	if (pch == NULL)
		return FALSE;

	while ((pch = strtok_r(NULL, ",", &last))) {
		if (g_str_has_prefix(partial_name, pch)) {
			BT_DBG("Match found\n");
			return TRUE;
		}
	}
	return FALSE;
}

gboolean _bt_agent_is_device_blacklist(const char *address,
		const char *name)
{
	char *buffer;
	char **lines;
	int i;
	FILE *fp;
	long size;
	size_t result;

	BT_DBG("+");

	fp = fopen(BT_AGENT_AUTO_PAIR_BLACKLIST_FILE, "r");

	if (fp == NULL) {
		BT_ERR("Unable to open blacklist file");
		return FALSE;
	}

	fseek(fp, 0, SEEK_END);
	size = ftell(fp);
	if (size <= 0) {
		BT_DBG("size is not a positive number");
		fclose(fp);
		return FALSE;
	}

	rewind(fp);

	buffer = g_malloc0(sizeof(char) * size);
	/* Fix : NULL_RETURNS */
	if (buffer == NULL) {
		BT_ERR("Fail to allocate memory");
		fclose(fp);
		return FALSE;
	}
	result = fread((char *)buffer, 1, size, fp);
	fclose(fp);
	if (result != size) {
		BT_ERR("Read Error");
		g_free(buffer);
		return FALSE;
	}

	BT_DBG("Buffer = %s", buffer);

	lines = g_strsplit_set(buffer, BT_AGENT_NEW_LINE, 0);
	g_free(buffer);

	if (lines == NULL) {
		BT_ERR("No lines in the file");
		return FALSE;
	}

	for (i = 0; lines[i] != NULL; i++) {
		if (g_str_has_prefix(lines[i], "AddressBlacklist"))
			if (__bt_agent_find_device_by_address_exactname(
						lines[i], address))
				goto done;
		if (g_str_has_prefix(lines[i], "ExactNameBlacklist"))
			if (__bt_agent_find_device_by_address_exactname(
						lines[i], name))
				goto done;
		if (g_str_has_prefix(lines[i], "PartialNameBlacklist"))
			if (__bt_agent_find_device_by_partial_name(lines[i],
						name))
				goto done;
		if (g_str_has_prefix(lines[i], "KeyboardAutoPair"))
			if (__bt_agent_find_device_by_address_exactname(
						lines[i], address))
				goto done;
	}
	g_strfreev(lines);
	BT_DBG("-");
	return FALSE;
done:
	BT_DBG("Found the device");
	g_strfreev(lines);
	return TRUE;
}

void _bt_agent_release_memory(void)
{
	/* Release Malloc Memory*/
	malloc_trim(0);

	/* Release Stack Memory*/
	stack_trim();
}

gboolean _bt_agent_is_auto_response(unsigned int dev_class,
		const gchar *address, const gchar *name)
{
	gboolean is_headset = FALSE;
	gboolean is_mouse = FALSE;
	char lap_address[BT_LOWER_ADDRESS_LENGTH];

	BT_DBG("bt_agent_is_headset_class, %d +", dev_class);

	if (address == NULL)
		return FALSE;

	switch ((dev_class & 0x1f00) >> 8) {
		case 0x04:
			switch ((dev_class & 0xfc) >> 2) {
				case 0x01:
				case 0x02:
					/* Headset */
					is_headset = TRUE;
					break;
				case 0x06:
					/* Headphone */
					is_headset = TRUE;
					break;
				case 0x0b:      /* VCR */
				case 0x0c:      /* Video Camera */
				case 0x0d:      /* Camcorder */
					break;
				default:
					/* Other audio device */
					is_headset = TRUE;
					break;
			}
			break;
		case 0x05:
			switch (dev_class & 0xff) {
				case 0x80:  /* 0x80: Pointing device(Mouse) */
					is_mouse = TRUE;
					break;

				case 0x40: /* 0x40: input device (BT keyboard) */
					/* Get the LAP(Lower Address part) */
					g_strlcpy(lap_address, address, sizeof(lap_address));

					/* Need to Auto pair the blacklisted Keyboard */
					if (_bt_agent_is_device_blacklist(lap_address, name) != TRUE) {
						BT_DBG("Device is not black listed\n");
						return FALSE;
					} else {
						BT_ERR("Device is black listed\n");
						return TRUE;
					}
			}
	}

	if ((!is_headset) && (!is_mouse))
		return FALSE;

	/* Get the LAP(Lower Address part) */
	g_strlcpy(lap_address, address, sizeof(lap_address));

	BT_DBG("Device address = %s\n", address);
	BT_DBG("Address 3 byte = %s\n", lap_address);

	if (_bt_agent_is_device_blacklist(lap_address, name)) {
		BT_ERR("Device is black listed\n");
		return FALSE;
	}
	return TRUE;
}

int _bt_agent_generate_passkey(char *passkey, int size)
{
	int i;
	ssize_t len;
	int random_fd;
	unsigned int value = 0;

	if (passkey == NULL)
		return -1;

	if (size <= 0)
		return -1;

	random_fd = open("/dev/urandom", O_RDONLY);

	if (random_fd < 0)
		return -1;

	for (i = 0; i < size; i++) {
		len = read(random_fd, &value, sizeof(value));
		if (len > 0)
			passkey[i] = '0' + (value % 10);
	}
	close(random_fd);
	BT_DBG("passkey: %s", passkey);
	return 0;
}
