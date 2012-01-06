/*
 *   bluetooth-media-control
 *
 * Copyright (c) 2000 - 2011 Samsung Electronics Co., Ltd. All rights reserved.
 *
 * Contact:  Hocheol Seo <hocheol.seo@samsung.com>
 *		 Girishashok Joshi <girish.joshi@samsung.com>
 *		 Chanyeol Park <chanyeol.park@samsung.com>
 *
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include "bluetooth-media-control-api.h"

#include <glib.h>
#include <dbus/dbus-glib.h>
#include <dbus/dbus-glib-lowlevel.h>

media_player_settings_t player_settings = {0x00, 0x00, 0x00,0x00, 0x01, 1111 };
media_metadata_attributes_t metadata = {"Test Track", "Chethan", "TNC", "Tumkur", 1, 1, 14400 };

void static __choose_metadata_settings(void)
{
	int cmd;
	media_metadata_attributes_t metadata = {0,};

	while (1) {
		printf("\nPlease choose metadata settings\n");
		printf("\t0: return to main menu\n");
		printf("\t1. Title\n");
		printf("\t2. Artist\n");
		printf("\t3. Album\n");
		printf("\t4. Genre \n");
		printf("\t5. NumberOfTracks \n");
		printf("\t6.Track Number \n");
		printf("\t7. Duration \n");
		printf("\tEnter your choice [ ]\b\b");

		scanf("%d", &cmd);

		switch (cmd) {
		case 0:
			return;
		case 1:	/* Title */
			metadata.title = calloc(1,256);
			printf("Enter the \"Track\" name\n");
			scanf("%s",(char*)metadata.title);

			break;
		case 2:	/*Artist */
			metadata.artist = calloc(1,256);
			printf(" Enter the \"Artist\" name\n");
			scanf("%s",(char*)metadata.artist);
			break;
		case 3:	/* Album */
			metadata.album = calloc(1,256);
			printf(" Enter the \"Album\" name\n");
			scanf("%s",(char*)metadata.album);
			break;
		case 4: /* Genre */
			metadata.genre = calloc(1,256);
			printf(" Enter the \"Genre\" \n");
			scanf("%s",(char*)metadata.genre);
			break;
		case 5: /* NumberOfTracks */
			printf(" Enter the \" Totol NumberOfTracks\" \n");
			scanf("%d",&metadata.total_tracks);
			break;
		case 6: /*Track Number */
			printf(" Enter the \" Track Number\" \n");
			scanf("%d",&metadata.number);
			break;
		case 7: /*Duration */
			printf(" Enter the \"Duration\" \n");
			scanf("%d",&metadata.duration);
			break;
		default:
			break;
		}
		bluetooth_media_control_player_track_changed(metadata);

		if(NULL !=  metadata.title) {
			free((void*)metadata.title);
			metadata.title = NULL;
		}
		if(NULL !=  metadata.artist) {
			free((void*)metadata.artist);
			metadata.artist= NULL;
		}
		if(NULL !=  metadata.album) {
			free((void*)metadata.album);
			metadata.album= NULL;
		}
		if(NULL !=  metadata.genre) {
			free((void*)metadata.genre);
			metadata.genre= NULL;
		}
	}
}

void static __choose_player_settings(void)
{
	int cmd;

	while (1) {
		printf("\nPlease choose player settings\n");
		printf("\t0: return to main menu\n");
		printf("\t1. Equilizer\n");
		printf("\t2. Repeat\n");
		printf("\t3. Shuffle\n");
		printf("\t4. Scan \n");
		printf("\t5. Status \n");
		printf("\t6. Position \n");
		printf("\tEnter your choice [ ]\b\b");

		scanf("%d", &cmd);

		switch (cmd) {
		case 0:
			return;
		case 1:	/* Equilizer */
			printf("Possible Values - EQUALIZER_OFF = 0x00 and EQUALIZER_ON = 0x01,\n");
			scanf("%d",&player_settings.equilizer);
			break;
		case 2:	/*Repeat */
			printf(" Possible Values - REPEAT_MODE_OFF = 0x00, REPEAT_SINGLE_TRACK = 0x01 , \
					REPEAT_ALL_TRACK = 0x02,	REPEAT_GROUP = 0x03\n");
			scanf("%d",&player_settings.repeat);
			break;
		case 3:	/* Shuffle */
			printf(" Possible Values - SHUFFLE_MODE_OFF = 0x00, SHUFFLE_ALL_TRACK = 0x01 , \
					SHUFFLE_GROUP = 0x02\n");
			scanf("%d",&player_settings.shuffle);
			break;
		case 4: /* Scan */
			printf(" Possible Values - SCAN_MODE_OFF = 0x00, SCAN_ALL_TRACK = 0x01 , \
					SCAN_GROUP = 0x02\n");
			scanf("%s",&player_settings.scan);
			break;
		case 5: /* Status */
			printf(" Possible Values - STATUS_PLAYING = 0x00, STATUS_STOPPED = 0x01 , \
					STATUS_PAUSED = 0x02,STATUS_FORWARD_SEEK = 0x03 STATUS_REVERSE_SEEK = 0x04 \
					STATUS_ERROR = 0x05\n");
			scanf("%d",&player_settings.status);
			break;
		case 6: /* Position */
			printf("Enter the possible value: []");
			scanf("%d",&player_settings.position);
			break;
		default:
			break;
		}
		bluetooth_media_control_player_property_changed(player_settings);
	}
}

int main()
{
	GMainLoop *agent_loop;
	int cmd;

	g_type_init();
	agent_loop = g_main_loop_new(NULL, FALSE);

	printf("MP-AV test application started\n");
	while (1) {
		printf("\n\n\t0. Exit\n");
		printf("\t1. bluetooth_media_control_init \n");
		printf("\t2. bluetooth_media_control_register_palyer\n");
		printf("\t3. bluetooth_media_control_player_property_changed\n");
		printf("\t4. bluetooth_media_control_player_track_changed\n");
		printf("\t5. bluetooth_media_control_unregister_palyer\n");
		printf("\tEnter your choice [  ]\b\b");

		scanf("%d", &cmd);

		switch (cmd) {
		case 0:	/* exit the application */
			{
				exit(0);
				break;
			}
		case 1:/*Initialization*/
			{
				bluetooth_media_control_init();
				break;
			}
		case 2: /*Register new Player*/
			{
				bluetooth_media_control_register_player(player_settings, metadata);
				break;
			}
		case 3:
			{
				__choose_player_settings();
				break;
			}
		case 4:
			{
				__choose_metadata_settings();
				break;
			}
		case 5: /*Unregister Player*/
			{
				bluetooth_media_control_unregister_player();
				break;
			}
		}
	}
	printf("gmain loop enter\n");
	g_main_loop_run(agent_loop);
	printf("gmain loop leave\n");
	return 0;
}
