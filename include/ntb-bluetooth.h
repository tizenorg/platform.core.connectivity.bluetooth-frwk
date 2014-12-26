#include "bluetooth.h"

/***********************adapter***************************/
int ntb_bt_adapter_enable(void);
int ntb_bt_adapter_disable(void);
int ntb_bt_adapter_recover(void);
int ntb_bt_adapter_reset(void);
int ntb_bt_adapter_get_state(bt_adapter_state_e *adapter_state);
int ntb_bt_adapter_get_address(char **address);
int ntb_bt_adapter_get_version(char **version);
int ntb_bt_adapter_get_local_info(char **chipset, char **firmware, char **stack_version, char **profiles);
int ntb_bt_adapter_get_name(char **name);
int ntb_bt_adapter_set_name(const char *name);
int ntb_bt_adapter_get_visibility(bt_adapter_visibility_mode_e *mode, int *duration);
int ntb_bt_adapter_set_visibility(bt_adapter_visibility_mode_e visibility_mode, int timeout_sec);
int ntb_bt_adapter_set_connectable_changed_cb(bt_adapter_connectable_changed_cb callback, void *user_data);
int ntb_bt_adapter_unset_connectable_changed_cb(void);
int ntb_bt_adapter_get_connectable(bool *connectable);
int ntb_bt_adapter_set_connectable(bool connectable);
int ntb_bt_adapter_foreach_bonded_device(bt_adapter_bonded_device_cb foreach_cb, void *user_data);
int ntb_bt_adapter_get_bonded_device_info(const char *remote_address, bt_device_info_s **device_info);
int ntb_bt_adapter_free_device_info(bt_device_info_s *device_info);
int ntb_bt_adapter_is_service_used(const char *service_uuid, bool *used);
int ntb_bt_adapter_set_state_changed_cb(bt_adapter_state_changed_cb callback, void *user_data);
int ntb_bt_adapter_set_name_changed_cb(bt_adapter_name_changed_cb callback, void *user_data);
int ntb_bt_adapter_set_visibility_mode_changed_cb(bt_adapter_visibility_mode_changed_cb callback, void *user_data);
int ntb_bt_adapter_set_device_discovery_state_changed_cb(bt_adapter_device_discovery_state_changed_cb callback, void *user_data);
int ntb_bt_adapter_unset_state_changed_cb(void);
int ntb_bt_adapter_unset_name_changed_cb(void);
int ntb_bt_adapter_unset_visibility_mode_changed_cb(void);
int ntb_bt_adapter_set_visibility_duration_changed_cb(bt_adapter_visibility_duration_changed_cb callback, void *user_data);
int ntb_bt_adapter_unset_visibility_duration_changed_cb(void);
int ntb_bt_adapter_unset_device_discovery_state_changed_cb(void);
int ntb_bt_adapter_start_device_discovery(void);
int ntb_bt_adapter_stop_device_discovery(void);
int ntb_bt_adapter_is_discovering(bool *is_discovering);
int ntb_bt_agent_register(bt_agent *agent);
int ntb_bt_agent_unregister(void);
void ntb_bt_agent_confirm_accept(bt_req_t *requestion);
void ntb_bt_agent_confirm_reject(bt_req_t *requestion);
void ntb_bt_agent_pincode_reply(const char *pin_code, bt_req_t *requestion);
void ntb_bt_agent_pincode_cancel(bt_req_t *requestion);
#ifdef TIZEN_3
int ntb_bt_agent_register_sync(void);
void ntb_bt_agent_reply_sync(bt_agent_accept_type_t reply);
#endif
/*
int bt_adapter_le_enable(void);
int bt_adapter_le_disable(void);
int bt_adapter_le_get_state(bt_adapter_le_state_e *adapter_le_state);
int bt_adapter_le_set_state_changed_cb(bt_adapter_le_state_changed_cb callback, void *user_data);
int bt_adapter_le_set_device_discovery_state_changed_cb(bt_adapter_le_device_discovery_state_changed_cb callback, void *user_data);
int bt_adapter_le_unset_state_changed_cb(void);
int bt_adapter_le_unset_device_discovery_state_changed_cb(void);
int bt_adapter_le_start_device_discovery(void);
int bt_adapter_le_stop_device_discovery(void);
int bt_adapter_le_is_discovering(bool *is_discovering);
int bt_adapter_le_add_white_list(const char *address, bt_device_address_type_e address_type);
int bt_adapter_le_remove_white_list(const char *address, bt_device_address_type_e address_type);
int bt_adapter_le_clear_white_list(void);
int bt_adapter_le_create_advertiser(bt_advertiser_h *advertiser);
int bt_adapter_le_destroy_advertiser(bt_advertiser_h advertiser);
int bt_adapter_le_add_advertising_data(bt_advertiser_h advertiser,
		bt_adapter_le_packet_type_e pkt_type, bt_adapter_le_packet_data_type_e data_type,
		void *data, unsigned int data_size);
int bt_adapter_le_remove_advertising_data(bt_advertiser_h advertiser,
		bt_adapter_le_packet_type_e pkt_type, bt_adapter_le_packet_data_type_e data_type);
int bt_adapter_le_clear_advertising_data(bt_advertiser_h advertiser,
		bt_adapter_le_packet_type_e pkt_type);
int bt_adapter_le_start_advertising(bt_advertiser_h advertiser,
		bt_adapter_le_advertising_params_s *adv_params,
		bt_adapter_le_advertising_state_changed_cb cb, void *user_data);
int bt_adapter_le_stop_advertising(bt_advertiser_h advertiser);
int bt_adapter_le_enable_privacy(bool enable_privacy);
int bt_adapter_get_local_oob_data(unsigned char **hash, unsigned char **randomizer,
					int *hash_len, int *randomizer_len);
int bt_adapter_set_remote_oob_data(const char *remote_address,
				unsigned char *hash, unsigned char *randomizer,
				int hash_len, int randomizer_len);
int bt_adapter_remove_remote_oob_data(const char *remote_address);
*/

/***********************audio***************************/
int ntb_bt_audio_initialize(void);
int ntb_bt_audio_deinitialize(void);
int ntb_bt_audio_connect(const char *remote_address, bt_audio_profile_type_e type);
int ntb_bt_audio_disconnect(const char *remote_address, bt_audio_profile_type_e type);
int ntb_bt_audio_set_connection_state_changed_cb(bt_audio_connection_state_changed_cb callback, void *user_data);
int ntb_bt_audio_unset_connection_state_changed_cb(void);
/*
int bt_ag_notify_speaker_gain(int gain);
int bt_ag_get_speaker_gain(int *gain);
int bt_ag_is_nrec_enabled(bool *enabled);
int bt_ag_set_microphone_gain_changed_cb(bt_ag_microphone_gain_changed_cb callback, void *user_data);
int bt_ag_unset_microphone_gain_changed_cb(void);
int bt_ag_set_speaker_gain_changed_cb(bt_ag_speaker_gain_changed_cb callback,
					void *user_data);
int bt_ag_unset_speaker_gain_changed_cb(void);
int bt_ag_open_sco(void);
int bt_ag_close_sco(void);
int bt_ag_is_sco_opened(bool *opened);
int bt_ag_set_sco_state_changed_cb(bt_ag_sco_state_changed_cb callback,
					void *user_data);
int bt_ag_unset_sco_state_changed_cb(void);
int bt_ag_notify_call_event(bt_ag_call_event_e event, unsigned int call_id, const char *phone_number);
int bt_ag_notify_call_list(bt_call_list_h list);
int bt_ag_notify_voice_recognition_state(bool state);
int bt_ag_set_call_handling_event_cb(bt_ag_call_handling_event_cb callback,
					void *user_data);
int bt_ag_unset_call_handling_event_cb(void);
int bt_ag_set_multi_call_handling_event_cb(
					bt_ag_multi_call_handling_event_cb callback,
					void *user_data);
int bt_ag_unset_multi_call_handling_event_cb(void);
int bt_ag_set_dtmf_transmitted_cb(bt_ag_dtmf_transmitted_cb callback,
						void *user_data);
int bt_ag_unset_dtmf_transmitted_cb(void);
int bt_call_list_create(bt_call_list_h *list);
int bt_call_list_destroy(bt_call_list_h list);
int bt_call_list_reset(bt_call_list_h list);
int bt_call_list_add(bt_call_list_h list, unsigned int call_id, bt_ag_call_state_e state, const char *phone_number);
*/

/***********************avrcp***************************/
int ntb_bt_avrcp_target_initialize(bt_avrcp_target_connection_state_changed_cb callback, void *user_data);
int ntb_bt_avrcp_target_deinitialize(void);
int ntb_bt_avrcp_target_notify_equalizer_state(bt_avrcp_equalizer_state_e state);
int ntb_bt_avrcp_target_notify_repeat_mode(bt_avrcp_repeat_mode_e mode);
int ntb_bt_avrcp_target_notify_shuffle_mode(bt_avrcp_shuffle_mode_e mode);
int ntb_bt_avrcp_target_notify_scan_mode(bt_avrcp_scan_mode_e mode);
int ntb_bt_avrcp_target_notify_player_state(bt_avrcp_player_state_e state);
int ntb_bt_avrcp_target_notify_position(unsigned int position);
int ntb_bt_avrcp_target_notify_track(const char *title, const char *artist, const char *album,
		const char *genre, unsigned int track_num, unsigned int total_tracks, unsigned int duration);
int ntb_bt_avrcp_set_equalizer_state_changed_cb(bt_avrcp_equalizer_state_changed_cb callback, void *user_data);
int ntb_bt_avrcp_unset_equalizer_state_changed_cb(void);
int ntb_bt_avrcp_set_repeat_mode_changed_cb(bt_avrcp_repeat_mode_changed_cb callback, void *user_data);
int ntb_bt_avrcp_unset_repeat_mode_changed_cb(void);
int ntb_bt_avrcp_set_shuffle_mode_changed_cb(bt_avrcp_shuffle_mode_changed_cb callback, void *user_data);
int ntb_bt_avrcp_unset_shuffle_mode_changed_cb(void);
int ntb_bt_avrcp_set_scan_mode_changed_cb(bt_avrcp_scan_mode_changed_cb callback, void *user_data);
int ntb_bt_avrcp_unset_scan_mode_changed_cb(void);

/***********************common***************************/
int ntb_bt_initialize(void);
int ntb_bt_deinitialize(void);

/***********************device***************************/
int ntb_bt_device_create_bond(const char *device_address);
int ntb_bt_device_create_bond_by_type(const char *device_address,
			bt_device_connection_link_type_e conn_type);
int ntb_bt_device_cancel_bonding(void);
int ntb_bt_device_destroy_bond(const char *device_address);
int ntb_bt_device_set_alias(const char *device_address, const char *alias);
int ntb_bt_device_set_authorization(const char *device_address, bt_device_authorization_e authorization);
int ntb_bt_device_start_service_search(const char *device_address);
int ntb_bt_device_cancel_service_search(void);
int ntb_bt_device_foreach_connected_profiles(const char *remote_address, bt_device_connected_profile callback, void *user_data);
int ntb_bt_device_set_bond_created_cb(bt_device_bond_created_cb callback, void *user_data);
int ntb_bt_device_set_bond_destroyed_cb(bt_device_bond_destroyed_cb callback, void *user_data);
int ntb_bt_device_set_authorization_changed_cb(bt_device_authorization_changed_cb callback, void *user_data);
int ntb_bt_device_set_service_searched_cb(bt_device_service_searched_cb callback, void *user_data);
int ntb_bt_device_set_connection_state_changed_cb(bt_device_connection_state_changed_cb callback, void *user_data);
int ntb_bt_device_unset_bond_created_cb(void);
int ntb_bt_device_unset_bond_destroyed_cb(void);
int ntb_bt_device_unset_authorization_changed_cb(void);
int ntb_bt_device_unset_service_searched_cb(void);
int ntb_bt_device_unset_connection_state_changed_cb(void);
int ntb_bt_device_get_service_mask_from_uuid_list(char **uuids,
				      int no_of_service,
				      bt_service_class_t *service_mask_list);
/*
int bt_device_is_profile_connected(const char *remote_address, bt_profile_e bt_profile,
				bool *connected_status);
int bt_device_le_conn_update(const char *device_address,
            const bt_le_conn_update_s *parameters);
*/

/***********************gatt***************************/
int ntb_bt_gatt_foreach_primary_services(const char *remote_address,
				bt_gatt_primary_service_cb callback,
				void *user_data);
int ntb_bt_gatt_discover_characteristics(bt_gatt_attribute_h service,
				bt_gatt_characteristics_discovered_cb callback,
				void *user_data);
int ntb_bt_gatt_get_service_uuid(bt_gatt_attribute_h service, char **uuid);
int ntb_bt_gatt_foreach_included_services(bt_gatt_attribute_h service,
				bt_gatt_included_service_cb callback,
				void *user_data);
int ntb_bt_gatt_get_characteristic_declaration(bt_gatt_attribute_h characteristic,
				char **uuid, unsigned char **value,
				int *value_length);
int ntb_bt_gatt_clone_attribute_handle(bt_gatt_attribute_h *clone,
				bt_gatt_attribute_h origin);
int ntb_bt_gatt_destroy_attribute_handle(bt_gatt_attribute_h handle);
int ntb_bt_gatt_read_characteristic_value(bt_gatt_attribute_h characteristic,
		bt_gatt_characteristic_read_cb callback);
/*
int bt_gatt_watch_characteristic_changes(bt_gatt_attribute_h service);
int bt_gatt_unwatch_characteristic_changes(bt_gatt_attribute_h service);
int bt_gatt_set_characteristic_value(bt_gatt_attribute_h characteristic,
				const unsigned char *value,
				int value_length);
int bt_gatt_discover_characteristic_descriptor(bt_gatt_attribute_h characteristic_handle,
				bt_gatt_characteristic_descriptor_discovered_cb callback,
				void *user_data);
int bt_gatt_connect(const char *address, bool auto_connect);
int bt_gatt_disconnect(const char *address);
int bt_gatt_set_connection_state_changed_cb(bt_gatt_connection_state_changed_cb callback, void *user_data);
int bt_gatt_unset_connection_state_changed_cb(void);

//Implemented, but error parameter type
int ntb_bt_gatt_set_characteristic_changed_cb(bt_gatt_characteristic_changed_cb callback,
				void *user_data);
int ntb_bt_gatt_unset_characteristic_changed_cb(void);
int ntb_bt_gatt_set_characteristic_value_request(bt_gatt_attribute_h characteristic,
				const unsigned char *value, int value_length,
				bt_gatt_characteristic_write_cb callback);
*/

/***********************hdp***************************/
int ntb_bt_hdp_register_sink_app(unsigned short data_type, char **app_id);
int ntb_bt_hdp_unregister_sink_app(const char *app_id);
int ntb_bt_hdp_send_data(unsigned int channel, const char *data, unsigned int size);
int ntb_bt_hdp_connect_to_source(const char *remote_address, const char *app_id);
int ntb_bt_hdp_disconnect(const char *remote_address, unsigned int channel);
int ntb_bt_hdp_set_connection_state_changed_cb(bt_hdp_connected_cb connected_cb,
		bt_hdp_disconnected_cb disconnected_cb, void *user_data);
int ntb_bt_hdp_unset_connection_state_changed_cb(void);
int ntb_bt_hdp_set_data_received_cb(bt_hdp_data_received_cb callback,
				void *user_data);
int ntb_bt_hdp_unset_data_received_cb(void);

/***********************hid***************************/
int ntb_bt_hid_host_initialize(bt_hid_host_connection_state_changed_cb connection_cb,
								void *user_data);
int ntb_bt_hid_host_deinitialize(void);
int ntb_bt_hid_host_connect(const char *remote_address);
int ntb_bt_hid_host_disconnect(const char *remote_address);

/***********************opp***************************/
//client
int ntb_bt_opp_client_initialize(void);
int ntb_bt_opp_client_deinitialize(void);
int ntb_bt_opp_client_add_file(const char *file);
int ntb_bt_opp_client_clear_files(void);
int ntb_bt_opp_client_push_files(const char *remote_address,
			bt_opp_client_push_responded_cb responded_cb,
			bt_opp_client_push_progress_cb progress_cb,
			bt_opp_client_push_finished_cb finished_cb,
			void *user_data);
int ntb_bt_opp_client_cancel_push(void);
//server
int ntb_bt_opp_server_initialize(const char *destination,
			bt_opp_server_push_requested_cb push_requested_cb,
			void *user_data);
int ntb_bt_opp_server_initialize_by_connection_request(const char *destination,
			bt_opp_server_connection_requested_cb connection_requested_cb,
			void *user_data);
int ntb_bt_opp_server_deinitialize(void);
int ntb_bt_opp_server_accept(bt_opp_server_transfer_progress_cb progress_cb,
			bt_opp_server_transfer_finished_cb finished_cb,
			const char *name,
			void *user_data,
			int *transfer_id);
int ntb_bt_opp_server_reject(void);
int ntb_bt_opp_server_set_destination(const char *destination);
int ntb_bt_opp_server_cancel_transfer(int transfer_id);

/***********************pan***************************/
//nap
int ntb_bt_nap_activate(void);
int ntb_bt_nap_deactivate(void);
int ntb_bt_nap_set_connection_state_changed_cb(
				bt_nap_connection_state_changed_cb callback,
				void *user_data);
int ntb_bt_nap_unset_connection_state_changed_cb(void);
/*
int bt_nap_disconnect_all(void);
int bt_nap_disconnect(const char *remote_address);
*/

//panu
int ntb_bt_panu_set_connection_state_changed_cb(
				bt_panu_connection_state_changed_cb callback,
				void *user_data);
int ntb_bt_panu_unset_connection_state_changed_cb(void);
int ntb_bt_panu_connect(const char *remote_address, bt_panu_service_type_e type);
int ntb_bt_panu_disconnect(const char *remote_address);

/***********************socket***************************/
int ntb_bt_socket_create_rfcomm(const char *uuid, int *socket_fd);
int ntb_bt_socket_destroy_rfcomm(int socket_fd);
int ntb_bt_socket_listen_and_accept_rfcomm(int socket_fd, int max_pending_connections);
int ntb_bt_socket_listen(int socket_fd, int max_pending_connections);
int ntb_bt_socket_accept(int socket_fd);
int ntb_bt_socket_reject(int socket_fd);
int ntb_bt_socket_connect_rfcomm(const char *remote_address, const char *remote_port_uuid);
int ntb_bt_socket_disconnect_rfcomm(int socket_fd);
int ntb_bt_socket_send_data(int socket_fd, const char *data, int length);
int ntb_bt_socket_set_data_received_cb(bt_socket_data_received_cb callback, void *user_data);
int ntb_bt_socket_unset_data_received_cb(void);
int ntb_bt_socket_set_connection_requested_cb(bt_socket_connection_requested_cb callback, void *user_data);
int ntb_bt_socket_unset_connection_requested_cb(void);
int ntb_bt_socket_set_connection_state_changed_cb(bt_socket_connection_state_changed_cb callback, void *user_data);
int ntb_bt_socket_unset_connection_state_changed_cb(void);
/* if or not capi
int bt_socket_is_service_used(const char* service_uuid, bool *used)
*/
