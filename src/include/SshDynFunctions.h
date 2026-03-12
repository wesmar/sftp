#if !defined(staticlinking) && !defined(SFTP_ALLINONE)
/* SSH*/
FUNCDEF(LIBSSH2_API LIBSSH2_SESSION*,libssh2_session_init_ex,(LIBSSH2_ALLOC_FUNC((*my_alloc)), LIBSSH2_FREE_FUNC((*my_free)), LIBSSH2_REALLOC_FUNC((*my_realloc)), void *abstract));
FUNCDEF(LIBSSH2_API void **,libssh2_session_abstract,(LIBSSH2_SESSION *session));
FUNCDEF(LIBSSH2_API void *,libssh2_session_callback_set,(LIBSSH2_SESSION *session, int cbtype, void *callback));
FUNCDEF(LIBSSH2_API int ,libssh2_banner_set,(LIBSSH2_SESSION *session, const char *banner));
FUNCDEF(LIBSSH2_API int ,libssh2_session_startup,(LIBSSH2_SESSION *session, int sock));
FUNCDEF(LIBSSH2_API int ,libssh2_session_disconnect_ex,(LIBSSH2_SESSION *session, int reason, const char *description, const char *lang));
FUNCDEF(LIBSSH2_API int ,libssh2_session_free,(LIBSSH2_SESSION *session));
FUNCDEF(LIBSSH2_API const char *,libssh2_hostkey_hash,(LIBSSH2_SESSION *session, int hash_type));
FUNCDEF(LIBSSH2_API int ,libssh2_session_method_pref,(LIBSSH2_SESSION *session, int method_type, const char *prefs));
FUNCDEF(LIBSSH2_API const char *,libssh2_session_methods,(LIBSSH2_SESSION *session, int method_type));
FUNCDEF(LIBSSH2_API int ,libssh2_session_last_error,(LIBSSH2_SESSION *session, char **errmsg, int *errmsg_len, int want_buf));
FUNCDEF(LIBSSH2_API int ,libssh2_session_last_errno,(LIBSSH2_SESSION *session));
FUNCDEF(LIBSSH2_API int ,libssh2_session_flag,(LIBSSH2_SESSION *session, int flag, int value));
FUNCDEF(LIBSSH2_API char *,libssh2_userauth_list,(LIBSSH2_SESSION *session, const char *username, unsigned int username_len));
FUNCDEF(LIBSSH2_API int ,libssh2_userauth_authenticated,(LIBSSH2_SESSION *session));
FUNCDEF(LIBSSH2_API int ,libssh2_userauth_password_ex,(LIBSSH2_SESSION *session, const char *username, unsigned int username_len, const char *password, unsigned int password_len, LIBSSH2_PASSWD_CHANGEREQ_FUNC((*passwd_change_cb))));
FUNCDEF(LIBSSH2_API int ,libssh2_userauth_publickey_fromfile_ex,(LIBSSH2_SESSION *session, const char *username, unsigned int username_len,
                                                                                 const char *publickey, const char *privatekey,
                                                                                 const char *passphrase));
FUNCDEF(LIBSSH2_API int ,libssh2_userauth_hostbased_fromfile_ex,(LIBSSH2_SESSION *session, const char *username, unsigned int username_len,
                                                                                 const char *publickey, const char *privatekey,
                                                                                 const char *passphrase,
                                                                                 const char *hostname, unsigned int hostname_len,
                                                                                 const char *local_username, unsigned int local_username_len));
FUNCDEF(LIBSSH2_API int ,libssh2_userauth_keyboard_interactive_ex,(LIBSSH2_SESSION* session, const char *username, unsigned int username_len,
                                                                   LIBSSH2_USERAUTH_KBDINT_RESPONSE_FUNC((*response_callback))));
FUNCDEF(LIBSSH2_API int ,libssh2_poll,(LIBSSH2_POLLFD *fds, unsigned int nfds, long timeout));
FUNCDEF(LIBSSH2_API LIBSSH2_CHANNEL *,libssh2_channel_open_ex,(LIBSSH2_SESSION *session, const char *channel_type, unsigned int channel_type_len, unsigned int window_size, unsigned int packet_size, const char *message, unsigned int message_len));
FUNCDEF(LIBSSH2_API LIBSSH2_CHANNEL *,libssh2_channel_direct_tcpip_ex,(LIBSSH2_SESSION *session, const char *host, int port, const char *shost, int sport));
FUNCDEF(LIBSSH2_API LIBSSH2_LISTENER *,libssh2_channel_forward_listen_ex,(LIBSSH2_SESSION *session, const char *host, int port, int *bound_port, int queue_maxsize));
FUNCDEF(LIBSSH2_API int ,libssh2_channel_forward_cancel,(LIBSSH2_LISTENER *listener));
FUNCDEF(LIBSSH2_API LIBSSH2_CHANNEL *,libssh2_channel_forward_accept,(LIBSSH2_LISTENER *listener));
FUNCDEF(LIBSSH2_API int ,libssh2_channel_setenv_ex,(LIBSSH2_CHANNEL *channel, const char *varname, unsigned int varname_len, const char *value, unsigned int value_len));
FUNCDEF(LIBSSH2_API int ,libssh2_channel_request_pty_ex,(LIBSSH2_CHANNEL *channel, const char *term, unsigned int term_len, const char *modes, unsigned int modes_len, int width, int height, int width_px, int height_px));
FUNCDEF(LIBSSH2_API int ,libssh2_channel_x11_req_ex,(LIBSSH2_CHANNEL *channel, int single_connection, const char *auth_proto, const char *auth_cookie, int screen_number));
FUNCDEF(LIBSSH2_API int ,libssh2_channel_process_startup,(LIBSSH2_CHANNEL *channel, const char *request, unsigned int request_len, const char *message, unsigned int message_len));
FUNCDEF(LIBSSH2_API ssize_t ,libssh2_channel_read_ex,(LIBSSH2_CHANNEL *channel, int stream_id, char *buf, size_t buflen));
FUNCDEF(LIBSSH2_API int ,libssh2_poll_channel_read,(LIBSSH2_CHANNEL *channel, int extended));
FUNCDEF(LIBSSH2_API unsigned long ,libssh2_channel_window_read_ex,(LIBSSH2_CHANNEL *channel, unsigned long *read_avail, unsigned long *window_size_initial));
FUNCDEF(LIBSSH2_API unsigned long ,libssh2_channel_receive_window_adjust,(LIBSSH2_CHANNEL *channel, unsigned long adjustment, unsigned char force));
FUNCDEF(LIBSSH2_API ssize_t ,libssh2_channel_write_ex,(LIBSSH2_CHANNEL *channel, int stream_id, const char *buf, size_t buflen));
FUNCDEF(LIBSSH2_API unsigned long ,libssh2_channel_window_write_ex,(LIBSSH2_CHANNEL *channel, unsigned long *window_size_initial));
FUNCDEF(LIBSSH2_API void ,libssh2_session_set_blocking,(LIBSSH2_SESSION* session, int blocking));
FUNCDEF(LIBSSH2_API int ,libssh2_session_get_blocking,(LIBSSH2_SESSION* session));
FUNCDEF(LIBSSH2_API void ,libssh2_channel_set_blocking,(LIBSSH2_CHANNEL *channel, int blocking));
FUNCDEF(LIBSSH2_API void ,libssh2_channel_handle_extended_data,(LIBSSH2_CHANNEL *channel, int ignore_mode));
FUNCDEF(LIBSSH2_API int ,libssh2_channel_handle_extended_data2,(LIBSSH2_CHANNEL *channel, int ignore_mode));
FUNCDEF(LIBSSH2_API int ,libssh2_channel_flush_ex,(LIBSSH2_CHANNEL *channel, int streamid));
FUNCDEF(LIBSSH2_API int ,libssh2_channel_get_exit_status,(LIBSSH2_CHANNEL* channel));
FUNCDEF(LIBSSH2_API int ,libssh2_channel_send_eof,(LIBSSH2_CHANNEL *channel));
FUNCDEF(LIBSSH2_API int ,libssh2_channel_eof,(LIBSSH2_CHANNEL *channel));
FUNCDEF(LIBSSH2_API int ,libssh2_channel_wait_eof,(LIBSSH2_CHANNEL *channel));
FUNCDEF(LIBSSH2_API int ,libssh2_channel_close,(LIBSSH2_CHANNEL *channel));
FUNCDEF(LIBSSH2_API int ,libssh2_channel_wait_closed,(LIBSSH2_CHANNEL *channel));
FUNCDEF(LIBSSH2_API int ,libssh2_channel_free,(LIBSSH2_CHANNEL *channel));
// libssh2_scp_recv is DEPRECATED
//FUNCDEF(LIBSSH2_API LIBSSH2_CHANNEL *,libssh2_scp_recv,(LIBSSH2_SESSION *session, const char *path, struct stat *sb));
FUNCDEF(LIBSSH2_API LIBSSH2_CHANNEL *,libssh2_scp_recv2,(LIBSSH2_SESSION *session, const char *path, libssh2_struct_stat *sb));
FUNCDEF(LIBSSH2_API LIBSSH2_CHANNEL *,libssh2_scp_send_ex,(LIBSSH2_SESSION *session, const char *path, int mode, size_t size, long mtime, long atime));
FUNCDEF(LIBSSH2_API LIBSSH2_CHANNEL *,libssh2_scp_send64,(LIBSSH2_SESSION *session, const char *path, int mode, libssh2_uint64_t size, __int64 mtime, __int64 atime));  // Ghisler: library uses 64-bit time_t also in 32-bit!
FUNCDEF(LIBSSH2_API int ,libssh2_base64_decode,(LIBSSH2_SESSION *session, char **dest, unsigned int *dest_len, const char *src, unsigned int src_len));
FUNCDEF(LIBSSH2_API int ,libssh2_trace,(LIBSSH2_SESSION *session, int bitmask));


/* SFTP *************************************************/
FUNCDEF(LIBSSH2_API LIBSSH2_SFTP *, libssh2_sftp_init, (LIBSSH2_SESSION *session));
FUNCDEF(LIBSSH2_API int, libssh2_sftp_shutdown,(LIBSSH2_SFTP *sftp));
FUNCDEF(LIBSSH2_API unsigned long, libssh2_sftp_last_error,(LIBSSH2_SFTP *sftp));

/* File / Directory Ops */
FUNCDEF(LIBSSH2_API LIBSSH2_SFTP_HANDLE*, libssh2_sftp_open_ex,(LIBSSH2_SFTP *sftp, const char *filename, unsigned int filename_len,unsigned long flags, long mode, int open_type));
FUNCDEF(LIBSSH2_API ssize_t, libssh2_sftp_read,(LIBSSH2_SFTP_HANDLE *handle, char *buffer, size_t buffer_maxlen));
FUNCDEF(LIBSSH2_API int, libssh2_sftp_readdir_ex,(LIBSSH2_SFTP_HANDLE *handle, char *buffer, size_t buffer_maxlen, char *longentry, size_t longentry_maxlen,LIBSSH2_SFTP_ATTRIBUTES *attrs));
FUNCDEF(LIBSSH2_API ssize_t, libssh2_sftp_write,(LIBSSH2_SFTP_HANDLE *handle, const char *buffer, size_t count));
FUNCDEF(LIBSSH2_API int, libssh2_sftp_close_handle,(LIBSSH2_SFTP_HANDLE *handle));
FUNCDEF(LIBSSH2_API void, libssh2_sftp_seek,(LIBSSH2_SFTP_HANDLE *handle, size_t offset));
FUNCDEF(LIBSSH2_API size_t, libssh2_sftp_tell,(LIBSSH2_SFTP_HANDLE *handle));
FUNCDEF(LIBSSH2_API int, libssh2_sftp_fstat_ex,(LIBSSH2_SFTP_HANDLE *handle, LIBSSH2_SFTP_ATTRIBUTES *attrs, int setstat));
FUNCDEF(LIBSSH2_API int, libssh2_sftp_rename_ex,(LIBSSH2_SFTP *sftp,  const char *source_filename,    unsigned int srouce_filename_len,const char *dest_filename,      unsigned int dest_filename_len,long flags));
FUNCDEF(LIBSSH2_API int, libssh2_sftp_unlink_ex,(LIBSSH2_SFTP *sftp, const char *filename, unsigned int filename_len));
FUNCDEF(LIBSSH2_API int, libssh2_sftp_mkdir_ex,(LIBSSH2_SFTP *sftp, const char *path, unsigned int path_len, long mode));
FUNCDEF(LIBSSH2_API int, libssh2_sftp_rmdir_ex,(LIBSSH2_SFTP *sftp, const char *path, unsigned int path_len));
FUNCDEF(LIBSSH2_API int, libssh2_sftp_stat_ex,(LIBSSH2_SFTP *sftp, const char *path, unsigned int path_len, int stat_type, LIBSSH2_SFTP_ATTRIBUTES *attrs));
FUNCDEF(LIBSSH2_API int, libssh2_sftp_symlink_ex,(LIBSSH2_SFTP *sftp, const char *path, unsigned int path_len, char *target, unsigned int target_len, int link_type));

/* Version **************/
FUNCDEF2(LIBSSH2_API const char*, libssh2_version,(int req_version_num));

/* Agent ****************/
FUNCDEF2(LIBSSH2_API LIBSSH2_AGENT*, libssh2_agent_init,(LIBSSH2_SESSION *session));
FUNCDEF2(LIBSSH2_API int, libssh2_agent_connect,(LIBSSH2_AGENT *agent));
FUNCDEF2(LIBSSH2_API int, libssh2_agent_list_identities,(LIBSSH2_AGENT *agent));
FUNCDEF2(LIBSSH2_API int, libssh2_agent_get_identity,(LIBSSH2_AGENT *agent, struct libssh2_agent_publickey **store, struct libssh2_agent_publickey *prev));
FUNCDEF2(LIBSSH2_API int, libssh2_agent_userauth,(LIBSSH2_AGENT *agent, const char *username, struct libssh2_agent_publickey *identity));
FUNCDEF2(LIBSSH2_API int, libssh2_agent_disconnect,(LIBSSH2_AGENT *agent));
FUNCDEF2(LIBSSH2_API void, libssh2_agent_free,(LIBSSH2_AGENT *agent));

#endif

