#ifndef LINUX_WMI_H
#define LINUX_WMI_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct WmiSession WmiSession;

/* 0 on success. On failure, the server's HRESULT when one is known (e.g.
 * 0x80070005 E_ACCESSDENIED, 0x8004100E WBEM_E_INVALID_NAMESPACE, read as a
 * negative int32), otherwise -1; *out_err then holds a message to free with
 * wmi_free_err. */
typedef int32_t wmi_status_t;

typedef uint32_t wmi_auth_flags_t;

/* Creates a session; does no network I/O. */
wmi_status_t wmi_session_new(const char* host, const char* username, const char* password, const char* domain, wmi_auth_flags_t auth_flags, WmiSession** out_sess, char** out_err);

/* Activates WMI on the host and logs in to the namespace (e.g. "root\\cimv2");
 * bad hosts, credentials and namespaces fail here. */
wmi_status_t wmi_namespace_open(WmiSession* sess, const char* ns, char** out_err);

/* Runs a WQL query; *out_json is a JSON array with one object per row.
 * timeout_ms bounds each network read/write (0 = default, 30 s). */
wmi_status_t wmi_exec_query_json(WmiSession* sess, const char* wql, uint32_t timeout_ms, uint8_t** out_json, size_t* out_len, char** out_err);

/* Not yet implemented on the DCOM transport: returns -1 with a message. */
wmi_status_t wmi_exec_method_json(WmiSession* sess, const char* path_or_class, const char* method, const char* in_params_json, uint32_t timeout_ms, uint8_t** out_json, size_t* out_len, char** out_err);

/* Releases the session and the server-side references it holds. */
void wmi_session_free(WmiSession* sess);

void wmi_free_json(uint8_t* ptr, size_t len);

void wmi_free_err(char* ptr);

#ifdef __cplusplus
}
#endif

#endif
