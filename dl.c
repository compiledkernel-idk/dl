/*
 * dl
 * Fast Windows downloader in pure C.
 *
 * Copyright (c) 2026, compiledkernel-idk
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#define SECURITY_WIN32

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <mswsock.h>
#include <mstcpip.h>
#include <sspi.h>
#include <schannel.h>
#include <wincrypt.h>
#include <winternl.h>
#include <strsafe.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stddef.h>
#include <ctype.h>
#include <wctype.h>
#include <math.h>
#include <intrin.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "secur32.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "kernel32.lib")
#pragma comment(lib, "ntdll.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "user32.lib")



#define DL_VERSION_W                L"dl 0.1.0"
#define DL_VERSION_A                "dl 0.1.0"

#ifndef DL_UPDATE_MANIFEST_URL_A
#define DL_UPDATE_MANIFEST_URL_A    "https://github.com/compiledkernel-idk/dl/releases/latest/download/dl-update.txt"
#endif

#ifndef DL_UPDATE_MANIFEST_URL_W
#define DL_UPDATE_MANIFEST_URL_W    L"https://github.com/compiledkernel-idk/dl/releases/latest/download/dl-update.txt"
#endif

#define DL_MAX_URL                  4096
#define DL_MAX_HOST                 512
#define DL_MAX_PATH_UTF8            4096
#define DL_MAX_PORT                 16
#define DL_MAX_HEADER_BLOCK         65536
#define DL_MAX_HEADER_VALUE         4096
#define DL_MAX_FILENAME             512
#define DL_MAX_REDIRECTS            10
#define DL_MAX_SEGMENTS             64
#define DL_MAX_DNS_CACHE            64
#define DL_MAX_ADDRS_PER_HOST       8
#define DL_MAX_ERROR_TEXT           512
#define DL_MAX_PROGRESS_TEXT        2048
#define DL_MAX_STATE_URL            4096
#define DL_MAX_TLS_IO               65536
#define DL_MAX_COMMAND_LINE         32767
#define DL_MIN_BUFFER               (16 * 1024u)
#define DL_DEFAULT_BUFFER           (4 * 1024 * 1024u)
#define DL_SEGMENT_THRESHOLD        (1024ull * 1024ull)
#define DL_SPLIT_THRESHOLD          (8ull * 1024ull * 1024ull)
#define DL_RATE_GRANULARITY_MS      50
#define DL_PROGRESS_INTERVAL_MS     100
#define DL_STATE_INTERVAL_MS        2000
#define DL_TIMEOUT_INTERVAL_MS      1000
#define DL_SEGMENT_TIMEOUT_MS       30000
#define DL_CONNECT_TIMEOUT_MS       10000
#define DL_MAX_RETRIES              10
#define DL_USER_AGENT               "dl/0.1"
#define DL_SIGNATURE_BYTES          4096
#define DL_MAGIC0                   'D'
#define DL_MAGIC1                   'L'
#define DL_MAGIC2                   0x01
#define DL_MAGIC3                   0x00
#define DL_FILE_ALLOCATION_CLASS    ((FILE_INFORMATION_CLASS)19)
#define DL_UPDATE_CHECK_ENV         L"DL_SKIP_AUTO_UPDATE"
#define DL_UPDATE_INTERVAL_SECONDS  (24ull * 60ull * 60ull)
#define DL_UPDATE_STAMP_NAME        L"update-check.bin"
#define DL_INSTALL_DIR_ENV          L"%LOCALAPPDATA%\\Programs\\dl"
#define DL_DATA_DIR_ENV             L"%LOCALAPPDATA%\\dl"

#ifndef ARRAYSIZE
#define ARRAYSIZE(a) (sizeof(a) / sizeof((a)[0]))
#endif

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

#ifndef SP_PROT_TLS1_3_CLIENT
#define SP_PROT_TLS1_3_CLIENT 0x00002000
#endif

#ifndef TLS1_3_VERSION
#define TLS1_3_VERSION 0x0304
#endif



typedef struct _DL_FILE_ALLOCATION_INFORMATION {
    LARGE_INTEGER AllocationSize;
} DL_FILE_ALLOCATION_INFORMATION;

typedef NTSTATUS (NTAPI *PFN_NTSETINFORMATIONFILE)(
    HANDLE,
    PIO_STATUS_BLOCK,
    PVOID,
    ULONG,
    FILE_INFORMATION_CLASS
);

typedef enum URL_SCHEME_TAG {
    URL_SCHEME_HTTP = 0,
    URL_SCHEME_HTTPS = 1
} URL_SCHEME;

typedef enum SEGMENT_STATE_TAG {
    SEGMENT_STATE_IDLE = 0,
    SEGMENT_STATE_RUNNING = 1,
    SEGMENT_STATE_COMPLETE = 2,
    SEGMENT_STATE_FAILED = 3,
    SEGMENT_STATE_STOPPED = 4
} SEGMENT_STATE;

typedef struct URL_PARTS_TAG {
    URL_SCHEME scheme;
    char host[DL_MAX_HOST];
    char path[DL_MAX_PATH_UTF8];
    char host_header[DL_MAX_HOST + DL_MAX_PORT + 8];
    unsigned short port;
} URL_PARTS;

typedef struct CONFIG_TAG {
    char url[DL_MAX_URL];
    WCHAR output_path[MAX_PATH * 4];
    DWORD buffer_size;
    DWORD segment_override;
    BOOL no_resume;
    BOOL insecure;
    BOOL verbose;
    BOOL quiet;
    BOOL show_help;
    BOOL show_version;
    BOOL output_explicit;
    BOOL limit_rate_enabled;
    double limit_rate_bytes_per_sec;
} CONFIG;

typedef struct DNS_CACHE_ENTRY_TAG {
    BOOL occupied;
    char host[DL_MAX_HOST];
    unsigned short port;
    int addr_count;
    int next_index;
    SOCKADDR_STORAGE addrs[DL_MAX_ADDRS_PER_HOST];
    int addr_lens[DL_MAX_ADDRS_PER_HOST];
} DNS_CACHE_ENTRY;

typedef struct TLS_CONNECTION_TAG {
    BOOL active;
    CtxtHandle context;
    BOOL context_initialized;
    SecPkgContext_StreamSizes sizes;
    BYTE incoming[DL_MAX_TLS_IO];
    DWORD incoming_len;
    BYTE plaintext[DL_MAX_TLS_IO];
    DWORD plaintext_len;
    DWORD plaintext_pos;
    BYTE send_buffer[DL_MAX_TLS_IO];
} TLS_CONNECTION;

typedef struct CONNECTION_TAG {
    SOCKET socket_fd;
    URL_PARTS url;
    BOOL use_tls;
    TLS_CONNECTION tls;
    char cache[DL_MAX_HEADER_BLOCK];
    size_t cache_len;
    size_t cache_pos;
    ULONG_PTR owner_segment;
    volatile LONG_PTR *socket_slot;
} CONNECTION;

typedef struct HTTP_RESPONSE_TAG {
    int status_code;
    BOOL chunked;
    BOOL keep_alive;
    BOOL accept_ranges;
    BOOL content_length_known;
    ULONGLONG content_length;
    BOOL content_range_known;
    ULONGLONG content_range_start;
    ULONGLONG content_range_end;
    ULONGLONG content_range_total;
    char location[DL_MAX_HEADER_VALUE];
    char content_disposition[DL_MAX_HEADER_VALUE];
    char connection_value[64];
    char transfer_encoding[64];
    ULONGLONG body_read;
    ULONGLONG chunk_remaining;
    BOOL chunk_done;
    BOOL saw_body_bytes;
    BOOL is_head;
} HTTP_RESPONSE;

typedef struct STATE_SEGMENT_TAG {
    ULONGLONG start;
    ULONGLONG end;
    ULONGLONG downloaded;
    DWORD signature;
} STATE_SEGMENT;

typedef struct SEGMENT_TAG {
    DWORD id;
    volatile LONG state;
    volatile LONG active;
    volatile LONG split_request;
    volatile LONGLONG downloaded;
    volatile LONGLONG range_end;
    volatile LONGLONG current_offset;
    volatile LONGLONG last_progress_qpc;
    volatile LONGLONG last_sample_bytes;
    volatile LONGLONG sample_total_bytes;
    volatile LONG retries;
    volatile LONG split_count;
    volatile LONG_PTR socket_slot;
    ULONGLONG start;
    ULONGLONG original_end;
    ULONGLONG requested_end;
    ULONGLONG expected_size;
    HANDLE thread;
    HANDLE write_event;
    DWORD thread_id;
    double speed_ema;
    BYTE prefix_bytes[DL_SIGNATURE_BYTES];
    DWORD prefix_len;
    BYTE suffix_bytes[DL_SIGNATURE_BYTES];
    DWORD suffix_len;
    BOOL resumed;
    BOOL can_split;
    BOOL range_mode;
    BOOL complete;
    BOOL failed;
    BOOL spawned_child;
} SEGMENT;

typedef struct PROBE_RESULT_TAG {
    char final_url[DL_MAX_URL];
    URL_PARTS parts;
    BOOL size_known;
    ULONGLONG total_size;
    BOOL accept_ranges;
    BOOL chunked;
    WCHAR filename_from_header[DL_MAX_FILENAME];
} PROBE_RESULT;

typedef struct UPDATE_MANIFEST_TAG {
    char version[64];
    char url[DL_MAX_URL];
    char sha256[65];
} UPDATE_MANIFEST;

typedef struct RUNTIME_TAG {
    CONFIG cfg;
    URL_PARTS final_parts;
    PROBE_RESULT probe;
    HANDLE output_file;
    HANDLE stdout_handle;
    HANDLE stderr_handle;
    HANDLE progress_thread;
    HANDLE state_event;
    HANDLE segment_table_lock_event;
    HANDLE process_heap;
    HANDLE token;
    CRITICAL_SECTION print_lock;
    CRITICAL_SECTION state_lock;
    CRITICAL_SECTION rate_lock;
    CRITICAL_SECTION segment_lock;
    SRWLOCK dns_lock;
    LARGE_INTEGER qpc_freq;
    volatile LONG stop_requested;
    volatile LONG fatal_error;
    volatile LONG progress_stop;
    volatile LONG active_threads;
    volatile LONG state_dirty;
    volatile LONG completed_segments;
    volatile LONG split_budget;
    DWORD logical_processors;
    DWORD initial_segments;
    DWORD max_segments;
    DWORD segment_count;
    BOOL vt_enabled;
    BOOL resume_loaded;
    BOOL range_supported;
    BOOL size_known;
    BOOL download_complete;
    ULONGLONG total_size;
    volatile LONGLONG total_downloaded;
    WCHAR error_text[DL_MAX_ERROR_TEXT];
    WCHAR output_path[MAX_PATH * 4];
    WCHAR state_path[(MAX_PATH * 4) + 16];
    WCHAR state_tmp_path[(MAX_PATH * 4) + 20];
    CredHandle schannel_cred;
    BOOL schannel_cred_ready;
    DNS_CACHE_ENTRY dns_cache[DL_MAX_DNS_CACHE];
    SEGMENT segments[DL_MAX_SEGMENTS];
    double rate_tokens;
    LONGLONG rate_last_qpc;
    double total_speed_ema;
    double peak_speed_ema;
    LONGLONG progress_last_qpc;
    LONGLONG progress_last_bytes;
    LONGLONG download_start_qpc;
    DWORD last_progress_chars;
    PFN_NTSETINFORMATIONFILE nt_set_information_file;
} RUNTIME;



static RUNTIME g_dl;
static DWORD g_crc32_table[256];



static void runtime_reset(void);
static BOOL parse_arguments(int argc, WCHAR **argv);
static void print_help(void);
static void print_version(void);
static BOOL initialize_runtime(void);
static void cleanup_runtime(void);
static BOOL probe_target(PROBE_RESULT *probe);
static BOOL parse_url(const char *url, URL_PARTS *parts);
static BOOL determine_output_path(const PROBE_RESULT *probe);
static BOOL prepare_output_file(void);
static BOOL initialize_segments_from_state_or_fresh(void);
static DWORD WINAPI progress_thread_proc(LPVOID context);
static DWORD WINAPI segment_thread_proc(LPVOID context);
static BOOL save_state_file(void);
static BOOL load_state_file(STATE_SEGMENT *state_segments, DWORD *segment_count);
static void mark_fatal_message(const WCHAR *text);
static void mark_fatal_win32(const WCHAR *prefix, DWORD error_code);
static void mark_segment_failure(SEGMENT *segment, const WCHAR *reason);
static BOOL start_initial_segments(void);
static BOOL wait_for_completion(void);
static void finalize_success(void);
static int run_download_job(void);
static int run_install_mode(void);
static int run_apply_update_mode(int argc, WCHAR **argv);
static BOOL maybe_offer_auto_update(void);



static __forceinline char ascii_tolower(char c)
{
    if (c >= 'A' && c <= 'Z') {
        return (char)(c + ('a' - 'A'));
    }
    return c;
}

static int ascii_ieq(const char *a, const char *b)
{
    while (*a && *b) {
        if (ascii_tolower(*a) != ascii_tolower(*b)) {
            return 0;
        }
        ++a;
        ++b;
    }
    return (*a == 0 && *b == 0);
}

static int ascii_nieq(const char *a, const char *b, size_t n)
{
    size_t i;
    for (i = 0; i < n; ++i) {
        if (a[i] == 0 || b[i] == 0) {
            return a[i] == b[i];
        }
        if (ascii_tolower(a[i]) != ascii_tolower(b[i])) {
            return 0;
        }
    }
    return 1;
}

static const char *ascii_stristr(const char *haystack, const char *needle)
{
    size_t needle_len;
    if (haystack == NULL || needle == NULL) {
        return NULL;
    }
    needle_len = strlen(needle);
    if (needle_len == 0) {
        return haystack;
    }
    while (*haystack) {
        if (ascii_nieq(haystack, needle, needle_len)) {
            return haystack;
        }
        ++haystack;
    }
    return NULL;
}

static void safe_copy_a(char *dst, size_t dst_count, const char *src)
{
    if (dst_count == 0) {
        return;
    }
    if (src == NULL) {
        dst[0] = 0;
        return;
    }
    StringCchCopyA(dst, dst_count, src);
}

static void safe_copy_w(WCHAR *dst, size_t dst_count, const WCHAR *src)
{
    if (dst_count == 0) {
        return;
    }
    if (src == NULL) {
        dst[0] = L'\0';
        return;
    }
    StringCchCopyW(dst, dst_count, src);
}

static BOOL utf8_to_wide(const char *src, WCHAR *dst, DWORD dst_count)
{
    int written;
    if (dst_count == 0) {
        return FALSE;
    }
    written = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, src, -1, dst, (int)dst_count);
    if (written > 0) {
        return TRUE;
    }
    written = MultiByteToWideChar(CP_ACP, 0, src, -1, dst, (int)dst_count);
    return (written > 0);
}

static BOOL wide_to_utf8(const WCHAR *src, char *dst, DWORD dst_count)
{
    int written;
    if (dst_count == 0) {
        return FALSE;
    }
    written = WideCharToMultiByte(CP_UTF8, 0, src, -1, dst, (int)dst_count, NULL, NULL);
    return (written > 0);
}

static void format_error_code(DWORD error_code, WCHAR *buffer, DWORD buffer_count)
{
    DWORD result;
    if (buffer_count == 0) {
        return;
    }
    buffer[0] = L'\0';
    result = FormatMessageW(
        FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL,
        error_code,
        0,
        buffer,
        buffer_count,
        NULL);
    if (result == 0) {
        StringCchPrintfW(buffer, buffer_count, L"Win32 error %lu", error_code);
        return;
    }
    while (result > 0 && (buffer[result - 1] == L'\r' || buffer[result - 1] == L'\n' || buffer[result - 1] == L' ')) {
        buffer[result - 1] = L'\0';
        --result;
    }
}

static void write_wide_handle(HANDLE handle, const WCHAR *text)
{
    DWORD mode = 0;
    DWORD written = 0;
    size_t len = 0;
    char utf8[DL_MAX_PROGRESS_TEXT * 4];

    if (text == NULL || handle == NULL || handle == INVALID_HANDLE_VALUE) {
        return;
    }

    StringCchLengthW(text, STRSAFE_MAX_CCH, &len);
    if (GetConsoleMode(handle, &mode)) {
        WriteConsoleW(handle, text, (DWORD)len, &written, NULL);
        return;
    }

    if (WideCharToMultiByte(CP_UTF8, 0, text, -1, utf8, (int)sizeof(utf8), NULL, NULL) > 0) {
        WriteFile(handle, utf8, (DWORD)strlen(utf8), &written, NULL);
    }
}

static void write_stdout(const WCHAR *text)
{
    write_wide_handle(g_dl.stdout_handle, text);
}

static void write_stderr(const WCHAR *text)
{
    write_wide_handle(g_dl.stderr_handle, text);
}

static void log_error(const WCHAR *format, ...)
{
    WCHAR buffer[DL_MAX_PROGRESS_TEXT];
    va_list args;

    EnterCriticalSection(&g_dl.print_lock);
    va_start(args, format);
    StringCchVPrintfW(buffer, ARRAYSIZE(buffer), format, args);
    va_end(args);
    write_stderr(buffer);
    LeaveCriticalSection(&g_dl.print_lock);
}

static BOOL parse_uint64_with_suffix(const WCHAR *text, ULONGLONG *value)
{
    ULONGLONG base = 0;
    ULONGLONG multiplier = 1;
    WCHAR *end = NULL;

    if (text == NULL || value == NULL) {
        return FALSE;
    }

    base = _wcstoui64(text, &end, 10);
    if (end == text) {
        return FALSE;
    }
    if (*end != L'\0') {
        WCHAR c = (WCHAR)towupper(*end);
        if (end[1] != L'\0') {
            return FALSE;
        }
        if (c == L'K') {
            multiplier = 1024ull;
        } else if (c == L'M') {
            multiplier = 1024ull * 1024ull;
        } else if (c == L'G') {
            multiplier = 1024ull * 1024ull * 1024ull;
        } else {
            return FALSE;
        }
    }
    *value = base * multiplier;
    return TRUE;
}

static BOOL has_file_extension_w(const WCHAR *name)
{
    const WCHAR *dot = wcsrchr(name, L'.');
    const WCHAR *slash1 = wcsrchr(name, L'\\');
    const WCHAR *slash2 = wcsrchr(name, L'/');
    const WCHAR *slash = slash1;
    if (slash2 != NULL && (slash == NULL || slash2 > slash)) {
        slash = slash2;
    }
    return (dot != NULL && (slash == NULL || dot > slash) && dot[1] != L'\0');
}

static void sanitize_filename_w(WCHAR *name)
{
    size_t i;
    if (name == NULL) {
        return;
    }
    for (i = 0; name[i] != L'\0'; ++i) {
        switch (name[i]) {
        case L'<':
        case L'>':
        case L':':
        case L'"':
        case L'/':
        case L'\\':
        case L'|':
        case L'?':
        case L'*':
            name[i] = L'_';
            break;
        default:
            break;
        }
    }
    while (i > 0 && (name[i - 1] == L' ' || name[i - 1] == L'.')) {
        name[i - 1] = L'\0';
        --i;
    }
    if (name[0] == L'\0') {
        StringCchCopyW(name, DL_MAX_FILENAME, L"download.bin");
    }
}

static void format_bytes(double bytes, WCHAR *buffer, size_t count)
{
    static const WCHAR *units[] = { L"B", L"KB", L"MB", L"GB", L"TB", L"PB" };
    int unit = 0;
    while (bytes >= 1024.0 && unit < (int)ARRAYSIZE(units) - 1) {
        bytes /= 1024.0;
        ++unit;
    }
    if (unit == 0) {
        StringCchPrintfW(buffer, count, L"%.0f %s", bytes, units[unit]);
    } else {
        StringCchPrintfW(buffer, count, L"%.1f %s", bytes, units[unit]);
    }
}

static void format_eta(double seconds, WCHAR *buffer, size_t count)
{
    if (seconds < 0.5 || !isfinite(seconds)) {
        StringCchCopyW(buffer, count, L"--");
        return;
    }
    if (seconds < 60.0) {
        StringCchPrintfW(buffer, count, L"%.0fs", seconds);
        return;
    }
    if (seconds < 3600.0) {
        StringCchPrintfW(buffer, count, L"%lum %lus",
            (unsigned long)(seconds / 60.0),
            (unsigned long)fmod(seconds, 60.0));
        return;
    }
    StringCchPrintfW(buffer, count, L"%luh %lum",
        (unsigned long)(seconds / 3600.0),
        (unsigned long)fmod(seconds / 60.0, 60.0));
}

static BOOL path_join_w(const WCHAR *left, const WCHAR *right, WCHAR *dst, size_t dst_count)
{
    size_t len = 0;
    if (StringCchCopyW(dst, dst_count, left) != S_OK) {
        return FALSE;
    }
    if (StringCchLengthW(dst, dst_count, &len) != S_OK) {
        return FALSE;
    }
    if (len > 0 && dst[len - 1] != L'\\' && dst[len - 1] != L'/') {
        if (StringCchCatW(dst, dst_count, L"\\") != S_OK) {
            return FALSE;
        }
    }
    return (StringCchCatW(dst, dst_count, right) == S_OK);
}

static BOOL ensure_directory_tree(const WCHAR *path)
{
    WCHAR temp[MAX_PATH * 4];
    size_t i;

    if (path == NULL || path[0] == L'\0') {
        return FALSE;
    }
    safe_copy_w(temp, ARRAYSIZE(temp), path);
    for (i = 0; temp[i] != L'\0'; ++i) {
        if ((temp[i] == L'\\' || temp[i] == L'/') && i > 0 && temp[i - 1] != L':') {
            WCHAR saved = temp[i];
            temp[i] = L'\0';
            if (temp[0] != L'\0' && GetFileAttributesW(temp) == INVALID_FILE_ATTRIBUTES) {
                if (!CreateDirectoryW(temp, NULL) && GetLastError() != ERROR_ALREADY_EXISTS) {
                    return FALSE;
                }
            }
            temp[i] = saved;
        }
    }
    if (GetFileAttributesW(temp) == INVALID_FILE_ATTRIBUTES) {
        if (!CreateDirectoryW(temp, NULL) && GetLastError() != ERROR_ALREADY_EXISTS) {
            return FALSE;
        }
    }
    return TRUE;
}

static BOOL expand_env_path(const WCHAR *spec, WCHAR *out_path, DWORD out_count)
{
    DWORD written = ExpandEnvironmentStringsW(spec, out_path, out_count);
    return (written > 0 && written < out_count);
}

static BOOL get_self_path(WCHAR *path, DWORD path_count)
{
    DWORD written = GetModuleFileNameW(NULL, path, path_count);
    return (written > 0 && written < path_count);
}

static BOOL get_install_dir(WCHAR *path, DWORD path_count)
{
    return expand_env_path(DL_INSTALL_DIR_ENV, path, path_count);
}

static BOOL get_data_dir(WCHAR *path, DWORD path_count)
{
    return expand_env_path(DL_DATA_DIR_ENV, path, path_count);
}

static BOOL get_data_path(const WCHAR *leaf, WCHAR *path, DWORD path_count)
{
    WCHAR dir[MAX_PATH * 4];
    if (!get_data_dir(dir, ARRAYSIZE(dir))) {
        return FALSE;
    }
    if (!ensure_directory_tree(dir)) {
        return FALSE;
    }
    return path_join_w(dir, leaf, path, path_count);
}

static BOOL append_command_line_char(WCHAR *command_line, size_t count, WCHAR ch)
{
    size_t len = 0;
    if (StringCchLengthW(command_line, count, &len) != S_OK) {
        return FALSE;
    }
    if ((len + 2) > count) {
        return FALSE;
    }
    command_line[len] = ch;
    command_line[len + 1] = L'\0';
    return TRUE;
}

static BOOL append_command_line_text(WCHAR *command_line, size_t count, const WCHAR *text)
{
    return (StringCchCatW(command_line, count, text) == S_OK);
}

static BOOL append_command_line_arg(WCHAR *command_line, size_t count, const WCHAR *arg)
{
    size_t i;
    size_t backslashes = 0;
    BOOL needs_quotes;

    if (arg == NULL) {
        arg = L"";
    }
    if (command_line[0] != L'\0' && !append_command_line_char(command_line, count, L' ')) {
        return FALSE;
    }
    needs_quotes = (*arg == L'\0' || wcspbrk(arg, L" \t\"") != NULL);
    if (!needs_quotes) {
        return append_command_line_text(command_line, count, arg);
    }
    if (!append_command_line_char(command_line, count, L'"')) {
        return FALSE;
    }
    for (i = 0; arg[i] != L'\0'; ++i) {
        if (arg[i] == L'\\') {
            ++backslashes;
            continue;
        }
        if (arg[i] == L'"') {
            size_t j;
            for (j = 0; j < (backslashes * 2) + 1; ++j) {
                if (!append_command_line_char(command_line, count, L'\\')) {
                    return FALSE;
                }
            }
            if (!append_command_line_char(command_line, count, L'"')) {
                return FALSE;
            }
            backslashes = 0;
            continue;
        }
        while (backslashes > 0) {
            if (!append_command_line_char(command_line, count, L'\\')) {
                return FALSE;
            }
            --backslashes;
        }
        if (!append_command_line_char(command_line, count, arg[i])) {
            return FALSE;
        }
    }
    while (backslashes > 0) {
        if (!append_command_line_char(command_line, count, L'\\')) {
            return FALSE;
        }
        if (!append_command_line_char(command_line, count, L'\\')) {
            return FALSE;
        }
        --backslashes;
    }
    return append_command_line_char(command_line, count, L'"');
}

static BOOL launch_process_wait(const WCHAR *application_name, WCHAR *command_line, DWORD creation_flags, DWORD *exit_code)
{
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;
    DWORD process_exit = 1;

    ZeroMemory(&si, sizeof(si));
    ZeroMemory(&pi, sizeof(pi));
    si.cb = sizeof(si);
    if (!CreateProcessW(application_name, command_line, NULL, NULL, FALSE, creation_flags, NULL, NULL, &si, &pi)) {
        return FALSE;
    }
    WaitForSingleObject(pi.hProcess, INFINITE);
    GetExitCodeProcess(pi.hProcess, &process_exit);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    if (exit_code != NULL) {
        *exit_code = process_exit;
    }
    return TRUE;
}

static BOOL launch_process_detached(const WCHAR *application_name, WCHAR *command_line, DWORD creation_flags)
{
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;

    ZeroMemory(&si, sizeof(si));
    ZeroMemory(&pi, sizeof(pi));
    si.cb = sizeof(si);
    if (!CreateProcessW(application_name, command_line, NULL, NULL, FALSE, creation_flags, NULL, NULL, &si, &pi)) {
        return FALSE;
    }
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return TRUE;
}

static BOOL create_temp_named_path(const WCHAR *prefix, const WCHAR *extension, WCHAR *path, DWORD path_count)
{
    WCHAR temp_dir[MAX_PATH * 4];
    WCHAR temp_file[MAX_PATH * 4];
    WCHAR *dot;

    if (GetTempPathW(ARRAYSIZE(temp_dir), temp_dir) == 0) {
        return FALSE;
    }
    if (!GetTempFileNameW(temp_dir, prefix, 0, temp_file)) {
        return FALSE;
    }
    DeleteFileW(temp_file);
    if (extension != NULL && extension[0] != L'\0') {
        dot = wcsrchr(temp_file, L'.');
        if (dot != NULL) {
            *dot = L'\0';
        }
        return (StringCchPrintfW(path, path_count, L"%s%s", temp_file, extension) == S_OK);
    }
    safe_copy_w(path, path_count, temp_file);
    return TRUE;
}

static BOOL download_url_via_subprocess(const WCHAR *url, const WCHAR *output_path)
{
    WCHAR self_path[MAX_PATH * 4];
    WCHAR command_line[DL_MAX_COMMAND_LINE];
    DWORD exit_code = 1;
    WCHAR old_skip[8];
    DWORD old_len;
    BOOL ok;

    if (!get_self_path(self_path, ARRAYSIZE(self_path))) {
        return FALSE;
    }
    command_line[0] = L'\0';
    if (!append_command_line_arg(command_line, ARRAYSIZE(command_line), self_path) ||
        !append_command_line_arg(command_line, ARRAYSIZE(command_line), url) ||
        !append_command_line_arg(command_line, ARRAYSIZE(command_line), L"-o") ||
        !append_command_line_arg(command_line, ARRAYSIZE(command_line), output_path) ||
        !append_command_line_arg(command_line, ARRAYSIZE(command_line), L"-q") ||
        !append_command_line_arg(command_line, ARRAYSIZE(command_line), L"--no-resume")) {
        return FALSE;
    }
    old_len = GetEnvironmentVariableW(DL_UPDATE_CHECK_ENV, old_skip, ARRAYSIZE(old_skip));
    SetEnvironmentVariableW(DL_UPDATE_CHECK_ENV, L"1");
    ok = launch_process_wait(self_path, command_line, CREATE_NO_WINDOW, &exit_code);
    if (old_len > 0 && old_len < ARRAYSIZE(old_skip)) {
        SetEnvironmentVariableW(DL_UPDATE_CHECK_ENV, old_skip);
    } else {
        SetEnvironmentVariableW(DL_UPDATE_CHECK_ENV, NULL);
    }
    return (ok && exit_code == 0);
}

static BOOL read_entire_file(const WCHAR *path, BYTE **buffer_out, DWORD *size_out)
{
    HANDLE file = INVALID_HANDLE_VALUE;
    LARGE_INTEGER size;
    BYTE *buffer = NULL;
    DWORD read_bytes = 0;

    *buffer_out = NULL;
    *size_out = 0;
    file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) {
        return FALSE;
    }
    if (!GetFileSizeEx(file, &size) || size.QuadPart < 0 || size.QuadPart > (LONGLONG)(64 * 1024 * 1024)) {
        CloseHandle(file);
        return FALSE;
    }
    buffer = (BYTE *)VirtualAlloc(NULL, (SIZE_T)size.QuadPart + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (buffer == NULL) {
        CloseHandle(file);
        return FALSE;
    }
    if (!ReadFile(file, buffer, (DWORD)size.QuadPart, &read_bytes, NULL) || read_bytes != (DWORD)size.QuadPart) {
        CloseHandle(file);
        VirtualFree(buffer, 0, MEM_RELEASE);
        return FALSE;
    }
    buffer[size.QuadPart] = 0;
    CloseHandle(file);
    *buffer_out = buffer;
    *size_out = (DWORD)size.QuadPart;
    return TRUE;
}

static char *trim_ascii_line(char *text)
{
    char *end;
    while (*text != 0 && isspace((unsigned char)*text)) {
        ++text;
    }
    end = text + strlen(text);
    while (end > text && isspace((unsigned char)end[-1])) {
        --end;
        *end = 0;
    }
    return text;
}

static BOOL parse_update_manifest_buffer(char *buffer, UPDATE_MANIFEST *manifest)
{
    char *cursor = buffer;

    ZeroMemory(manifest, sizeof(*manifest));
    while (cursor != NULL && *cursor != 0) {
        char *line = cursor;
        char *next = strchr(cursor, '\n');
        char *key;
        char *value;
        if (next != NULL) {
            *next = 0;
            cursor = next + 1;
        } else {
            cursor = NULL;
        }
        line = trim_ascii_line(line);
        if (line[0] == 0 || line[0] == '#') {
            continue;
        }
        key = line;
        value = strchr(line, '=');
        if (value == NULL) {
            continue;
        }
        *value++ = 0;
        key = trim_ascii_line(key);
        value = trim_ascii_line(value);
        if (ascii_ieq(key, "version")) {
            safe_copy_a(manifest->version, ARRAYSIZE(manifest->version), value);
        } else if (ascii_ieq(key, "url")) {
            safe_copy_a(manifest->url, ARRAYSIZE(manifest->url), value);
        } else if (ascii_ieq(key, "sha256")) {
            safe_copy_a(manifest->sha256, ARRAYSIZE(manifest->sha256), value);
        }
    }
    return (manifest->version[0] != 0 && manifest->url[0] != 0);
}

static BOOL load_update_manifest(UPDATE_MANIFEST *manifest)
{
    WCHAR temp_path[MAX_PATH * 4];
    BYTE *buffer = NULL;
    DWORD size = 0;
    BOOL ok = FALSE;

    if (DL_UPDATE_MANIFEST_URL_A[0] == 0) {
        return FALSE;
    }
    if (!create_temp_named_path(L"dlu", L".txt", temp_path, ARRAYSIZE(temp_path))) {
        return FALSE;
    }
    if (!download_url_via_subprocess(DL_UPDATE_MANIFEST_URL_W, temp_path)) {
        DeleteFileW(temp_path);
        return FALSE;
    }
    if (!read_entire_file(temp_path, &buffer, &size)) {
        DeleteFileW(temp_path);
        return FALSE;
    }
    ok = parse_update_manifest_buffer((char *)buffer, manifest);
    VirtualFree(buffer, 0, MEM_RELEASE);
    DeleteFileW(temp_path);
    return ok;
}

static int compare_version_strings(const char *left, const char *right)
{
    const char *a = left;
    const char *b = right;

    for (;;) {
        unsigned long long av = 0;
        unsigned long long bv = 0;

        while (*a != 0 && !isdigit((unsigned char)*a)) {
            ++a;
        }
        while (*b != 0 && !isdigit((unsigned char)*b)) {
            ++b;
        }
        while (*a != 0 && isdigit((unsigned char)*a)) {
            av = (av * 10ull) + (unsigned long long)(*a - '0');
            ++a;
        }
        while (*b != 0 && isdigit((unsigned char)*b)) {
            bv = (bv * 10ull) + (unsigned long long)(*b - '0');
            ++b;
        }
        if (av < bv) {
            return -1;
        }
        if (av > bv) {
            return 1;
        }
        if (*a == 0 && *b == 0) {
            break;
        }
    }
    return 0;
}

static BOOL compute_file_sha256_hex(const WCHAR *path, char *hex, DWORD hex_count)
{
    HANDLE file = INVALID_HANDLE_VALUE;
    HCRYPTPROV provider = 0;
    HCRYPTHASH hash = 0;
    BYTE *buffer = NULL;
    BOOL ok = FALSE;
    BYTE digest[32];
    DWORD digest_len = sizeof(digest);
    DWORD read_bytes = 0;
    DWORD i;

    if (hex_count < 65) {
        return FALSE;
    }
    file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) {
        return FALSE;
    }
    if (!CryptAcquireContextW(&provider, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        CloseHandle(file);
        return FALSE;
    }
    if (!CryptCreateHash(provider, CALG_SHA_256, 0, 0, &hash)) {
        CloseHandle(file);
        CryptReleaseContext(provider, 0);
        return FALSE;
    }
    buffer = (BYTE *)VirtualAlloc(NULL, 1024 * 1024, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (buffer == NULL) {
        CloseHandle(file);
        CryptDestroyHash(hash);
        CryptReleaseContext(provider, 0);
        return FALSE;
    }
    for (;;) {
        if (!ReadFile(file, buffer, 1024 * 1024, &read_bytes, NULL)) {
            goto cleanup_hash;
        }
        if (read_bytes == 0) {
            break;
        }
        if (!CryptHashData(hash, buffer, read_bytes, 0)) {
            goto cleanup_hash;
        }
    }
    if (!CryptGetHashParam(hash, HP_HASHVAL, digest, &digest_len, 0) || digest_len != sizeof(digest)) {
        goto cleanup_hash;
    }
    for (i = 0; i < digest_len; ++i) {
        static const char digits[] = "0123456789abcdef";
        hex[i * 2] = digits[(digest[i] >> 4) & 0x0F];
        hex[(i * 2) + 1] = digits[digest[i] & 0x0F];
    }
    hex[64] = 0;
    ok = TRUE;

cleanup_hash:
    if (buffer != NULL) {
        VirtualFree(buffer, 0, MEM_RELEASE);
    }
    CloseHandle(file);
    CryptDestroyHash(hash);
    CryptReleaseContext(provider, 0);
    return ok;
}

static ULONGLONG filetime_now_utc(void)
{
    FILETIME ft;
    ULARGE_INTEGER value;
    GetSystemTimeAsFileTime(&ft);
    value.LowPart = ft.dwLowDateTime;
    value.HighPart = ft.dwHighDateTime;
    return value.QuadPart;
}

static BOOL read_u64_file(const WCHAR *path, ULONGLONG *value)
{
    HANDLE file = INVALID_HANDLE_VALUE;
    DWORD read_bytes = 0;
    ULONGLONG temp = 0;

    file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) {
        return FALSE;
    }
    if (!ReadFile(file, &temp, sizeof(temp), &read_bytes, NULL) || read_bytes != sizeof(temp)) {
        CloseHandle(file);
        return FALSE;
    }
    CloseHandle(file);
    *value = temp;
    return TRUE;
}

static BOOL write_u64_file(const WCHAR *path, ULONGLONG value)
{
    HANDLE file = INVALID_HANDLE_VALUE;
    DWORD written = 0;

    file = CreateFileW(path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) {
        return FALSE;
    }
    if (!WriteFile(file, &value, sizeof(value), &written, NULL) || written != sizeof(value)) {
        CloseHandle(file);
        return FALSE;
    }
    FlushFileBuffers(file);
    CloseHandle(file);
    return TRUE;
}

static BOOL should_check_for_updates(void)
{
    WCHAR stamp_path[MAX_PATH * 4];
    ULONGLONG now = filetime_now_utc();
    ULONGLONG last = 0;
    ULONGLONG interval = DL_UPDATE_INTERVAL_SECONDS * 10000000ull;

    if (GetEnvironmentVariableW(DL_UPDATE_CHECK_ENV, NULL, 0) > 0) {
        return FALSE;
    }
    if (!get_data_path(DL_UPDATE_STAMP_NAME, stamp_path, ARRAYSIZE(stamp_path))) {
        return TRUE;
    }
    if (!read_u64_file(stamp_path, &last) || now < last || (now - last) >= interval) {
        write_u64_file(stamp_path, now);
        return TRUE;
    }
    return FALSE;
}

static BOOL stdin_is_console(void)
{
    DWORD mode = 0;
    HANDLE input = GetStdHandle(STD_INPUT_HANDLE);
    return (input != NULL && input != INVALID_HANDLE_VALUE && GetConsoleMode(input, &mode));
}

static BOOL prompt_yes_no(const WCHAR *prompt, BOOL default_yes)
{
    HANDLE input = GetStdHandle(STD_INPUT_HANDLE);
    WCHAR buffer[32];
    DWORD read_chars = 0;
    DWORD i;

    if (!stdin_is_console()) {
        return FALSE;
    }
    write_stdout(prompt);
    if (!ReadConsoleW(input, buffer, ARRAYSIZE(buffer) - 1, &read_chars, NULL)) {
        return FALSE;
    }
    buffer[min(read_chars, ARRAYSIZE(buffer) - 1)] = L'\0';
    for (i = 0; buffer[i] != L'\0'; ++i) {
        WCHAR ch = (WCHAR)towlower(buffer[i]);
        if (ch == L'y') {
            return TRUE;
        }
        if (ch == L'n') {
            return FALSE;
        }
    }
    return default_yes;
}

static void normalize_path_token(WCHAR *text)
{
    size_t len = wcslen(text);
    while (len > 0 && (text[len - 1] == L' ' || text[len - 1] == L'\\' || text[len - 1] == L'/')) {
        text[len - 1] = L'\0';
        --len;
    }
    while (*text == L' ') {
        memmove(text, text + 1, (wcslen(text + 1) + 1) * sizeof(WCHAR));
    }
}

static BOOL path_value_contains_dir(const WCHAR *path_value, const WCHAR *dir)
{
    WCHAR candidate[MAX_PATH * 4];
    WCHAR target[MAX_PATH * 4];
    const WCHAR *cursor = path_value;

    safe_copy_w(target, ARRAYSIZE(target), dir);
    normalize_path_token(target);
    while (*cursor != L'\0') {
        size_t len = 0;
        const WCHAR *semi = wcschr(cursor, L';');
        if (semi == NULL) {
            semi = cursor + wcslen(cursor);
        }
        len = (size_t)(semi - cursor);
        if (len >= ARRAYSIZE(candidate)) {
            len = ARRAYSIZE(candidate) - 1;
        }
        memcpy(candidate, cursor, len * sizeof(WCHAR));
        candidate[len] = L'\0';
        normalize_path_token(candidate);
        if (_wcsicmp(candidate, target) == 0) {
            return TRUE;
        }
        cursor = (*semi == L';') ? semi + 1 : semi;
    }
    return FALSE;
}

static BOOL append_user_path_entry(const WCHAR *dir)
{
    HKEY key = NULL;
    LONG rc;
    DWORD type = REG_EXPAND_SZ;
    DWORD size = 0;
    WCHAR *current = NULL;
    WCHAR *updated = NULL;
    BOOL ok = FALSE;
    ULONG_PTR ignored = 0;

    rc = RegOpenKeyExW(HKEY_CURRENT_USER, L"Environment", 0, KEY_QUERY_VALUE | KEY_SET_VALUE, &key);
    if (rc != ERROR_SUCCESS) {
        return FALSE;
    }

    rc = RegQueryValueExW(key, L"Path", NULL, &type, NULL, &size);
    if (rc == ERROR_FILE_NOT_FOUND) {
        size = sizeof(WCHAR);
        current = (WCHAR *)VirtualAlloc(NULL, size + sizeof(WCHAR), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (current == NULL) {
            goto cleanup_path;
        }
        current[0] = L'\0';
        type = REG_EXPAND_SZ;
    } else if (rc == ERROR_SUCCESS) {
        current = (WCHAR *)VirtualAlloc(NULL, size + sizeof(WCHAR), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (current == NULL) {
            goto cleanup_path;
        }
        if (RegQueryValueExW(key, L"Path", NULL, &type, (BYTE *)current, &size) != ERROR_SUCCESS) {
            goto cleanup_path;
        }
        current[size / sizeof(WCHAR)] = L'\0';
    } else {
        goto cleanup_path;
    }

    if (path_value_contains_dir(current, dir)) {
        ok = TRUE;
        goto cleanup_path;
    }

    {
        size_t current_len = wcslen(current);
        size_t dir_len = wcslen(dir);
        size_t total = current_len + dir_len + 2;
        updated = (WCHAR *)VirtualAlloc(NULL, total * sizeof(WCHAR), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (updated == NULL) {
            goto cleanup_path;
        }
        updated[0] = L'\0';
        if (current_len > 0) {
            StringCchCopyW(updated, total, current);
            if (updated[current_len - 1] != L';') {
                StringCchCatW(updated, total, L";");
            }
        }
        StringCchCatW(updated, total, dir);
    }

    if (RegSetValueExW(key, L"Path", 0, type == REG_SZ ? REG_SZ : REG_EXPAND_SZ,
        (const BYTE *)updated, (DWORD)((wcslen(updated) + 1) * sizeof(WCHAR))) != ERROR_SUCCESS) {
        goto cleanup_path;
    }
    SendMessageTimeoutW(HWND_BROADCAST, WM_SETTINGCHANGE, 0, (LPARAM)L"Environment", SMTO_ABORTIFHUNG, 5000, &ignored);
    ok = TRUE;

cleanup_path:
    if (current != NULL) {
        VirtualFree(current, 0, MEM_RELEASE);
    }
    if (updated != NULL) {
        VirtualFree(updated, 0, MEM_RELEASE);
    }
    if (key != NULL) {
        RegCloseKey(key);
    }
    return ok;
}

static BOOL install_self_copy(BOOL quiet)
{
    WCHAR install_dir[MAX_PATH * 4];
    WCHAR self_path[MAX_PATH * 4];
    WCHAR target_path[MAX_PATH * 4];
    WCHAR line[DL_MAX_PROGRESS_TEXT];

    if (!get_install_dir(install_dir, ARRAYSIZE(install_dir))) {
        mark_fatal_message(L"failed to resolve install directory");
        return FALSE;
    }
    if (!ensure_directory_tree(install_dir)) {
        mark_fatal_win32(L"failed to create install directory", GetLastError());
        return FALSE;
    }
    if (!get_self_path(self_path, ARRAYSIZE(self_path))) {
        mark_fatal_message(L"failed to locate running executable");
        return FALSE;
    }
    if (!path_join_w(install_dir, L"dl.exe", target_path, ARRAYSIZE(target_path))) {
        mark_fatal_message(L"failed to build install path");
        return FALSE;
    }
    if (_wcsicmp(self_path, target_path) != 0) {
        if (!CopyFileW(self_path, target_path, FALSE)) {
            mark_fatal_win32(L"failed to copy executable", GetLastError());
            return FALSE;
        }
    }
    if (!append_user_path_entry(install_dir)) {
        mark_fatal_message(L"installed dl but failed to update user PATH");
        return FALSE;
    }
    if (!quiet) {
        StringCchPrintfW(line, ARRAYSIZE(line),
            L"installed to %s\nPATH updated for future shells\n",
            target_path);
        write_stdout(line);
    }
    return TRUE;
}

static BOOL apply_update_from_manifest(const UPDATE_MANIFEST *manifest, const WCHAR *relaunch_command)
{
    WCHAR payload_path[MAX_PATH * 4];
    WCHAR self_path[MAX_PATH * 4];
    WCHAR helper_path[MAX_PATH * 4];
    WCHAR url_w[DL_MAX_URL];
    WCHAR command_line[DL_MAX_COMMAND_LINE];
    WCHAR pid_text[32];
    char actual_sha256[65];

    if (!utf8_to_wide(manifest->url, url_w, ARRAYSIZE(url_w))) {
        return FALSE;
    }
    if (!create_temp_named_path(L"dlu", L".exe", payload_path, ARRAYSIZE(payload_path))) {
        return FALSE;
    }
    if (!download_url_via_subprocess(url_w, payload_path)) {
        DeleteFileW(payload_path);
        return FALSE;
    }
    if (manifest->sha256[0] != 0) {
        if (!compute_file_sha256_hex(payload_path, actual_sha256, ARRAYSIZE(actual_sha256)) ||
            !ascii_ieq(actual_sha256, manifest->sha256)) {
            DeleteFileW(payload_path);
            return FALSE;
        }
    }
    if (!get_self_path(self_path, ARRAYSIZE(self_path))) {
        DeleteFileW(payload_path);
        return FALSE;
    }
    if (!create_temp_named_path(L"dlu", L".exe", helper_path, ARRAYSIZE(helper_path))) {
        DeleteFileW(payload_path);
        return FALSE;
    }
    if (!CopyFileW(self_path, helper_path, FALSE)) {
        DeleteFileW(payload_path);
        return FALSE;
    }

    command_line[0] = L'\0';
    StringCchPrintfW(pid_text, ARRAYSIZE(pid_text), L"%lu", GetCurrentProcessId());
    if (!append_command_line_arg(command_line, ARRAYSIZE(command_line), helper_path) ||
        !append_command_line_arg(command_line, ARRAYSIZE(command_line), L"--apply-update") ||
        !append_command_line_arg(command_line, ARRAYSIZE(command_line), self_path) ||
        !append_command_line_arg(command_line, ARRAYSIZE(command_line), payload_path) ||
        !append_command_line_arg(command_line, ARRAYSIZE(command_line), pid_text)) {
        DeleteFileW(payload_path);
        return FALSE;
    }
    if (relaunch_command != NULL && relaunch_command[0] != L'\0') {
        if (!append_command_line_arg(command_line, ARRAYSIZE(command_line), relaunch_command)) {
            DeleteFileW(payload_path);
            return FALSE;
        }
    }
    if (!launch_process_detached(helper_path, command_line, CREATE_NO_WINDOW)) {
        DeleteFileW(payload_path);
        return FALSE;
    }
    return TRUE;
}

static BOOL maybe_offer_auto_update(void)
{
    UPDATE_MANIFEST manifest;
    WCHAR version_w[64];
    WCHAR prompt[DL_MAX_PROGRESS_TEXT];

    if (g_dl.cfg.quiet || !stdin_is_console() || !should_check_for_updates()) {
        return FALSE;
    }
    if (!load_update_manifest(&manifest)) {
        return FALSE;
    }
    if (compare_version_strings(DL_VERSION_A, manifest.version) >= 0) {
        return FALSE;
    }
    if (!utf8_to_wide(manifest.version, version_w, ARRAYSIZE(version_w))) {
        safe_copy_w(version_w, ARRAYSIZE(version_w), L"new build");
    }
    StringCchPrintfW(prompt, ARRAYSIZE(prompt), L"\n%s is out. update now? [Y/n] ", version_w);
    if (!prompt_yes_no(prompt, TRUE)) {
        write_stdout(L"\n");
        return FALSE;
    }
    write_stdout(L"\nupdating dl...\n");
    if (!apply_update_from_manifest(&manifest, GetCommandLineW())) {
        log_error(L"update failed, keeping current build\n");
        return FALSE;
    }
    return TRUE;
}

static LONGLONG qpc_now(void)
{
    LARGE_INTEGER qpc;
    QueryPerformanceCounter(&qpc);
    return qpc.QuadPart;
}

static double qpc_seconds(LONGLONG delta)
{
    return (double)delta / (double)g_dl.qpc_freq.QuadPart;
}

static DWORD auto_segment_count(ULONGLONG total_size)
{
    if (total_size < (16ull * 1024ull * 1024ull)) {
        return 4;
    }
    if (total_size < (128ull * 1024ull * 1024ull)) {
        return 8;
    }
    if (total_size < (512ull * 1024ull * 1024ull)) {
        return 16;
    }
    if (total_size < (1024ull * 1024ull * 1024ull)) {
        return 24;
    }
    if (total_size < (4ull * 1024ull * 1024ull * 1024ull)) {
        return 48;
    }
    return 64;
}

static DWORD initial_segment_target(void)
{
    DWORD count = g_dl.cfg.segment_override ? g_dl.cfg.segment_override : auto_segment_count(g_dl.total_size);
    if (count > DL_MAX_SEGMENTS) {
        count = DL_MAX_SEGMENTS;
    }
    if (count == 0) {
        count = 1;
    }
    return count;
}

static void crc32_init(void)
{
    DWORD i;
    for (i = 0; i < 256; ++i) {
        DWORD crc = i;
        DWORD j;
        for (j = 0; j < 8; ++j) {
            crc = (crc >> 1) ^ (0xEDB88320u & (DWORD)(-(LONG)(crc & 1)));
        }
        g_crc32_table[i] = crc;
    }
}

static DWORD crc32_update(DWORD crc, const BYTE *data, size_t len)
{
    size_t i;
    crc = ~crc;
    for (i = 0; i < len; ++i) {
        crc = g_crc32_table[(crc ^ data[i]) & 0xFFu] ^ (crc >> 8);
    }
    return ~crc;
}

static DWORD segment_signature_crc_parts(
    const BYTE *prefix,
    DWORD prefix_len,
    const BYTE *suffix,
    DWORD suffix_len,
    ULONGLONG downloaded)
{
    DWORD crc = 0;
    DWORD overlap = 0;

    if (downloaded == 0) {
        return 0;
    }

    crc = crc32_update(0, prefix, prefix_len);
    if ((ULONGLONG)prefix_len + (ULONGLONG)suffix_len > downloaded) {
        overlap = (DWORD)(((ULONGLONG)prefix_len + (ULONGLONG)suffix_len) - downloaded);
        if (overlap > suffix_len) {
            overlap = suffix_len;
        }
    }
    if (suffix_len > overlap) {
        crc = crc32_update(crc, suffix + overlap, suffix_len - overlap);
    }
    return crc;
}

static void segment_signature_update(SEGMENT *segment, const BYTE *data, DWORD len)
{
    DWORD copy_len;
    if (segment == NULL || data == NULL || len == 0) {
        return;
    }

    if (segment->prefix_len < DL_SIGNATURE_BYTES) {
        copy_len = DL_SIGNATURE_BYTES - segment->prefix_len;
        if (copy_len > len) {
            copy_len = len;
        }
        CopyMemory(segment->prefix_bytes + segment->prefix_len, data, copy_len);
        segment->prefix_len += copy_len;
    }

    if (len >= DL_SIGNATURE_BYTES) {
        CopyMemory(segment->suffix_bytes, data + (len - DL_SIGNATURE_BYTES), DL_SIGNATURE_BYTES);
        segment->suffix_len = DL_SIGNATURE_BYTES;
    } else {
        if (segment->suffix_len + len <= DL_SIGNATURE_BYTES) {
            CopyMemory(segment->suffix_bytes + segment->suffix_len, data, len);
            segment->suffix_len += len;
        } else {
            DWORD overflow = (segment->suffix_len + len) - DL_SIGNATURE_BYTES;
            MoveMemory(segment->suffix_bytes, segment->suffix_bytes + overflow, segment->suffix_len - overflow);
            CopyMemory(segment->suffix_bytes + (segment->suffix_len - overflow), data, len);
            segment->suffix_len = DL_SIGNATURE_BYTES;
        }
    }
}

static DWORD segment_signature_finalize(const SEGMENT *segment)
{
    if (segment == NULL) {
        return 0;
    }
    return segment_signature_crc_parts(
        segment->prefix_bytes,
        segment->prefix_len,
        segment->suffix_bytes,
        segment->suffix_len,
        (ULONGLONG)segment->downloaded);
}

static BOOL read_file_range_exact(HANDLE file, ULONGLONG offset, BYTE *buffer, DWORD length)
{
    OVERLAPPED ovl;
    DWORD read_bytes = 0;

    if (file == NULL || file == INVALID_HANDLE_VALUE || buffer == NULL || length == 0) {
        return FALSE;
    }

    ZeroMemory(&ovl, sizeof(ovl));
    ovl.Offset = (DWORD)(offset & 0xFFFFFFFFu);
    ovl.OffsetHigh = (DWORD)(offset >> 32);
    if (!ReadFile(file, buffer, length, NULL, &ovl)) {
        DWORD error = GetLastError();
        if (error != ERROR_IO_PENDING) {
            return FALSE;
        }
        if (!GetOverlappedResult(file, &ovl, &read_bytes, TRUE)) {
            return FALSE;
        }
    } else {
        read_bytes = length;
    }
    return (read_bytes == length);
}

static BOOL segment_load_existing_signature(HANDLE file, SEGMENT *segment, ULONGLONG downloaded)
{
    DWORD prefix_len;
    DWORD suffix_len;

    if (segment == NULL) {
        return FALSE;
    }
    segment->prefix_len = 0;
    segment->suffix_len = 0;
    if (downloaded == 0) {
        return TRUE;
    }

    prefix_len = (DWORD)((downloaded < DL_SIGNATURE_BYTES) ? downloaded : DL_SIGNATURE_BYTES);
    if (!read_file_range_exact(file, segment->start, segment->prefix_bytes, prefix_len)) {
        return FALSE;
    }
    segment->prefix_len = prefix_len;

    suffix_len = (DWORD)((downloaded < DL_SIGNATURE_BYTES) ? downloaded : DL_SIGNATURE_BYTES);
    if (!read_file_range_exact(file, (segment->start + downloaded) - suffix_len, segment->suffix_bytes, suffix_len)) {
        return FALSE;
    }
    segment->suffix_len = suffix_len;
    return TRUE;
}

static BOOL verify_segment_signature(HANDLE file, SEGMENT *segment, ULONGLONG downloaded, DWORD expected_signature)
{
    if (expected_signature == 0) {
        return TRUE;
    }
    if (file == NULL || file == INVALID_HANDLE_VALUE || segment == NULL) {
        return FALSE;
    }
    if (!segment_load_existing_signature(file, segment, downloaded)) {
        return FALSE;
    }
    return (segment_signature_crc_parts(
        segment->prefix_bytes,
        segment->prefix_len,
        segment->suffix_bytes,
        segment->suffix_len,
        downloaded) == expected_signature);
}

static void mark_fatal_message(const WCHAR *text)
{
    if (InterlockedCompareExchange(&g_dl.fatal_error, 1, 0) == 0) {
        safe_copy_w(g_dl.error_text, ARRAYSIZE(g_dl.error_text), text);
        InterlockedExchange(&g_dl.stop_requested, 1);
    }
}

static void mark_fatal_win32(const WCHAR *prefix, DWORD error_code)
{
    WCHAR sys[256];
    WCHAR full[DL_MAX_ERROR_TEXT];
    format_error_code(error_code, sys, ARRAYSIZE(sys));
    StringCchPrintfW(full, ARRAYSIZE(full), L"%s: %s", prefix, sys);
    mark_fatal_message(full);
}

static void mark_segment_failure(SEGMENT *segment, const WCHAR *reason)
{
    WCHAR full[DL_MAX_ERROR_TEXT];
    if (segment != NULL) {
        StringCchPrintfW(full, ARRAYSIZE(full), L"segment %lu failed: %s", segment->id, reason);
        mark_fatal_message(full);
    } else {
        mark_fatal_message(reason);
    }
}



typedef struct BUFFER_NODE_TAG {
    SLIST_ENTRY entry;
    BYTE data[1];
} BUFFER_NODE;



static BOOL dns_cache_lookup(const char *host, unsigned short port, DNS_CACHE_ENTRY *out_entry)
{
    DWORD i;
    BOOL found = FALSE;
    AcquireSRWLockShared(&g_dl.dns_lock);
    for (i = 0; i < ARRAYSIZE(g_dl.dns_cache); ++i) {
        if (g_dl.dns_cache[i].occupied &&
            g_dl.dns_cache[i].port == port &&
            ascii_ieq(g_dl.dns_cache[i].host, host)) {
            *out_entry = g_dl.dns_cache[i];
            found = TRUE;
            break;
        }
    }
    ReleaseSRWLockShared(&g_dl.dns_lock);
    return found;
}

static void dns_cache_store(const DNS_CACHE_ENTRY *entry)
{
    DWORD i;
    AcquireSRWLockExclusive(&g_dl.dns_lock);
    for (i = 0; i < ARRAYSIZE(g_dl.dns_cache); ++i) {
        if (!g_dl.dns_cache[i].occupied) {
            g_dl.dns_cache[i] = *entry;
            g_dl.dns_cache[i].occupied = TRUE;
            ReleaseSRWLockExclusive(&g_dl.dns_lock);
            return;
        }
    }
    g_dl.dns_cache[0] = *entry;
    g_dl.dns_cache[0].occupied = TRUE;
    ReleaseSRWLockExclusive(&g_dl.dns_lock);
}

static BOOL resolve_host_cached(const URL_PARTS *url, DNS_CACHE_ENTRY *entry)
{
    struct addrinfo hints;
    struct addrinfo *result = NULL;
    struct addrinfo *iter = NULL;
    char port_text[DL_MAX_PORT];
    DNS_CACHE_ENTRY local;

    ZeroMemory(&local, sizeof(local));
    if (dns_cache_lookup(url->host, url->port, entry)) {
        return TRUE;
    }

    ZeroMemory(&hints, sizeof(hints));
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_family = AF_UNSPEC;
    hints.ai_flags = AI_ADDRCONFIG;

    StringCchPrintfA(port_text, ARRAYSIZE(port_text), "%u", (unsigned)url->port);
    if (getaddrinfo(url->host, port_text, &hints, &result) != 0) {
        return FALSE;
    }

    safe_copy_a(local.host, ARRAYSIZE(local.host), url->host);
    local.port = url->port;
    for (iter = result; iter != NULL && local.addr_count < DL_MAX_ADDRS_PER_HOST; iter = iter->ai_next) {
        if (iter->ai_addrlen > (int)sizeof(local.addrs[0])) {
            continue;
        }
        CopyMemory(&local.addrs[local.addr_count], iter->ai_addr, iter->ai_addrlen);
        local.addr_lens[local.addr_count] = (int)iter->ai_addrlen;
        ++local.addr_count;
    }
    freeaddrinfo(result);

    if (local.addr_count == 0) {
        return FALSE;
    }

    dns_cache_store(&local);
    *entry = local;
    return TRUE;
}



static BOOL schannel_initialize_credentials(void)
{
    SCHANNEL_CRED cred;
    SECURITY_STATUS status;

    if (g_dl.schannel_cred_ready) {
        return TRUE;
    }

    ZeroMemory(&cred, sizeof(cred));
    cred.dwVersion = SCHANNEL_CRED_VERSION;
    cred.grbitEnabledProtocols = SP_PROT_TLS1_2_CLIENT | SP_PROT_TLS1_3_CLIENT;
    cred.dwFlags = SCH_USE_STRONG_CRYPTO | SCH_CRED_NO_DEFAULT_CREDS;
    if (g_dl.cfg.insecure) {
        cred.dwFlags |= SCH_CRED_MANUAL_CRED_VALIDATION;
    } else {
        cred.dwFlags |= SCH_CRED_AUTO_CRED_VALIDATION;
    }

    status = AcquireCredentialsHandleA(
        NULL,
        UNISP_NAME_A,
        SECPKG_CRED_OUTBOUND,
        NULL,
        &cred,
        NULL,
        NULL,
        &g_dl.schannel_cred,
        NULL);
    if (status != SEC_E_OK) {
        mark_fatal_message(L"AcquireCredentialsHandleA failed for SChannel");
        return FALSE;
    }

    g_dl.schannel_cred_ready = TRUE;
    return TRUE;
}

static int raw_socket_send_all(SOCKET socket_fd, const BYTE *buffer, int length)
{
    int sent_total = 0;
    while (sent_total < length) {
        int sent = send(socket_fd, (const char *)buffer + sent_total, length - sent_total, 0);
        if (sent == SOCKET_ERROR) {
            return SOCKET_ERROR;
        }
        sent_total += sent;
    }
    return sent_total;
}

static int raw_socket_recv_with_timeout(SOCKET socket_fd, BYTE *buffer, int length, DWORD timeout_ms)
{
    UNREFERENCED_PARAMETER(timeout_ms);
    return recv(socket_fd, (char *)buffer, length, 0);
}

static BOOL tls_send_token(SOCKET socket_fd, const SecBuffer *buffer)
{
    if (buffer->cbBuffer == 0 || buffer->pvBuffer == NULL) {
        return TRUE;
    }
    return (raw_socket_send_all(socket_fd, (const BYTE *)buffer->pvBuffer, (int)buffer->cbBuffer) != SOCKET_ERROR);
}

static BOOL tls_handshake(CONNECTION *connection)
{
    SECURITY_STATUS status;
    SecBufferDesc out_desc;
    SecBuffer out_buffers[1];
    DWORD flags = ISC_REQ_SEQUENCE_DETECT |
        ISC_REQ_REPLAY_DETECT |
        ISC_REQ_CONFIDENTIALITY |
        ISC_REQ_EXTENDED_ERROR |
        ISC_REQ_ALLOCATE_MEMORY |
        ISC_REQ_STREAM;
    DWORD out_flags = 0;
    BYTE recv_buf[DL_MAX_TLS_IO];
    DWORD recv_len = 0;
    BOOL have_context = FALSE;

    if (!schannel_initialize_credentials()) {
        return FALSE;
    }

    ZeroMemory(&connection->tls, sizeof(connection->tls));

    for (;;) {
        SecBufferDesc in_desc;
        SecBuffer in_buffers[2];

        ZeroMemory(out_buffers, sizeof(out_buffers));
        out_buffers[0].BufferType = SECBUFFER_TOKEN;
        out_desc.ulVersion = SECBUFFER_VERSION;
        out_desc.cBuffers = 1;
        out_desc.pBuffers = out_buffers;

        if (!have_context) {
            status = InitializeSecurityContextA(
                &g_dl.schannel_cred,
                NULL,
                connection->url.host,
                flags,
                0,
                SECURITY_NATIVE_DREP,
                NULL,
                0,
                &connection->tls.context,
                &out_desc,
                &out_flags,
                NULL);
        } else {
            DWORD out_flags2 = 0;
            in_buffers[0].pvBuffer = recv_buf;
            in_buffers[0].cbBuffer = recv_len;
            in_buffers[0].BufferType = SECBUFFER_TOKEN;
            in_buffers[1].pvBuffer = NULL;
            in_buffers[1].cbBuffer = 0;
            in_buffers[1].BufferType = SECBUFFER_EMPTY;
            in_desc.ulVersion = SECBUFFER_VERSION;
            in_desc.cBuffers = 2;
            in_desc.pBuffers = in_buffers;

            status = InitializeSecurityContextA(
                &g_dl.schannel_cred,
                &connection->tls.context,
                connection->url.host,
                flags,
                0,
                SECURITY_NATIVE_DREP,
                &in_desc,
                0,
                &connection->tls.context,
                &out_desc,
                &out_flags2,
                NULL);

            if (in_buffers[1].BufferType == SECBUFFER_EXTRA) {
                DWORD extra = in_buffers[1].cbBuffer;
                MoveMemory(recv_buf, recv_buf + (recv_len - extra), extra);
                recv_len = extra;
            } else {
                recv_len = 0;
            }
        }

        if (out_buffers[0].cbBuffer != 0 && out_buffers[0].pvBuffer != NULL) {
            BOOL sent = tls_send_token(connection->socket_fd, &out_buffers[0]);
            FreeContextBuffer(out_buffers[0].pvBuffer);
            if (!sent) {
                return FALSE;
            }
        }

        if (status == SEC_E_OK) {
            break;
        }
        if (status != SEC_I_CONTINUE_NEEDED && status != SEC_E_INCOMPLETE_MESSAGE) {
            return FALSE;
        }

        have_context = TRUE;
        if (status == SEC_E_INCOMPLETE_MESSAGE || recv_len == 0 || status == SEC_I_CONTINUE_NEEDED) {
            int got = raw_socket_recv_with_timeout(connection->socket_fd, recv_buf + recv_len, (int)(sizeof(recv_buf) - recv_len), DL_CONNECT_TIMEOUT_MS);
            if (got <= 0) {
                return FALSE;
            }
            recv_len += (DWORD)got;
        }
    }

    if (QueryContextAttributesA(&connection->tls.context, SECPKG_ATTR_STREAM_SIZES, &connection->tls.sizes) != SEC_E_OK) {
        return FALSE;
    }

    connection->tls.context_initialized = TRUE;
    connection->tls.active = TRUE;
    connection->tls.incoming_len = 0;
    return TRUE;
}

static void tls_shutdown(CONNECTION *connection)
{
    if (connection->tls.context_initialized) {
        DeleteSecurityContext(&connection->tls.context);
        connection->tls.context_initialized = FALSE;
    }
    connection->tls.active = FALSE;
    connection->tls.incoming_len = 0;
}

static BOOL tls_send_plaintext(CONNECTION *connection, const BYTE *data, DWORD data_len)
{
    SecBufferDesc desc;
    SecBuffer buffers[4];
    DWORD payload = data_len;
    DWORD total;

    while (payload > 0) {
        DWORD chunk = payload;
        if (chunk > connection->tls.sizes.cbMaximumMessage) {
            chunk = connection->tls.sizes.cbMaximumMessage;
        }

        CopyMemory(connection->tls.send_buffer + connection->tls.sizes.cbHeader, data, chunk);
        buffers[0].BufferType = SECBUFFER_STREAM_HEADER;
        buffers[0].pvBuffer = connection->tls.send_buffer;
        buffers[0].cbBuffer = connection->tls.sizes.cbHeader;
        buffers[1].BufferType = SECBUFFER_DATA;
        buffers[1].pvBuffer = connection->tls.send_buffer + connection->tls.sizes.cbHeader;
        buffers[1].cbBuffer = chunk;
        buffers[2].BufferType = SECBUFFER_STREAM_TRAILER;
        buffers[2].pvBuffer = connection->tls.send_buffer + connection->tls.sizes.cbHeader + chunk;
        buffers[2].cbBuffer = connection->tls.sizes.cbTrailer;
        buffers[3].BufferType = SECBUFFER_EMPTY;
        buffers[3].pvBuffer = NULL;
        buffers[3].cbBuffer = 0;
        desc.ulVersion = SECBUFFER_VERSION;
        desc.cBuffers = 4;
        desc.pBuffers = buffers;

        if (EncryptMessage(&connection->tls.context, 0, &desc, 0) != SEC_E_OK) {
            return FALSE;
        }

        total = buffers[0].cbBuffer + buffers[1].cbBuffer + buffers[2].cbBuffer;
        if (raw_socket_send_all(connection->socket_fd, connection->tls.send_buffer, (int)total) == SOCKET_ERROR) {
            return FALSE;
        }

        data += chunk;
        payload -= chunk;
    }
    return TRUE;
}

static BOOL tls_recv_plaintext(CONNECTION *connection, BYTE *buffer, DWORD buffer_len, DWORD *received)
{
    SECURITY_STATUS status;

    *received = 0;
    if (connection->tls.plaintext_pos < connection->tls.plaintext_len) {
        DWORD available = connection->tls.plaintext_len - connection->tls.plaintext_pos;
        if (available > buffer_len) {
            available = buffer_len;
        }
        CopyMemory(buffer, connection->tls.plaintext + connection->tls.plaintext_pos, available);
        connection->tls.plaintext_pos += available;
        if (connection->tls.plaintext_pos == connection->tls.plaintext_len) {
            connection->tls.plaintext_pos = 0;
            connection->tls.plaintext_len = 0;
        }
        *received = available;
        return TRUE;
    }

    for (;;) {
        SecBufferDesc desc;
        SecBuffer buffers[4];
        ULONG qop = 0;
        DWORD extra = 0;
        BYTE *plain = NULL;
        DWORD plain_len = 0;

        if (connection->tls.incoming_len == 0) {
            int got = raw_socket_recv_with_timeout(connection->socket_fd,
                connection->tls.incoming,
                (int)sizeof(connection->tls.incoming),
                DL_TIMEOUT_INTERVAL_MS);
            if (got == 0) {
                return TRUE;
            }
            if (got < 0) {
                if (WSAGetLastError() == WSAETIMEDOUT) {
                    return FALSE;
                }
                return FALSE;
            }
            connection->tls.incoming_len = (DWORD)got;
        }

        buffers[0].pvBuffer = connection->tls.incoming;
        buffers[0].cbBuffer = connection->tls.incoming_len;
        buffers[0].BufferType = SECBUFFER_DATA;
        buffers[1].BufferType = SECBUFFER_EMPTY;
        buffers[2].BufferType = SECBUFFER_EMPTY;
        buffers[3].BufferType = SECBUFFER_EMPTY;
        desc.ulVersion = SECBUFFER_VERSION;
        desc.cBuffers = ARRAYSIZE(buffers);
        desc.pBuffers = buffers;

        status = DecryptMessage(&connection->tls.context, &desc, 0, &qop);
        if (status == SEC_E_INCOMPLETE_MESSAGE) {
            int got_more;
            if (connection->tls.incoming_len == sizeof(connection->tls.incoming)) {
                return FALSE;
            }
            got_more = raw_socket_recv_with_timeout(connection->socket_fd,
                connection->tls.incoming + connection->tls.incoming_len,
                (int)(sizeof(connection->tls.incoming) - connection->tls.incoming_len),
                DL_TIMEOUT_INTERVAL_MS);
            if (got_more <= 0) {
                return FALSE;
            }
            connection->tls.incoming_len += (DWORD)got_more;
            continue;
        }
        if (status == SEC_I_CONTEXT_EXPIRED) {
            return TRUE;
        }
        if (status != SEC_E_OK && status != SEC_I_RENEGOTIATE) {
            return FALSE;
        }

        for (extra = 0; extra < ARRAYSIZE(buffers); ++extra) {
            if (buffers[extra].BufferType == SECBUFFER_DATA) {
                plain = (BYTE *)buffers[extra].pvBuffer;
                plain_len = buffers[extra].cbBuffer;
            } else if (buffers[extra].BufferType == SECBUFFER_EXTRA) {
                extra = buffers[extra].cbBuffer;
                break;
            }
        }

        if (plain_len > 0) {
            if (plain_len > sizeof(connection->tls.plaintext)) {
                return FALSE;
            }
            CopyMemory(connection->tls.plaintext, plain, plain_len);
            connection->tls.plaintext_len = plain_len;
            connection->tls.plaintext_pos = 0;
            {
                DWORD available2 = plain_len;
                if (available2 > buffer_len) {
                    available2 = buffer_len;
                }
                CopyMemory(buffer, connection->tls.plaintext, available2);
                connection->tls.plaintext_pos = available2;
                if (connection->tls.plaintext_pos == connection->tls.plaintext_len) {
                    connection->tls.plaintext_pos = 0;
                    connection->tls.plaintext_len = 0;
                }
                *received = available2;
            }
        }

        {
            DWORD extra_bytes = 0;
            DWORD i;
            for (i = 0; i < ARRAYSIZE(buffers); ++i) {
                if (buffers[i].BufferType == SECBUFFER_EXTRA) {
                    extra_bytes = buffers[i].cbBuffer;
                    break;
                }
            }
            if (extra_bytes > 0) {
                MoveMemory(connection->tls.incoming,
                    connection->tls.incoming + (connection->tls.incoming_len - extra_bytes),
                    extra_bytes);
                connection->tls.incoming_len = extra_bytes;
            } else {
                connection->tls.incoming_len = 0;
            }
        }

        if (status == SEC_I_RENEGOTIATE) {
            return FALSE;
        }
        return TRUE;
    }
}



static char *trim_ascii(char *text)
{
    char *end;
    while (*text == ' ' || *text == '\t') {
        ++text;
    }
    end = text + strlen(text);
    while (end > text && (end[-1] == ' ' || end[-1] == '\t' || end[-1] == '\r' || end[-1] == '\n')) {
        --end;
    }
    *end = 0;
    return text;
}

static BOOL parse_status_line(const char *line, HTTP_RESPONSE *response)
{
    const char *sp1 = strchr(line, ' ');
    const char *sp2;
    if (sp1 == NULL) {
        return FALSE;
    }
    while (*sp1 == ' ') {
        ++sp1;
    }
    sp2 = strchr(sp1, ' ');
    if (sp2 == NULL) {
        response->status_code = atoi(sp1);
    } else {
        char code[8];
        size_t len = (size_t)(sp2 - sp1);
        if (len >= sizeof(code)) {
            len = sizeof(code) - 1;
        }
        memcpy(code, sp1, len);
        code[len] = 0;
        response->status_code = atoi(code);
    }
    return (response->status_code >= 100);
}

static BOOL parse_content_range_value(const char *value, ULONGLONG *start, ULONGLONG *end, ULONGLONG *total)
{
    const char *bytes = value;
    WCHAR temp[128];
    if (_strnicmp(bytes, "bytes", 5) == 0) {
        bytes += 5;
    }
    while (*bytes == ' ' || *bytes == '=') {
        ++bytes;
    }
    if (swscanf((const wchar_t *)L"", L"") == 0) {
        
    }
    if (MultiByteToWideChar(CP_ACP, 0, bytes, -1, temp, ARRAYSIZE(temp)) <= 0) {
        return FALSE;
    }
    return (swscanf(temp, L"%llu-%llu/%llu", start, end, total) == 3);
}

static BOOL percent_decode_utf8(const char *src, char *dst, size_t dst_count)
{
    size_t out = 0;
    while (*src && out + 1 < dst_count) {
        if (*src == '%' && isxdigit((unsigned char)src[1]) && isxdigit((unsigned char)src[2])) {
            int hi = src[1];
            int lo = src[2];
            hi = (hi >= '0' && hi <= '9') ? (hi - '0') : (10 + ascii_tolower((char)hi) - 'a');
            lo = (lo >= '0' && lo <= '9') ? (lo - '0') : (10 + ascii_tolower((char)lo) - 'a');
            dst[out++] = (char)((hi << 4) | lo);
            src += 3;
        } else if (*src == '+') {
            dst[out++] = ' ';
            ++src;
        } else {
            dst[out++] = *src++;
        }
    }
    dst[out] = 0;
    return TRUE;
}

static BOOL extract_filename_from_content_disposition(const char *value, WCHAR *out_name, size_t out_count)
{
    const char *filename_star;
    const char *filename;
    char temp[DL_MAX_FILENAME];
    char decoded[DL_MAX_FILENAME];
    const char *start;
    const char *end;

    if (value == NULL || out_name == NULL || out_count == 0) {
        return FALSE;
    }

    filename_star = ascii_stristr(value, "filename*=");
    if (filename_star != NULL) {
        filename_star += 10;
        if (_strnicmp(filename_star, "UTF-8''", 7) == 0) {
            filename_star += 7;
        }
        start = filename_star;
        end = start;
        while (*end && *end != ';') {
            ++end;
        }
        if ((size_t)(end - start) >= sizeof(temp)) {
            return FALSE;
        }
        memcpy(temp, start, (size_t)(end - start));
        temp[end - start] = 0;
        percent_decode_utf8(temp, decoded, sizeof(decoded));
        if (!utf8_to_wide(decoded, out_name, (DWORD)out_count)) {
            return FALSE;
        }
        sanitize_filename_w(out_name);
        return TRUE;
    }

    filename = ascii_stristr(value, "filename=");
    if (filename == NULL) {
        return FALSE;
    }
    filename += 9;
    while (*filename == ' ' || *filename == '\t') {
        ++filename;
    }
    if (*filename == '"') {
        ++filename;
        start = filename;
        end = strchr(start, '"');
        if (end == NULL) {
            end = start + strlen(start);
        }
    } else {
        start = filename;
        end = start;
        while (*end && *end != ';' && *end != '\r' && *end != '\n') {
            ++end;
        }
    }
    if ((size_t)(end - start) >= sizeof(temp)) {
        return FALSE;
    }
    memcpy(temp, start, (size_t)(end - start));
    temp[end - start] = 0;
    if (!utf8_to_wide(temp, out_name, (DWORD)out_count)) {
        return FALSE;
    }
    sanitize_filename_w(out_name);
    return TRUE;
}

static BOOL resolve_redirect_url(const char *base_url, const char *location, char *out_url, size_t out_count)
{
    URL_PARTS base;
    const char *slash;
    char temp[DL_MAX_URL];

    if (location == NULL || out_url == NULL) {
        return FALSE;
    }
    if (ascii_stristr(location, "http://") == location || ascii_stristr(location, "https://") == location) {
        StringCchCopyA(out_url, out_count, location);
        return TRUE;
    }
    if (!parse_url(base_url, &base)) {
        return FALSE;
    }
    if (location[0] == '/' && location[1] == '/') {
        StringCchPrintfA(out_url, out_count, "%s:%s", (base.scheme == URL_SCHEME_HTTPS) ? "https" : "http", location);
        return TRUE;
    }
    if (location[0] == '/') {
        StringCchPrintfA(out_url, out_count, "%s://%s%s",
            (base.scheme == URL_SCHEME_HTTPS) ? "https" : "http",
            base.host_header,
            location);
        return TRUE;
    }
    StringCchCopyA(temp, ARRAYSIZE(temp), base.path);
    slash = strrchr(temp, '/');
    if (slash != NULL) {
        temp[(slash - temp) + 1] = 0;
    } else {
        StringCchCopyA(temp, ARRAYSIZE(temp), "/");
    }
    StringCchPrintfA(out_url, out_count, "%s://%s%s%s",
        (base.scheme == URL_SCHEME_HTTPS) ? "https" : "http",
        base.host_header,
        temp,
        location);
    return TRUE;
}



static BOOL parse_url(const char *url, URL_PARTS *parts)
{
    const char *scheme_end;
    const char *authority;
    const char *path;
    const char *host_end;
    const char *port_sep = NULL;
    size_t host_len;
    size_t path_len;
    unsigned long port = 0;

    ZeroMemory(parts, sizeof(*parts));
    scheme_end = strstr(url, "://");
    if (scheme_end == NULL) {
        return FALSE;
    }
    if (_strnicmp(url, "http", (size_t)(scheme_end - url)) == 0 && (scheme_end - url) == 4) {
        parts->scheme = URL_SCHEME_HTTP;
        parts->port = 80;
    } else if (_strnicmp(url, "https", (size_t)(scheme_end - url)) == 0 && (scheme_end - url) == 5) {
        parts->scheme = URL_SCHEME_HTTPS;
        parts->port = 443;
    } else {
        return FALSE;
    }

    authority = scheme_end + 3;
    path = strchr(authority, '/');
    if (path == NULL) {
        path = authority + strlen(authority);
    }

    if (*authority == '[') {
        host_end = strchr(authority, ']');
        if (host_end == NULL || host_end >= path) {
            return FALSE;
        }
        ++authority;
        host_len = (size_t)(host_end - authority);
        if (host_end[1] == ':') {
            port_sep = host_end + 1;
        }
    } else {
        host_end = authority;
        while (host_end < path && *host_end != ':') {
            ++host_end;
        }
        host_len = (size_t)(host_end - authority);
        if (host_end < path && *host_end == ':') {
            port_sep = host_end;
        }
    }
    if (host_len == 0 || host_len >= ARRAYSIZE(parts->host)) {
        return FALSE;
    }
    memcpy(parts->host, authority, host_len);
    parts->host[host_len] = 0;

    if (port_sep != NULL) {
        port = strtoul(port_sep + 1, NULL, 10);
        if (port == 0 || port > 65535) {
            return FALSE;
        }
        parts->port = (unsigned short)port;
    }

    if (*path == 0) {
        StringCchCopyA(parts->path, ARRAYSIZE(parts->path), "/");
    } else {
        const char *fragment = strchr(path, '#');
        if (fragment == NULL) {
            fragment = path + strlen(path);
        }
        path_len = (size_t)(fragment - path);
        if (path_len >= ARRAYSIZE(parts->path)) {
            return FALSE;
        }
        memcpy(parts->path, path, path_len);
        parts->path[path_len] = 0;
    }

    if (strchr(parts->host, ':') != NULL) {
        if ((parts->scheme == URL_SCHEME_HTTP && parts->port == 80) ||
            (parts->scheme == URL_SCHEME_HTTPS && parts->port == 443)) {
            StringCchPrintfA(parts->host_header, ARRAYSIZE(parts->host_header), "[%s]", parts->host);
        } else {
            StringCchPrintfA(parts->host_header, ARRAYSIZE(parts->host_header), "[%s]:%u", parts->host, (unsigned)parts->port);
        }
    } else {
        if ((parts->scheme == URL_SCHEME_HTTP && parts->port == 80) ||
            (parts->scheme == URL_SCHEME_HTTPS && parts->port == 443)) {
            StringCchCopyA(parts->host_header, ARRAYSIZE(parts->host_header), parts->host);
        } else {
            StringCchPrintfA(parts->host_header, ARRAYSIZE(parts->host_header), "%s:%u", parts->host, (unsigned)parts->port);
        }
    }
    return TRUE;
}

static BOOL load_connect_ex(SOCKET socket_fd, LPFN_CONNECTEX *connect_ex)
{
    GUID guid = WSAID_CONNECTEX;
    DWORD bytes = 0;
    return (WSAIoctl(socket_fd,
        SIO_GET_EXTENSION_FUNCTION_POINTER,
        &guid,
        sizeof(guid),
        connect_ex,
        sizeof(*connect_ex),
        &bytes,
        NULL,
        NULL) == 0);
}

static void socket_set_timeouts(SOCKET socket_fd, DWORD recv_timeout_ms, DWORD send_timeout_ms)
{
    setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&recv_timeout_ms, sizeof(recv_timeout_ms));
    setsockopt(socket_fd, SOL_SOCKET, SO_SNDTIMEO, (const char *)&send_timeout_ms, sizeof(send_timeout_ms));
}

static BOOL connect_socket_with_select(SOCKET socket_fd, const struct sockaddr *addr, int addr_len)
{
    u_long nonblocking = 1;
    fd_set write_fds;
    fd_set error_fds;
    TIMEVAL tv;
    int result;
    int so_error = 0;
    int so_len = sizeof(so_error);

    if (ioctlsocket(socket_fd, FIONBIO, &nonblocking) == SOCKET_ERROR) {
        return FALSE;
    }

    result = connect(socket_fd, addr, addr_len);
    if (result == SOCKET_ERROR) {
        int error = WSAGetLastError();
        if (error != WSAEWOULDBLOCK && error != WSAEINPROGRESS && error != WSAEINVAL) {
            nonblocking = 0;
            ioctlsocket(socket_fd, FIONBIO, &nonblocking);
            return FALSE;
        }
    }

    FD_ZERO(&write_fds);
    FD_ZERO(&error_fds);
    FD_SET(socket_fd, &write_fds);
    FD_SET(socket_fd, &error_fds);
    tv.tv_sec = DL_CONNECT_TIMEOUT_MS / 1000;
    tv.tv_usec = (DL_CONNECT_TIMEOUT_MS % 1000) * 1000;
    result = select(0, NULL, &write_fds, &error_fds, &tv);
    nonblocking = 0;
    ioctlsocket(socket_fd, FIONBIO, &nonblocking);
    if (result <= 0) {
        if (result == 0) {
            WSASetLastError(WSAETIMEDOUT);
        }
        return FALSE;
    }
    if (getsockopt(socket_fd, SOL_SOCKET, SO_ERROR, (char *)&so_error, &so_len) == SOCKET_ERROR) {
        return FALSE;
    }
    if (so_error != 0) {
        WSASetLastError(so_error);
        return FALSE;
    }
    return TRUE;
}

static void apply_socket_options(SOCKET socket_fd)
{
    int opt = 1;
    int rcvbuf = 8 * 1024 * 1024;
    int sndbuf = 1024 * 1024;
    struct tcp_keepalive keepalive;
    DWORD bytes = 0;

    setsockopt(socket_fd, IPPROTO_TCP, TCP_NODELAY, (const char *)&opt, sizeof(opt));
    setsockopt(socket_fd, SOL_SOCKET, SO_RCVBUF, (const char *)&rcvbuf, sizeof(rcvbuf));
    setsockopt(socket_fd, SOL_SOCKET, SO_SNDBUF, (const char *)&sndbuf, sizeof(sndbuf));
    setsockopt(socket_fd, SOL_SOCKET, SO_KEEPALIVE, (const char *)&opt, sizeof(opt));
    socket_set_timeouts(socket_fd, DL_CONNECT_TIMEOUT_MS, DL_CONNECT_TIMEOUT_MS);
    keepalive.onoff = 1;
    keepalive.keepalivetime = 10000;
    keepalive.keepaliveinterval = 1000;
    WSAIoctl(socket_fd, SIO_KEEPALIVE_VALS, &keepalive, sizeof(keepalive), NULL, 0, &bytes, NULL, NULL);
}

static BOOL connect_socket_with_timeout(SOCKET socket_fd, const struct sockaddr *addr, int addr_len)
{
    LPFN_CONNECTEX connect_ex = NULL;
    OVERLAPPED ovl;
    HANDLE event_handle = NULL;
    SOCKADDR_STORAGE bind_addr;
    int bind_len = 0;
    BOOL ok = FALSE;
    DWORD bytes = 0;

    if (load_connect_ex(socket_fd, &connect_ex)) {
        ZeroMemory(&bind_addr, sizeof(bind_addr));
        if (addr->sa_family == AF_INET) {
            struct sockaddr_in *sin = (struct sockaddr_in *)&bind_addr;
            sin->sin_family = AF_INET;
            bind_len = sizeof(*sin);
        } else {
            struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&bind_addr;
            sin6->sin6_family = AF_INET6;
            bind_len = sizeof(*sin6);
        }
        if (bind(socket_fd, (const struct sockaddr *)&bind_addr, bind_len) == 0) {
            ZeroMemory(&ovl, sizeof(ovl));
            event_handle = CreateEventW(NULL, TRUE, FALSE, NULL);
            if (event_handle != NULL) {
                ovl.hEvent = event_handle;
                if (!connect_ex(socket_fd, addr, addr_len, NULL, 0, NULL, &ovl)) {
                    DWORD error = WSAGetLastError();
                    if (error == ERROR_IO_PENDING) {
                        if (WaitForSingleObject(event_handle, DL_CONNECT_TIMEOUT_MS) == WAIT_OBJECT_0) {
                            ok = WSAGetOverlappedResult(socket_fd, &ovl, &bytes, FALSE, NULL);
                        } else {
                            WSASetLastError(WSAETIMEDOUT);
                            ok = FALSE;
                        }
                    } else {
                        ok = FALSE;
                    }
                } else {
                    ok = TRUE;
                }
                CloseHandle(event_handle);
                if (ok && setsockopt(socket_fd, SOL_SOCKET, SO_UPDATE_CONNECT_CONTEXT, NULL, 0) == 0) {
                    return TRUE;
                }
            }
        }
    }

    return connect_socket_with_select(socket_fd, addr, addr_len);
}

static BOOL connection_open(CONNECTION *connection, const URL_PARTS *url, volatile LONG_PTR *socket_slot)
{
    DNS_CACHE_ENTRY dns_entry;
    int i;

    ZeroMemory(connection, sizeof(*connection));
    connection->socket_fd = INVALID_SOCKET;
    connection->url = *url;
    connection->use_tls = (url->scheme == URL_SCHEME_HTTPS);
    connection->socket_slot = socket_slot;

    if (!resolve_host_cached(url, &dns_entry)) {
        return FALSE;
    }

    for (i = 0; i < dns_entry.addr_count; ++i) {
        SOCKET sock = WSASocketW(((struct sockaddr *)&dns_entry.addrs[i])->sa_family,
            SOCK_STREAM,
            IPPROTO_TCP,
            NULL,
            0,
            WSA_FLAG_OVERLAPPED);
        if (sock == INVALID_SOCKET) {
            continue;
        }
        apply_socket_options(sock);
        if (connect_socket_with_timeout(sock, (struct sockaddr *)&dns_entry.addrs[i], dns_entry.addr_lens[i])) {
            connection->socket_fd = sock;
            if (socket_slot != NULL) {
                InterlockedExchangePointer((PVOID volatile *)socket_slot, (PVOID)(ULONG_PTR)sock);
            }
            if (connection->use_tls && !tls_handshake(connection)) {
                if (socket_slot != NULL) {
                    InterlockedExchangePointer((PVOID volatile *)socket_slot, (PVOID)(ULONG_PTR)INVALID_SOCKET);
                }
                tls_shutdown(connection);
                closesocket(sock);
                connection->socket_fd = INVALID_SOCKET;
                continue;
            }
            socket_set_timeouts(sock, DL_SEGMENT_TIMEOUT_MS, DL_SEGMENT_TIMEOUT_MS);
            return TRUE;
        }
        closesocket(sock);
    }

    return FALSE;
}

static void connection_close(CONNECTION *connection)
{
    SOCKET sock;
    if (connection == NULL) {
        return;
    }
    tls_shutdown(connection);
    sock = connection->socket_fd;
    if (sock != INVALID_SOCKET) {
        if (connection->socket_slot != NULL) {
            ULONG_PTR current = (ULONG_PTR)InterlockedExchangePointer((PVOID volatile *)connection->socket_slot, (PVOID)(ULONG_PTR)INVALID_SOCKET);
            if ((SOCKET)current != INVALID_SOCKET) {
                shutdown(sock, SD_BOTH);
                closesocket(sock);
            }
        } else {
            shutdown(sock, SD_BOTH);
            closesocket(sock);
        }
        connection->socket_fd = INVALID_SOCKET;
    }
}

static BOOL connection_send_bytes(CONNECTION *connection, const BYTE *data, DWORD length)
{
    if (connection->use_tls) {
        return tls_send_plaintext(connection, data, length);
    }
    return (raw_socket_send_all(connection->socket_fd, data, (int)length) != SOCKET_ERROR);
}

static BOOL connection_recv_bytes(CONNECTION *connection, BYTE *buffer, DWORD buffer_len, DWORD *received, DWORD idle_ms)
{
    UNREFERENCED_PARAMETER(idle_ms);
    *received = 0;
    while (!g_dl.stop_requested) {
        if (connection->use_tls) {
            if (tls_recv_plaintext(connection, buffer, buffer_len, received)) {
                return TRUE;
            }
        } else {
            int got = raw_socket_recv_with_timeout(connection->socket_fd, buffer, (int)buffer_len, idle_ms);
            if (got > 0) {
                *received = (DWORD)got;
                return TRUE;
            }
            if (got == 0) {
                return TRUE;
            }
        }
        return FALSE;
    }
    return FALSE;
}

static BOOL connection_read_some(CONNECTION *connection, BYTE *buffer, DWORD buffer_len, DWORD *received)
{
    DWORD got = 0;

    *received = 0;
    if (connection->cache_pos < connection->cache_len) {
        size_t available = connection->cache_len - connection->cache_pos;
        if (available > buffer_len) {
            available = buffer_len;
        }
        CopyMemory(buffer, connection->cache + connection->cache_pos, available);
        connection->cache_pos += available;
        *received = (DWORD)available;
        if (connection->cache_pos == connection->cache_len) {
            connection->cache_pos = 0;
            connection->cache_len = 0;
        }
        return TRUE;
    }

    if (!connection_recv_bytes(connection, buffer, buffer_len, &got, DL_SEGMENT_TIMEOUT_MS)) {
        return FALSE;
    }
    *received = got;
    return TRUE;
}

static BOOL connection_read_line(CONNECTION *connection, char *line, size_t line_count)
{
    size_t used = 0;
    while (used + 1 < line_count) {
        BYTE ch;
        DWORD got = 0;
        if (!connection_read_some(connection, &ch, 1, &got)) {
            return FALSE;
        }
        if (got == 0) {
            break;
        }
        line[used++] = (char)ch;
        if (used >= 2 && line[used - 2] == '\r' && line[used - 1] == '\n') {
            line[used - 2] = 0;
            return TRUE;
        }
    }
    line[used] = 0;
    return (used > 0);
}

static BOOL http_send_request(CONNECTION *connection,
    const char *method,
    const URL_PARTS *url,
    ULONGLONG range_start,
    ULONGLONG range_end,
    BOOL use_range)
{
    char request[8192];
    HRESULT hr;
    if (use_range) {
        hr = StringCchPrintfA(request, ARRAYSIZE(request),
            "%s %s HTTP/1.1\r\n"
            "Host: %s\r\n"
            "User-Agent: %s\r\n"
            "Accept: */*\r\n"
            "Accept-Encoding: identity\r\n"
            "Connection: close\r\n"
            "Range: bytes=%llu-%llu\r\n"
            "\r\n",
            method,
            url->path,
            url->host_header,
            DL_USER_AGENT,
            range_start,
            range_end);
    } else {
        hr = StringCchPrintfA(request, ARRAYSIZE(request),
            "%s %s HTTP/1.1\r\n"
            "Host: %s\r\n"
            "User-Agent: %s\r\n"
            "Accept: */*\r\n"
            "Accept-Encoding: identity\r\n"
            "Connection: close\r\n"
            "\r\n",
            method,
            url->path,
            url->host_header,
            DL_USER_AGENT);
    }
    if (FAILED(hr)) {
        return FALSE;
    }
    return connection_send_bytes(connection, (const BYTE *)request, (DWORD)strlen(request));
}

static BOOL http_read_headers(CONNECTION *connection, HTTP_RESPONSE *response)
{
    char header_block[DL_MAX_HEADER_BLOCK];
    size_t used = 0;
    DWORD got = 0;
    char *header_end;
    char *cursor;

    ZeroMemory(response, sizeof(*response));

    while (used + 1 < sizeof(header_block)) {
        DWORD want = (DWORD)(sizeof(header_block) - 1 - used);
        if (want > 4096) {
            want = 4096;
        }
        if (!connection_read_some(connection, (BYTE *)header_block + used, want, &got)) {
            return FALSE;
        }
        if (got == 0) {
            return FALSE;
        }
        used += got;
        header_block[used] = 0;
        header_end = strstr(header_block, "\r\n\r\n");
        if (header_end != NULL) {
            size_t header_size = (size_t)((header_end + 4) - header_block);
            size_t extra = used - header_size;
            if (extra > 0) {
                memcpy(connection->cache, header_end + 4, extra);
                connection->cache_len = extra;
                connection->cache_pos = 0;
            }
            *header_end = 0;
            break;
        }
    }
    if (used == 0) {
        return FALSE;
    }

    cursor = header_block;
    {
        char *line_end = strstr(cursor, "\r\n");
        if (line_end == NULL) {
            return FALSE;
        }
        *line_end = 0;
        if (!parse_status_line(cursor, response)) {
            return FALSE;
        }
        cursor = line_end + 2;
    }

    while (*cursor != 0) {
        char *line_end = strstr(cursor, "\r\n");
        char *colon;
        char *value;
        if (line_end == NULL) {
            line_end = cursor + strlen(cursor);
        }
        *line_end = 0;
        if (*cursor == 0) {
            break;
        }
        colon = strchr(cursor, ':');
        if (colon != NULL) {
            *colon = 0;
            value = trim_ascii(colon + 1);
            if (ascii_ieq(cursor, "Content-Length")) {
                response->content_length = _strtoui64(value, NULL, 10);
                response->content_length_known = TRUE;
            } else if (ascii_ieq(cursor, "Transfer-Encoding")) {
                safe_copy_a(response->transfer_encoding, ARRAYSIZE(response->transfer_encoding), value);
                if (ascii_stristr(value, "chunked") != NULL) {
                    response->chunked = TRUE;
                }
            } else if (ascii_ieq(cursor, "Accept-Ranges")) {
                if (ascii_stristr(value, "bytes") != NULL) {
                    response->accept_ranges = TRUE;
                }
            } else if (ascii_ieq(cursor, "Connection")) {
                safe_copy_a(response->connection_value, ARRAYSIZE(response->connection_value), value);
                response->keep_alive = (ascii_stristr(value, "close") == NULL);
            } else if (ascii_ieq(cursor, "Location")) {
                safe_copy_a(response->location, ARRAYSIZE(response->location), value);
            } else if (ascii_ieq(cursor, "Content-Disposition")) {
                safe_copy_a(response->content_disposition, ARRAYSIZE(response->content_disposition), value);
            } else if (ascii_ieq(cursor, "Content-Range")) {
                response->content_range_known = parse_content_range_value(
                    value,
                    &response->content_range_start,
                    &response->content_range_end,
                    &response->content_range_total);
            }
        }
        cursor = line_end + 2;
    }

    if (response->status_code == 206 && response->content_range_known) {
        response->accept_ranges = TRUE;
        if (!response->content_length_known) {
            response->content_length = response->content_range_end - response->content_range_start + 1;
            response->content_length_known = TRUE;
        }
    }
    return TRUE;
}

static BOOL http_read_chunked_body(CONNECTION *connection, HTTP_RESPONSE *response, BYTE *buffer, DWORD capacity, DWORD *out_len, BOOL *eof)
{
    char line[128];
    DWORD produced = 0;
    *eof = FALSE;
    *out_len = 0;

    while (produced < capacity) {
        if (response->chunk_done) {
            *eof = TRUE;
            break;
        }
        if (response->chunk_remaining == 0) {
            if (!connection_read_line(connection, line, ARRAYSIZE(line))) {
                return FALSE;
            }
            response->chunk_remaining = strtoull(line, NULL, 16);
            if (response->chunk_remaining == 0) {
                for (;;) {
                    if (!connection_read_line(connection, line, ARRAYSIZE(line))) {
                        return FALSE;
                    }
                    if (line[0] == 0) {
                        break;
                    }
                }
                response->chunk_done = TRUE;
                *eof = TRUE;
                break;
            }
        }

        while (response->chunk_remaining > 0 && produced < capacity) {
            DWORD want = capacity - produced;
            DWORD got = 0;
            if (want > response->chunk_remaining) {
                want = (DWORD)response->chunk_remaining;
            }
            if (!connection_read_some(connection, buffer + produced, want, &got)) {
                return FALSE;
            }
            if (got == 0) {
                return FALSE;
            }
            produced += got;
            response->chunk_remaining -= got;
            response->body_read += got;
        }

        if (response->chunk_remaining == 0) {
            BYTE crlf[2];
            DWORD got2 = 0;
            if (!connection_read_some(connection, crlf, 2, &got2) || got2 != 2) {
                return FALSE;
            }
            if (crlf[0] != '\r' || crlf[1] != '\n') {
                return FALSE;
            }
        }

        if (produced > 0) {
            break;
        }
    }

    *out_len = produced;
    return TRUE;
}

static BOOL http_read_body(CONNECTION *connection, HTTP_RESPONSE *response, BYTE *buffer, DWORD capacity, DWORD *out_len, BOOL *eof)
{
    DWORD got = 0;
    *out_len = 0;
    *eof = FALSE;

    if (response->is_head) {
        *eof = TRUE;
        return TRUE;
    }

    if (response->chunked) {
        return http_read_chunked_body(connection, response, buffer, capacity, out_len, eof);
    }

    if (response->content_length_known) {
        ULONGLONG remaining = response->content_length - response->body_read;
        if (remaining == 0) {
            *eof = TRUE;
            return TRUE;
        }
        if (remaining < capacity) {
            capacity = (DWORD)remaining;
        }
    }

    if (!connection_read_some(connection, buffer, capacity, &got)) {
        return FALSE;
    }
    if (got == 0) {
        *eof = TRUE;
        return TRUE;
    }
    response->body_read += got;
    response->saw_body_bytes = TRUE;
    *out_len = got;
    return TRUE;
}



static void segment_init(SEGMENT *segment, DWORD id, ULONGLONG start, ULONGLONG end, ULONGLONG downloaded, BOOL range_mode)
{
    ZeroMemory(segment, sizeof(*segment));
    segment->id = id;
    segment->state = (downloaded >= (end >= start ? (end - start + 1) : 0) && range_mode) ? SEGMENT_STATE_COMPLETE : SEGMENT_STATE_IDLE;
    segment->active = 0;
    segment->start = start;
    segment->original_end = end;
    segment->range_end = (LONGLONG)end;
    segment->requested_end = end;
    segment->downloaded = (LONGLONG)downloaded;
    segment->current_offset = (LONGLONG)(start + downloaded);
    segment->expected_size = (range_mode && end >= start) ? (end - start + 1) : downloaded;
    segment->can_split = range_mode;
    segment->range_mode = range_mode;
    if (range_mode && downloaded >= segment->expected_size) {
        segment->complete = TRUE;
        segment->state = SEGMENT_STATE_COMPLETE;
    }
    segment->write_event = CreateEventW(NULL, TRUE, FALSE, NULL);
}

static void build_fresh_ranged_segments(DWORD count)
{
    DWORD i;
    ULONGLONG segment_size;
    ULONGLONG offset = 0;

    if (count == 0) {
        count = 1;
    }
    if (count > DL_MAX_SEGMENTS) {
        count = DL_MAX_SEGMENTS;
    }

    g_dl.segment_count = count;
    g_dl.initial_segments = count;
    g_dl.max_segments = (count < (DL_MAX_SEGMENTS / 2)) ? min(DL_MAX_SEGMENTS, count * 2) : count;
    segment_size = g_dl.total_size / count;
    if (segment_size == 0) {
        segment_size = g_dl.total_size;
    }
    for (i = 0; i < count; ++i) {
        ULONGLONG start = offset;
        ULONGLONG end = (i == count - 1) ? (g_dl.total_size - 1) : (start + segment_size - 1);
        if (end >= g_dl.total_size) {
            end = g_dl.total_size - 1;
        }
        segment_init(&g_dl.segments[i], i, start, end, 0, TRUE);
        offset = end + 1;
    }
}

static BOOL rebuild_single_segment_resume(const STATE_SEGMENT *persisted, DWORD target_count)
{
    ULONGLONG completed_prefix = persisted[0].downloaded;
    DWORD active_count;
    ULONGLONG offset;
    ULONGLONG remaining;
    ULONGLONG segment_size;
    DWORD index = 0;
    DWORD i;
    SEGMENT probe_segment;

    if (completed_prefix > g_dl.total_size) {
        completed_prefix = g_dl.total_size;
    }

    if (completed_prefix > 0) {
        segment_init(&probe_segment, 0, persisted[0].start, persisted[0].start + completed_prefix - 1, completed_prefix, TRUE);
        probe_segment.expected_size = completed_prefix;
        if (!verify_segment_signature(g_dl.output_file, &probe_segment, completed_prefix, persisted[0].signature)) {
            completed_prefix = 0;
        }
    }

    if (completed_prefix > 0) {
        segment_init(&g_dl.segments[0], 0, persisted[0].start, persisted[0].start + completed_prefix - 1, completed_prefix, TRUE);
        g_dl.segments[0].expected_size = completed_prefix;
        g_dl.segments[0].complete = TRUE;
        g_dl.segments[0].state = SEGMENT_STATE_COMPLETE;
        segment_load_existing_signature(g_dl.output_file, &g_dl.segments[0], completed_prefix);
        g_dl.completed_segments = 1;
        g_dl.total_downloaded = completed_prefix;
        index = 1;
        offset = persisted[0].start + completed_prefix;
    } else {
        offset = persisted[0].start;
    }

    if (offset >= g_dl.total_size) {
        g_dl.segment_count = index ? index : 1;
        g_dl.initial_segments = target_count;
        {
            DWORD max_initial = max(target_count, g_dl.segment_count);
            g_dl.max_segments = (max_initial < (DL_MAX_SEGMENTS / 2)) ? min(DL_MAX_SEGMENTS, max_initial * 2) : max_initial;
        }
        if (index == 0) {
            segment_init(&g_dl.segments[0], 0, 0, g_dl.total_size ? (g_dl.total_size - 1) : 0, 0, TRUE);
        }
        return TRUE;
    }

    active_count = target_count;
    if (index > 0 && active_count > 1) {
        active_count -= 1;
    }
    if (active_count == 0) {
        active_count = 1;
    }
    if (index + active_count > DL_MAX_SEGMENTS) {
        active_count = DL_MAX_SEGMENTS - index;
    }

    remaining = g_dl.total_size - offset;
    if (remaining < active_count) {
        active_count = (DWORD)remaining;
        if (active_count == 0) {
            active_count = 1;
        }
    }

    segment_size = remaining / active_count;
    if (segment_size == 0) {
        segment_size = remaining;
    }

    for (i = 0; i < active_count; ++i) {
        ULONGLONG start = offset;
        ULONGLONG end = (i == active_count - 1) ? (g_dl.total_size - 1) : (start + segment_size - 1);
        if (end >= g_dl.total_size) {
            end = g_dl.total_size - 1;
        }
        segment_init(&g_dl.segments[index], index, start, end, 0, TRUE);
        offset = end + 1;
        ++index;
    }

    g_dl.segment_count = index;
    g_dl.initial_segments = target_count;
    {
        DWORD max_initial = max(target_count, g_dl.segment_count);
        g_dl.max_segments = (max_initial < (DL_MAX_SEGMENTS / 2)) ? min(DL_MAX_SEGMENTS, max_initial * 2) : max_initial;
    }
    return TRUE;
}

static BOOL split_segment_request(SEGMENT *segment)
{
    ULONGLONG current = (ULONGLONG)segment->current_offset;
    ULONGLONG end = (ULONGLONG)segment->range_end;
    ULONGLONG remaining;
    ULONGLONG midpoint;

    if (!segment->can_split || segment->split_request || segment->split_count >= 1) {
        return FALSE;
    }
    if (current >= end) {
        return FALSE;
    }
    remaining = (end - current) + 1;
    if (remaining < DL_SPLIT_THRESHOLD) {
        return FALSE;
    }
    midpoint = current + (remaining / 2) - 1;
    if (midpoint <= current || midpoint >= end) {
        return FALSE;
    }
    segment->requested_end = midpoint;
    InterlockedExchange(&segment->split_request, 1);
    return TRUE;
}

static BOOL spawn_child_segment(SEGMENT *parent, ULONGLONG start, ULONGLONG end)
{
    DWORD i;
    HANDLE thread_handle;
    if (start > end) {
        return TRUE;
    }

    EnterCriticalSection(&g_dl.segment_lock);
    if (g_dl.segment_count >= g_dl.max_segments) {
        LeaveCriticalSection(&g_dl.segment_lock);
        return FALSE;
    }
    i = g_dl.segment_count++;
    segment_init(&g_dl.segments[i], i, start, end, 0, TRUE);
    g_dl.segments[i].split_count = parent->split_count + 1;
    g_dl.segments[i].speed_ema = parent->speed_ema;
    LeaveCriticalSection(&g_dl.segment_lock);

    thread_handle = CreateThread(NULL, 0, segment_thread_proc, &g_dl.segments[i], 0, &g_dl.segments[i].thread_id);
    if (thread_handle == NULL) {
        mark_fatal_win32(L"CreateThread failed for child segment", GetLastError());
        return FALSE;
    }
    g_dl.segments[i].thread = thread_handle;
    SetThreadPriority(thread_handle, THREAD_PRIORITY_ABOVE_NORMAL);
    InterlockedIncrement(&g_dl.active_threads);
    return TRUE;
}

static BOOL overlapped_write_exact(HANDLE file, ULONGLONG offset, const BYTE *data, DWORD length, HANDLE event_handle)
{
    OVERLAPPED ovl;
    DWORD written = 0;
    ResetEvent(event_handle);
    ZeroMemory(&ovl, sizeof(ovl));
    ovl.Offset = (DWORD)(offset & 0xFFFFFFFFu);
    ovl.OffsetHigh = (DWORD)(offset >> 32);
    ovl.hEvent = event_handle;

    if (!WriteFile(file, data, length, NULL, &ovl)) {
        DWORD error = GetLastError();
        if (error != ERROR_IO_PENDING) {
            SetLastError(error);
            return FALSE;
        }
        if (!GetOverlappedResult(file, &ovl, &written, TRUE)) {
            return FALSE;
        }
    } else {
        written = length;
    }
    if (written != length) {
        SetLastError(ERROR_WRITE_FAULT);
        return FALSE;
    }
    return TRUE;
}

static DWORD rate_limit_acquire(DWORD desired, LONG active_segments)
{
    DWORD grant = desired;
    if (!g_dl.cfg.limit_rate_enabled || g_dl.cfg.limit_rate_bytes_per_sec <= 0.0) {
        return grant;
    }
    if (active_segments <= 0) {
        active_segments = 1;
    }

    for (;;) {
        LONGLONG now = qpc_now();
        double elapsed;
        double per_segment_cap;
        EnterCriticalSection(&g_dl.rate_lock);
        elapsed = qpc_seconds(now - g_dl.rate_last_qpc);
        if (elapsed > 0.0) {
            g_dl.rate_tokens += elapsed * g_dl.cfg.limit_rate_bytes_per_sec;
            if (g_dl.rate_tokens > g_dl.cfg.limit_rate_bytes_per_sec) {
                g_dl.rate_tokens = g_dl.cfg.limit_rate_bytes_per_sec;
            }
            g_dl.rate_last_qpc = now;
        }
        per_segment_cap = g_dl.cfg.limit_rate_bytes_per_sec / (double)active_segments;
        if (per_segment_cap < 1024.0) {
            per_segment_cap = 1024.0;
        }
        if ((double)grant > per_segment_cap) {
            grant = (DWORD)per_segment_cap;
        }
        if (grant == 0) {
            grant = 1024;
        }
        if (g_dl.rate_tokens >= (double)grant) {
            g_dl.rate_tokens -= (double)grant;
            LeaveCriticalSection(&g_dl.rate_lock);
            return grant;
        }
        LeaveCriticalSection(&g_dl.rate_lock);
        Sleep(DL_RATE_GRANULARITY_MS);
    }
}



static BOOL handle_segment_response_headers(SEGMENT *segment, HTTP_RESPONSE *response)
{
    if (segment->range_mode) {
        if (response->status_code == 206) {
            return TRUE;
        }
        if (response->status_code == 200) {
            mark_segment_failure(segment, L"server ignored Range and returned 200");
            return FALSE;
        }
        if (response->status_code >= 400) {
            mark_segment_failure(segment, L"HTTP error while downloading segment");
            return FALSE;
        }
        mark_segment_failure(segment, L"unexpected HTTP status for ranged download");
        return FALSE;
    }

    if (response->status_code >= 400) {
        mark_segment_failure(segment, L"HTTP error while downloading file");
        return FALSE;
    }
    return TRUE;
}

static DWORD WINAPI segment_thread_proc(LPVOID context)
{
    SEGMENT *segment = (SEGMENT *)context;
    BYTE *buffer = NULL;

    if (g_dl.logical_processors > 0 && g_dl.logical_processors <= 64) {
        DWORD index = segment->id % g_dl.logical_processors;
        SetThreadAffinityMask(GetCurrentThread(), ((DWORD_PTR)1) << index);
    }
    SetThreadPriority(GetCurrentThread(), THREAD_PRIORITY_ABOVE_NORMAL);

    buffer = (BYTE *)VirtualAlloc(NULL, g_dl.cfg.buffer_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (buffer == NULL) {
        mark_segment_failure(segment, L"VirtualAlloc failed for segment buffer");
        goto done;
    }

    while (!g_dl.stop_requested) {
        CONNECTION connection;
        HTTP_RESPONSE response;
        BOOL eof = FALSE;
        BOOL split_now = FALSE;
        ULONGLONG request_start;
        ULONGLONG request_end;

        if (segment->complete) {
            break;
        }

        request_start = segment->start + (ULONGLONG)segment->downloaded;
        request_end = segment->range_mode ? (ULONGLONG)segment->range_end : 0;

        if (segment->range_mode && request_start > request_end) {
            segment->complete = TRUE;
            segment->state = SEGMENT_STATE_COMPLETE;
            InterlockedIncrement(&g_dl.completed_segments);
            break;
        }

        segment->state = SEGMENT_STATE_RUNNING;
        segment->active = 1;

        if (!connection_open(&connection, &g_dl.final_parts, &segment->socket_slot)) {
            DWORD retries = (DWORD)InterlockedIncrement(&segment->retries);
            if (retries > DL_MAX_RETRIES) {
                mark_segment_failure(segment, L"connection failed too many times");
                segment->failed = TRUE;
                break;
            }
            Sleep(min((DWORD)(100u << min(retries, 5u)), 5000u));
            continue;
        }

        if (!http_send_request(&connection, "GET", &g_dl.final_parts, request_start, request_end, segment->range_mode)) {
            connection_close(&connection);
            {
                DWORD retries2 = (DWORD)InterlockedIncrement(&segment->retries);
                if (retries2 > DL_MAX_RETRIES) {
                    mark_segment_failure(segment, L"request send failed too many times");
                    segment->failed = TRUE;
                    break;
                }
                Sleep(min((DWORD)(100u << min(retries2, 5u)), 5000u));
            }
            continue;
        }

        if (!http_read_headers(&connection, &response)) {
            connection_close(&connection);
            {
                DWORD retries3 = (DWORD)InterlockedIncrement(&segment->retries);
                if (retries3 > DL_MAX_RETRIES) {
                    mark_segment_failure(segment, L"HTTP header read failed too many times");
                    segment->failed = TRUE;
                    break;
                }
                Sleep(min((DWORD)(100u << min(retries3, 5u)), 5000u));
            }
            continue;
        }

        if (!handle_segment_response_headers(segment, &response)) {
            connection_close(&connection);
            segment->failed = TRUE;
            break;
        }

        for (;;) {
            DWORD out_len = 0;
            DWORD allowed = g_dl.cfg.buffer_size;
            ULONGLONG remaining = 0;
            if (g_dl.stop_requested) {
                break;
            }
            if (segment->range_mode) {
                remaining = ((ULONGLONG)segment->range_end - (segment->start + (ULONGLONG)segment->downloaded)) + 1;
                if (remaining == 0) {
                    eof = TRUE;
                    break;
                }
                if (remaining < allowed) {
                    allowed = (DWORD)remaining;
                }
            }
            allowed = rate_limit_acquire(allowed, g_dl.active_threads);
            if (allowed == 0) {
                allowed = min((DWORD)remaining, 1024u);
            }
            if (!http_read_body(&connection, &response, buffer, allowed, &out_len, &eof)) {
                break;
            }
            if (out_len == 0) {
                if (eof) {
                    break;
                }
                continue;
            }

            if (segment->range_mode) {
                remaining = ((ULONGLONG)segment->range_end - (segment->start + (ULONGLONG)segment->downloaded)) + 1;
                if ((ULONGLONG)out_len > remaining) {
                    out_len = (DWORD)remaining;
                }
            }

            if (!overlapped_write_exact(
                g_dl.output_file,
                segment->start + (ULONGLONG)segment->downloaded,
                buffer,
                out_len,
                segment->write_event)) {
                DWORD write_error = GetLastError();
                if (write_error == ERROR_DISK_FULL) {
                    mark_segment_failure(segment, L"disk full");
                } else {
                    mark_fatal_win32(L"WriteFile failed", write_error);
                }
                segment->failed = TRUE;
                break;
            }

            segment_signature_update(segment, buffer, out_len);
            segment->downloaded += out_len;
            segment->current_offset = (LONGLONG)(segment->start + (ULONGLONG)segment->downloaded);
            segment->last_progress_qpc = qpc_now();
            InterlockedAdd64(&g_dl.total_downloaded, out_len);
            InterlockedExchange(&g_dl.state_dirty, 1);

            if (segment->split_request && !segment->spawned_child) {
                ULONGLONG old_end = (ULONGLONG)segment->range_end;
                ULONGLONG new_end = segment->requested_end;
                ULONGLONG next_offset = segment->start + (ULONGLONG)segment->downloaded;
                if (next_offset <= new_end && new_end < old_end) {
                    segment->range_end = (LONGLONG)new_end;
                    segment->expected_size = (new_end - segment->start) + 1;
                    segment->split_request = 0;
                    segment->spawned_child = TRUE;
                    if (!spawn_child_segment(segment, new_end + 1, old_end)) {
                        segment->failed = TRUE;
                        mark_segment_failure(segment, L"failed to spawn child segment");
                        break;
                    }
                    split_now = TRUE;
                    break;
                }
                segment->split_request = 0;
            }
        }

        connection_close(&connection);

        if (g_dl.stop_requested) {
            break;
        }

        if (segment->failed) {
            break;
        }

        if (split_now) {
            continue;
        }

        if (segment->range_mode) {
            if ((ULONGLONG)segment->downloaded >= segment->expected_size) {
                segment->complete = TRUE;
                segment->state = SEGMENT_STATE_COMPLETE;
                InterlockedIncrement(&g_dl.completed_segments);
                break;
            }
        } else if (eof) {
            segment->complete = TRUE;
            segment->state = SEGMENT_STATE_COMPLETE;
            InterlockedIncrement(&g_dl.completed_segments);
            break;
        }

        {
            DWORD retry_count = (DWORD)InterlockedIncrement(&segment->retries);
            if (retry_count > DL_MAX_RETRIES) {
                mark_segment_failure(segment, L"segment exhausted retries");
                segment->failed = TRUE;
                break;
            }
            Sleep(min((DWORD)(100u << min(retry_count, 5u)), 5000u));
        }
    }

done:
    segment->active = 0;
    if (buffer != NULL) {
        VirtualFree(buffer, 0, MEM_RELEASE);
    }
    InterlockedDecrement(&g_dl.active_threads);
    return 0;
}



static BOOL try_enable_privilege(LPCWSTR privilege_name)
{
    HANDLE token = NULL;
    TOKEN_PRIVILEGES tp;
    LUID luid;

    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &token)) {
        return FALSE;
    }
    if (!LookupPrivilegeValueW(NULL, privilege_name, &luid)) {
        CloseHandle(token);
        return FALSE;
    }
    ZeroMemory(&tp, sizeof(tp));
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    AdjustTokenPrivileges(token, FALSE, &tp, 0, NULL, NULL);
    CloseHandle(token);
    return (GetLastError() == ERROR_SUCCESS);
}

static void try_file_allocation_hint(HANDLE file, ULONGLONG size)
{
    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    IO_STATUS_BLOCK iosb;
    DL_FILE_ALLOCATION_INFORMATION info;

    if (ntdll == NULL) {
        return;
    }
    if (g_dl.nt_set_information_file == NULL) {
        g_dl.nt_set_information_file = (PFN_NTSETINFORMATIONFILE)GetProcAddress(ntdll, "NtSetInformationFile");
    }
    if (g_dl.nt_set_information_file == NULL) {
        return;
    }
    info.AllocationSize.QuadPart = size;
    ZeroMemory(&iosb, sizeof(iosb));
    g_dl.nt_set_information_file(file, &iosb, &info, sizeof(info), DL_FILE_ALLOCATION_CLASS);
}

static BOOL prepare_output_file(void)
{
    DWORD creation = CREATE_ALWAYS;
    DWORD state_attrs = INVALID_FILE_ATTRIBUTES;
    DWORD file_attrs = INVALID_FILE_ATTRIBUTES;

    if (!g_dl.cfg.no_resume) {
        state_attrs = GetFileAttributesW(g_dl.state_path);
        file_attrs = GetFileAttributesW(g_dl.output_path);
        if (state_attrs != INVALID_FILE_ATTRIBUTES && file_attrs != INVALID_FILE_ATTRIBUTES) {
            creation = OPEN_EXISTING;
        }
    }

    g_dl.output_file = CreateFileW(
        g_dl.output_path,
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        creation,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_OVERLAPPED,
        NULL);
    if (g_dl.output_file == INVALID_HANDLE_VALUE) {
        mark_fatal_win32(L"CreateFileW failed", GetLastError());
        return FALSE;
    }

    if (g_dl.size_known) {
        LARGE_INTEGER size;
        size.QuadPart = g_dl.total_size;
        try_file_allocation_hint(g_dl.output_file, g_dl.total_size);
        if (!SetFilePointerEx(g_dl.output_file, size, NULL, FILE_BEGIN)) {
            mark_fatal_win32(L"SetFilePointerEx failed", GetLastError());
            return FALSE;
        }
        if (!SetEndOfFile(g_dl.output_file)) {
            mark_fatal_win32(L"SetEndOfFile failed", GetLastError());
            return FALSE;
        }
        if (try_enable_privilege(SE_MANAGE_VOLUME_NAME)) {
            SetFileValidData(g_dl.output_file, g_dl.total_size);
        }
    }
    return TRUE;
}

static void state_write_u32(BYTE **cursor, DWORD value)
{
    memcpy(*cursor, &value, sizeof(value));
    *cursor += sizeof(value);
}

static void state_write_u64(BYTE **cursor, ULONGLONG value)
{
    memcpy(*cursor, &value, sizeof(value));
    *cursor += sizeof(value);
}

static BOOL save_state_file(void)
{
    HANDLE file = INVALID_HANDLE_VALUE;
    BYTE *buffer = NULL;
    BYTE *cursor;
    DWORD url_len;
    DWORD i;
    SIZE_T total_size;
    DWORD written = 0;
    BOOL ok = FALSE;

    if (g_dl.cfg.no_resume || !g_dl.size_known || g_dl.download_complete) {
        return TRUE;
    }

    EnterCriticalSection(&g_dl.state_lock);

    url_len = (DWORD)strlen(g_dl.probe.final_url);
    total_size = 4 + 4 + url_len + 8 + 4 + (g_dl.segment_count * (8 + 8 + 8 + 4));
    buffer = (BYTE *)VirtualAlloc(NULL, total_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (buffer == NULL) {
        LeaveCriticalSection(&g_dl.state_lock);
        return FALSE;
    }

    cursor = buffer;
    *cursor++ = DL_MAGIC0;
    *cursor++ = DL_MAGIC1;
    *cursor++ = DL_MAGIC2;
    *cursor++ = DL_MAGIC3;
    state_write_u32(&cursor, url_len);
    memcpy(cursor, g_dl.probe.final_url, url_len);
    cursor += url_len;
    state_write_u64(&cursor, g_dl.total_size);
    state_write_u32(&cursor, g_dl.segment_count);
    for (i = 0; i < g_dl.segment_count; ++i) {
        DWORD signature = segment_signature_finalize(&g_dl.segments[i]);
        state_write_u64(&cursor, g_dl.segments[i].start);
        state_write_u64(&cursor, (ULONGLONG)g_dl.segments[i].range_end);
        state_write_u64(&cursor, (ULONGLONG)g_dl.segments[i].downloaded);
        state_write_u32(&cursor, signature);
    }

    file = CreateFileW(g_dl.state_tmp_path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) {
        goto cleanup;
    }
    if (!WriteFile(file, buffer, (DWORD)(cursor - buffer), &written, NULL)) {
        goto cleanup;
    }
    FlushFileBuffers(file);
    CloseHandle(file);
    file = INVALID_HANDLE_VALUE;
    if (!MoveFileExW(g_dl.state_tmp_path, g_dl.state_path, MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        goto cleanup;
    }
    ok = TRUE;

cleanup:
    if (file != INVALID_HANDLE_VALUE) {
        CloseHandle(file);
    }
    if (buffer != NULL) {
        VirtualFree(buffer, 0, MEM_RELEASE);
    }
    LeaveCriticalSection(&g_dl.state_lock);
    return ok;
}

static BOOL load_state_file(STATE_SEGMENT *state_segments, DWORD *segment_count)
{
    HANDLE file = INVALID_HANDLE_VALUE;
    LARGE_INTEGER size;
    BYTE *buffer = NULL;
    BYTE *cursor;
    DWORD url_len = 0;
    DWORD count = 0;
    DWORD i;
    ULONGLONG state_total_size = 0;
    DWORD read_bytes = 0;

    if (g_dl.cfg.no_resume) {
        return FALSE;
    }
    file = CreateFileW(g_dl.state_path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) {
        return FALSE;
    }
    if (!GetFileSizeEx(file, &size) || size.QuadPart < 16) {
        CloseHandle(file);
        return FALSE;
    }

    buffer = (BYTE *)VirtualAlloc(NULL, (SIZE_T)size.QuadPart, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (buffer == NULL) {
        CloseHandle(file);
        return FALSE;
    }
    if (!ReadFile(file, buffer, (DWORD)size.QuadPart, &read_bytes, NULL) || read_bytes != (DWORD)size.QuadPart) {
        VirtualFree(buffer, 0, MEM_RELEASE);
        CloseHandle(file);
        return FALSE;
    }
    CloseHandle(file);

    cursor = buffer;
    if (cursor[0] != DL_MAGIC0 || cursor[1] != DL_MAGIC1 || cursor[2] != DL_MAGIC2 || cursor[3] != DL_MAGIC3) {
        VirtualFree(buffer, 0, MEM_RELEASE);
        return FALSE;
    }
    cursor += 4;
    memcpy(&url_len, cursor, sizeof(url_len));
    cursor += sizeof(url_len);
    if (url_len == 0 || url_len >= DL_MAX_STATE_URL || (cursor + url_len) > (buffer + size.QuadPart)) {
        VirtualFree(buffer, 0, MEM_RELEASE);
        return FALSE;
    }
    if (strlen(g_dl.probe.final_url) != url_len || memcmp(cursor, g_dl.probe.final_url, url_len) != 0) {
        VirtualFree(buffer, 0, MEM_RELEASE);
        return FALSE;
    }
    cursor += url_len;
    memcpy(&state_total_size, cursor, sizeof(state_total_size));
    cursor += sizeof(state_total_size);
    if (state_total_size != g_dl.total_size) {
        VirtualFree(buffer, 0, MEM_RELEASE);
        return FALSE;
    }
    memcpy(&count, cursor, sizeof(count));
    cursor += sizeof(count);
    if (count == 0 || count > DL_MAX_SEGMENTS) {
        VirtualFree(buffer, 0, MEM_RELEASE);
        return FALSE;
    }

    for (i = 0; i < count; ++i) {
        memcpy(&state_segments[i].start, cursor, sizeof(ULONGLONG));
        cursor += sizeof(ULONGLONG);
        memcpy(&state_segments[i].end, cursor, sizeof(ULONGLONG));
        cursor += sizeof(ULONGLONG);
        memcpy(&state_segments[i].downloaded, cursor, sizeof(ULONGLONG));
        cursor += sizeof(ULONGLONG);
        memcpy(&state_segments[i].signature, cursor, sizeof(DWORD));
        cursor += sizeof(DWORD);
    }
    *segment_count = count;
    VirtualFree(buffer, 0, MEM_RELEASE);
    return TRUE;
}



static void display_progress(void)
{
    WCHAR line[DL_MAX_PROGRESS_TEXT];
    WCHAR spaces[256];
    WCHAR done_buf[64];
    WCHAR total_buf[64];
    WCHAR speed_buf[64];
    WCHAR eta_buf[64];
    WCHAR name_buf[DL_MAX_FILENAME];
    WCHAR *file_name = wcsrchr(g_dl.output_path, L'\\');
    double speed = g_dl.total_speed_ema;
    double percent = 0.0;
    double eta = 0.0;
    ULONGLONG downloaded = (ULONGLONG)g_dl.total_downloaded;
    size_t line_len = 0;

    if (g_dl.cfg.quiet) {
        return;
    }

    if (file_name == NULL) {
        file_name = g_dl.output_path;
    } else {
        ++file_name;
    }
    safe_copy_w(name_buf, ARRAYSIZE(name_buf), file_name);
    format_bytes((double)downloaded, done_buf, ARRAYSIZE(done_buf));
    if (g_dl.size_known) {
        format_bytes((double)g_dl.total_size, total_buf, ARRAYSIZE(total_buf));
        percent = (g_dl.total_size == 0) ? 100.0 : (100.0 * (double)downloaded / (double)g_dl.total_size);
        if (speed > 0.0 && downloaded <= g_dl.total_size) {
            eta = (double)(g_dl.total_size - downloaded) / speed;
        }
    } else {
        StringCchCopyW(total_buf, ARRAYSIZE(total_buf), L"?");
    }
    format_bytes(speed, speed_buf, ARRAYSIZE(speed_buf));
    format_eta(eta, eta_buf, ARRAYSIZE(eta_buf));

    StringCchPrintfW(line, ARRAYSIZE(line),
        L"[%s] %5.1f%% | %s / %s | %s/s | ETA %s | [%lu segments]",
        name_buf,
        percent,
        done_buf,
        total_buf,
        speed_buf,
        eta_buf,
        g_dl.segment_count);
    StringCchLengthW(line, ARRAYSIZE(line), &line_len);

    EnterCriticalSection(&g_dl.print_lock);
    if (g_dl.vt_enabled) {
        write_stdout(L"\r\x1b[2K");
        write_stdout(line);
    } else {
        DWORD pad = 0;
        write_stdout(L"\r");
        write_stdout(line);
        if (g_dl.last_progress_chars > (DWORD)line_len) {
            pad = g_dl.last_progress_chars - (DWORD)line_len;
            while (pad > 0) {
                DWORD chunk = pad;
                DWORD i;
                if (chunk >= ARRAYSIZE(spaces)) {
                    chunk = ARRAYSIZE(spaces) - 1;
                }
                for (i = 0; i < chunk; ++i) {
                    spaces[i] = L' ';
                }
                spaces[chunk] = L'\0';
                write_stdout(spaces);
                pad -= chunk;
            }
        }
    }
    g_dl.last_progress_chars = (DWORD)line_len;
    if (g_dl.cfg.verbose) {
        WCHAR verbose_line[DL_MAX_PROGRESS_TEXT];
        DWORD i;
        StringCchCopyW(verbose_line, ARRAYSIZE(verbose_line), L"\n");
        for (i = 0; i < g_dl.segment_count; ++i) {
            WCHAR seg_speed[64];
            WCHAR seg_done[64];
            format_bytes(g_dl.segments[i].speed_ema, seg_speed, ARRAYSIZE(seg_speed));
            format_bytes((double)g_dl.segments[i].downloaded, seg_done, ARRAYSIZE(seg_done));
            StringCchPrintfW(verbose_line + wcslen(verbose_line),
                ARRAYSIZE(verbose_line) - wcslen(verbose_line),
                L"  #%lu %s %s/s\n",
                g_dl.segments[i].id,
                seg_done,
                seg_speed);
        }
        write_stdout(verbose_line);
    }
    LeaveCriticalSection(&g_dl.print_lock);
}



static void rate_limiter_initialize(void)
{
    g_dl.rate_tokens = g_dl.cfg.limit_rate_enabled ? g_dl.cfg.limit_rate_bytes_per_sec : 0.0;
    g_dl.rate_last_qpc = qpc_now();
}



static BOOL WINAPI console_ctrl_handler(DWORD ctrl_type)
{
    switch (ctrl_type) {
    case CTRL_C_EVENT:
    case CTRL_BREAK_EVENT:
    case CTRL_CLOSE_EVENT:
    case CTRL_SHUTDOWN_EVENT:
        InterlockedExchange(&g_dl.stop_requested, 1);
        return TRUE;
    default:
        return FALSE;
    }
}

static void runtime_reset(void)
{
    ZeroMemory(&g_dl, sizeof(g_dl));
    g_dl.output_file = INVALID_HANDLE_VALUE;
    g_dl.stdout_handle = GetStdHandle(STD_OUTPUT_HANDLE);
    g_dl.stderr_handle = GetStdHandle(STD_ERROR_HANDLE);
    InitializeCriticalSection(&g_dl.print_lock);
    InitializeCriticalSection(&g_dl.state_lock);
    InitializeCriticalSection(&g_dl.rate_lock);
    InitializeCriticalSection(&g_dl.segment_lock);
    InitializeSRWLock(&g_dl.dns_lock);
    QueryPerformanceFrequency(&g_dl.qpc_freq);
    g_dl.logical_processors = GetActiveProcessorCount(ALL_PROCESSOR_GROUPS);
    if (g_dl.logical_processors == 0) {
        g_dl.logical_processors = 1;
    }
}

static BOOL initialize_runtime(void)
{
    WSADATA wsa;
    DWORD mode = 0;
    crc32_init();

    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        mark_fatal_message(L"WSAStartup failed");
        return FALSE;
    }

    if (GetConsoleMode(g_dl.stdout_handle, &mode)) {
        if (SetConsoleMode(g_dl.stdout_handle, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING)) {
            g_dl.vt_enabled = TRUE;
        }
    }

    rate_limiter_initialize();
    SetConsoleCtrlHandler(console_ctrl_handler, TRUE);
    return TRUE;
}

static void cleanup_runtime(void)
{
    DWORD i;
    if (g_dl.output_file != INVALID_HANDLE_VALUE) {
        CloseHandle(g_dl.output_file);
        g_dl.output_file = INVALID_HANDLE_VALUE;
    }
    if (g_dl.progress_thread != NULL) {
        CloseHandle(g_dl.progress_thread);
        g_dl.progress_thread = NULL;
    }
    for (i = 0; i < g_dl.segment_count; ++i) {
        if (g_dl.segments[i].thread != NULL) {
            CloseHandle(g_dl.segments[i].thread);
            g_dl.segments[i].thread = NULL;
        }
        if (g_dl.segments[i].write_event != NULL) {
            CloseHandle(g_dl.segments[i].write_event);
            g_dl.segments[i].write_event = NULL;
        }
    }
    if (g_dl.schannel_cred_ready) {
        FreeCredentialsHandle(&g_dl.schannel_cred);
        g_dl.schannel_cred_ready = FALSE;
    }
    SetConsoleCtrlHandler(console_ctrl_handler, FALSE);
    WSACleanup();
    DeleteCriticalSection(&g_dl.segment_lock);
    DeleteCriticalSection(&g_dl.rate_lock);
    DeleteCriticalSection(&g_dl.state_lock);
    DeleteCriticalSection(&g_dl.print_lock);
}



static BOOL parse_arguments(int argc, WCHAR **argv)
{
    int i;
    ZeroMemory(&g_dl.cfg, sizeof(g_dl.cfg));
    g_dl.cfg.buffer_size = DL_DEFAULT_BUFFER;

    for (i = 1; i < argc; ++i) {
        if (wcscmp(argv[i], L"--help") == 0) {
            g_dl.cfg.show_help = TRUE;
            return TRUE;
        }
        if (wcscmp(argv[i], L"--version") == 0) {
            g_dl.cfg.show_version = TRUE;
            return TRUE;
        }
    }

    for (i = 1; i < argc; ++i) {
        if (wcscmp(argv[i], L"-o") == 0) {
            if (i + 1 >= argc) {
                mark_fatal_message(L"-o requires a filename");
                return FALSE;
            }
            safe_copy_w(g_dl.cfg.output_path, ARRAYSIZE(g_dl.cfg.output_path), argv[++i]);
            g_dl.cfg.output_explicit = TRUE;
        } else if (wcscmp(argv[i], L"-j") == 0) {
            ULONGLONG parsed = 0;
            if (i + 1 >= argc || !parse_uint64_with_suffix(argv[++i], &parsed) || parsed == 0 || parsed > DL_MAX_SEGMENTS) {
                mark_fatal_message(L"-j expects a segment count between 1 and 64");
                return FALSE;
            }
            g_dl.cfg.segment_override = (DWORD)parsed;
        } else if (wcscmp(argv[i], L"-b") == 0) {
            ULONGLONG parsed2 = 0;
            if (i + 1 >= argc || !parse_uint64_with_suffix(argv[++i], &parsed2) || parsed2 < DL_MIN_BUFFER || parsed2 > (64ull * 1024ull * 1024ull)) {
                mark_fatal_message(L"-b expects a buffer size between 16K and 64M");
                return FALSE;
            }
            g_dl.cfg.buffer_size = (DWORD)parsed2;
        } else if (wcscmp(argv[i], L"--no-resume") == 0) {
            g_dl.cfg.no_resume = TRUE;
        } else if (wcscmp(argv[i], L"--insecure") == 0) {
            g_dl.cfg.insecure = TRUE;
        } else if (wcscmp(argv[i], L"-v") == 0) {
            g_dl.cfg.verbose = TRUE;
        } else if (wcscmp(argv[i], L"-q") == 0) {
            g_dl.cfg.quiet = TRUE;
        } else if (wcscmp(argv[i], L"--limit-rate") == 0) {
            ULONGLONG parsed3 = 0;
            if (i + 1 >= argc || !parse_uint64_with_suffix(argv[++i], &parsed3) || parsed3 == 0) {
                mark_fatal_message(L"--limit-rate expects a positive rate like 10M or 500K");
                return FALSE;
            }
            g_dl.cfg.limit_rate_enabled = TRUE;
            g_dl.cfg.limit_rate_bytes_per_sec = (double)parsed3;
        } else if (argv[i][0] == L'-') {
            mark_fatal_message(L"unknown option");
            return FALSE;
        } else if (g_dl.cfg.url[0] == 0) {
            if (!wide_to_utf8(argv[i], g_dl.cfg.url, ARRAYSIZE(g_dl.cfg.url))) {
                mark_fatal_message(L"failed to convert URL to UTF-8");
                return FALSE;
            }
        } else {
            mark_fatal_message(L"only one URL is supported");
            return FALSE;
        }
    }

    if (g_dl.cfg.url[0] == 0) {
        mark_fatal_message(L"missing URL");
        return FALSE;
    }
    return TRUE;
}

static void print_help(void)
{
    write_stdout(
        L"Usage:\n"
        L"  dl <url>\n"
        L"  dl <url> -o <filename>\n"
        L"  dl <url> -j <num>\n"
        L"  dl <url> -b <bytes>\n"
        L"  dl <url> --no-resume\n"
        L"  dl <url> --insecure\n"
        L"  dl <url> -v\n"
        L"  dl <url> -q\n"
        L"  dl <url> --limit-rate <speed>\n"
        L"  dl --install\n"
        L"  dl --version\n"
        L"  dl --help\n"
        L"\n"
        L"Defaults:\n"
        L"  buffer: 4 MiB\n"
        L"  auto segments: 4 / 8 / 16 / 24 / 48 / 64 by file size\n"
        L"  retries: 10 per segment\n");
}

static void print_version(void)
{
    write_stdout(L"" DL_VERSION_W L"\n");
}



static BOOL probe_once(const char *url, const char *method, BOOL range_probe, PROBE_RESULT *probe, HTTP_RESPONSE *response)
{
    CONNECTION connection;
    URL_PARTS parts;
    if (!parse_url(url, &parts)) {
        mark_fatal_message(L"invalid URL");
        return FALSE;
    }
    if (!connection_open(&connection, &parts, NULL)) {
        mark_fatal_message(L"failed to connect to host");
        return FALSE;
    }
    if (!http_send_request(&connection, method, &parts, 0, 0, range_probe)) {
        connection_close(&connection);
        mark_fatal_message(L"failed to send probe request");
        return FALSE;
    }
    if (!http_read_headers(&connection, response)) {
        connection_close(&connection);
        mark_fatal_message(L"failed to read probe response headers");
        return FALSE;
    }
    probe->parts = parts;
    connection_close(&connection);
    return TRUE;
}

static BOOL probe_target(PROBE_RESULT *probe)
{
    char current_url[DL_MAX_URL];
    DWORD redirects = 0;

    ZeroMemory(probe, sizeof(*probe));
    safe_copy_a(current_url, ARRAYSIZE(current_url), g_dl.cfg.url);

    for (;;) {
        HTTP_RESPONSE response;
        if (!probe_once(current_url, "HEAD", FALSE, probe, &response)) {
            return FALSE;
        }

        if ((response.status_code == 301 || response.status_code == 302 || response.status_code == 303 ||
            response.status_code == 307 || response.status_code == 308) && response.location[0] != 0) {
            if (++redirects > DL_MAX_REDIRECTS) {
                mark_fatal_message(L"too many redirects");
                return FALSE;
            }
            if (!resolve_redirect_url(current_url, response.location, current_url, ARRAYSIZE(current_url))) {
                mark_fatal_message(L"failed to resolve redirect URL");
                return FALSE;
            }
            continue;
        }

        if (response.status_code >= 400 && response.status_code != 405 && response.status_code != 501) {
            WCHAR message[128];
            StringCchPrintfW(message, ARRAYSIZE(message), L"HTTP %d during probe", response.status_code);
            mark_fatal_message(message);
            return FALSE;
        }

        probe->chunked = response.chunked;
        probe->size_known = response.content_length_known;
        probe->total_size = response.content_length;
        probe->accept_ranges = response.accept_ranges;
        safe_copy_a(probe->final_url, ARRAYSIZE(probe->final_url), current_url);
        if (response.content_disposition[0] != 0) {
            extract_filename_from_content_disposition(response.content_disposition, probe->filename_from_header, ARRAYSIZE(probe->filename_from_header));
        }

        {
            HTTP_RESPONSE get0;
            if (!probe_once(current_url, "GET", TRUE, probe, &get0)) {
                return FALSE;
            }
            if (get0.status_code == 206 && get0.content_range_known) {
                probe->accept_ranges = TRUE;
                probe->size_known = TRUE;
                probe->total_size = get0.content_range_total;
            } else if (!probe->size_known && get0.content_length_known) {
                probe->size_known = TRUE;
                probe->total_size = get0.content_length;
            }
            if (get0.content_disposition[0] != 0 && probe->filename_from_header[0] == 0) {
                extract_filename_from_content_disposition(get0.content_disposition, probe->filename_from_header, ARRAYSIZE(probe->filename_from_header));
            }
        }
        return TRUE;
    }
}

static BOOL determine_output_path(const PROBE_RESULT *probe)
{
    WCHAR name[DL_MAX_FILENAME];
    const char *base;
    char temp[DL_MAX_FILENAME];
    const char *slash;
    WCHAR cwd[MAX_PATH * 4];

    if (g_dl.cfg.output_explicit) {
        safe_copy_w(g_dl.output_path, ARRAYSIZE(g_dl.output_path), g_dl.cfg.output_path);
    } else if (probe->filename_from_header[0] != 0) {
        safe_copy_w(name, ARRAYSIZE(name), probe->filename_from_header);
        sanitize_filename_w(name);
        safe_copy_w(g_dl.output_path, ARRAYSIZE(g_dl.output_path), name);
    } else {
        base = strrchr(probe->parts.path, '/');
        if (base == NULL) {
            base = probe->parts.path;
        } else {
            ++base;
        }
        slash = strchr(base, '?');
        if (slash == NULL) {
            slash = base + strlen(base);
        }
        if (slash > base && (size_t)(slash - base) < sizeof(temp)) {
            memcpy(temp, base, (size_t)(slash - base));
            temp[slash - base] = 0;
        } else {
            temp[0] = 0;
        }
        if (temp[0] != 0 && utf8_to_wide(temp, name, ARRAYSIZE(name)) && has_file_extension_w(name)) {
            sanitize_filename_w(name);
            safe_copy_w(g_dl.output_path, ARRAYSIZE(g_dl.output_path), name);
        } else {
            safe_copy_w(g_dl.output_path, ARRAYSIZE(g_dl.output_path), L"download.bin");
        }
    }

    if (!g_dl.cfg.output_explicit) {
        if (GetFullPathNameW(g_dl.output_path, ARRAYSIZE(g_dl.output_path), cwd, NULL) > 0) {
            safe_copy_w(g_dl.output_path, ARRAYSIZE(g_dl.output_path), cwd);
        }
    }

    StringCchPrintfW(g_dl.state_path, ARRAYSIZE(g_dl.state_path), L"%s.dl.state", g_dl.output_path);
    StringCchPrintfW(g_dl.state_tmp_path, ARRAYSIZE(g_dl.state_tmp_path), L"%s.tmp", g_dl.state_path);
    return TRUE;
}

static BOOL initialize_segments_from_state_or_fresh(void)
{
    STATE_SEGMENT persisted[DL_MAX_SEGMENTS];
    DWORD persisted_count = 0;
    DWORD i;
    DWORD target_count;

    ZeroMemory(persisted, sizeof(persisted));

    g_dl.range_supported = (g_dl.probe.accept_ranges && g_dl.probe.size_known && g_dl.probe.total_size > DL_SEGMENT_THRESHOLD);
    g_dl.size_known = g_dl.probe.size_known;
    g_dl.total_size = g_dl.probe.total_size;
    g_dl.total_downloaded = 0;
    target_count = g_dl.range_supported ? initial_segment_target() : 1;

    if (g_dl.range_supported && load_state_file(persisted, &persisted_count)) {
        g_dl.resume_loaded = TRUE;
        if (persisted_count == 1 && target_count > 1) {
            return rebuild_single_segment_resume(persisted, target_count);
        }
        g_dl.segment_count = persisted_count;
        g_dl.initial_segments = max(target_count, persisted_count);
        g_dl.max_segments = (g_dl.initial_segments < (DL_MAX_SEGMENTS / 2))
            ? min(DL_MAX_SEGMENTS, g_dl.initial_segments * 2)
            : g_dl.initial_segments;
        for (i = 0; i < persisted_count; ++i) {
            ULONGLONG expected_size = persisted[i].end - persisted[i].start + 1;
            if (persisted[i].downloaded > expected_size) {
                persisted[i].downloaded = 0;
            }
            segment_init(&g_dl.segments[i], i, persisted[i].start, persisted[i].end, persisted[i].downloaded, TRUE);
            g_dl.segments[i].expected_size = expected_size;
            if (persisted[i].downloaded > 0) {
                if (!verify_segment_signature(g_dl.output_file, &g_dl.segments[i], persisted[i].downloaded, persisted[i].signature)) {
                    g_dl.segments[i].downloaded = 0;
                    g_dl.segments[i].current_offset = (LONGLONG)g_dl.segments[i].start;
                    g_dl.segments[i].state = SEGMENT_STATE_IDLE;
                    g_dl.segments[i].complete = FALSE;
                    g_dl.segments[i].prefix_len = 0;
                    g_dl.segments[i].suffix_len = 0;
                } else if (persisted[i].downloaded == expected_size) {
                    g_dl.segments[i].complete = TRUE;
                    g_dl.segments[i].state = SEGMENT_STATE_COMPLETE;
                    ++g_dl.completed_segments;
                }
            }
            g_dl.total_downloaded += g_dl.segments[i].downloaded;
        }
        return TRUE;
    }

    if (!g_dl.range_supported) {
        g_dl.segment_count = 1;
        g_dl.initial_segments = 1;
        g_dl.max_segments = 1;
        segment_init(&g_dl.segments[0], 0, 0, g_dl.size_known ? (g_dl.total_size ? g_dl.total_size - 1 : 0) : 0, 0, FALSE);
        return TRUE;
    }

    build_fresh_ranged_segments(target_count);
    return TRUE;
}

static BOOL start_initial_segments(void)
{
    DWORD i;
    for (i = 0; i < g_dl.segment_count; ++i) {
        if (g_dl.segments[i].complete) {
            continue;
        }
        g_dl.segments[i].thread = CreateThread(NULL, 0, segment_thread_proc, &g_dl.segments[i], 0, &g_dl.segments[i].thread_id);
        if (g_dl.segments[i].thread == NULL) {
            mark_fatal_win32(L"CreateThread failed", GetLastError());
            return FALSE;
        }
        SetThreadPriority(g_dl.segments[i].thread, THREAD_PRIORITY_ABOVE_NORMAL);
        InterlockedIncrement(&g_dl.active_threads);
    }
    return TRUE;
}

static DWORD WINAPI progress_thread_proc(LPVOID context)
{
    UNREFERENCED_PARAMETER(context);
    while (!g_dl.progress_stop) {
        DWORD i;
        LONGLONG now = qpc_now();
        double dt = qpc_seconds(now - g_dl.progress_last_qpc);
        ULONGLONG total = (ULONGLONG)g_dl.total_downloaded;
        if (dt > 0.0) {
            double inst = (double)(total - (ULONGLONG)g_dl.progress_last_bytes) / dt;
            if (g_dl.total_speed_ema == 0.0) {
                g_dl.total_speed_ema = inst;
            } else {
                g_dl.total_speed_ema = (g_dl.total_speed_ema * 0.7) + (inst * 0.3);
            }
            if (inst > g_dl.peak_speed_ema) {
                g_dl.peak_speed_ema = inst;
            }
            g_dl.progress_last_qpc = now;
            g_dl.progress_last_bytes = (LONGLONG)total;
        }

        for (i = 0; i < g_dl.segment_count; ++i) {
            SEGMENT *segment = &g_dl.segments[i];
            ULONGLONG sampled = (ULONGLONG)segment->downloaded;
            double seg_inst = (double)(sampled - (ULONGLONG)segment->last_sample_bytes) / max(dt, 0.001);
            if (segment->speed_ema == 0.0) {
                segment->speed_ema = seg_inst;
            } else {
                segment->speed_ema = (segment->speed_ema * 0.7) + (seg_inst * 0.3);
            }
            segment->last_sample_bytes = sampled;
        }

        if (!g_dl.cfg.quiet) {
            display_progress();
        }

        if (InterlockedExchange(&g_dl.state_dirty, 0) != 0) {
            static DWORD state_counter = 0;
            state_counter += DL_PROGRESS_INTERVAL_MS;
            if (state_counter >= DL_STATE_INTERVAL_MS) {
                save_state_file();
                state_counter = 0;
            }
        }

        if (g_dl.range_supported && g_dl.segment_count < g_dl.max_segments) {
            double avg_speed = 0.0;
            DWORD active = 0;
            for (i = 0; i < g_dl.segment_count; ++i) {
                if (!g_dl.segments[i].complete && g_dl.segments[i].speed_ema > 0.0) {
                    avg_speed += g_dl.segments[i].speed_ema;
                    ++active;
                }
            }
            if (active > 1) {
                avg_speed /= active;
                for (i = 0; i < g_dl.segment_count; ++i) {
                    SEGMENT *segment = &g_dl.segments[i];
                    ULONGLONG remaining;
                    if (segment->complete || segment->split_request || segment->spawned_child) {
                        continue;
                    }
                    remaining = ((ULONGLONG)segment->range_end >= (segment->start + (ULONGLONG)segment->downloaded))
                        ? (((ULONGLONG)segment->range_end - (segment->start + (ULONGLONG)segment->downloaded)) + 1)
                        : 0;
                    if (remaining < DL_SPLIT_THRESHOLD) {
                        continue;
                    }
                    if (segment->speed_ema > 0.0 && segment->speed_ema < (avg_speed * 0.25) && g_dl.completed_segments > 0) {
                        if (split_segment_request(segment)) {
                            break;
                        }
                    }
                }
            }
        }

        for (i = 0; i < g_dl.segment_count; ++i) {
            SEGMENT *segment2 = &g_dl.segments[i];
            SOCKET socket_fd = (SOCKET)(ULONG_PTR)segment2->socket_slot;
            if (segment2->complete || socket_fd == INVALID_SOCKET || socket_fd == 0) {
                continue;
            }
            if (segment2->last_progress_qpc != 0 &&
                qpc_seconds(now - segment2->last_progress_qpc) > (double)DL_SEGMENT_TIMEOUT_MS / 1000.0) {
                shutdown(socket_fd, SD_BOTH);
                closesocket(socket_fd);
                InterlockedExchangePointer((PVOID volatile *)&segment2->socket_slot, (PVOID)(ULONG_PTR)INVALID_SOCKET);
            }
        }

        if (g_dl.active_threads == 0) {
            break;
        }
        Sleep(DL_PROGRESS_INTERVAL_MS);
    }
    return 0;
}

static BOOL wait_for_completion(void)
{
    g_dl.download_start_qpc = qpc_now();
    g_dl.progress_last_qpc = g_dl.download_start_qpc;
    g_dl.progress_last_bytes = g_dl.total_downloaded;
    g_dl.progress_thread = CreateThread(NULL, 0, progress_thread_proc, NULL, 0, NULL);
    if (g_dl.progress_thread == NULL) {
        mark_fatal_win32(L"CreateThread failed for progress thread", GetLastError());
        return FALSE;
    }

    while (g_dl.active_threads > 0 && !g_dl.fatal_error) {
        Sleep(100);
    }
    g_dl.progress_stop = 1;
    WaitForSingleObject(g_dl.progress_thread, INFINITE);

    if (g_dl.fatal_error) {
        return FALSE;
    }
    if (g_dl.stop_requested && !g_dl.download_complete) {
        return FALSE;
    }
    return TRUE;
}

static void finalize_success(void)
{
    g_dl.download_complete = TRUE;
    FlushFileBuffers(g_dl.output_file);
    DeleteFileW(g_dl.state_path);
    DeleteFileW(g_dl.state_tmp_path);
    if (!g_dl.cfg.quiet) {
        WCHAR summary[DL_MAX_PROGRESS_TEXT];
        WCHAR size_buf[64];
        WCHAR avg_buf[64];
        WCHAR peak_buf[64];
        WCHAR elapsed_buf[64];
        WCHAR *file_name = wcsrchr(g_dl.output_path, L'\\');
        double elapsed = qpc_seconds(qpc_now() - g_dl.download_start_qpc);
        double average_speed = (elapsed > 0.0) ? ((double)(ULONGLONG)g_dl.total_downloaded / elapsed) : 0.0;

        if (file_name == NULL) {
            file_name = g_dl.output_path;
        } else {
            ++file_name;
        }
        format_bytes((double)(ULONGLONG)g_dl.total_downloaded, size_buf, ARRAYSIZE(size_buf));
        format_bytes(average_speed, avg_buf, ARRAYSIZE(avg_buf));
        format_bytes(g_dl.peak_speed_ema, peak_buf, ARRAYSIZE(peak_buf));
        format_eta(elapsed, elapsed_buf, ARRAYSIZE(elapsed_buf));
        write_stdout(L"\n");
        StringCchPrintfW(summary, ARRAYSIZE(summary),
            L"%s done | %s in %s | avg %s/s | peak %s/s\n",
            file_name,
            size_buf,
            elapsed_buf,
            avg_buf,
            peak_buf);
        write_stdout(summary);
    }
}

static int run_install_mode(void)
{
    if (!install_self_copy(FALSE)) {
        log_error(L"%s\n", g_dl.error_text[0] ? g_dl.error_text : L"install failed");
        return 1;
    }
    return 0;
}

static int run_apply_update_mode(int argc, WCHAR **argv)
{
    DWORD parent_pid = 0;
    HANDLE parent = NULL;
    DWORD wait_result = WAIT_OBJECT_0;
    DWORD attempts;

    if (argc < 5) {
        log_error(L"internal updater arguments are incomplete\n");
        return 1;
    }

    parent_pid = wcstoul(argv[4], NULL, 10);
    if (parent_pid != 0) {
        parent = OpenProcess(SYNCHRONIZE, FALSE, parent_pid);
        if (parent != NULL) {
            wait_result = WaitForSingleObject(parent, 30000);
            CloseHandle(parent);
            if (wait_result != WAIT_OBJECT_0 && wait_result != WAIT_TIMEOUT) {
                log_error(L"failed waiting for old process to exit\n");
                return 1;
            }
        }
    }

    for (attempts = 0; attempts < 60; ++attempts) {
        if (MoveFileExW(argv[3], argv[2], MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH | MOVEFILE_COPY_ALLOWED)) {
            break;
        }
        Sleep(250);
    }
    if (attempts == 60) {
        log_error(L"failed to swap in the new build\n");
        return 1;
    }

    if (argc >= 6 && argv[5][0] != L'\0') {
        STARTUPINFOW si;
        PROCESS_INFORMATION pi;
        WCHAR relaunch[DL_MAX_COMMAND_LINE];

        ZeroMemory(&si, sizeof(si));
        ZeroMemory(&pi, sizeof(pi));
        si.cb = sizeof(si);
        safe_copy_w(relaunch, ARRAYSIZE(relaunch), argv[5]);
        SetEnvironmentVariableW(DL_UPDATE_CHECK_ENV, L"1");
        if (CreateProcessW(NULL, relaunch, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
        }
    }

    return 0;
}

static int run_download_job(void)
{
    int exit_code = 1;

    if (!initialize_runtime()) {
        if (g_dl.error_text[0] != 0) {
            log_error(L"%s\n", g_dl.error_text);
        }
        cleanup_runtime();
        return 1;
    }

    if (!probe_target(&g_dl.probe)) {
        log_error(L"%s\n", g_dl.error_text[0] ? g_dl.error_text : L"probe failed");
        cleanup_runtime();
        return 1;
    }

    g_dl.final_parts = g_dl.probe.parts;
    if (!determine_output_path(&g_dl.probe)) {
        log_error(L"%s\n", g_dl.error_text[0] ? g_dl.error_text : L"failed to determine output path");
        cleanup_runtime();
        return 1;
    }

    if (!prepare_output_file()) {
        log_error(L"%s\n", g_dl.error_text[0] ? g_dl.error_text : L"failed to prepare output file");
        cleanup_runtime();
        return 1;
    }

    if (!initialize_segments_from_state_or_fresh()) {
        log_error(L"%s\n", g_dl.error_text[0] ? g_dl.error_text : L"failed to initialize segments");
        cleanup_runtime();
        return 1;
    }

    if (g_dl.size_known && g_dl.total_size == 0) {
        finalize_success();
        cleanup_runtime();
        return 0;
    }

    if (!start_initial_segments()) {
        log_error(L"%s\n", g_dl.error_text[0] ? g_dl.error_text : L"failed to start download threads");
        cleanup_runtime();
        return 1;
    }

    if (wait_for_completion()) {
        finalize_success();
        exit_code = 0;
    } else {
        save_state_file();
        if (g_dl.fatal_error) {
            log_error(L"\n%s\n", g_dl.error_text[0] ? g_dl.error_text : L"download failed");
        } else if (g_dl.stop_requested) {
            log_error(L"\ninterrupted, state saved to %s\n", g_dl.state_path);
        }
        exit_code = 1;
    }

    cleanup_runtime();
    return exit_code;
}

int wmain(int argc, WCHAR **argv)
{
    runtime_reset();
    if (argc >= 2 && wcscmp(argv[1], L"--install") == 0) {
        return run_install_mode();
    }
    if (argc >= 2 && wcscmp(argv[1], L"--apply-update") == 0) {
        return run_apply_update_mode(argc, argv);
    }
    if (!parse_arguments(argc, argv)) {
        if (g_dl.error_text[0] != 0) {
            log_error(L"%s\n", g_dl.error_text);
        }
        return 1;
    }

    if (g_dl.cfg.show_help) {
        print_help();
        return 0;
    }
    if (g_dl.cfg.show_version) {
        print_version();
        return 0;
    }
    if (maybe_offer_auto_update()) {
        return 0;
    }
    return run_download_job();
}
