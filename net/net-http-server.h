/*
    This file is part of Mtproto-proxy Library.

    Mtproto-proxy Library is free software: you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation, either version 2 of the License, or
    (at your option) any later version.

    Mtproto-proxy Library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with Mtproto-proxy Library.  If not, see <http://www.gnu.org/licenses/>.

    Copyright 2010-2012 Vkontakte Ltd
              2010-2012 Nikolai Durov
              2010-2012 Andrey Lopatin
                   2012 Anton Maydell
    
    Copyright 2014-2016 Telegram Messenger Inc             
              2015-2016 Vitaly Valtman
*/

#pragma once

#include "net/net-connections.h"
//#include "net/net-buffers.h"
#define	MAX_HTTP_HEADER_SIZE	16384

struct http_server_functions {
  void *info;
  int (*execute)(connection_job_t c, struct raw_message *raw, int op);		/* invoked from parse_execute() */
  int (*ht_wakeup)(connection_job_t c);
  int (*ht_alarm)(connection_job_t c);
  int (*ht_close)(connection_job_t c, int who);
};

#define	HTTP_V09	9
#define	HTTP_V10	0x100
#define	HTTP_V11	0x101

/* in conn->custom_data, 104 bytes */
struct hts_data {
  int query_type;
  int query_flags;
  int query_words;
  int header_size;
  int first_line_size;
  int data_size;
  int host_offset;
  int host_size;
  int uri_offset;
  int uri_size;
  int http_ver;
  int wlen;
  char word[16];
  void *extra;  
  int extra_int;
  int extra_int2;
  int extra_int3;
  int extra_int4;
  double extra_double, extra_double2;
  int parse_state;
  int query_seqno;
};

/* for hts_data.query_type */
enum hts_query_type {
  htqt_none,
  htqt_head,
  htqt_get,
  htqt_post,
  htqt_options,
  htqt_error,
  htqt_empty
};

#define	QF_ERROR	1
#define QF_HOST		2
#define QF_DATASIZE	4
#define	QF_CONNECTION	8
#define	QF_TRANSFER_ENCODING 16
#define	QF_TRANSFER_ENCODING_CHUNKED 32
#define	QF_KEEPALIVE	0x100
#define	QF_EXTRA_HEADERS	0x200

#define	HTS_DATA(c)	((struct hts_data *) (CONN_INFO(c)->custom_data))
#define	HTS_FUNC(c)	((struct http_server_functions *) (CONN_INFO(c)->extra))

extern conn_type_t ct_http_server;
extern struct http_server_functions default_http_server;

int hts_do_wakeup (connection_job_t c);
int hts_parse_execute (connection_job_t c);
int hts_std_wakeup (connection_job_t c);
int hts_std_alarm (connection_job_t c);
int hts_init_accepted (connection_job_t c);
int hts_close_connection (connection_job_t c, int who);
void http_flush (connection_job_t C, struct raw_message *raw);

extern int http_connections;
extern long long http_queries, http_bad_headers, http_queries_size;

extern char *extra_http_response_headers;

/* useful functions */
int get_http_header (const char *qHeaders, const int qHeadersLen, char *buffer, int b_len, const char *arg_name, const int arg_len);

#define	HTTP_DATE_LEN	29
void gen_http_date (char date_buffer[29], int time);
int gen_http_time (char *date_buffer, int *time);
char *cur_http_date (void);
//int write_basic_http_header (connection_job_t c, int code, int date, int len, const char *add_header, const char *content_type);
int write_basic_http_header_raw (connection_job_t c, struct raw_message *raw, int code, int date, int len, const char *add_header, const char *content_type);
int write_http_error (connection_job_t c, int code);
int write_http_error_raw (connection_job_t c, struct raw_message *raw, int code);

/* END */
