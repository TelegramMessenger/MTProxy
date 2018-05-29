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

#define        _FILE_OFFSET_BITS        64

#include <assert.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "crc32.h"
#include "kprintf.h"
#include "net/net-events.h"
#include "precise-time.h"
#include "net/net-connections.h"
#include "net/net-http-server.h"

/*
 *
 *                HTTP SERVER INTERFACE
 *
 */

#define        SERVER_VERSION        "MTProxy/1.0"

int http_connections;
long long http_queries, http_bad_headers, http_queries_size;

char *extra_http_response_headers = "";

int hts_std_wakeup (connection_job_t c);
int hts_parse_execute (connection_job_t c);
int hts_std_alarm (connection_job_t c);
int hts_do_wakeup (connection_job_t c);
int hts_init_accepted (connection_job_t c);
int hts_close_connection (connection_job_t c, int who);
int hts_write_packet (connection_job_t C, struct raw_message *raw);

conn_type_t ct_http_server = {
  .magic = CONN_FUNC_MAGIC,
  .title = "http_server",
  .flags = C_RAWMSG,
  .accept = net_accept_new_connections,
  .init_accepted = hts_init_accepted,
  .parse_execute = hts_parse_execute,
  .close = hts_close_connection,
  .init_outbound = server_failed,
  .connected = server_failed,
  .wakeup = hts_std_wakeup,
  .alarm = hts_std_alarm,
  .write_packet = hts_write_packet
};

enum http_query_parse_state {
  htqp_start,
  htqp_readtospace,
  htqp_readtocolon,
  htqp_readint,
  htqp_skipspc,
  htqp_skiptoeoln,
  htqp_skipspctoeoln,
  htqp_eoln,
  htqp_wantlf,
  htqp_wantlastlf,
  htqp_linestart,
  htqp_fatal,
  htqp_done
};

int hts_default_execute (connection_job_t c, struct raw_message *raw, int op);

struct http_server_functions default_http_server = {
  .execute = hts_default_execute,
  .ht_wakeup = hts_do_wakeup,
  .ht_alarm = hts_do_wakeup
};

int hts_default_execute (connection_job_t c, struct raw_message *raw, int op) {
  struct hts_data *D = HTS_DATA(c);

  vkprintf (1, "http_server: op=%d, header_size=%d\n", op, D->header_size);

  switch (op) {

  case htqt_empty:
    break;

  case htqt_get:
  case htqt_post:
  case htqt_head:
  case htqt_options:

  default:
    D->query_flags |= QF_ERROR;
    break;
  }

  return D->data_size >= 0 ? -413 : -501;
}

int hts_init_accepted (connection_job_t c) {
  http_connections++;
  return 0;
}

int hts_close_connection (connection_job_t c, int who) {
  http_connections--;

  if (HTS_FUNC(c)->ht_close != NULL) {
    HTS_FUNC(c)->ht_close (c, who);
  } 

  return cpu_server_close_connection (c, who);
}

static inline char *http_get_error_msg_text (int *code) {
  /* the most frequent case */
  if (*code == 200) {
    return "OK";
  }
  switch (*code) {
    /* python generated from old array */
    case 201: return "Created";
    case 202: return "Accepted";
    case 204: return "No Content";
    case 206: return "Partial Content";
    case 301: return "Moved Permanently";
    case 302: return "Found";
    case 303: return "See Other";
    case 304: return "Not Modified";
    case 307: return "Temporary Redirect";
    case 400: return "Bad Request";
    case 403: return "Forbidden";
    case 404: return "Not Found";
    case 405: return "Method Not Allowed";
    case 406: return "Not Acceptable";
    case 408: return "Request Timeout";
    case 411: return "Length Required";
    case 413: return "Request Entity Too Large";
    case 414: return "Request URI Too Long";
    case 418: return "I'm a teapot";
    case 429: return "Too Many Requests";
    case 501: return "Not Implemented";
    case 502: return "Bad Gateway";
    case 503: return "Service Unavailable";
    default: *code = 500;
  }
  return "Internal Server Error";
}

static char error_text_pattern[] =
"<html>\r\n"
"<head><title>%d %s</title></head>\r\n"
"<body bgcolor=\"white\">\r\n"
"<center><h1>%d %s</h1></center>\r\n"
"<hr><center>" SERVER_VERSION "</center>\r\n"
"</body>\r\n"
"</html>\r\n";

int write_http_error_raw (connection_job_t C, struct raw_message *raw, int code) {
  if (code == 204) {
    write_basic_http_header_raw (C, raw, code, 0, -1, 0, 0);
    return 0;
  } else {
    static char buff[1024];
    char *ptr = buff;
    const char *error_message = http_get_error_msg_text (&code);
    ptr += sprintf (ptr, error_text_pattern, code, error_message, code, error_message);
    write_basic_http_header_raw (C, raw, code, 0, ptr - buff, 0, 0);
    assert (rwm_push_data (raw, buff, ptr - buff) == ptr - buff);
    return ptr - buff;
  }
}

int write_http_error (connection_job_t C, int code) {
  struct raw_message *raw = calloc (sizeof (*raw), 1);
  rwm_init (raw, 0);
  int r = write_http_error_raw (C, raw, code);
  
  mpq_push_w (CONN_INFO(C)->out_queue, raw, 0);
  job_signal (JOB_REF_CREATE_PASS (C), JS_RUN);

  return r;
}

int hts_write_packet (connection_job_t C, struct raw_message *raw) {
  rwm_union (&CONN_INFO(C)->out, raw);
  return 0;
}


int hts_parse_execute (connection_job_t C) {
  struct connection_info *c = CONN_INFO (C);
  
  struct hts_data *D = HTS_DATA(C);
  char *ptr, *ptr_s, *ptr_e;
  int len;
  long long tt;

  D->parse_state = htqp_start;

  struct raw_message raw;
  rwm_clone (&raw, &c->in);

  while (c->status == conn_working && !c->pending_queries && raw.total_bytes) {
    if (c->flags & (C_ERROR | C_STOPPARSE)) {
      break;
    }
   
    len = rwm_get_block_ptr_bytes (&raw);
    assert (len > 0);
    ptr = ptr_s = rwm_get_block_ptr (&raw);
    ptr_e = ptr + len;

    assert (ptr);

    while (ptr < ptr_e && D->parse_state != htqp_done) {
      switch (D->parse_state) {
        case htqp_start:
          //fprintf (stderr, "htqp_start: ptr=%p (%.8s), hsize=%d, qf=%d, words=%d\n", ptr, ptr, D->header_size, D->query_flags, D->query_words);
          memset (D, 0, offsetof (struct hts_data, query_seqno));
	  D->query_seqno++;
          D->query_type = htqt_none;
          D->data_size = -1;
          D->parse_state = htqp_readtospace;

        case htqp_readtospace:
          //fprintf (stderr, "htqp_readtospace: ptr=%p (%.8s), hsize=%d, qf=%d, words=%d\n", ptr, ptr, D->header_size, D->query_flags, D->query_words);
          while (ptr < ptr_e && ((unsigned) *ptr > ' ')) {
            if (D->wlen < 15) {
              D->word[D->wlen] = *ptr;
            }
            D->wlen++;
            ptr++;
          }
          if (D->wlen > 4096) {
            D->parse_state = htqp_fatal;
            break;
          }
          if (ptr == ptr_e) {
            break;
          }
          D->parse_state = htqp_skipspc;
          D->query_words++;
          if (D->query_words == 1) {
            D->query_type = htqt_error;
            if (D->wlen == 3 && !memcmp (D->word, "GET", 3)) {
              D->query_type = htqt_get;
            } else if (D->wlen == 4) {
              if (!memcmp (D->word, "HEAD", 4)) {
                D->query_type = htqt_head;
              } else if (!memcmp (D->word, "POST", 4)) {
                D->query_type = htqt_post;
              }
            } else if (D->wlen == 7 && !memcmp (D->word, "OPTIONS", 7)) {
              D->query_type = htqt_options;
            }
            if (D->query_type == htqt_error) {
              D->parse_state = htqp_skiptoeoln;
              D->query_flags |= QF_ERROR;
            }
          } else if (D->query_words == 2) {
            D->uri_offset = D->header_size;
            D->uri_size = D->wlen;
            if (!D->wlen) {
              D->parse_state = htqp_skiptoeoln;
              D->query_flags |= QF_ERROR;
            }
          } else if (D->query_words == 3) {
            D->parse_state = htqp_skipspctoeoln;
            if (D->wlen != 0) {
              /* HTTP/x.y */
              if (D->wlen != 8) {
                D->parse_state = htqp_skiptoeoln;
                D->query_flags |= QF_ERROR;
              } else {
                if (!memcmp (D->word, "HTTP/1.0", 8)) {
                  D->http_ver = HTTP_V10;
                } else if (!memcmp (D->word, "HTTP/1.1", 8)) {
                  D->http_ver = HTTP_V11;
                } else {
                  D->parse_state = htqp_skiptoeoln;
                  D->query_flags |= QF_ERROR;
                }
              }
            } else {
              D->http_ver = HTTP_V09;
            }
          } else {
            assert (D->query_flags & (QF_HOST | QF_CONNECTION));
            if (D->wlen) {
              if (D->query_flags & QF_HOST) {
                D->host_offset = D->header_size;
                D->host_size = D->wlen;
              } else if (D->wlen == 10 && !strncasecmp (D->word, "keep-alive", 10)) {
                D->query_flags |= QF_KEEPALIVE;
              }
            }
            D->query_flags &= ~(QF_HOST | QF_CONNECTION);
            D->parse_state = htqp_skipspctoeoln;
          }
          D->header_size += D->wlen;
          break;

        case htqp_skipspc:
        case htqp_skipspctoeoln:
          //fprintf (stderr, "htqp_skipspc[toeoln]: ptr=%p (%.8s), hsize=%d, qf=%d, words=%d\n", ptr, ptr, D->header_size, D->query_flags, D->query_words);
          while (D->header_size < MAX_HTTP_HEADER_SIZE && ptr < ptr_e && (*ptr == ' ' || (*ptr == '\t' && D->query_words >= 8))) {
            D->header_size++;
            ptr++;
          }
          if (D->header_size >= MAX_HTTP_HEADER_SIZE) {
            D->parse_state = htqp_fatal;
            break;
          }
          if (ptr == ptr_e) {
            break;
          }
          if (D->parse_state == htqp_skipspctoeoln) {
            D->parse_state = htqp_eoln;
            break;
          }
          if (D->query_words < 3) {
            D->wlen = 0;
            D->parse_state = htqp_readtospace;
          } else {
            assert (D->query_words >= 4);
            if (D->query_flags & QF_DATASIZE) {
              if (D->data_size != -1) {
                D->parse_state = htqp_skiptoeoln;
                D->query_flags |= QF_ERROR;
              } else {
                D->parse_state = htqp_readint;
                D->data_size = 0;
              }
            } else if (D->query_flags & (QF_HOST | QF_CONNECTION)) {
              D->wlen = 0;
              D->parse_state = htqp_readtospace;
            } else {
              D->parse_state = htqp_skiptoeoln;
            }
          }
          break;

        case htqp_readtocolon:
          //fprintf (stderr, "htqp_readtocolon: ptr=%p (%.8s), hsize=%d, qf=%d, words=%d\n", ptr, ptr, D->header_size, D->query_flags, D->query_words);
          while (ptr < ptr_e && *ptr != ':' && *ptr > ' ') {
            if (D->wlen < 15) {
              D->word[D->wlen] = *ptr;
            }
            D->wlen++;
            ptr++;
          }
          if (D->wlen > 4096) {
            D->parse_state = htqp_fatal;
            break;
          }
          if (ptr == ptr_e) {
            break;
          }

          if (*ptr != ':') {
            D->header_size += D->wlen;
            D->parse_state = htqp_skiptoeoln;
            D->query_flags |= QF_ERROR;
            break;
          }

          ptr++;

          if (D->wlen == 4 && !strncasecmp (D->word, "host", 4)) {
            D->query_flags |= QF_HOST;
          } else if (D->wlen == 10 && !strncasecmp (D->word, "connection", 10)) {
            D->query_flags |= QF_CONNECTION;
          } else if (D->wlen == 14 && !strncasecmp (D->word, "content-length", 14)) {
            D->query_flags |= QF_DATASIZE;
          } else {
            D->query_flags &= ~(QF_HOST | QF_DATASIZE | QF_CONNECTION);
          }

          D->header_size += D->wlen + 1;
          D->parse_state = htqp_skipspc;
          break;

        case htqp_readint:        
          //fprintf (stderr, "htqp_readint: ptr=%p (%.8s), hsize=%d, qf=%d, words=%d\n", ptr, ptr, D->header_size, D->query_flags, D->query_words);

          tt = D->data_size;
          while (ptr < ptr_e && *ptr >= '0' && *ptr <= '9') {
            if (tt >= 0x7fffffffL / 10) {
              D->query_flags |= QF_ERROR;
              D->parse_state = htqp_skiptoeoln;
              break;
            }
            tt = tt * 10 + (*ptr - '0');
            ptr++;
            D->header_size++;
            D->query_flags &= ~QF_DATASIZE;
          }

          D->data_size = tt;
          if (ptr == ptr_e) {
            break;
          }

          if (D->query_flags & QF_DATASIZE) {
            D->query_flags |= QF_ERROR;
            D->parse_state = htqp_skiptoeoln;
          } else {
            D->parse_state = htqp_skipspctoeoln;
          }
          break;

        case htqp_skiptoeoln:
          //fprintf (stderr, "htqp_skiptoeoln: ptr=%p (%.8s), hsize=%d, qf=%d, words=%d\n", ptr, ptr, D->header_size, D->query_flags, D->query_words);

          while (D->header_size < MAX_HTTP_HEADER_SIZE && ptr < ptr_e && (*ptr != '\r' && *ptr != '\n')) {
            D->header_size++;
            ptr++;
          }
          if (D->header_size >= MAX_HTTP_HEADER_SIZE) {
            D->parse_state = htqp_fatal;
            break;
          }
          if (ptr == ptr_e) {
            break;
          }

          D->parse_state = htqp_eoln;

        case htqp_eoln:

          if (ptr == ptr_e) {
            break;
          }
          if (*ptr == '\r') {
            ptr++;
            D->header_size++;
          }
          D->parse_state = htqp_wantlf;

        case htqp_wantlf:
          //fprintf (stderr, "htqp_wantlf: ptr=%p (%.8s), hsize=%d, qf=%d, words=%d\n", ptr, ptr, D->header_size, D->query_flags, D->query_words);

          if (ptr == ptr_e) {
            break;
          }
          if (++D->query_words < 8) {
            D->query_words = 8;
            if (D->query_flags & QF_ERROR) {
              D->parse_state = htqp_fatal;
              break;
            }
          }

          if (D->http_ver <= HTTP_V09) {
            D->parse_state = htqp_wantlastlf;
            break;
          }

          if (*ptr != '\n') {
            D->query_flags |= QF_ERROR;
            D->parse_state = htqp_skiptoeoln;
            break;
          }

          ptr++;
          D->header_size++;

          D->parse_state = htqp_linestart;

        case htqp_linestart:
          //fprintf (stderr, "htqp_linestart: ptr=%p (%.8s), hsize=%d, qf=%d, words=%d\n", ptr, ptr, D->header_size, D->query_flags, D->query_words);

          if (ptr == ptr_e) {
            break;
          }

          if (!D->first_line_size) {
            D->first_line_size = D->header_size;
          }

          if (*ptr == '\r') {
            ptr++;
            D->header_size++;
            D->parse_state = htqp_wantlastlf;
            break;
          }
          if (*ptr == '\n') {
            D->parse_state = htqp_wantlastlf;
            break;
          }

          if (D->query_flags & QF_ERROR) {
            D->parse_state = htqp_skiptoeoln;
          } else {
            D->wlen = 0;
            D->parse_state = htqp_readtocolon;
          }
          break;

        case htqp_wantlastlf:
          //fprintf (stderr, "htqp_wantlastlf: ptr=%p (%.8s), hsize=%d, qf=%d, words=%d\n", ptr, ptr, D->header_size, D->query_flags, D->query_words);

          if (ptr == ptr_e) {
            break;
          }
          if (*ptr != '\n') {
            D->parse_state = htqp_fatal;
            break;
          }
          ptr++;
          D->header_size++;

          if (!D->first_line_size) {
            D->first_line_size = D->header_size;
          }

          D->parse_state = htqp_done;

        case htqp_done:
          //fprintf (stderr, "htqp_done: ptr=%p (%.8s), hsize=%d, qf=%d, words=%d\n", ptr, ptr, D->header_size, D->query_flags, D->query_words);
          break;

        case htqp_fatal:
          //fprintf (stderr, "htqp_fatal: ptr=%p (%.8s), hsize=%d, qf=%d, words=%d\n", ptr, ptr, D->header_size, D->query_flags, D->query_words);
          D->query_flags |= QF_ERROR;
          D->parse_state = htqp_done;
          break;

        default:
          assert (0);
      }
    }

    len = ptr - ptr_s;
    assert (rwm_skip_data (&raw, len) == len);

    if (D->parse_state == htqp_done) {
      if (D->header_size >= MAX_HTTP_HEADER_SIZE) {
        D->query_flags |= QF_ERROR;
      }
      if (!(D->query_flags & QF_ERROR)) {
        if (!HTS_FUNC(C)->execute) {
          HTS_FUNC(C)->execute = hts_default_execute;
        }       
        
        int res;
        if (D->query_type == htqt_post && D->data_size < 0) {
          // assert (rwm_skip_data (&c->in, D->header_size) == D->header_size);
          res = -411;
        } else if (D->query_type != htqt_post && D->data_size > 0) {
          res = -413;
        } else {
          int bytes = D->header_size;
          if (D->query_type == htqt_post) {
            bytes += D->data_size;
          }
          struct raw_message r;
          rwm_clone (&r, &c->in);
          if (bytes < c->in.total_bytes) {
            rwm_trunc (&r, bytes);
          }

          res = HTS_FUNC(C)->execute (C, &r, D->query_type);
          rwm_free (&r);
        }
        http_queries++;
        http_queries_size += D->header_size + D->data_size;
        if (res > 0) {
          //c->status = conn_reading_query;
          rwm_free (&raw);
          return res;        // need more bytes
        } else {
          assert (rwm_skip_data (&c->in, D->header_size) == D->header_size);
          if (res == SKIP_ALL_BYTES || !res) {
            if (D->data_size > 0) {
              int x = c->in.total_bytes;
              int y = x > D->data_size ? D->data_size : x;
              assert (rwm_skip_data (&c->in, y) == y);
              if (y < x) {
                D->parse_state = htqp_start;
                return y - x;
              }
            }
          } else {
            if (res == -413) {
              D->query_flags &= ~QF_KEEPALIVE;
            }
            write_http_error (C, -res);
            D->query_flags &= ~QF_ERROR;
          }
        }
      } else {
        //fprintf (stderr, "[parse error]\n");
        assert (rwm_skip_data (&c->in, D->header_size) == D->header_size);
        http_bad_headers++;
      }
      if (D->query_flags & QF_ERROR) {
        D->query_flags &= ~QF_KEEPALIVE;
        write_http_error (C, 400);
      }
      if (!c->pending_queries && !(D->query_flags & QF_KEEPALIVE)) {
        connection_write_close (C);
        D->parse_state = -1;
        return 0;
      }
      D->parse_state = htqp_start;
      rwm_free (&raw);
      rwm_clone (&raw, &c->in);
    }
  }
  
  rwm_free (&raw);
  return NEED_MORE_BYTES;
}


int hts_std_wakeup (connection_job_t c) {
  if (HTS_FUNC(c)->ht_wakeup) {
    HTS_FUNC(c)->ht_wakeup (c);
  }
  CONN_INFO(c)->generation = new_conn_generation ();
  return 0;
}

int hts_std_alarm (connection_job_t c) {
  if (HTS_FUNC(c)->ht_alarm) {
    HTS_FUNC(c)->ht_alarm (c);
  }
  CONN_INFO(c)->generation = new_conn_generation ();
  return 0;
}

int hts_do_wakeup (connection_job_t c) {
  //struct hts_data *D = HTS_DATA(c);
  assert (0);
  return 0;
}

/*
 *
 *                USEFUL HTTP FUNCTIONS
 *
 */

#define        HTTP_DATE_LEN        29
char now_date_string[] = "Thu, 01 Jan 1970 00:00:00 GMT";
int now_date_utime;

static char months [] = "JanFebMarAprMayJunJulAugSepOctNovDecGlk";
static char dows [] = "SunMonTueWedThuFriSatEar";


int dd [] =
{31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};

void gen_http_date (char date_buffer[29], int time) {
  int day, mon, year, hour, min, sec, xd, i, dow;
  if (time < 0) time = 0;
  sec = time % 60;
  time /= 60;
  min = time % 60;
  time /= 60;
  hour = time % 24;
  time /= 24;
  dow = (time + 4) % 7;
  xd = time % (365 * 3 + 366);
  time /= (365 * 3 + 366);
  year = time * 4 + 1970;
  if (xd >= 365) {
    year++;
    xd -= 365;
    if (xd >= 365) {
      year++;
      xd -= 365;
      if (xd >= 366) {
        year++;
        xd -= 366;
      }
    }
  }
  if (year & 3) {
    dd[1] = 28;
  } else {
    dd[1] = 29;
  }

  for (i = 0; i < 12; i++) {
    if (xd < dd[i]) {
      break;
    }
    xd -= dd[i];
  }

  day = xd + 1;
  mon = i;
  assert (day >= 1 && day <= 31 && mon >=0 && mon <= 11 &&
      year >= 1970 && year <= 2039);

  sprintf (date_buffer, "%.3s, %.2d %.3s %d %.2d:%.2d:%.2d GM", 
      dows + dow * 3, day, months + mon * 3, year,
      hour, min, sec);
  date_buffer[28] = 'T';
}

int gen_http_time (char *date_buffer, int *time) {
  char dow[4];
  char month[4];
  char tz[16];
  int i, year, mon, day, hour, min, sec;
  int argc = sscanf (date_buffer, "%3s, %d %3s %d %d:%d:%d %15s", dow, &day, month, &year, &hour, &min, &sec, tz);
  if (argc != 8) {
    return (argc > 0) ? -argc : -8;
  }
  for (mon = 0; mon < 12; mon++) {
    if (!memcmp (months + mon * 3, month, 3)) {
      break;
    }
  }
  if (mon == 12) {
    return -11;
  }
  if (year < 1970 || year > 2039) {
    return -12;
  }
  if (hour < 0 || hour >= 24) {
    return -13;
  }
  if (min < 0 || min >= 60) {
    return -14;
  }
  if (sec < 0 || sec >= 60) {
    return -15;
  }
  if (strcmp (tz, "GMT")) {
    return -16;
  }
  int d = (year - 1970) * 365 + ((year - 1969) >> 2) + (day - 1);
  if (!(year & 3) && mon >= 2) {
    d++;
  }
  dd[1] = 28;
  for (i = 0; i < mon; i++) { 
    d += dd[i];
  }
  *time = (((d * 24 + hour) * 60 + min) * 60) + sec;
  return 0;
}

char *cur_http_date (void) {
  if (now_date_utime != now) {
    gen_http_date (now_date_string, now_date_utime = now);
  }
  return now_date_string;
}

int get_http_header (const char *qHeaders, const int qHeadersLen, char *buffer, int b_len, const char *arg_name, const int arg_len) {
  const char *where = qHeaders;
  const char *where_end = where + qHeadersLen;
  while (where < where_end) {
    const char *start = where;
    while (where < where_end && (*where != ':' && *where != '\n')) {
      ++where;
    }
    if (where == where_end) {
      buffer[0] = 0;
      return -1;
    }
    if (*where == ':') {
      if (arg_len == where - start && !strncasecmp (arg_name, start, arg_len)) {
        where++;
        while (where < where_end && (*where == 9 || *where == 32)) {
          where++;
        }
        start = where;
        while (where < where_end && *where != '\r' && *where != '\n') {
          ++where;
        }
        while (where > start && (where[-1] == ' ' || where[-1] == 9)) {
          where--;
        }
        b_len--;
        if (where - start < b_len) {
          b_len = where - start;
        }
        memcpy (buffer, start, b_len);
        buffer[b_len] = 0;
        return b_len;
      }
      ++where;
    }
    while (where < where_end && *where != '\n') {
      ++where;
    }
    if (where < where_end) {
      ++where;
    }
  }
  buffer[0] = 0;
  return -1;
}

static char header_pattern[] = 
"HTTP/1.1 %d %s\r\n"
"Server: " SERVER_VERSION "\r\n"
"Date: %s\r\n"
"Content-Type: %.256s\r\n"
"Connection: %s\r\n%.1024s%.1024s";

int write_basic_http_header_raw (connection_job_t C, struct raw_message *raw, int code, int date, int len, const char *add_header, const char *content_type) {
  struct hts_data *D = HTS_DATA(C);

  if (D->http_ver >= HTTP_V10 || D->http_ver == 0) {
#define B_SZ        4096
    static char buff[B_SZ], date_buff[32];
    char *ptr = buff;
    const char *error_message = http_get_error_msg_text (&code);
    if (date) {
      gen_http_date (date_buff, date);
    }
    ptr += snprintf (ptr, B_SZ - 64, header_pattern, code, error_message,
                     date ? date_buff : cur_http_date(), 
                     content_type ? content_type : "text/html", 
                     (D->query_flags & QF_KEEPALIVE) ? "keep-alive" : "close", 
                     (D->query_flags & QF_EXTRA_HEADERS) && extra_http_response_headers ? extra_http_response_headers : "", 
                     add_header ?: "");
    D->query_flags &= ~QF_EXTRA_HEADERS;
    assert (ptr < buff + B_SZ - 64);
    if (len >= 0) {
      ptr += sprintf (ptr, "Content-Length: %d\r\n", len);
    }

    ptr += sprintf (ptr, "\r\n");

    assert (rwm_push_data (raw, buff, ptr - buff) == ptr - buff);
    return ptr - buff;
  }

  return 0;
}

void http_flush (connection_job_t C, struct raw_message *raw) {
  if (raw) {
    mpq_push_w (CONN_INFO(C)->out_queue, raw, 0);
  }
  struct hts_data *D = HTS_DATA(C);
  if (!CONN_INFO(C)->pending_queries && !(D->query_flags & QF_KEEPALIVE)) {
    connection_write_close (C);
    D->parse_state = -1;
  }
  job_signal (JOB_REF_CREATE_PASS (C), JS_RUN);
}

//int write_basic_http_header (connection_job_t C, struct raw_message *raw, int code, int date, int len, const char *add_header, const char *content_type) {


/*
 *
 *                END (HTTP SERVER)
 *
 */

