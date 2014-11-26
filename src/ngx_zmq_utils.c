/*!
 * \file ngx_zmq_utils.c
 * \author Nathan Eloe
 * \brief Implementation of utility functions for the zmq module for nginx
 */

#include "ngx_zmq_utils.h"

int rpoll(void* sock, int toms)
{
  zmq_pollitem_t items[1] = {{sock, 0, ZMQ_POLLIN, 0}};
  return zmq_poll(items, 1, toms);
}
int spoll(void* sock, int toms)
{
  zmq_pollitem_t items[1] = {{sock, 0, ZMQ_POLLOUT, 0}};
  return zmq_poll(items, 1, toms);
}

void timer_init(ztimer_t* timer, const int ms)
{
  timer->_remain = ms;
  timer->_last = clock();
  timer->_total = 0;
  return;
}

void timer_update(ztimer_t * timer)
{
  clock_t now = clock();
  timer->_remain -= to_ms(now - timer->_last);
  timer->_total += to_ms(now - timer->_last);
  timer->_last = now;
  return;
}

int time_left(ztimer_t* timer)
{
  return timer->_remain;
}

int time_elapsed(ztimer_t* timer)
{
  return timer->_total;
}

void build_reply_header(ngx_http_request_t* r, const int len, const int status)
{
  r->headers_out.status = status;
  r->header_only = 0;
  r->headers_out.content_length_n = len;
  r->headers_out.content_type.len = sizeof("text/plain") - 1;
  r->headers_out.content_type.data = (u_char *) "text/plain";
  return;
}



