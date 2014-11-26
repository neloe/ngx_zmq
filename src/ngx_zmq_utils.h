/*!
 * \file ngx_zmq_utils.h
 * \author Nathan Eloe
 * \brief Utility functions and structures for the ngx_http_zmq_module
 */

#include <zmq.h>
#include <time.h>
#include <ngx_http.h>
/*
 * \brief poller wrapping functions
 */
int rpoll(void* sock, int toms);
int spoll(void* sock, int toms);

typedef struct {
  clock_t _last;
  double _remain, _total;
} ztimer_t;

double to_ms(const clock_t delta);

/*!
 * \brief Sets up a timer object
 * \pre None
 * \post The timer object is set up, remain == ms
 */
void timer_init(ztimer_t * timer, const int ms);
/*!
 * \brief Updates the timer
 * \pre The timer has been initialized
 * \post the last updated time and time remaining time are updated to current values
 */
void timer_update(ztimer_t * timer);

/*!
 * \brief Returns the time left on the timer
 * \pre The timer has been initialized; only accurate if timer_update called before this
 * \post None
 * \returns the time remaining
 */
int time_left(ztimer_t * timer);
/*!
 * \brief Determines the amount of time elapsed
 * \pre The timer has been initialized; only accurate if timer_update called before this
 * \post None
 * \returns the time elapsed
 */
double time_elapsed(ztimer_t* timer);

void build_reply_header(ngx_http_request_t *r, const int len, const int status);