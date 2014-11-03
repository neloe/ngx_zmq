/*!
 * \file ngx_http_zmq_module.c
 * \author Nathan Eloe
 * \brief definition of the zmq upstream module for nginx
 */

#define DEBUG 1

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <zmq.h>
#include <time.h>
#include "conn_pool.h"

static char* ngx_http_zmq(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static void* ngx_http_zmq_create_loc_conf(ngx_conf_t *cf);

static char* ngx_http_zmq_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);

static unsigned int to_ms(clock_t delta) {return (int)((float)delta / CLOCKS_PER_SEC * 1000);}

static int get_socktype(ngx_http_request_t *r);

/* Module Configuration Struct
	ngx_http__(main|srv|loc)_conf_t
*/
typedef struct 
{
    ngx_flag_t  zmq;
    ngx_str_t zmq_endpoint;
    ngx_str_t zmq_timeout;
    ngx_str_t zmq_stype;
    connpool * m_cpool;
} ngx_http_zmq_loc_conf_t;

/* Module Directives
	This is an array of of the ngx_command_t struct:
	struct ngx_command_t {
		ngx_str_t             name; //Just a Name, string, no spaces, instanciate with ngx_str("proxy_pass")
		ngx_uint_t            type; //where is the directive is legal and how many arguments does it takes
		char               *(*set)(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
		ngx_uint_t            conf; // Save this to the module's NGX_HTTP_MAIN_CONF_OFFSET,
					    // NGX_HTTP_SRV_CONF_OFFSET, or NGX_HTTP_LOC_CONF_OFFSET Location
		ngx_uint_t            offset; // which part of this configuration struct to use
		void                 *post; //Set to NULL for now
	};
	Note: Terminate the array with a ngx_null_command
*/
static ngx_command_t  ngx_http_zmq_commands[] = {
    {   
        ngx_string("zmq"),
        NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
        ngx_http_zmq,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL
    }, {
        ngx_string("zmq_endpoint"),
        NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_zmq_loc_conf_t, zmq_endpoint),
        NULL
    },
    {
        ngx_string("zmq_timeout"),
        NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_zmq_loc_conf_t, zmq_timeout),
        NULL
    },
    {
        ngx_string("zmq_socktype"),
        NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_zmq_loc_conf_t, zmq_stype),
        NULL
    },
    ngx_null_command
};

/* Module Context
	ngx_http__module_ctx
	This basically merges all our config in to the main Nginx config
*/
static ngx_http_module_t  ngx_http_zmq_module_ctx = {
    NULL,                          /* preconfiguration */
    NULL,                          /* postconfiguration */

    NULL,                          /* create main configuration */
    NULL,                          /* init main configuration */

    NULL,                          /* create server configuration */
    NULL,                          /* merge server configuration */

    ngx_http_zmq_create_loc_conf,  /* create location configuration */
    ngx_http_zmq_merge_loc_conf /* merge location configuration */
};

static void *
ngx_http_zmq_create_loc_conf(ngx_conf_t *cf)
{

  ngx_http_zmq_loc_conf_t  *conf;

  conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_zmq_loc_conf_t));
  if (conf == NULL) 
      return NGX_CONF_ERROR;
  conf->zmq = NGX_CONF_UNSET;
  conf->m_cpool = init_pool(zmq_init(1), cf->pool, ZMQ_REQ);
  return conf;
}

static char *
ngx_http_zmq_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{

  ngx_http_zmq_loc_conf_t *prev = parent;
  ngx_http_zmq_loc_conf_t *conf = child;
  ngx_conf_merge_str_value(conf->zmq_timeout, prev->zmq_timeout, "-1");
  
  return NGX_CONF_OK;
}
/* Module Definition
	ngx_http__module
*/
ngx_module_t  ngx_http_zmq_module = {
    NGX_MODULE_V1,
    &ngx_http_zmq_module_ctx, /* module context */
    ngx_http_zmq_commands,   /* module directives */
    NGX_HTTP_MODULE,               /* module type */
    NULL,                          /* init master */
    NULL,                          /* init module */
    NULL,                          /* init process */
    NULL,                          /* init thread */
    NULL,                          /* exit thread */
    NULL,                          /* exit process */
    NULL,                          /* exit master */
    NGX_MODULE_V1_PADDING
};

/* some helper to clean up fcns */
static ngx_int_t header_only_response(ngx_http_request_t *r, ngx_int_t err)
{
  r->headers_out.status = err;
  r->header_only = 1;
  r->headers_out.content_length_n = 0;
  return ngx_http_send_header(r);
}

static void zmq_err_reply(ngx_http_request_t *r, unsigned char ** string)
{
  r->headers_out.status = NGX_HTTP_BAD_GATEWAY;
  r->header_only = 0;
  r->headers_out.content_length_n = strlen(zmq_strerror(zmq_errno()));
  *string = ngx_pcalloc(r->pool, strlen(zmq_strerror(zmq_errno())));
  ngx_memcpy(*string, zmq_strerror(zmq_errno()), strlen(zmq_strerror(zmq_errno())));
}

static int min(const int a, const int b)
{
  return a < b? a : b;
}

/* Module Handler
	ngx_http__handler
*/
static ngx_int_t
ngx_http_zmq_handler(ngx_http_request_t *r)
{
  clock_t start = clock();
  ngx_int_t    rc;
  ngx_buf_t    *b;
  ngx_chain_t   out;
  unsigned char *string;
  ngx_int_t mlen = 0;
  int zrc = 0;
  int stype = get_socktype(r);
  // Get access to the module config variables
  ngx_http_zmq_loc_conf_t  *zmq_config;
  zmq_config = ngx_http_get_module_loc_conf(r, ngx_http_zmq_module);
  unsigned int to = atoi((char*)(zmq_config->zmq_timeout.data));
  /*set the parameters, because things are stupid*/
  set_endpt(zmq_config->m_cpool, zmq_config->zmq_endpoint);
  set_socktype(zmq_config->m_cpool, stype);
  ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_zmq got a request with content_length_n %i", (int)r->headers_in.content_length_n);
  ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "socket type %d, %d", stype, ZMQ_PUSH);
/* --------------- BEGIN MAGIC ------------------------- */

  /* If there's an empty body, it's a bad request */
  if (r->headers_in.content_length_n <= 0)
    return header_only_response(r, NGX_HTTP_BAD_REQUEST);

  unsigned char *input;
  input = ngx_pcalloc(r->pool, r->headers_in.content_length_n+1);
  unsigned char *it = input;
  /* get the message? */
  ngx_chain_t * c1;
  int cpyd = 0;
  
  for (c1 = r->request_body->bufs; c1 && cpyd < r->headers_in.content_length_n; c1 = c1 -> next)
  {
    ngx_memcpy(it, c1->buf->pos, min((c1->buf->last - c1->buf->pos), r->headers_in.content_length_n - cpyd));
    it += min((c1->buf->last - c1->buf->pos), r->headers_in.content_length_n - cpyd);
    cpyd += min((c1->buf->last - c1->buf->pos), r->headers_in.content_length_n - cpyd);
  }
  
  ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_zmq sending %s to %s", (char*)input, zmq_config->m_cpool->m_endpt);
  /* ----------- ZMQ LOOPY THING -------------- */
  conn* con = get_conn(zmq_config->m_cpool);
  void* sock = con->m_sock;
  zmq_msg_t msg;
  /* a MUCH smarter way to handle timeouts, methinks */
  do
  {
    zrc = zmq_send(sock, input , (int)r->headers_in.content_length_n, ZMQ_NOBLOCK);
  } while (to_ms(clock() - start) < to && zrc == -1 && zmq_errno() == EAGAIN);
  if (zrc == -1) /* send errored for some reason */
  {
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,"ngx_zmq erroring out on send");
    if (zmq_errno() == EAGAIN)
    {
      rc = header_only_response(r, NGX_HTTP_GATEWAY_TIME_OUT);
      free_conn(&con);
      return rc;
    }
    free_conn(&con);
    zmq_err_reply(r, &string);
    mlen = strlen(zmq_strerror(zmq_errno()));
  }
  else if (stype != ZMQ_REQ) /* This is either a PUSH or a PUB socket... no recv */
  {
    rel_conn(zmq_config->m_cpool, &con);
    return header_only_response(r, NGX_HTTP_OK); 
  }
  else
  {
    zmq_msg_init(&msg);
    do 
    {
      zrc = zmq_msg_recv(&msg, sock, ZMQ_NOBLOCK);
    } while (to_ms(clock() - start) < to && zrc == -1 && zmq_errno() == EAGAIN);
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_zmq recv: zrc: %d, errstr: %s, errno: %d, EAGAIN: %d", zrc, zmq_strerror(zmq_errno()), zmq_errno(), EAGAIN);
    if (zrc == -1)
    {
      ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,"ngx_zmq erroring out on recv, %d", zmq_errno());
      if (zmq_errno() == EAGAIN)
      {
	rc = header_only_response(r, NGX_HTTP_GATEWAY_TIME_OUT);
	free_conn(&con);
	return rc;
      }
      free_conn(&con);
      zmq_err_reply(r, &string);
      mlen = strlen(zmq_strerror(zmq_errno()));
    }
    else 
    {          
      mlen = zmq_msg_size(&msg);
      ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,"ngx_zmq got message of length %i", mlen);
      rel_conn(zmq_config->m_cpool, &con);
      string = ngx_pcalloc(r->pool, mlen+1);
      ngx_memcpy(string, zmq_msg_data(&msg), mlen);
      ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,"ngx_zmq got message %s", (char*)string );
      
      zmq_msg_close(&msg);
      
      /* ----------- END ZMQ LOOPY THING -----------*/

    /* --------------- END MAGIC ------------------------- */
      
      rc = ngx_http_discard_request_body(r);

      r->headers_out.status = NGX_HTTP_OK;
      r->headers_out.content_length_n = mlen;
      r->headers_out.content_type.len = sizeof("text/plain") - 1;
      r->headers_out.content_type.data = (u_char *) "text/plain";
    }
  }
  ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_zmq: alloc'ing buffer");
  b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));

  if (b == NULL) 
  {
      ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Failed to allocate response buffer.");
      return NGX_HTTP_INTERNAL_SERVER_ERROR;
  }

  out.buf = b;
  out.next = NULL;
  ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_zmq: setting up to return %s", string);
  b->pos = string; /* first position in memory of the data */
  b->last = string + mlen; /* last position */

  b->memory = 1; /* content is in read-only memory */

  b->last_buf = 1; /* there will be no more buffers in the request */
  ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_zmq: sending header");
  rc = ngx_http_send_header(r);
  if (rc == NGX_ERROR || rc > NGX_OK || r->header_only)
    return rc;

  ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "ngx_zmq: completed, returning");

  return ngx_http_output_filter(r, &out);

}

static ngx_int_t ngx_http_zmq_handler1(ngx_http_request_t *r)
{
  ngx_http_read_client_request_body(r, (void*)ngx_http_zmq_handler);
  return NGX_DONE;
}

static char * ngx_http_zmq(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{

  ngx_http_core_loc_conf_t  *clcf;

  clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
  clcf->handler = ngx_http_zmq_handler1;

  return NGX_CONF_OK;
}

static int get_socktype(ngx_http_request_t *r)
{
  ngx_http_zmq_loc_conf_t  *zmq_config;
  zmq_config = ngx_http_get_module_loc_conf(r, ngx_http_zmq_module);
  char * type = ngx_pcalloc(r->pool, zmq_config->zmq_stype.len + 1);
  memcpy(type, zmq_config->zmq_stype.data, zmq_config->zmq_stype.len);
  
  if (strcmp("REQ", type) == 0)
    return ZMQ_REQ;
  if (strcmp("PUSH", type) == 0)
    return ZMQ_PUSH;
  if (strcmp("PUB", type) == 0)
    return ZMQ_PUB;
  
  ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Invalid socket type %s, defaulting to ZMQ_REQ", type);
  return ZMQ_REQ;
}
