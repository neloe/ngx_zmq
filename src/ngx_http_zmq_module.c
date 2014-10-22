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

static char* ngx_http_zmq(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static void* ngx_http_zmq_create_loc_conf(ngx_conf_t *cf);

static char* ngx_http_zmq_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);


/* Module Configuration Struct
	ngx_http__(main|srv|loc)_conf_t
*/
typedef struct {
    ngx_flag_t  zmq;
    ngx_str_t zmq_endpoint;
    void* ctx;
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
    {   ngx_string("zmq"),
        NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
        ngx_http_zmq,
        NGX_HTTP_LOC_CONF_OFFSET,
        0,
        NULL
    }, {
        ngx_string("zmq_endpoint"),
        NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_zmq_loc_conf_t, zmq_endpoint),
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
    if (conf == NULL) {
        return NGX_CONF_ERROR;
    }
    conf->zmq = NGX_CONF_UNSET;

    return conf;
}

static char *
ngx_http_zmq_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{

    ngx_http_zmq_loc_conf_t *prev = parent;
    ngx_http_zmq_loc_conf_t *conf = child;

    if (prev->ctx && prev->ctx != conf->ctx)
    {
      if (conf->ctx)
	zmq_term(conf->ctx);
      conf->ctx = prev->ctx;
    }
    else if (conf->ctx)
      prev->ctx = conf->ctx;
    else
      prev->ctx = conf->ctx = zmq_init(1);
    
    ngx_conf_merge_str_value(conf->zmq_endpoint, prev->zmq_endpoint, "Hello World!");

    if (conf->zmq_endpoint.len < 1) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "You can't specify a blank string for the zmq_endpoint directive");
        return NGX_CONF_ERROR;
    }

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

/* Module Handler
	ngx_http__handler
*/
static ngx_int_t
ngx_http_zmq_handler(ngx_http_request_t *r)
{

    ngx_int_t    rc;
    ngx_buf_t    *b;
    ngx_chain_t   out;
    unsigned char *string;
    ngx_int_t mlen;

    // Get access to the module config variables
    ngx_http_zmq_loc_conf_t  *zmq_config;
    zmq_config = ngx_http_get_module_loc_conf(r, ngx_http_zmq_module);
#if DEBUG
    fprintf(stderr, "context: %ld\n", (long)zmq_config->ctx);
#endif
    if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD))) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    /* ----------- ZMQ LOOPY THING -------------- */
    void* sock = zmq_socket(zmq_config->ctx, ZMQ_REQ);
    char* endpt = ngx_pcalloc(r->pool, zmq_config->zmq_endpoint.len+1);
    zmq_msg_t msg;
    ngx_memcpy(endpt, zmq_config->zmq_endpoint.data, zmq_config->zmq_endpoint.len);
    zmq_connect(sock, endpt);
    zmq_send(sock, "Hello", 5, 0);
    zmq_msg_init(&msg);
    zmq_msg_recv(&msg, sock, 0);
    mlen = zmq_msg_size(&msg);
    string = ngx_pcalloc(r->pool, mlen+1);
    ngx_memcpy(string, zmq_msg_data(&msg), mlen);
    
#if DEBUG
    fprintf(stderr, "Got a reply, it is: %s with length %d\n", (char*)zmq_msg_data(&msg), (int)mlen);
    fprintf(stderr, "sending back: %s\n", (char*)string);
#endif
    zmq_msg_close(&msg);
    zmq_close(sock);
    /* ----------- END ZMQ LOOPY THING -----------*/
    
    rc = ngx_http_discard_request_body(r);

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = mlen;
    r->headers_out.content_type.len = sizeof("text/html") - 1;
    r->headers_out.content_type.data = (u_char *) "text/html";

    if (r->method == NGX_HTTP_HEAD) {
        rc = ngx_http_send_header(r);

        if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
            return rc;
        }
    }

    b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));

    if (b == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "Failed to allocate response buffer.");

        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    out.buf = b;
    out.next = NULL;

    //string = ngx_palloc(r->pool, zmq_config->zmq_endpoint.len);
    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "zmq_endpoint: %s", zmq_config->zmq_endpoint.data);
    /*if (string == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "Failed to allocate memory for zmq_endpoint.");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    ngx_memcpy(string, zmq_config->zmq_endpoint.data, zmq_config->zmq_endpoint.len);
*/
    b->pos = string; /* first position in memory of the data */
    b->last = string + mlen; /* last position */

    b->memory = 1; /* content is in read-only memory */
    /* (i.e., filters should copy it rather than rewrite in place) */

    b->last_buf = 1; /* there will be no more buffers in the request */

    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "GOT THIS FAR!");


    return ngx_http_output_filter(r, &out);

}

static char *
ngx_http_zmq(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{

    ngx_http_core_loc_conf_t  *clcf;

    clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    clcf->handler = ngx_http_zmq_handler;

    return NGX_CONF_OK;
}