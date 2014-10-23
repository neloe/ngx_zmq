/*!
 * \file conn_pool.c
 * \author Nathan Eloe
 * \brief The zmq connection connection pool function definitions
 */

#include "conn_pool.h"
#define DEBUG 1
connpool* init_pool ( void* ctx, ngx_pool_t* mpool, int stype) 
{
  connpool * p = ngx_pcalloc(mpool, sizeof(connpool));
  p->m_ctx = ctx;
  p->m_stype = stype;
  p->m_to = -2;
  /* not going to set up a connection yet, that will happen later */
  return p;
}

void set_endpt ( connpool* cp, ngx_str_t endpt )
{
  if (!cp->m_endpt)
  {
    cp -> m_endpt = calloc(endpt.len + 1, 1);
    ngx_memcpy(cp->m_endpt, endpt.data, endpt.len);
    fprintf(stderr,"Setting endpoint to: %s\n", cp->m_endpt);
  }
  return;
}

void set_to ( connpool* cp, int to )
{
  if (cp->m_to == -2)
    cp->m_to = to;
  fprintf(stderr,"timeout is %d\n", cp->m_to);
  return;
}


conn* init_conn(connpool* cp)
{
#if DEBUG
  fprintf(stderr, "making new connection\n");
#endif
  conn * c = malloc(sizeof(conn));
  c->m_sock = zmq_socket(cp->m_ctx, cp->m_stype);
  zmq_setsockopt(c->m_sock, ZMQ_RCVTIMEO, &(cp->m_to), sizeof(int));
  zmq_setsockopt(c->m_sock, ZMQ_SNDTIMEO, &(cp->m_to), sizeof(int));
  zmq_connect(c->m_sock, cp->m_endpt);
  return c;
}

conn* get_conn ( connpool* cp )
{
  #if DEBUG
  fprintf(stderr, "getting a connection\n");
#endif
  conn* c;
  if (cp->m_front)
  {
    c = cp->m_front;
    if (cp->m_front == cp->m_back)
      cp->m_back = NULL;
    cp->m_front = cp->m_front->m_next;
  }
  else
    c = init_conn(cp);
  return c;
}

void rel_conn ( connpool* cp, conn** con )
{
  #if DEBUG
  fprintf(stderr, "releasing connection to pool\n");
#endif
  if (cp->m_back)
    cp->m_back = cp->m_back->m_next = *con;
  else
    cp->m_front = cp->m_back = *con;
  *con = NULL;
  return;
}

void free_conn ( conn** con ) 
{
  #if DEBUG
  fprintf(stderr, "destroying connection\n");
#endif
  int time = 0;
  if (!(*con))
    return;
  if ((*con)->m_sock)
  {
    zmq_setsockopt((*con)->m_sock, ZMQ_LINGER, &time, sizeof(time));
    zmq_close((*con)->m_sock);
  }
  free(*con);
  (*con) = NULL;
  return;
}

void free_pool ( connpool** cp )
{
  if (!(*cp))
    return;
  conn * it = (*cp)->m_front;
  conn * i = it;
  while (i)
  {
    it = it->m_next;
    free_conn(&i);
    i = it;
  }
  /*I do not want to muck with the memory pools or the context*/
  (*cp)->m_ctx = NULL;
  ngx_free(*cp);
  *cp = NULL;
  return;
}

