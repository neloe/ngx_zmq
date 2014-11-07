# ngx_zmq

An upstream ZeroMQ module for nginx.  It offers the following features:
* Endpoint configuration
* Per location timeout configuration
* Connection pooling

The following features and improvements are planned and in development
* Selection of ZeroMQ socket type
  * Currently defaults to REQ
  * Would like to be able to select PUB or PUSH
* Code cleanup
* Memory profiling/cleanup

## Adding to Nginx
Complation of the module only requires libzmq 3.x+ (as well as nginx).  It has been tested to build against nginx 1.5.12 and 1.7.4 (OpenResty versions). They can be compiled in simply with
```bash
./configure --add-module=<path_to_ngx_zmq>
``` 
from the nginx source directory, followed by your standard `make` and `make install` commands.


## nginx Configuration
ngx_zmq uses location blocks to set up endpoints, and provides the following directives:
```nginx
location /zmq {
  zmq;
  zmq_endpoint "tcp://localhost:5555"; #endpoint is required
  zmq_timeout 10; #in milliseconds, total time spent in function. optional, defaults to -1 (no timeout)
}
```
Assuming a zmq server (example included in us.cpp) is running, a request over ZMQ can be made via
```bash
$ curl -X POST -d 'what_to_send' http://localhost/zmq
```

The sample upstream zmq server can be compiled and run with:
```bash
$ g++ us.cpp -lzmq; ./a.out
```
The sample server will always reply with "World"

### With the lua-nginx-module
[As per this issue](https://github.com/openresty/lua-nginx-module/issues/415), we cannot just do a ngx.location.capture() from the lua nginx module.  This requires a bit of a workaround.  Try:
```nginx
  location ~ /zmq/proxy/(?<target>[\S]+) {
  internal; # so only this server can access this
  proxy_pass http://127.0.0.1/zmq/$1;
}

location /zmq/my_endpoint/ {
  zmq_endpoint "tcp://my.endpoint.org:5555";
  zmq_timeout 10;
  zmq;
}
```
and in Lua (assuming [readurl](https://github.com/jamesmarlowe/lua-resty-readurl) is available):
```lua
local reply, err = readurl.capture("/zmq/proxy/my_endpoint/",
                                   {body=thing_to_send},
                                   false,
                                   {failure_log_level=ngx.CRIT}
)
```
Using appropriate options.  You could use other request frameworks as well (one such is mentioned in the above linked issue).

## Supported Socket types
ngx_zmq allows using REQ sockets, PUSH sockets, and PUB sockets.  The socket type is set with the zmq_socktype.  Examples:
```nginx
location /zmq1/ {
  zmq_endpoint "tcp://localhost:5555";
  zmq_socktype PUSH;
}

location /zmq2/ {
  zmq_endpoint "tcp://localhost:5556";
  zmq_socktype REQ;
}

location /zmq3/ {
  zmq_endpoint "tcp://localhost:5557";
  zmq_socktype PUB;
}
```

Invalid/unrecognized socktype arguments force a default to REQ.

## Error handling
ngx_zmq will give the following codes/request bodies under the specified conditions:

| HTTP Code | Request Body | Condition|
|-----------|--------------|----------|
| Gateway Timeout (504) | <empty> | send/recv times out|
| Bad Gateway (502) | ZeroMQ error message | send/recv fails, but does not timeout (errno != EAGAIN)|
| Accepted (202) | <empty> | no error from sending over a PUSH/PUB socket |
| OK (200) | Response from ZMQ server | successful round-trip (from ZMQ_REQ socket|

## Reference Materials
There does not seem to be a single good set of documentation on writing nginx modules.  The definitive guide linked below is great, but frequently errors happened I wouldn't know how to find.  A list of some of the resources I used:

[Search nginx source](http://lxr.nginx.org/ident)

[simple module](http://www.nginxguts.com/2011/01/how-to-return-a-simple-page/)

[Evan's Definitive guide](http://www.evanmiller.org/nginx-modules-guide.html)

[agentzh explaining nginx](http://openresty.org/download/agentzh-nginx-tutorials-en.html)
