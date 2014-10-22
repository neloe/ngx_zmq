ngx_zmq
=======
An upstream ZeroMQ module for nginx

Reference Materials
-------------------
search nginx source: http://lxr.nginx.org/ident

simple module: http://www.nginxguts.com/2011/01/how-to-return-a-simple-page/

evans guide: http://www.evanmiller.org/nginx-modules-guide.html

agentzh explaining nginx: http://openresty.org/download/agentzh-nginx-tutorials-en.html

Adding to Nginx
---------------
```bash
# make dir for modules
cd ~/
sudo mkdir nginx
cd ~/nginx/

# get https://github.com/neloe/ngx_zmq
git clone git@github.com:neloe/ngx_zmq.git

# get http://wiki.nginx.org/HttpEchoModule
wget https://github.com/openresty/echo-nginx-module/archive/v0.56.tar.gz
tar xzvf v0.56.tar.gz

# get nginx
wget http://nginx.org/download/nginx-1.5.12.tar.gz
tar xzvf nginx-1.5.12.tar.gz
cd nginx-1.5.12/
./configure --add-module=~/nginx/ngx_zmq --add-module=~/nginx/echo-nginx-module-0.56
make && sudo make install
```

Usage
-----
Start nginx with these directives (as seen in nginx.conf, run with `bash restart.sh`)
```nginx
    location /zmq {
        echo_read_request_body;
        zmq;
        zmq_endpoint "tcp://localhost:5555";
    }
```
Start a zmq server (example included in us.cpp)
```
g++ us.cpp -lzmq
./a.out
```
Curl nginx to get the response from the zmq server with
```$ curl -X POST -d 'hello' http://localhost/zmq```

Which will give
`World`
