#!/bin/bash

clear

echo "stopping nginx"
sudo killall nginx

echo "removing nginx logs"
sudo rm logs/*.log

echo "starting nginx from nginx.conf"
sudo /usr/local/nginx/sbin/nginx -c nginx.conf -p `pwd`
