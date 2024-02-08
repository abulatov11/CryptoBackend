#!/bin/bash

sudo docker container stop crypto-backend || true
sudo docker container prune || true
sudo docker run -p 8888:8888 -d --restart always --name crypto-backend crypto/backend