#!/bin/bash

sudo docker container purge
sudo docker image rm crypto/backend:latest || true
sudo docker image ls
sudo docker build --file Dockerfile.backend -t crypto/backend .
