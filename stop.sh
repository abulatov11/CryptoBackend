#!/bin/bash

sudo docker container stop crypto-backend || true
sudo docker container prune || true
