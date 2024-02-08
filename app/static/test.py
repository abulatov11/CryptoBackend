#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import requests

URL = "http://seed789-01/assignment2/api/v1.0/test"

iv = "00112233445566778899AABBCCDDEEFF"
text = "AABBCCDDEEFF0123456789FFEEDDCCBBAA"

data = {"iv": iv, "text": text}

try:
    response = requests.post(URL, json=data)
    
    print("Server replied:")
    print(response.text)
except Exception as e:
    print(" ERROR: %s" % str(e))