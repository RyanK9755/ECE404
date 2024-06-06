#!/usr/bin/env python
import base64
import sys

input_string = sys.argv[1].encode('utf-8')
encoded_string = base64.b64encode(input_string).decode('utf-8')
print(encoded_string)