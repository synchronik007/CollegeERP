import urllib.request, json
import re
try:
    req = urllib.request.Request('http://localhost:8000/api/auth/login/', data=json.dumps({'user_id':'EMP2026A002','password':'password'}).encode('utf-8'), headers={'Content-Type': 'application/json'})
    urllib.request.urlopen(req)
except Exception as e:
    html = getattr(e, 'read', lambda: b'')().decode('utf-8', errors='ignore')
    match = re.search(r'<textarea id="traceback_area".*?>(.*?)</textarea>', html, re.DOTALL)
    if match:
        print(match.group(1).strip())
    else:
        print(html[:1000])
