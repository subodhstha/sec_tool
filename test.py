import urllib.request
import json

req = urllib.request.Request(
    'http://localhost:3000/api/v1/scans',
    data=json.dumps({
        "target_url": "https://vyomite.com.np",
        "config": {
            "verification_token": "vyomite-dev-token"
        }
    }).encode('utf-8'),
    headers={'Content-Type': 'application/json'}
)

try:
    with urllib.request.urlopen(req) as f:
        print(f"Status: {f.status}")
        print(f"Headers: {f.headers}")
        print(f"Body: {f.read().decode('utf-8')}")
except urllib.error.HTTPError as e:
    print(f"Error Status: {e.code}")
    print(f"Error Headers: {e.headers}")
    print(f"Error Body: {e.read().decode('utf-8')}")
