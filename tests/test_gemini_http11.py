import httpx

try:
    with httpx.Client(http2=False, timeout=20) as client:
        r = client.get(
            "https://generativelanguage.googleapis.com/v1beta/models"
        )
        print(r.status_code)
        print(r.text[:200])
except Exception as e:
    print(repr(e))