import httpx

try:
    r = httpx.get("https://www.google.com", timeout=10)
    print("SUCCESS")
    print(r.status_code)
except Exception as e:
    print("FAILED")
    print(repr(e))