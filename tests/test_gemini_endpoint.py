import httpx

url = "https://generativelanguage.googleapis.com/v1beta/models"

try:
    response = httpx.get(url, timeout=20)
    print("SUCCESS")
    print(response.status_code)
    print(response.text[:300])
except Exception as e:
    print("FAILED")
    print(repr(e))