import requests
import argparse
import re
import json

def parse_login_request(file_path):
    """Parses login request file dynamically to detect login method, URL, and payload."""
    with open(file_path, "r") as f:
        lines = f.readlines()

    method, url, headers, payload = None, None, {}, None
    body_lines = []
    
    for line in lines:
        line = line.strip()
        if line.startswith(("POST", "GET")):
            parts = line.split()
            method = parts[0]
            url = parts[1]
        elif ": " in line and not line.startswith(("POST", "GET")):
            key, value = line.split(": ", 1)
            headers[key] = value
        elif "=" in line or "{" in line:
            body_lines.append(line)

    if body_lines:
        body_text = "\n".join(body_lines)
        if headers.get("Content-Type") == "application/json":
            payload = json.loads(body_text)  # JSON-based login
        else:
            payload = dict(re.findall(r"([^&=]+)=([^&]*)", body_text))  # Form-data login

    return method, url, headers, payload

def login(session, base_url, login_request_file):
    """Perform dynamic login detection and authentication, maintaining session persistence."""
    method, login_path, headers, payload = parse_login_request(login_request_file)
    login_url = f"{base_url}{login_path}"

    response = session.post(login_url, headers=headers, json=payload if isinstance(payload, dict) else payload)
    
    if response.status_code == 200 and "Set-Cookie" in response.headers:
        print(f"[+] Login successful: {login_url}")
        return session
    else:
        print(f"[-] Login failed: {response.status_code}")
        return None

def enumerate_http_methods(session, url):
    """Enumerates supported HTTP methods using OPTIONS request."""
    response = session.options(url)
    if response.status_code == 200 and "Allow" in response.headers:
        print(f"[+] Supported Methods: {response.headers['Allow']}")
    else:
        print("[-] Could not enumerate HTTP methods or access denied.")

def test_access_control(session, url):
    """Checks if restricted pages can be accessed without proper authorization."""
    response = session.get(url)
    if response.status_code == 200 and "Access Denied" not in response.text:
        print(f"[+] Possible Access Control Bypass: {url}")
    else:
        print("[-] Access control seems enforced.")

def test_xst(session, url):
    """Tests for Cross-Site Tracing (XST) vulnerability."""
    response = session.request("TRACE", url)
    if response.status_code == 200 and "TRACE" in response.text:
        print(f"[+] XST Vulnerability Found: {url}")
    else:
        print("[-] TRACE method is not enabled or access denied.")

def test_http_method_override(session, url):
    """Tests HTTP method overriding using headers."""
    headers = {
        "X-HTTP-Method-Override": "PUT",
        "X-Method-Override": "PUT"
    }
    response = session.post(url, headers=headers)
    if response.status_code in [200, 201, 204]:
        print(f"[+] HTTP Method Override Successful: {url}")
    else:
        print("[-] HTTP Method Override not allowed or access denied.")

def test_put_method(session, target_url, test_file_path):
    """Tests if HTTP PUT method is enabled and confirm via GET."""
    headers = {"Content-Type": "text/html"}
    test_content = "<html>HTTP PUT Method is Enabled</html>"
    
    put_response = session.put(f"{target_url}/{test_file_path}", data=test_content, headers=headers)

    if put_response.status_code in [200, 201, 204, 301, 302, 307, 308]:
        print(f"[+] PUT request successful on {target_url}/{test_file_path}")
        get_response = session.get(f"{target_url}/{test_file_path}")
        if get_response.status_code == 200 and "HTTP PUT Method is Enabled" in get_response.text:
            print(f"[+] Confirmed: File successfully uploaded at {target_url}/{test_file_path}")
        else:
            print("[-] PUT method allowed but file retrieval failed.")
    else:
        print(f"[-] PUT request failed on {target_url}, Status Code: {put_response.status_code}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Advanced HTTP Method Vulnerability Tester with Session Persistence")
    parser.add_argument("--url", help="Single target URL to test")
    parser.add_argument("--list", help="File containing list of URLs")
    parser.add_argument("--login", help="Login request file (e.g., login-request.txt)", required=True)
    
    args = parser.parse_args()
    session = requests.Session()
    
    if args.url:
        urls = [args.url]
    elif args.list:
        with open(args.list, "r") as f:
            urls = [line.strip() for line in f.readlines()]
    else:
        print("[-] You must specify either --url or --list")
        exit(1)

    base_url = urls[0]  # Assuming login is at the first URL
    session = login(session, base_url, args.login)

    if session:
        for url in urls:
            enumerate_http_methods(session, url)
            test_access_control(session, url)
            test_xst(session, url)
            test_http_method_override(session, url)
            test_put_method(session, url, "test.html")
    else:
        print("[-] Login failed. Exiting.")
