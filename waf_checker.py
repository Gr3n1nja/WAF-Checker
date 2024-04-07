import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from urllib3.exceptions import InsecureRequestWarning
import csv

# Suppress InsecureRequestWarning when verify=False
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

def ensure_url_scheme(url):
    """Ensure the URL starts with http:// or https://."""
    if not url.startswith(('http://', 'https://')):
        return 'https://' + url
    return url

def requests_retry_session(retries=3, backoff_factor=0.3, status_forcelist=(500, 502, 503, 504), session=None):
    """Create a requests session with retry logic."""
    session = session or requests.Session()
    retry = Retry(
        total=retries,
        read=retries,
        connect=retries,
        backoff_factor=backoff_factor,
        status_forcelist=status_forcelist,
        allowed_methods=frozenset(['GET', 'POST']),
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    return session

def identify_waf_from_response(response):
    """Check the response for signs of Cloudflare or F5 Big-IP."""
    # Cloudflare signature
    if "server" in response.headers and "cloudflare" in response.headers["server"].lower():
        return "Cloudflare"
    if "cf-ray" in response.headers:  # Specific to Cloudflare
        return "Cloudflare"
    
    # F5 Big-IP signature
    if "x-wa-info" in response.headers or "x-cnection" in response.headers:  # Indicative of F5
        return "F5 Big-IP"
    if "support id" in response.text.lower():  # Check response body for F5 Big-IP specific signature
        return "F5 Big-IP"

    return "Unknown"

def detect_waf(url):
    """Attempt to identify WAF by making both GET and POST requests and checking the response."""
    session = requests_retry_session()
    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3'}
    get_url = f"{url}/%3Cscript%3E"
    post_data = {"payload": "<script>"}

    try:
        # First, attempt a GET request
        response = session.get(get_url, headers=headers, timeout=5, verify=False)
        waf_name = identify_waf_from_response(response)
        if waf_name != "Unknown":
            return f"Potential WAF Detected (GET request), WAF: {waf_name}"

        # If GET request doesn't conclusively identify a WAF, try a POST request
        response = session.post(url, headers=headers, data=post_data, timeout=5, verify=False)
        waf_name = identify_waf_from_response(response)
        if waf_name != "Unknown":
            return f"Potential WAF Detected (POST request), WAF: {waf_name}"
        
    except requests.exceptions.RequestException as e:
        return f"Error determining WAF: {e}"

    return "No WAF Detected or Unknown"

def process_urls(file_path):
    results = []
    with open(file_path, 'r') as file:
        for line in file:
            url = ensure_url_scheme(line.strip())
            waf_status = detect_waf(url)
            results.append((url, waf_status))
            print(f"URL: {url}, WAF Status: {waf_status}")
    return results

def write_results_to_csv(results, output_file):
    with open(output_file, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(["URL", "WAF Status"])
        writer.writerows(results)

# File paths
input_file = 'urls.txt'
output_file = 'waf_detection_results.csv'

# Process URLs and write results
results = process_urls(input_file)
write_results_to_csv(results, output_file)
print("Completed. Results have been written to 'waf_detection_results.csv'.")
