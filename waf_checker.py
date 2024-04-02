import requests
import csv
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# Suppress only the single InsecureRequestWarning from urllib3 needed for verify=False.
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

def ensure_url_scheme(url):
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    return url

def requests_retry_session(retries=3, backoff_factor=0.3, status_forcelist=(500, 502, 503, 504), session=None):
    session = session or requests.Session()
    retry = Retry(total=retries, read=retries, connect=retries, backoff_factor=backoff_factor, status_forcelist=status_forcelist)
    adapter = HTTPAdapter(max_retries=retry)
    session.mount('http://', adapter)
    session.mount('https://', adapter)
    return session

def detect_waf_by_behavior(url):
    payloads = ["'", "<script>alert('XSS')</script>", "SELECT * FROM users"]
    headers = {'User-Agent': 'Mozilla/5.0'}

    for method in ['GET', 'POST']:
        for payload in payloads:
            try:
                if method == 'GET':
                    response = requests_retry_session().get(url, headers=headers, params={'testparam': payload}, verify=False, timeout=10)
                else:
                    response = requests_retry_session().post(url, headers=headers, data={'testparam': payload}, verify=False, timeout=10)
                
                if "cloudflare" in response.text.lower() or "cf-ray" in response.headers:
                    return "Cloudflare"
                elif "the requested url was rejected" in response.text.lower():
                    return "F5 Big-IP"
            except requests.exceptions.RequestException as e:
                return f"Error during {method} request: {e}"

    return "No specific WAF detected or the site is not reachable"

def process_urls_from_file(file_path):
    results = []
    with open(file_path, 'r') as file:
        for line in file:
            url = line.strip()
            if url:
                url_with_scheme = ensure_url_scheme(url)
                waf_detection_result = detect_waf_by_behavior(url_with_scheme)
                results.append((url, waf_detection_result))
                print(url)
    return results

def write_results_to_csv(results, csv_file_path):
    with open(csv_file_path, 'w', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["URL", "WAF Detection Result"])
        writer.writerows(results)

# Specify the input and output file paths
urls_file_path = 'urls.txt'
csv_file_path = 'waf_detection_results.csv'

# Process the URLs and write the results to the CSV
results = process_urls_from_file(urls_file_path)
write_results_to_csv(results, csv_file_path)

print(f"Completed. The WAF detection results have been written to {csv_file_path}.")
