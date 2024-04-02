# WAF-Checker
A Python script for detecting Cloudflare and F5 Big-IP WAFs by analyzing responses to crafted GET and POST requests.

## Overview
This Python script is designed to help identify whether websites are protected by specific Web Application Firewalls (WAFs), focusing on Cloudflare and F5 Big-IP. It employs a robust approach by making sequential GET and POST requests with specially crafted payloads, aiming to trigger and identify WAF-specific behaviors. The script integrates retry logic with exponential backoff to handle transient network issues and rate limiting more gracefully.

## Prerequisites
- Python 3.6+
- `requests` library

Ensure Python is installed on your system. You can download it from [python.org](https://www.python.org/downloads/).

The `requests` library is required. Install it using pip:

```
pip install requests
```

## Setup
1. Clone the repository or download the script to your local machine.
2. In the script's directory, create a text file named `urls.txt`. Add the URLs you wish to check, each on a new line.

## Usage
Navigate to the directory containing the script and `urls.txt`, then run the following command:

```
python3 waf_checker.py
```

The script processes each URL from `urls.txt`, attempting to detect the WAF, and writes the results into `waf_detection_results.csv`.

## Output
The output CSV contains two columns:
- **URL**: The URL checked.
- **WAF Detection Result**: Indicates whether Cloudflare, F5 Big-IP, or no specific WAF was detected, or if the site was not reachable.

## Features
- **Sequential Request Logic**: Tries detecting WAF presence using both GET and POST requests.
- **Retry with Exponential Backoff**: Addresses transient errors and rate limiting.
- **Flexible SSL Verification**: Includes an option to disable SSL verification to bypass related errors, with a caution on security implications.

## Security and Legal Considerations
This tool is intended for security research and professional use. Testing websites without permission may violate terms of service or local laws. Obtain appropriate authorization before scanning any URLs with this script.

## Contributions
Contributions are welcome. If you have suggestions or improvements, feel free to fork the repository, make your changes, and submit a pull request.

## License
This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
