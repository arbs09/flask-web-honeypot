import os
from flask import Flask, request, render_template
import requests
from datetime import datetime, timedelta

app = Flask(__name__)

ABUSEIPDB_API_KEY = os.environ.get('API_KEY', 'default_key')
REPORT_INTERVAL = timedelta(minutes=15)
reported_ips = {}

def report_ip(ip, categories, comment):
  url = 'https://api.abuseipdb.com/api/v2/report'
  headers = {
    'Key': ABUSEIPDB_API_KEY,
    'Content-Type': 'application/x-www-form-urlencoded'
  }
  payload = {
    'ip': ip,
    'categories': categories,
    'comment': comment
  }
  response = requests.post(url, headers=headers, data=payload)
  return response.json()

def save_to_file(ip):
  timestamp = datetime.now().strftime('%Y.%m.%d %H:%M')
  with open('report.txt', 'a') as file:
    file.write(f'{timestamp} ; {ip}\n')

@app.before_request
def get_client_ip():
  global request  # Modify the global request object
  request.client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)

@app.route('/', methods=['GET', 'POST'])
def index():
  return render_template('index.html')


@app.route('/wp-login.php', methods=['GET', 'POST'])
@app.route('/wp-info.php', methods=['GET', 'POST'])
@app.route('/wp-admin/<path:path>', methods=['GET', 'POST'])
@app.route('/wp-admin/', methods=['GET', 'POST'])
@app.route('/wp-json/<path:path>', methods=['GET', 'POST'])
@app.route('/wp-json/', methods=['GET', 'POST'])
@app.route('/wp-content/<path:path>', methods=['GET', 'POST'])
@app.route('/wp-content/', methods=['GET', 'POST'])
@app.route('/wp-includes/<path:path>', methods=['GET', 'POST'])
@app.route('/wp-includes/', methods=['GET', 'POST'])
def wp_vulnerability_scan(path=None):
  ip = request.client_ip
  if ip not in reported_ips or datetime.now() - reported_ips[ip] > REPORT_INTERVAL:
    save_to_file(ip)
    report_ip(ip, '18,19,21,15', 'Automated report for WordPress vulnerability scanning')
    reported_ips[ip] = datetime.now()
  return '404'

@app.route('/.vscode/<path:path>', methods=['GET', 'POST'])
@app.route('/.git/<path:path>', methods=['GET', 'POST'])
def sensitive_folders_access(path=None):
  ip = request.client_ip
  if ip not in reported_ips or datetime.now() - reported_ips[ip] > REPORT_INTERVAL:
    save_to_file(ip)
    folder_name = request.path.split('/')[1]
    report_ip(ip, '18,19,21,15', f'Automated report for accessing {folder_name} folder')
    reported_ips[ip] = datetime.now()
  return '404'

@app.before_request
def check_path():
  if '../' in request.path:
    ip = request.client_ip
    if ip not in reported_ips or datetime.now() - reported_ips[ip] > REPORT_INTERVAL:
      save_to_file(ip)
      report_ip(ip, '18,19,21,15', 'Automated report for attempting to traverse directories')
      reported_ips[ip] = datetime.now()
    return '404'

@app.route('/<path:filename>')
def report_rules(filename):
  ip = request.client_ip
  if filename in ['xmlrpc.php', 'check.js', 'my1.php', '.env', 'admin.php', 'wlwmanifest.xml', '.DS_Store', '.htaccess', 'core.js', 'install.php', 'config.php', 'st.php', 'repeater.php', 'dropdown.php', 'cjfuns.php', 'file.php', '_all_dbs', 'config.json', 'login.action', 'sftp.json', 'style.php', 'setup-config']:
    if ip not in reported_ips or datetime.now() - reported_ips[ip] > REPORT_INTERVAL:
      save_to_file(ip)
      report_ip(ip, '18,19,21,15', f'Automated report for accessing {filename} on my Honeypot')
      reported_ips[ip] = datetime.now()
  return '404'

if __name__ == '__main__':
  app.run(debug=False,port=80, host="0.0.0.0")
