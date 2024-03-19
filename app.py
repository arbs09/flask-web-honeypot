import os
from flask import Flask, request, render_template, send_from_directory
import requests
from datetime import datetime, timedelta

app = Flask(__name__)

ABUSEIPDB_API_KEY = os.environ.get('API_KEY', 'default_key')
REPORT_INTERVAL = timedelta(minutes=15)
reported_ips = {}
MALICIOUS_USER_AGENTS = ["Go-http-client", "python", "sqlmap", "Nmap Scripting Engine", "pycurl"]

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
    if not os.path.exists('data'):
        os.makedirs('data')
    with open(os.path.join('data', 'report.txt'), 'a') as file:
        file.write(f'{timestamp} ; {ip}\n')

@app.before_request
def get_client_ip():
    global request  # Modify the global request object
    request.client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    request.user_agent = request.headers.get('X-Forwarded-User-Agent', None)

@app.route('/', methods=['GET', 'POST'])
def index():
    return render_template('index.html')

@app.route("/robots.txt")
def send_robots():
    return send_from_directory("assets", "robots.txt")

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

@app.before_request
def check_user_agent():
    user_agent = request.user_agent
    if user_agent and any(malicious_agent in user_agent for malicious_agent in MALICIOUS_USER_AGENTS):
        ip = request.client_ip
        if ip not in reported_ips or datetime.now() - reported_ips[ip] > REPORT_INTERVAL:
            save_to_file(ip)
            report_ip(ip, '18,19,21,15', f'Automated report for using malicious user-agent: {user_agent}')
            reported_ips[ip] = datetime.now()

@app.route('/<path:filename>')
def report_rules(filename):
    ip = request.client_ip
    if filename in ['xmlrpc.php', 'check.js', 'my1.php', '.env', 'admin.php', 'wlwmanifest.xml', '.DS_Store', '.htaccess', 'core.js', 'install.php', 'config.php', 'st.php', 'repeater.php', 'dropdown.php', 'cjfuns.php', 'file.php', '_all_dbs', 'config.json', 'login.action', 'sftp.json', 'style.php', 'setup-config?step=1', 'hetong.js', 'ae.php', 'moon.php', 'wp-sigunq.php', 'jquery.query.js', 'ajax-actions.php', 'admin-post.php', 'repeater.php', 'install.php', 'plugins.php', 'shell.php', 'wp.php', 'wp-config.php-backup', 'config', 'wp-emoji-release.min.js', 'HEAD', 'wp_filemanager.php']:
        if ip not in reported_ips or datetime.now() - reported_ips[ip] > REPORT_INTERVAL:
            save_to_file(ip)
            report_ip(ip, '18,19,21,15', f'Automated report for accessing {filename} on my Honeypot')
            reported_ips[ip] = datetime.now()
    return '404'

if __name__ == '__main__':
    app.run(debug=False, port=80, host="0.0.0.0")
