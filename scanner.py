import sys
import nmap
import socket
import os
import subprocess
import json
from datetime import datetime
from pathlib import Path
import time
import zipfile
import platform

NUCLEI_BIN = "/usr/local/bin/nuclei"
NUCLEI_VERSION = "3.3.5"  # можно вынести в конфиг

targets = "targets"
# Конфигурация
DIRSEARCH_REPO = "https://github.com/maurosoria/dirsearch.git"
DIRSEARCH_DIR = "/home/kali/PycharmProjects/scan/dirsearch-master"
DIRSEARCH_PATH = os.path.join(DIRSEARCH_DIR, "dirsearch.py")
REPORTS_DIR = "security_reports"


def load_targets(source):
    if source == "-":
        lines = sys.stdin.read().splitlines()
    elif os.path.isfile(source):
        with open(source, "r", encoding="utf-8") as f:
            lines = f.read().splitlines()
    else:
        return [source.strip()]
    return [ln.strip() for ln in lines if ln.strip() and not ln.startswith("#")]


def install_dirsearch():
    """
    Устанавливает dirsearch из GitHub, если его нет.
    Возвращает путь к python из venv или системный python.
    """
    venv_python = os.path.join(DIRSEARCH_DIR, "venv", "bin", "python3")

    # Если папка уже существует — пропускаем установку
    if os.path.exists(DIRSEARCH_DIR) and os.path.exists(DIRSEARCH_PATH):
        print(f"✅ dirsearch already installed at: {DIRSEARCH_DIR}")
        if os.path.exists(venv_python):
            return venv_python
        return "python3"

    print(f"📥 dirsearch not found. Installing from GitHub...")

    try:
        # Клонируем репозиторий
        clone_cmd = ["git", "clone", DIRSEARCH_REPO, DIRSEARCH_DIR]
        print(f"🚀 Cloning: {' '.join(clone_cmd)}")
        result = subprocess.run(
            clone_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=300
        )

        if result.returncode != 0:
            print(f"❌ Git clone failed: {result.stderr}")
            return None

        print(f"✅ Repository cloned successfully")

        # Создаём виртуальное окружение
        print(f"🔧 Creating virtual environment...")
        venv_cmd = ["python3", "-m", "venv", os.path.join(DIRSEARCH_DIR, "venv")]
        result = subprocess.run(
            venv_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=120
        )

        if result.returncode != 0:
            print(f"⚠ Venv creation failed: {result.stderr}")
            print(f"⚠ Will use system python")
            return "python3"

        # Устанавливаем зависимости
        print(f"📦 Installing dependencies...")
        pip_cmd = [venv_python, "-m", "pip", "install", "-r",
                   os.path.join(DIRSEARCH_DIR, "requirements.txt")]
        result = subprocess.run(
            pip_cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=600
        )

        if result.returncode != 0:
            print(f"⚠ pip install failed: {result.stderr}")
            print(f"⚠ Will try system python")
            return "python3"

        print(f"✅ dirsearch installed successfully!")
        return venv_python

    except subprocess.TimeoutExpired:
        print(f"❌ Installation timeout")
        return None
    except Exception as e:
        print(f"❌ Installation error: {e}")
        return None


def ensure_directories():
    """Создание директории для отчётов с АБСОЛЮТНЫМ путем"""
    global REPORTS_DIR

    REPORTS_DIR = "/home/kali/PycharmProjects/scan/security_reports/"

    if not os.path.exists(REPORTS_DIR):
        os.makedirs(REPORTS_DIR, mode=0o755, exist_ok=True)
        print(f"✅ Created reports directory: {REPORTS_DIR}")
    else:
        print(f"✅ Reports directory exists: {REPORTS_DIR}")
        if os.access(REPORTS_DIR, os.W_OK):
            print(f"✅ Directory is writable")
        else:
            print(f"⚠ Directory is NOT writable, fixing...")
            os.chmod(REPORTS_DIR, 0o755)

    return REPORTS_DIR


def run_dirsearch(target, port, auto_confirm=False):
    """Запуск dirsearch для указанной цели с автоустановкой"""

    try:
        if not auto_confirm:
            # Формируем URL заранее, чтобы показать пользователю
            if port:
                # _proto = "https" if port == 443 else "http"
                _proto = "https" if "443" in str(port) else "http"
                _preview_url = f"{_proto}://{target}:{port}"
            else:
                _preview_url = f"https://{target}"

            print(f"=" * 60)
            print(f"❓ Запустить скан dirsearch по цели: {_preview_url} ?")
            print(f"=" * 60)

            while True:
                answer = input("   [y]es / [n]o: ").strip().lower()
                if answer in ('y', 'yes', 'д', 'да', ''):
                    print(f"✅ Запускаем скан...")
                    break
                elif answer in ('n', 'no', 'н', 'нет'):
                    print(f"⏭ Скан пропущен пользователем")
                    return {
                        'success': False,
                        'skipped': True,
                        'reason': 'user_skipped',
                        'url': _preview_url,
                        'port': port,
                        'error': 'Skipped by user'
                    }
                else:
                    print(f"⚠ Введите 'y' (да) или 'n' (нет)")
        # Устанавливаем dirsearch, если его нет
        venv_python = install_dirsearch()
        if venv_python is None:
            return {
                'success': False,
                'error': 'Failed to install dirsearch'
            }

        reports_dir = ensure_directories()

        # Формируем URL
        if port:
            # protocol = "https" if port == 443 else "http"
            protocol = "https" if "443" in str(port) else "http"
            url = f"{protocol}://{target}:{port}"
        else:
            url = f"https://{target}"

        # Абсолютный путь к файлу отчёта
        safe_target = target.replace('.', '_').replace(':', '_')
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"dirsearch_{safe_target}_{port if port else 'auto'}_{timestamp}.txt"
        output_file = os.path.join(REPORTS_DIR, filename)

        print(f"=" * 60)
        print(f"📁 OUTPUT FILE: {output_file}")
        print(f"=" * 60)

        cmd = [
            venv_python,
            DIRSEARCH_PATH,
            "-u", url,
            "-o", output_file,
            "--random-agent",
            "-t", "10",
            # "--timeout=5",
            "--deep-recursive",
            "--force-recursive",
            "--full-url",
            "--no-color",
            "-q"
        ]

        print(f"🚀 Executing command:")
        print(f"{' '.join(cmd)}")
        print(f"=" * 60)

        process = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=1800,
            cwd=DIRSEARCH_DIR  # запускаем из папки dirsearch
        )

        time.sleep(2)

        if os.path.exists(output_file):
            file_size = os.path.getsize(output_file)
            print(f"✅ SUCCESS! File created: {output_file}")
            print(f"📊 File size: {file_size} bytes")

            urls = []
            if file_size > 0:
                with open(output_file, 'r', encoding='utf-8', errors='ignore') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#') \
                                and not line.startswith('[') \
                                and not line.startswith('Time'):
                            urls.append(line)
                print(f"🔗 Found {len(urls)} URLs")

                if urls:
                    print(f"📋 First 5 URLs:")
                    for i, url_found in enumerate(urls[:5], 1):
                        print(f"   {i}. {url_found}")
            else:
                print(f"⚠ File is empty")

            return {
                'success': True,
                'url': url,
                'port': port,
                'output_file': output_file,
                'urls': urls[:100],
                'total_urls': len(urls),
                'command': ' '.join(cmd)
            }
        else:
            print(f"❌ FAILED! File not created: {output_file}")
            if process.stderr:
                print(f"❌ STDERR: {process.stderr}")
            return {
                'success': False,
                'url': url,
                'port': port,
                'error': process.stderr or 'Output file was not created',
                'output_file': output_file
            }

    except subprocess.TimeoutExpired:
        print(f"⏰ Timeout expired")
        return {'success': False, 'error': 'Timeout'}
    except Exception as e:
        print(f"❌ Error: {e}")
        return {'success': False, 'error': str(e)}


def install_nuclei():
    """Проверяет наличие nuclei, если нет — качает бинарник с GitHub Releases."""
    if os.path.exists(NUCLEI_BIN):
        print(f"✅ nuclei already installed: {NUCLEI_BIN}")
        return NUCLEI_BIN

    # fallback: может быть в PATH, но не в /usr/local/bin
    try:
        result = subprocess.run(["which", "nuclei"], capture_output=True, text=True)
        if result.returncode == 0 and result.stdout.strip():
            print(f"✅ nuclei found in PATH: {result.stdout.strip()}")
            return result.stdout.strip()
    except Exception:
        pass

    print("📥 nuclei not found. Downloading from GitHub Releases...")
    arch = "amd64" if platform.machine() in ("x86_64", "AMD64") else "arm64"
    url = (
        f"https://github.com/projectdiscovery/nuclei/releases/download/"
        f"v{NUCLEI_VERSION}/nuclei_{NUCLEI_VERSION}_linux_{arch}.zip"
    )
    zip_path = "/tmp/nuclei.zip"

    try:
        subprocess.run(["wget", "-q", url, "-O", zip_path], check=True, timeout=300)

        with zipfile.ZipFile(zip_path, "r") as z:
            z.extract("nuclei", "/tmp/")

        subprocess.run(["chmod", "+x", "/tmp/nuclei"], check=True)
        subprocess.run(["sudo", "mv", "/tmp/nuclei", NUCLEI_BIN], check=True)

        # Обновляем шаблоны (важно для работы)
        subprocess.run([NUCLEI_BIN, "-update-templates", "-silent"], timeout=300)
        print(f"✅ nuclei installed: {NUCLEI_BIN}")
        return NUCLEI_BIN

    except Exception as e:
        print(f"❌ nuclei install failed: {e}")
        return None
    finally:
        if os.path.exists(zip_path):
            os.remove(zip_path)


def run_nuclei(target, port=None, auto_confirm=False):
    """Запуск nuclei с проверкой установки и подтверждением."""
    try:
        # --- Подтверждение ---
        if not auto_confirm:
            if port:
                # _proto = "https" if port == 443 else "http"
                _proto = "https" if "443" in str(port) else "http"
                _preview = f"{_proto}://{target}:{port}"
            else:
                _preview = f"https://{target}"

            print("=" * 60)
            print(f"❓ Запустить nuclei по цели: {_preview} ?")
            print("=" * 60)
            while True:
                ans = input("   [y]es / [n]o: ").strip().lower()
                if ans in ("y", "yes", "д", "да", ""):
                    break
                if ans in ("n", "no", "н", "нет"):
                    return {"success": False, "skipped": True,
                            "reason": "user_skipped", "url": _preview, "port": port}
                print("⚠ Введите 'y' или 'n'")

        # --- Установка ---
        nuclei_bin = install_nuclei()
        if not nuclei_bin:
            return {"success": False, "error": "Failed to install nuclei"}

        # --- Формируем URL ---
        if port:
            # protocol = "https" if port == 443 else "http"
            protocol = "https" if "443" in str(port) else "http"
            url = f"{protocol}://{target}:{port}"
        else:
            url = f"https://{target}"

        # --- Отчёт ---
        reports_dir = ensure_directories()
        safe = target.replace(".", "_").replace(":", "_")
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = os.path.join(reports_dir, f"nuclei_{safe}_{port or 'auto'}_{ts}.txt")

        cmd = [
            nuclei_bin,
            "-u", url,
            "-o", output_file,
            "-silent",           # только результаты, без мусора
            "-stats",            # прогресс
            "-severity", "low,medium,high,critical",  # можно убрать — будет всё
        ]

        print(f"🚀 Executing: {' '.join(cmd)}")
        process = subprocess.run(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, timeout=3600
        )

        time.sleep(2)

        if os.path.exists(output_file):
            findings = []
            with open(output_file, encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        findings.append(line)

            print(f"✅ nuclei done. Findings: {len(findings)}")
            for i, fnd in enumerate(findings[:5], 1):
                print(f"   {i}. {fnd}")

            return {
                "success": True, "url": url, "port": port,
                "output_file": output_file,
                "findings": findings[:100],
                "total_findings": len(findings),
            }
        else:
            return {
                "success": False, "url": url, "port": port,
                "error": process.stderr or "Output file not created",
            }

    except subprocess.TimeoutExpired:
        return {"success": False, "error": "Timeout"}
    except Exception as e:
        return {"success": False, "error": str(e)}


def scan_certificate(target, port=443):
    """Детальная проверка SSL сертификата"""
    try:
        print(f"Scanning SSL certificate on {target}:{port}...")
        scanner = nmap.PortScanner()
        scanner.scan(target, arguments=f'-p {port} --script ssl-cert')

        results = []
        for host in scanner.all_hosts():
            if 'tcp' in scanner[host] and port in scanner[host]['tcp']:
                port_info = scanner[host]['tcp'][port]

                cert_results = f"\n------ Certificate Scan ------"
                cert_results += f"\nHost: {host} | Port: {port}"
                results.append(cert_results)

                if port_info.get('script') and 'ssl-cert' in port_info['script']:
                    cert_info = port_info['script']['ssl-cert']

                    if isinstance(cert_info, str):
                        results.append("Certificate Information:")
                        results.append(cert_info)
                    elif isinstance(cert_info, dict):
                        results.append("Structured Certificate Information:")
                        if 'Subject' in cert_info:
                            results.append(f"Subject: {cert_info['Subject']}")
                        if 'Issuer' in cert_info:
                            results.append(f"Issuer: {cert_info['Issuer']}")
                        if 'Not valid before' in cert_info:
                            results.append(f"Valid from: {cert_info['Not valid before']}")
                        if 'Not valid after' in cert_info:
                            results.append(f"Valid until: {cert_info['Not valid after']}")
                    else:
                        results.append(f"Raw certificate info: {cert_info}")
                else:
                    results.append("No certificate information available")

        return results if results else ["No certificate information available"]

    except Exception as e:
        return [f"Error during certificate scan on {target}:{port}: {str(e)}"]


def get_https_ports(scanner, host):
    """Поиск HTTPS портов (443 и альтернативных)"""
    https_ports = []
    if 'tcp' in scanner[host]:
        for port, info in scanner[host]['tcp'].items():
            if info['state'] == 'open':
                if port == 'http' or 'https' in info.get('name', '').lower() or 'ssl' in info.get('name', '').lower():
                    https_ports.append(port)
                elif 'https' in info.get('version', '').lower() or 'ssl' in info.get('version', '').lower():
                    https_ports.append(port)
    print('HTTP Ports:             ',https_ports)
    return https_ports


def scan_security_headers(target, port=443):
    """Проверка заголовков безопасности"""
    try:
        print(f"Scanning security headers on {target}:{port}...")
        scanner = nmap.PortScanner()
        scripts = 'http-security-headers,http-headers'
        scanner.scan(target, arguments=f'-p {port} --script {scripts}')

        results = []
        for host in scanner.all_hosts():
            if 'tcp' in scanner[host] and port in scanner[host]['tcp']:
                port_info = scanner[host]['tcp'][port]

                header_results = f"\n------ Security Headers Scan ------"
                header_results += f"\nHost: {host} | Port: {port}"
                header_results += f"\nService: {port_info.get('name', 'unknown')}"
                results.append(header_results)

                security_headers_found = []
                missing_security_headers = []

                common_security_headers = [
                    'Strict-Transport-Security',
                    'Content-Security-Policy',
                    'X-Content-Type-Options',
                    'X-Frame-Options',
                    'X-XSS-Protection',
                    'Referrer-Policy',
                    'Permissions-Policy',
                    'Cache-Control'
                ]

                headers_text = ""

                if port_info.get('script'):
                    for script_name in ['http-security-headers', 'http-headers']:
                        if script_name in port_info['script']:
                            script_output = port_info['script'][script_name]
                            if isinstance(script_output, str):
                                headers_text += script_output + "\n"
                            elif isinstance(script_output, dict):
                                for key, value in script_output.items():
                                    headers_text += f"{key}: {value}\n"

                    if headers_text:
                        results.append(f"\nRaw Headers:\n{headers_text}")

                    for header in common_security_headers:
                        if header.lower() in headers_text.lower():
                            security_headers_found.append(header)
                        else:
                            missing_security_headers.append(header)

                if security_headers_found:
                    results.append(f"\n✓ Found security headers: {', '.join(security_headers_found)}")
                if missing_security_headers:
                    results.append(f"\n✗ Missing security headers: {', '.join(missing_security_headers)}")

        return results if results else ["No security headers information available"]

    except Exception as e:
        return [f"Error during security headers scan on {target}:{port}: {str(e)}"]


def scan_tcp_host(target):
    """Сканирование TCP портов хоста"""
    try:
        print(f"Starting TCP scan for {target}...")
        scanner = nmap.PortScanner()
        scanner.scan(target, arguments="-sV -Pn -p- --open --host-timeout 30m")

        results = []
        open_ports_info = []
        https_ports_found = []

        for host in scanner.all_hosts():
            host_header = f"\n------ TCP Port Scan Results ------"
            host_header += f"\nHost: {target} ({scanner[host].hostname()})"
            host_header += f"\nIP Address: {scanner[host]['addresses'].get('ipv4', 'N/A')}"
            host_header += f"\nStatus: {scanner[host].state()}"
            results.append(host_header)

            if not scanner[host].all_protocols():
                results.append("No open ports found")
                return results, []

            for proto in scanner[host].all_protocols():
                ports = scanner[host][proto].items()
                open_ports_count = 0

                for port, info in ports:
                    if info['state'] == 'open':
                        open_ports_count += 1
                        port_info = f"Port: {port:5} | Protocol: {proto:4} | Service: {info.get('name', 'unknown'):15} | Version: {info.get('product', 'unknown')} {info.get('version', '')}"
                        open_ports_info.append(port_info)
                        results.append(port_info)
                        print('RESULT PORTS',results)
                    if info['name'] == 'http':
                        https_ports_found.append(port)
                        print('HTTP NEW PORTS          ',https_ports_found)

                        if port == 'http' or 'https' in info.get('name', '').lower() or 'ssl' in info.get('name', '').lower():
                            https_ports_found.append(port)

                if open_ports_count == 0:
                    results.append("No open ports found for this protocol")
                else:
                    results.append(f""
                                   f"Total open {proto} ports: {open_ports_count}")

        https_ports = get_https_ports(scanner, host)
        https_ports_found.extend([p for p in https_ports if p not in https_ports_found])

        if https_ports_found:
            results.append(f"\nFound HTTPS/SSL ports: {', '.join(map(str, https_ports_found))}")
        else:
            results.append("\nNo HTTPS/SSL ports found")

        return results, https_ports_found

    except Exception as e:
        error_msg = [f"Error scanning {target}: {str(e)}"]
        return error_msg, []


def scan_ssl(target, port=443):
    """Проверка SSL шифров"""
    try:
        print(f"Scanning SSL ciphers on {target}:{port}...")
        scanner = nmap.PortScanner()
        scanner.scan(target, arguments=f'-p {port} --script ssl-enum-ciphers,ssl-cert,ssl-date')

        results = []
        for host in scanner.all_hosts():
            if 'tcp' in scanner[host] and port in scanner[host]['tcp']:
                port_info = scanner[host]['tcp'][port]

                ssl_results = f"\n------ SSL Ciphers Scan ------"
                ssl_results += f"\nHost: {host} | Port: {port}"
                ssl_results += f"\nService: {port_info.get('name', 'unknown')}"
                ssl_results += f"\nState: {port_info.get('state', 'unknown')}"
                results.append(ssl_results)

                if port_info.get('script') and 'ssl-enum-ciphers' in port_info['script']:
                    cipher_info = port_info['script']['ssl-enum-ciphers']
                    if isinstance(cipher_info, dict):
                        results.append("\nSSL Ciphers Information:")
                        for protocol, cipher_data in cipher_info.items():
                            if isinstance(cipher_data, dict):
                                results.append(f"\n{protocol}:")
                                if 'ciphers' in cipher_data:
                                    results.append("Supported ciphers:")
                                    for cipher in cipher_data['ciphers']:
                                        results.append(f"  - {cipher}")
                    else:
                        results.append(f"\nSSL Ciphers Information:\n{cipher_info}")
                else:
                    results.append("\nNo SSL cipher information available")

        return results if results else ["No SSL information available"]

    except Exception as e:
        return [f"Error during SSL scan on {target}:{port}: {str(e)}"]


def check_hostname(hostname):
    """Проверка возможности разрешения FQDN в IP-адрес"""
    try:
        ip = socket.gethostbyname(hostname)
        print(f"✓ {hostname} resolved to {ip}")
        return True, ip
    except socket.gaierror as e:
        print(f"✗ Cannot resolve {hostname}: {e}")
        return False, None


def scan_targets(target_file):
    """Основная функция сканирования"""
    reports_dir = ensure_directories()
    scan_data = {
        'timestamp': datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        'targets': []
    }

    try:
        with open(target_file, 'r', encoding='utf-8') as f:
            targets = [line.strip() for line in f.readlines() if line.strip() and not line.startswith('#')]

        print(f"Found {len(targets)} target(s) to scan")
        print(f"Using dirsearch from: {DIRSEARCH_PATH}")

        for target in targets:
            print(f"\n{'=' * 60}")
            print(f"SCANNING: {target}")
            print(f"{'=' * 60}")

            target_data = {
                'target': target,
                'tcp_results': [],
                'https_ports': [],
                'ssl_results': [],
                'header_results': [],
                'cert_results': [],
                'dirsearch_results': [],
                'nuclei_results': []
            }

            can_resolve, ip = check_hostname(target)
            target_data['ip'] = ip

            if not can_resolve:
                print(f"Skipping {target} - cannot resolve hostname")
                scan_data['targets'].append(target_data)
                continue

            # Сканируем порты
            tcp_results, https_ports = scan_tcp_host(target)
            target_data['tcp_results'] = tcp_results
            target_data['https_ports'] = https_ports

            # Сохраняем текстовые результаты
            safe_filename = create_safe_filename(target)
            text_report_path = os.path.join(reports_dir, safe_filename)
            save_results(text_report_path, tcp_results)

            # Если найдены HTTPS порты, выполняем дополнительные проверки
            if https_ports:
                print(f"Found HTTPS ports: {https_ports}")
                
                for https_port in https_ports:
                    # SSL шифры
                    ssl_results = scan_ssl(target, https_port)
                    target_data['ssl_results'].extend(ssl_results)
                    add_results(text_report_path, ssl_results)

                    # Заголовки безопасности
                    header_results = scan_security_headers(target, https_port)
                    target_data['header_results'].extend(header_results)
                    add_results(text_report_path, header_results)

                    # Детальная проверка сертификата
                    cert_results = scan_certificate(target, https_port)
                    target_data['cert_results'].extend(cert_results)
                    add_results(text_report_path, cert_results)

                    # Dirsearch сканирование
                    print(f"\nStarting dirsearch on {target}:{https_port}...")
                    dirsearch_result = run_dirsearch(target, https_port)
                    target_data['dirsearch_results'].append(dirsearch_result)

                    if dirsearch_result.get('success'):
                        dirsearch_summary = [
                            f"\n------ Dirsearch Results for {dirsearch_result['url']} ------",
                            f"Total URLs discovered: {dirsearch_result['total_urls']}",
                            f"Output file: {dirsearch_result['output_file']}",
                            f"\nFirst 50 discovered URLs:"
                        ]
                        dirsearch_summary.extend(dirsearch_result['urls'])
                        add_results(text_report_path, dirsearch_summary)

                    # Nuclei сканирование
                    print(f"\nStarting nuclei on {target}:{https_port}...")
                    nuclei_result = run_nuclei(target, https_port)
                    target_data['nuclei_results'].append(nuclei_result)

                    if nuclei_result.get('success'):
                        nuclei_summary = [
                            f"\n------ Nuclei Results for {target}:{https_port} ------",
                            f"Total findings: {nuclei_result.get('total_findings', 0)}",
                            f"Output file: {nuclei_result.get('output_file', '')}",
                            f"\nFirst 50 findings:"
                        ]
                        nuclei_summary.extend(nuclei_result.get('findings', []))
                        add_results(text_report_path, nuclei_summary)

                    # if nuclei_result.get('success'):
                    #     nuclei_summary = [
                    #         f"\n------ Dirsearch Results for {nuclei_result} ------",
                    #         f"Total URLs discovered: {nuclei_result}",
                    #         f"Output file: {nuclei_result['output_file']}",
                    #         f"\nFirst 50 discovered URLs:"
                    #     ]
                    #     nuclei_summary.extend(nuclei_result)
                    #     add_results(text_report_path, nuclei_summary)

            else:
                print("No HTTPS ports found - skipping additional scans")
                # Всё равно пробуем сканировать стандартные порты через dirsearch
                # for port in [80, 443]:
                #     print(f"\nTrying dirsearch on {target}:{port}...")
                #     dirsearch_result = run_dirsearch(target, port)
                #     # nuclei_result = run_nuclei(target, port)
                #     target_data['dirsearch_results'].append(dirsearch_result)
                #     # target_data['nuclei_results'].append(nuclei_result)

            scan_data['targets'].append(target_data)

        # Генерируем HTML отчёт
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        html_report_path = os.path.join(reports_dir, f"security_scan_complete_{timestamp}.html")
        generate_html_report(scan_data, html_report_path)

        print(f"\n{'=' * 60}")
        print("SCAN COMPLETED SUCCESSFULLY")
        print(f"{'=' * 60}")
        print(f"Text reports saved in: {reports_dir}/")
        print(f"HTML report saved as: {html_report_path}")

    except FileNotFoundError:
        print(f"Error: Target file '{target_file}' not found")
    except Exception as e:
        print(f"Error during scan: {str(e)}")


def create_safe_filename(target):
    """Создание безопасного имени файла"""
    safe_name = target.replace('/', '_').replace('\\', '_').replace(':', '_')
    safe_name = safe_name.replace('*', '_').replace('?', '_').replace('"', '_')
    safe_name = safe_name.replace('<', '_').replace('>', '_').replace('|', '_')
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    return f"scan_{safe_name}_{timestamp}.txt"


def save_results(file, results):
    """Сохранение результатов в файл"""
    try:
        os.makedirs(os.path.dirname(file), exist_ok=True)
        with open(file, "w", encoding='utf-8') as f:
            f.write('=' * 60 + '\n')
            f.write('Comprehensive Security Scan Results\n')
            f.write(f'Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}\n')
            f.write('=' * 60 + '\n\n')
            if isinstance(results, list):
                f.write("\n".join(map(str, results)))
            else:
                f.write(str(results))
        print(f"Results saved to: {file}")
    except Exception as e:
        print(f"Error saving results to {file}: {e}")


def add_results(file, results):
    """Добавление результатов в существующий файл"""
    try:
        with open(file, "a", encoding='utf-8') as f:
            f.write("\n\n")
            if isinstance(results, list):
                f.write("\n".join(map(str, results)))
            else:
                f.write(str(results))
    except Exception as e:
        print(f"Error appending results to {file}: {e}")


def generate_html_report(scan_data, output_file):
    """Генерация HTML отчёта"""
    html_template = f"""
    <!DOCTYPE html>
    <html lang="ru">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Security Scan Report</title>
        <style>
            body {{
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                line-height: 1.6;
                color: #333;
                max-width: 1200px;
                margin: 0 auto;
                padding: 20px;
                background-color: #f5f5f5;
            }}
            h1, h2, h3 {{
                color: #2c3e50;
            }}
            .header {{
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white;
                padding: 30px;
                border-radius: 10px;
                margin-bottom: 30px;
            }}
            .target {{
                background: white;
                border-radius: 10px;
                padding: 20px;
                margin-bottom: 30px;
                box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            }}
            .section {{
                background: #f8f9fa;
                border-left: 4px solid #667eea;
                padding: 15px;
                margin: 20px 0;
                border-radius: 0 10px 10px 0;
            }}
            .success {{
                color: #27ae60;
                font-weight: bold;
            }}
            .warning {{
                color: #e67e22;
                font-weight: bold;
            }}
            .danger {{
                color: #c0392b;
                font-weight: bold;
            }}
            .info {{
                color: #3498db;
                font-weight: bold;
            }}
            pre {{
                background: #2d2d2d;
                color: #f8f8f2;
                padding: 15px;
                border-radius: 5px;
                overflow-x: auto;
                font-family: 'Courier New', monospace;
            }}
            table {{
                width: 100%;
                border-collapse: collapse;
                margin: 20px 0;
            }}
            th, td {{
                padding: 12px;
                text-align: left;
                border-bottom: 1px solid #ddd;
            }}
            th {{
                background-color: #667eea;
                color: white;
            }}
            tr:hover {{
                background-color: #f5f5f5;
            }}
            .url-list {{
                max-height: 300px;
                overflow-y: auto;
                border: 1px solid #ddd;
                padding: 10px;
                border-radius: 5px;
            }}
            .stats {{
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                gap: 20px;
                margin: 20px 0;
            }}
            .stat-card {{
                background: white;
                padding: 20px;
                border-radius: 10px;
                box-shadow: 0 2px 5px rgba(0,0,0,0.1);
                text-align: center;
            }}
            .stat-number {{
                font-size: 2em;
                font-weight: bold;
                color: #667eea;
            }}
        </style>
    </head>
    <body>
        <div class="header">
            <h1>🔐 Comprehensive Security Scan Report</h1>
            <p>Generated: {scan_data['timestamp']}</p>
            <p>Total targets scanned: {len(scan_data['targets'])}</p>
        </div>

        {''.join([generate_target_html(target_data) for target_data in scan_data['targets']])}

        <div style="text-align: center; margin-top: 50px; color: #666;">
            <p>Report generated by Comprehensive Security Scanner</p>
            <p>Scan completed at: {scan_data['timestamp']}</p>
        </div>
    </body>
    </html>
    """

    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(html_template)
    print(f"HTML report saved to: {output_file}")


def to_lines(items):
    """Безопасно превращает список любых элементов в список строк."""
    if not items:
        return ["No data"]
    result = []
    for item in items:
        if isinstance(item, str):
            result.append(item)
        elif isinstance(item, dict):
            # Для dict — печатаем читаемо
            if item.get('success') is False:
                result.append(f"[FAIL] {item.get('error', 'unknown error')}")
            elif 'urls' in item:      # dirsearch
                result.append(f"URL: {item.get('url', '?')} | "
                              f"URLs: {item.get('total_urls', 0)} | "
                              f"File: {item.get('output_file', '?')}")
                result.extend(f"   • {u}" for u in item.get('urls', [])[:50])
            elif 'findings' in item:  # nuclei
                result.append(f"URL: {item.get('url', '?')} | "
                              f"Findings: {item.get('total_findings', 0)} | "
                              f"File: {item.get('output_file', '?')}")
                result.extend(f"   • {f}" for f in item.get('findings', [])[:50])
            else:
                result.append(str(item))
        elif isinstance(item, (list, tuple)):
            result.append(" ".join(str(x) for x in item))
        else:
            result.append(str(item))
    return result


def generate_target_html(target_data):
    """Генерация HTML секции для одного таргета"""
    target = target_data['target']
    ip = target_data.get('ip', 'Unknown')

    html = f"""
    <div class="target">
        <h2>🎯 Target: {target} <span style="font-size: 0.8em;">({ip})</span></h2>

        <div class="stats">
            <div class="stat-card">
                <div class="stat-number">{len(target_data.get('https_ports', []))}</div>
                <div>HTTPS Ports</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{len(target_data.get('dirsearch_results', []))}</div>
                <div>Dirsearch Scans</div>
            </div>
            <div class="stat-card">
                <div class="stat-number">{sum([r.get('total_urls', 0) for r in target_data.get('dirsearch_results', [])])}</div>
                <div>Discovered URLs</div>
            </div>
        </div>

        <div class="section">
            <h3>📋 TCP Port Scan Results</h3>
            <pre>{"\\n".join(target_data.get('tcp_results', ['No data']))}</pre>
        </div>
    """

    # HTTPS Ports и Dirsearch результаты
    if target_data.get('https_ports'):
        html += f"""
        <div class="section">
            <h3>🔒 HTTPS Ports Found</h3>
            <table>
                <tr>
                    <th>Port</th>
                    <th>Status</th>
                    <th>Dirsearch Results</th>
                </tr>
        """

        for port in target_data['https_ports']:
            dirsearch_data = next((d for d in target_data.get('dirsearch_results', []) if d.get('port') == port), None)
            dirsearch_info = f"Found {dirsearch_data['total_urls']} URLs" if dirsearch_data and dirsearch_data.get(
                'success') else "Not scanned"

            html += f"""
                <tr>
                    <td>{port}</td>
                    <td><span class="success">✓ Open</span></td>
                    <td>{dirsearch_info}</td>
                </tr>
            """

        html += "</table>"

        # Подробные результаты Dirsearch
        for dirsearch_result in target_data.get('dirsearch_results', []):
            if dirsearch_result.get('success'):
                html += f"""
                <div style="margin-top: 20px; background: white; padding: 15px; border-radius: 5px;">
                    <h4>📁 Dirsearch Results for {dirsearch_result['url']}</h4>
                    <p>Total URLs discovered: <strong style="color: #27ae60;">{dirsearch_result['total_urls']}</strong></p>
                    <p>Command used: <code style="background: #f0f0f0; padding: 5px; border-radius: 3px;">{dirsearch_result.get('command', 'N/A')}</code></p>
                    <div style="max-height: 400px; overflow-y: auto; border: 1px solid #ddd; padding: 10px; border-radius: 5px; background: #fafafa;">
                        <small>
                        {"<br>".join(dirsearch_result.get('urls', ['No URLs discovered']))}
                        </small>
                    </div>
                </div>
                """
    else:
        html += '<p class="warning">No HTTPS ports found on this target</p>'

    # SSL результаты
    if target_data.get('ssl_results'):
        html += f"""
        <div class="section">
            <h3>🔐 SSL/TLS Scan Results</h3>
            <pre>{"\\n".join(target_data['ssl_results'])}</pre>
        </div>
        """

    # Security Headers результаты
    if target_data.get('header_results'):
        html += f"""
        <div class="section">
            <h3>️ Security Headers</h3>
            <pre>{"\\n".join(to_lines(target_data['header_results']))}</pre>
        </div>
        """

    # Certificate результаты
    if target_data.get('cert_results'):
        html += f"""
        <div class="section">
            <h3>📜 SSL Certificate Information</h3>
            <pre>{"\\n".join(target_data['cert_results'])}</pre>
        </div>
        """

    # Nuclei результаты
    if target_data.get('nuclei_results'):
        html += f"""
        <div class="section">
            <h3> Nuclei Results</h3>
            <pre>{"\\n".join(to_lines(target_data['nuclei_results']))}</pre>
        </div>
        """

    html += "</div>"
    return html


# if __name__ == "__main__":
#     print("=" * 60)
#     print("COMPREHENSIVE SECURITY SCANNER WITH DIRSEARCH")
#     print("Scans: TCP Ports | SSL Ciphers | Security Headers | Certificates | Web Directories (Dirsearch)")
#     print("=" * 60)
#
#     # Проверяем наличие dirsearch
#     if not os.path.exists(DIRSEARCH_PATH):
#         print(f"⚠ Warning: Dirsearch not found at {DIRSEARCH_PATH}")
#         print("Please update DIRSEARCH_PATH variable with correct path")
#         response = input("Continue without dirsearch? (y/n): ")
#         if response.lower() != 'y':
#             exit()
#
#     scan_targets(targets)