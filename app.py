import subprocess
from flask import Flask, render_template, request, jsonify, redirect, url_for
import time 

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
@app.route('/dns_enum', methods=['GET', 'POST'])
def dns_enum():
    if request.method == 'POST':
        if request.is_json:
            scan_data = request.get_json()  # Ako su podaci u JSON formatu
            target = scan_data['target']
            tool = scan_data['tool']
        else:
            target = request.form.get('target')  # Ako su podaci iz HTML forme
            tool = request.form.get('tool')

        result = ""
        
        # Pokretanje odgovarajuće komande na osnovu izabranog alata
        if tool == 'dnsrecon':
            result = subprocess.run(['dnsrecon', '-d', target], capture_output=True, text=True).stdout
        elif tool == 'sublister':
            result = subprocess.run(['sublister', '-d', target], capture_output=True, text=True).stdout
        elif tool == 'amass':
            result = subprocess.run(['amass', 'enum', '-d', target], capture_output=True, text=True).stdout
        elif tool == 'dnssdumpster':
            result = subprocess.run(['curl', '-s', f'https://dnsdumpster.com/static/map/resolve.php?host={target}'], capture_output=True, text=True).stdout
        
        return jsonify({'result': result})  # Vraća rezultat u JSON formatu

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
@app.route('/exploitation_tools', methods=['GET', 'POST'])
def exploitation_tools():
    if request.method == 'POST':
        tool = request.form.get('tool')
        arguments = request.form.get('arguments', '')

        # Mapa dostupnih alata i komandi
        tools = {
            "metasploit": "msfconsole -q",
            "msfvenom": f"msfvenom {arguments}",
            "searchsploit": f"searchsploit {arguments}",
            "exploitdb": f"exploitdb {arguments}",
        }

        if tool not in tools:
            return render_template('exploitation_tools.html', result="Invalid tool selected!")

        command = tools[tool]

        try:
            print(f"Running command: {command}")  # Debug log
            result = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT, universal_newlines=True)
        except subprocess.CalledProcessError as e:
            result = f"Error executing command: {e.output}"

        return render_template('exploitation_tools.html', result=result)

    return render_template('exploitation_tools.html')
@app.route('/wifi_tools', methods=['GET', 'POST'])
def wifi_tools():
    result = None
    if request.method == 'POST':
        tool = request.form.get('tool')
        arguments = request.form.get('arguments')
        
        # Map the tool to a corresponding command
        commands = {
            'aircrack-ng': f"aircrack-ng {arguments}",
            'kismet': f"kismet {arguments}",
            'wifite': f"wifite {arguments}",
            'wash': f"wash {arguments}"
        }
        
        command = commands.get(tool, None)
        if command:
            try:
                # Run the tool and capture the output
                result = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT, text=True)
            except subprocess.CalledProcessError as e:
                result = f"Error: {e.output}"
        else:
            result = "Invalid tool selected."

    return render_template('wifi_tools.html', result=result)
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

    if tool not in ['tcpdump', 'wireshark', 'ettercap']:
        return jsonify({"error": "Invalid tool selected"}), 400

    # Simulating command execution (replace this with actual commands)
    command_map = {
        "tcpdump": "tcpdump -c 10 -i any",  # Example TCPDump command
        "wireshark": "echo 'Wireshark GUI cannot run here'",  # Wireshark simulation
        "ettercap": "ettercap --help"  # Example Ettercap command
    }
    
    try:
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


@app.route('/social_engineering')
def social_engineering_page():
    return render_template('social_engineering.html')

@app.route('/run_social_tool', methods=['POST'])
def run_social_tool():
    data = request.get_json()
    tool = data.get('tool')
    target = data.get('target')

    if not tool or not target:
        return jsonify({"error": "Morate odabrati alat i uneti ciljnu adresu."}), 400

    # Mapiranje alata na komande
    command_map = {
        "phishing_email": f"echo 'Simulating phishing email to {target}'",
        "fake_website": f"echo 'Creating fake website for {target}'",
        "sms_spoofing": f"echo 'Simulating SMS spoofing to {target}'"
    }

    command = command_map.get(tool)
    if not command:
        return jsonify({"error": "Izabrani alat nije podržan."}), 400

    try:
        result = subprocess.run(command, shell=True, text=True, capture_output=True)
        output = result.stdout or result.stderr
    except Exception as e:
        output = f"Greška prilikom pokretanja alata: {str(e)}"

    return jsonify({"output": output})

if __name__ == '__main__':
    app.run(debug=True)
