import subprocess
from flask import Flask, render_template, request, jsonify, redirect, url_for

app = Flask(__name__)

# Početna stranica
@app.route('/')
def index():
    return render_template('index.html')

# Stranica za Reconnaissance
@app.route('/scan')
def scan():
    return render_template('scan.html')


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
@app.route('/password_cracking', methods=['GET', 'POST'])
def password_cracking():
    result = None
    if request.method == 'POST':
        tool = request.form['tool']
        arguments = request.form['arguments']
        
        # Komandne linije za alatke
        tools = {
            'hydra': 'hydra',
            'medusa': 'medusa',
            'johntheripper': 'john',
            'hashcat': 'hashcat'
        }
        
        # Proveri da li je alat dostupan
        if tool in tools:
            try:
                # Izvrši alat sa argumentima
                command = f"{tools[tool]} {arguments}"
                process = subprocess.run(command.split(), capture_output=True, text=True)
                result = process.stdout or process.stderr
            except Exception as e:
                result = f"Error: {e}"
        else:
            result = "Invalid tool selected."
    
    return render_template('password_cracking.html', result=result)
if __name__ == '__main__':
    app.run(debug=True)
