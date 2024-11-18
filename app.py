import subprocess
from flask import Flask, render_template, request, jsonify

app = Flask(__name__)
app.secret_key = "your_secret_key"

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

# Stranica za Nmap formu
@app.route('/nmap', methods=['GET', 'POST'])
def nmap():
    if request.method == 'GET':
        # Prikaz forme za Nmap
        return render_template('nmap.html')
    
    if request.method == 'POST':
        # Obrada podataka sa frontend-a
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
            # Izvršavanje Nmap komande
            result = subprocess.check_output(command, stderr=subprocess.STDOUT, universal_newlines=True)
            return jsonify({'result': result})  # Vraćanje rezultata u JSON formatu
        except subprocess.CalledProcessError as e:
            # Obrada greške
            return jsonify({'result': f"Error: {e.output}"})

if __name__ == '__main__':
    app.run(debug=True)
