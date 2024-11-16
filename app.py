from flask import Flask, render_template, request, jsonify
import nmap

app = Flask(__name__)
nm = nmap.PortScanner()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    data = request.get_json()
    ip_address = data.get('ipAddress')
    
    # Log za primanje IP adrese
    print(f"Received IP address: {ip_address}")
    
    try:
        # Validacija IP adrese
        if not ip_address:
            return jsonify({'result': "Invalid IP address format"})
        
        print(f"Starting scan for IP address: {ip_address}")
        
        # Pokretanje skeniranja sa širim opsegom portova
        nm.scan(hosts=ip_address, arguments='-p-')  # Skener za sve portove
        
        scan_result = ""
        
        # Proveri sve hostove koji su pronađeni
        if not nm.all_hosts():  # Ako nema hostova u rezultatu
            print("No hosts found")
            return jsonify({'result': "No open ports found on the provided IP address."})
        
        # Proveri sve portove za svakog hosta
        for host in nm.all_hosts():
            print(f"Scanning results for {host}: {nm[host]}")
            scan_result += f"Host: {host} ({nm[host].hostname()})\n"
            scan_result += "Ports:\n"
            try:
                for port in nm[host]['tcp']:  # Proveri ako postoje TCP portovi
                    port_state = nm[host]['tcp'][port]['state']
                    scan_result += f"Port {port}: {port_state}\n"
            except KeyError:
                scan_result += "No TCP ports found or scanned.\n"
        
        print("Scan complete. Results:", scan_result)
        return jsonify({'result': scan_result})

    except Exception as e:
        print("Error during scan:", str(e))
        return jsonify({'result': f"Error: {str(e)}"})

if __name__ == "__main__":
    app.run(debug=True)
