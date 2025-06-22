from flask import Flask, request, jsonify
from flask_cors import CORS
import subprocess
import re

app = Flask(__name__)
CORS(app)


# Friendly explanation map
explanations = {
    22: "SSH: Used for remote login. Secure if configured well, but attackers often scan this.",
    80: "HTTP: This is a web server port. Make sure the website is secure and up to date.",
    443: "HTTPS: Secure web server port. Usually safe if certificates are valid.",
    139: "NetBIOS: Used for file sharing on Windows. Dangerous if exposed to internet.",
    445: "SMB: Windows file sharing. Vulnerable to many attacks. Disable if not needed.",
    3306: "MySQL Database: Make sure it's password protected and not publicly accessible.",
    21: "FTP: File transfer. Not secure unless encrypted. Avoid using without protection.",
    25: "SMTP: Email sending. Make sure it's not being abused for spam.",
    3389: "RDP: Remote Desktop. Common attack target. Secure with strong passwords and firewall.",
    9929: "Nping Echo: Nmap testing tool. Not usually dangerous.",
    31337: "Elite: Often used by hackers in test networks. Might be suspicious."
}

def parse_nmap_output(output):
    findings = []
    for line in output.splitlines():
        match = re.match(r"(\d+)/tcp\s+(\w+)\s+(\S+)", line)
        if match:
            port = int(match.group(1))
            state = match.group(2)
            service = match.group(3)
            explanation = explanations.get(port, f"{service.upper()}: Open port. Check if needed.")
            findings.append({
                "port": port,
                "state": state,
                "service": service,
                "explanation": explanation
            })
    return findings

@app.route('/scan', methods=['GET'])
def scan():
    target = request.args.get('target')
    if not target:
        return jsonify({'error': 'Target is required'}), 400

    try:
        result = subprocess.check_output(['nmap', '-Pn', target], stderr=subprocess.STDOUT, text=True)
        parsed = parse_nmap_output(result)
        return jsonify({
            "target": target,
            "raw_output": result,
            "vulnerabilities": parsed
        })
    except subprocess.CalledProcessError as e:
        return jsonify({'error': e.output}), 500

if __name__ == '__main__':
    app.run(port=5000)
