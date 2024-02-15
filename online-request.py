import argparse
import http.server
import socketserver
import http.client
import os
import ssl
import requests

# Colors escape codes
class Color:
    PURPLE = '\033[95m'
    CYAN = '\033[96m'
    DARKCYAN = '\033[36m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'

# Create an ArgumentParser object
parser = argparse.ArgumentParser()

# Add arguments with names
parser.add_argument('--IP', '--ip', dest='IP_ADDRESS', type=str, default=os.getenv('IP_ADDRESS', '0.0.0.0'), help='IP_ADDRESS')
parser.add_argument('--LIP', '--lip', dest='LOCAL_IP_ADDRESS', type=str, default=os.getenv('LOCAL_IP_ADDRESS', '127.0.0.1'), help='LOCAL_IP_ADDRESS')
parser.add_argument('--P', '--p', dest='PORT', type=str, default=os.getenv('PORT', '8080'), help='PORT')
parser.add_argument('--LP', '--lp', dest='LOCAL_PORT', type=str, default=os.getenv('LOCAL_PORT', '5000'), help='LOCAL_PORT')
parser.add_argument('--SSL', '--ssl', dest='SSL', action='store_true', default=bool(os.getenv('SSL', False)), help='')


# Parse the command-line arguments
args = parser.parse_args()

class ProxyRequestHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.proxy_request('GET')

    def do_POST(self):
        self.proxy_request('POST')

    def proxy_request(self, method):
        try:
            # Set the IP address and port for the local server
            LOCAL_IP_ADDRESS = args.LOCAL_IP_ADDRESS
            LOCAL_PORT = int(args.LOCAL_PORT)

            # Check if the request is HTTP or HTTPS
            if self.path.startswith('https://'):
                conn = http.client.HTTPSConnection(LOCAL_IP_ADDRESS, LOCAL_PORT, context=ssl.create_default_context())
            else:
                conn = http.client.HTTPConnection(LOCAL_IP_ADDRESS, LOCAL_PORT)

            # Read the request body if present
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length) if content_length > 0 else None

            conn.request(method, self.path, body=body, headers=self.headers)

            # Get the response from the local web server
            response = conn.getresponse()

            # Send the response back to the client
            self.send_response(response.status)
            for header, value in response.getheaders():
                self.send_header(header, value)
            self.end_headers()
            self.wfile.write(response.read())

            # Close the connection to the local web server
            conn.close()
        except Exception as e:
            self.send_response(500)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            error_message = f"Error: {str(e)}"
            self.wfile.write(error_message.encode())

def get_public_ip():
    try:
        # Use a reliable IP address lookup service
        response = requests.get('https://api.ipify.org')
        if response.status_code == 200:
            return response.text.strip()  # Extract the IP address from the response
        else:
            print(f"Failed to fetch IP address: {response.status_code} - {response.reason}")
    except Exception as e:
        print(f"An error occurred: {e}")

    return None

# Set the IP address and port for the proxy server
IP_ADDRESS = args.IP_ADDRESS  # Serve on all available network interfaces
PORT = int(args.PORT)
SSL = args.SSL

# Create the HTTP server
with socketserver.TCPServer((IP_ADDRESS, PORT), ProxyRequestHandler) as httpd:
    protocol = 'https' if SSL else 'http'
    if SSL:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile='server.pem', keyfile='server.pem')
        httpd.socket = context.wrap_socket(httpd.socket, server_side=True)

    public_ip = get_public_ip()
    if public_ip:
        print(f"Your public Web address is: {protocol}://{public_ip}:{PORT}")
    else:
        print("Failed to retrieve public IP address.")

    print(f"{Color.GREEN}Proxy server listening on {IP_ADDRESS}:{PORT}{Color.END}")
    
    httpd.serve_forever()
