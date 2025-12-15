from http.server import BaseHTTPRequestHandler, HTTPServer

class HeaderPrinterHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        print("\n=== Incoming Request ===")
        print(f"{self.command} {self.path}")
        print("Headers:")
        for k, v in self.headers.items():
            print(f"{k}: {v}")

        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"OK\n")

    def do_POST(self):
        self.do_GET()  # same behavior

    # Silence default logging
    def log_message(self, format, *args):
        return


if __name__ == "__main__":
    server = HTTPServer(("0.0.0.0", 8001), HeaderPrinterHandler)
    print("Listening on :8001")
    server.serve_forever()
