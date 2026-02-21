import uvicorn
import os

# Entry point — only runs when this script is called directly:
#   py run_secure_server.py
if __name__ == "__main__":

    # ── Pre-flight check: ensure TLS certificate files exist ──────────────────
    # The server cannot start HTTPS without both of these files.
    # If they are missing, run:  py generate_cert.py
    if not os.path.exists("key.pem") or not os.path.exists("cert.pem"):
        print("Error: key.pem or cert.pem not found. Run generate_cert.py first.")
        exit(1)   # exit with a non-zero code to signal failure to the OS / shell

    print("Starting secure server on https://0.0.0.0:8000")

    # ── Start the uvicorn ASGI server with TLS enabled ────────────────────────
    # uvicorn is the high-performance ASGI server that runs the FastAPI app.
    # Passing ssl_keyfile and ssl_certfile tells uvicorn to wrap every connection
    # in TLS, so all data between the client (Flutter app) and this server is
    # encrypted — this is what makes the server run HTTPS instead of plain HTTP.
    uvicorn.run(
        "server.api:app",       # module path to the FastAPI app instance
        host="0.0.0.0",         # listen on all network interfaces (not just localhost)
                                #   0.0.0.0 = accept connections from any IP on the machine
        port=8000,              # port number; Flutter app connects to https://127.0.0.1:8000
        ssl_keyfile="key.pem",  # RSA private key — used to decrypt incoming TLS handshakes
        ssl_certfile="cert.pem",# X.509 certificate — sent to clients so they can verify identity
        reload=False            # disable auto-reload; reload=True would break TLS in some setups
                                # use reload=True only for plain HTTP development
    )
