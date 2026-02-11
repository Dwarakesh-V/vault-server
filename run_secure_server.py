import uvicorn
import os

if __name__ == "__main__":
    if not os.path.exists("key.pem") or not os.path.exists("cert.pem"):
        print("Error: key.pem or cert.pem not found. Run generate_cert.py first.")
        exit(1)

    print("Starting secure server on https://0.0.0.0:8000")
    uvicorn.run(
        "server.api:app",
        host="0.0.0.0",
        port=8000,
        ssl_keyfile="key.pem",
        ssl_certfile="cert.pem",
        reload=False
    )
