
import uvicorn
import os
import sys

if __name__ == "__main__":
    # Check if certificates exist
    if not os.path.exists("key.pem") or not os.path.exists("cert.pem"):
        print("Error: SSL certificates not found.")
        print("Please run 'python generate_cert.py' to generate 'key.pem' and 'cert.pem'.")
        sys.exit(1)

    print("Starting secure server at https://localhost:8000")
    uvicorn.run(
        "server.api:app",
        host="0.0.0.0",
        port=8000,
        ssl_keyfile="key.pem",
        ssl_certfile="cert.pem",
        reload=True
    )
