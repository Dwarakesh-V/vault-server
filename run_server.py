
import uvicorn
import os
import sys

if __name__ == "__main__":
    print("WARNING: Starting insecure server at http://127.0.0.1:8000")
    print("For secure vault operations, use: py run_secure_server.py")
    uvicorn.run(
        "server.api:app",
        host="0.0.0.0",
        port=8000,
        reload=True
    )
