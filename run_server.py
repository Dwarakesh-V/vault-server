
import uvicorn
import os
import sys

if __name__ == "__main__":
    print("Starting server at http://127.0.0.1:8000")
    uvicorn.run(
        "server.api:app",
        host="0.0.0.0",
        port=8000,
        reload=True
    )
