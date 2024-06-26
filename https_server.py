import uvicorn

if __name__ == '__main__':
    uvicorn.run("main:app",
                host="0.0.0.0",
                port=9443,
                reload=True,
                ssl_keyfile="key.pem",
                ssl_certfile="cert.pem"
                )
