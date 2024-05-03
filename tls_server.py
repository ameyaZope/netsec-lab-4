import socket
import ssl


def handle_client_connection(client_socket):
    try:
        # Send a message to the client
        client_socket.sendall(b'Hello, TLS client!\n')
    except Exception as e:
        print(f"Error handling client: {e}")
    finally:
        # Close the connection
        client_socket.close()


def create_server(address):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile='cert.pem', keyfile='key.pem')  # Load your cert and key

    wrapped_socket = context.wrap_socket(sock, server_side=True)
    wrapped_socket.bind(address)
    wrapped_socket.listen(5)
    print(f"Server listening on {address}")

    while True:
        # Accept connections
        client_socket, fromaddr = wrapped_socket.accept()
        print(f"Connection from {fromaddr}")

        # Handle client connection
        handle_client_connection(client_socket)


if __name__ == "__main__":
    # The host must be either 0.0.0.0 or the specific IP address of the computer on
    # which you plan to run this. Please do not use localhost,
    # because then you will not be able to detect this server from a different computer
    create_server(('0.0.0.0', 9443))
