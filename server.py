import argparse
import base64
import datetime
import json
import os
import socket
import threading
import uuid


def parse_args():
    parser = argparse.ArgumentParser(description='HTTP File Manager Server')
    parser.add_argument('-i', '--host', default='localhost', help='Server host address')
    parser.add_argument('-p', '--port', type=int, default=8080, help='Server port number')
    return parser.parse_args()
sessions = {}# Dictionary to store session information (session_id: (username, expiration_time))
root_directory = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'data')
def start_server(host, port):
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((host, port))
    server_socket.listen(5)
    print(f"Server listening on {host}:{port}")

    while True:
        client_socket, client_address = server_socket.accept()
        client_thread = threading.Thread(target=handle_client, args=(client_socket,))
        client_thread.start()


def validate_session(session_cookie):
    # Check if the session cookie is valid and not expired
    if session_cookie in sessions:
        _, expiration_time = sessions[session_cookie]
        return expiration_time > datetime.now()
    return False


def check_authorization(auth_header):
    # Extract and decode the base64-encoded credentials
    _, encoded_info = auth_header.split(' ')
    decoded_info = base64.b64decode(encoded_info).decode('utf-8')

    # Check the credentials (You should replace this with your own user authentication logic)
    # For example, you can store user credentials in a dictionary
    # and check if the provided credentials match any user's credentials
    valid_credentials = {'username': 'password'}  # Replace with actual user credentials
    return decoded_info in valid_credentials.values()


def send_unauthorized_response(client_socket):
    # Send 401 Unauthorized response with WWW-Authenticate header
    response_headers = 'HTTP/1.1 401 Unauthorized\r\nWWW-Authenticate: Basic realm="Authorization Required"\r\n\r\n'
    client_socket.send(response_headers.encode('utf-8'))


def get_username(auth_header):
    _, encoded_info = auth_header.split(' ')
    decoded_info = base64.b64decode(encoded_info).decode('utf-8')

    # Extract username from decoded credentials
    username, _ = decoded_info.split(':', 1)
    return username


def send_response_with_cookie(client_socket, session_id):
    # Send a response with Set-Cookie header containing the new session ID
    response_headers = f'HTTP/1.1 200 OK\r\nSet-Cookie: session-id={session_id}; Path=/\r\n\r\n'
    client_socket.send(response_headers.encode('utf-8'))


def generate_directory_listing(file_path):
    pass


def get_files_in_directory(file_path):
    pass


def handle_get(client_socket, path,query_params):
    file_path = os.path.join(root_directory, path.lstrip('/'))
    # Check if the requested path is a directory
    if os.path.isdir(file_path):
        sustech_http_param = query_params.get('SUSTech-HTTP', '0')

        if sustech_http_param == '0':
            # If SUSTech-HTTP=0, generate and send an HTML page with the directory listing
            directory_listing = generate_directory_listing(file_path)
            response_headers = 'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: ' + str(
                len(directory_listing)) + '\r\n\r\n'
            client_socket.send(response_headers.encode('utf-8') + directory_listing.encode('utf-8'))
        elif sustech_http_param == '1':
            # If SUSTech-HTTP=1, send a JSON response with the list of files in the directory
            files_in_directory = get_files_in_directory(file_path)
            json_response = json.dumps(files_in_directory)
            response_headers = 'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: ' + str(
                len(json_response)) + '\r\n\r\n'
            client_socket.send(response_headers.encode('utf-8') + json_response.encode('utf-8'))
        else:
            # Invalid SUSTech-HTTP value, return a 400 Bad Request response
            response_headers = 'HTTP/1.1 400 Bad Request\r\nContent-Type: text/html\r\n\r\n'
            client_socket.send(response_headers.encode('utf-8') + b'<html><body><h1>400 Bad Request</h1></body></html>')

    elif os.path.isfile(file_path):
        # If it's a file, send the file content with appropriate Content-Type header
        with open(file_path, 'rb') as file:
            file_content = file.read()
            content_type = get_content_type(file_path)
            response_headers = f'HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nContent-Length: {len(file_content)}\r\n\r\n'
            client_socket.send(response_headers.encode('utf-8') + file_content)
    else:
        # If the path does not exist, return a 404 Not Found response
        response_headers = 'HTTP/1.1 404 Not Found\r\nContent-Type: text/html\r\n\r\n'
        client_socket.send(response_headers.encode('utf-8') + b'<html><body><h1>404 Not Found</h1></body></html>')


def handle_client(client_socket):
    try:

        while True:
            request_data = client_socket.recv(1024).decode('utf-8')
            if not request_data:
                break

            # Parse the HTTP request
            method, path, headers, _ = parse_http_request(request_data)
            auth_header = headers.get('Authorization', None)
            # Check if session cookie is present
            session_cookie = headers.get('Cookie', None)
            if not session_cookie or not validate_session(session_cookie):
                # If no session cookie or invalid session, check Authorization
                auth_header = headers.get('Authorization', None)

                if not auth_header or not check_authorization(auth_header):
                    # Send 401 Unauthorized response if Authorization header is not present or credentials are invalid
                    send_unauthorized_response(client_socket)
                    return

                # Authorization successful, generate a new session ID
                username = get_username(auth_header)
                session_id = str(uuid.uuid4())
                expiration_time = datetime.now() + datetime.timedelta(
                    minutes=30)  # Set session expiration time (adjust as needed)
                sessions[session_id] = (username, expiration_time)
                send_response_with_cookie(client_socket, session_id)
            else:
                # If a valid session cookie is present, continue processing the request


            # Check the Connection header
                connection_header = headers.get('Connection', '').lower()
                keep_alive = connection_header == 'keep-alive'
            # Call the appropriate function based on the request
                if method == 'GET':
                    handle_get(client_socket, path,headers)
                elif method == 'POST':
                    pass
                # Add more methods as needed (e.g., DELETE, PUT)

                # If Connection: Close, close the connection
                if not keep_alive:
                    break

    except Exception as e:
        print(f"Error handling client: {e}")

    finally:
        client_socket.close()
def parse_http_request(request_data):
    lines = request_data.split('\r\n')

    # Parse the first line to get method, path, and protocol
    method, path, protocol = lines[0].split(' ')

    # Parse headers
    headers = {}
    for line in lines[1:]:
        if not line:
            break
        key, value = line.split(': ', 1)
        headers[key] = value

    return method, path, headers, protocol

if __name__ == "__main__":
    args = parse_args()
    start_server(args.host, args.port)
