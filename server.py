import argparse
import base64
import time
import os
import socket
import threading
import uuid
import json

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
    #print(sessions)
    #print(session_cookie)
    sess_id = session_cookie.split("session-id=")[1]

    # Check if the session cookie is valid and not expired
    if sess_id in sessions:

        _, expiration_time = sessions[sess_id]

        result = expiration_time > time.time()

        return result
    return False


def check_authorization(auth_header):
    valid_credentials = {'username': 'password'}  # Replace with actual user credentials
    # Extract and decode the base64-encoded credentials
    _, encoded_info = auth_header.split(' ')
    decoded_info = base64.b64decode(encoded_info).decode('utf-8')
    # print(decoded_info)
    result = False
    username , password = decoded_info.split(":")[0], decoded_info.split(":")[1]
    # print(f'user is {username}, pass is {password}')
    if username in valid_credentials:
        if password == valid_credentials[username]:
            result = True
    # print(result)
    return result


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
def parse_query_string(query_string):
    query_params = {}
    if query_string:
        # Splitting the query string into key-value pairs
        pairs = query_string.split('&')
        for pair in pairs:
            # Splitting each pair into key and value
            key_value = pair.split('=')
            # Decoding key and value (replace '+' with ' ' and then decode as URL)
            key = key_value[0].replace('+', ' ').strip()
            value = key_value[1].replace('+', ' ').strip() if len(key_value) > 1 else None
            query_params[key] = value
    return query_params

def handle_get(request_data,client_socket):
    method, full_path, headers, _ = parse_http_request(request_data)
    # Splitting the path and handling query parameters
    path, _, query_string = full_path.partition('?')
    query_params = parse_query_string(query_string)

    file_path = os.path.join(root_directory, path.lstrip('/'))
    print(file_path)

    # Check if the SUSTech-HTTP query parameter is present
    sustech_http_param = query_params.get('SUSTech-HTTP', None)

    if sustech_http_param is None:
        # If SUSTech-HTTP parameter is missing, return 400 Bad Request
        response = 'HTTP/1.1 400 Bad Request\r\n\r\n'
        return response.encode('utf-8')

    if not os.path.exists(file_path):
        print('not exist')
        # If the requested path does not exist, return 404 Not Found
        response = 'HTTP/1.1 404 Not Found\r\n\r\n'
        return response.encode('utf-8')

    if os.path.isdir(file_path):
        print('is dir')
        # If the requested path is a directory
        if sustech_http_param == '0':
            # SUSTech-HTTP=0: return an HTML page showing the file tree
            directory_listing = generate_directory_listing(file_path)
            response = f'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {len(directory_listing)}\r\n\r\n{directory_listing}'
            print(response)
        elif sustech_http_param == '1':
            # SUSTech-HTTP=1: return a list of files in the directory
            files_list = [f for f in os.listdir(file_path) if os.path.isfile(os.path.join(file_path, f))]
            print(files_list)
            response = f'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {len(files_list)}\r\n\r\n{json.dumps(files_list)}'
            print(response)
        else:
            # Invalid value for SUSTech-HTTP parameter
            response = 'HTTP/1.1 400 Bad Request\r\n\r\n'
    elif os.path.isfile(file_path):
        print('is file')
        # If the requested path is a file
        with open(file_path, 'rb') as file:
            file_content = file.read()
            content_type = get_content_type(file_path)
            response = f'HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nContent-Length: {len(file_content)}\r\n\r\n'
            response = response.encode('utf-8') + file_content
    else:
        # If the path does not exist, return 404 Not Found
        response = 'HTTP/1.1 404 Not Found\r\n\r\n'

    return  client_socket.send(response.encode('utf-8'))


def get_content_type(file_path):
    file_extension = os.path.splitext(file_path)[1].lower()
    mime_types = {
        '.html': 'text/html',
        '.css': 'text/css',
        '.js': 'application/javascript',
        '.png': 'image/png',
        '.jpg': 'image/jpeg',
        '.gif': 'image/gif',
        '.txt': 'text/plain',
        '.pdf': 'application/pdf',
    }
    # Default to binary data if the file extension is not recognized
    return mime_types.get(file_extension, 'application/octet-stream')


def generate_directory_listing(directory_path):
    # Generate an HTML page showing the file tree of the directory
    directory_listing = f'<h1>Index of {directory_path}</h1>'
    directory_listing += '<ul>'
    for file in os.listdir(directory_path):
        file_path = os.path.join(directory_path, file)
        if os.path.isdir(file_path):
            file += '/'
        directory_listing += f'<li><a href="{file}">{file}</a></li>'
    directory_listing += '</ul>'
    return directory_listing.encode('utf-8')


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
                # print(auth_header)
                # print(session_cookie)
                if not auth_header or not check_authorization(auth_header):
                    # Send 401 Unauthorized response if Authorization header is not present or credentials are invalid
                    send_unauthorized_response(client_socket)
                    print('登陆失败')
                    return

                # Authorization successful, generate a new session ID
                username = get_username(auth_header)
                session_id = str(uuid.uuid4())
                expiration_time = time.time() + 360000.0
                print(expiration_time)
                sessions[session_id] = (username, expiration_time)
                
                send_response_with_cookie(client_socket, session_id)
            else:
                # If a valid session cookie is present, continue processing the request


            # Check the Connection header
                connection_header = headers.get('Connection', '').lower()
                keep_alive = connection_header == 'keep-alive'
            # Call the appropriate function based on the request
                if method == 'GET':
                    print('get get')
                  # print(request_data)
                    handle_get(request_data,client_socket)
                elif method == 'POST':
                    print('get post')
                    print(request_data)
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
