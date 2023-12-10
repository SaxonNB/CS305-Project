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
            directory_listing = generate_directory_listing(file_path,path)
            response = f'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {len(directory_listing)}\r\n\r\n{directory_listing}'
            
        elif sustech_http_param == '1':
            # SUSTech-HTTP=1: return a list of files in the directory
            files_list = [f for f in os.listdir(file_path) if os.path.isfile(os.path.join(file_path, f))]
            print(files_list)
            response = f'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length:{len(json.dumps(files_list))}\r\n\r\n{json.dumps(files_list)}'
            
        else:
            # Invalid value for SUSTech-HTTP par ameter
            response = 'HTTP/1.1 400 Bad Request\r\n\r\n'
    elif os.path.isfile(file_path):
        print('is file')
        # If the requested path is a file
        with open(file_path, 'rb') as file:
            file_content = file.read()
            content_type = get_content_type(file_path)
            response = f'HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nContent-Length: {len(file_content)}\r\n\r\n'
            response = response.encode('utf-8') + file_content
            return client_socket.send(response)
    else:
        print("aaaaaa")
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

def generate_directory_listing(directory_path,path):
    # Get the list of files and subdirectories in the directory
    entries = os.listdir(directory_path)
   

    # Create an HTML page with links to files and subdirectories
    html_content = '<html><body><ul>'
    
    # Add a link to the parent directory (if not the root directory)
    if path != '/':
        parent_link = f'<li><a href="../?SUSTech-HTTP=0">Parent Directory</a></li>'
        html_content += parent_link
        root_directory=f'<li><a href="../?SUSTech-HTTP=0">root Directory</a></li>'
        html_content +=root_directory

    for entry in entries:
        entry_path = os.path.join(directory_path, entry)
        if os.path.isdir(entry_path):
            # For directories, add a trailing slash
            entry_link = f'<li><a href="{entry}/?SUSTech-HTTP=0">{entry}/</a></li>'
        else:
            entry_link = f'<li><a href="{entry}">{entry}</a></li>'
        html_content += entry_link

    html_content += '</ul></body></html>'
    return html_content

def check_valid_post(path):
    print(f'path is {path}')
    splited_path = path.split('?')
    result = False
    if len(splited_path) != 2:
        result = False
        print('illeagl length')
        return result
    if splited_path[0] != "/delete" and splited_path[0] != "/upload":
        print(f'not upload nor delete {splited_path[0]}')
        result = False
        return result
    if "path=" not in splited_path[1]:
        print(f'no path= {splited_path[1]}')
        result = False
        return result
    result = True
    return result

def handle_upload(client_socket, headers, path, request_data):
    # 构建用户目录的绝对路径
    file_path = path.split('=')[1]
    # print()
    user_directory = os.path.join('data/', file_path)
    print(user_directory)
    if not os.path.exists(user_directory):
        # 如果目标目录不存在，则返回404 Not Found
        response = 'HTTP/1.1 404 Not Found\r\n\r\n'
        client_socket.send(response.encode('utf-8'))
        print('not find filepath')
        return
    print(f'filepath is {path}')
    # 从客户端接收文件内容
    # print(request_data)

    body_entity = request_data.split('\r\n\r\n')
    # print(f'bodyentity is {body_entity}')
    part1 = body_entity[1]
    # print(f'part1 is {part1}')
    name_line = part1.split('\r\n')[1]
    print(f'nameline is {name_line}')
    part2 = body_entity[2]
    # print(f'part2 is {part2}')
    content_line = part2.split('\r\n')[0]
    print(f'contentline is {content_line}')
    # 查找关键字 "filename="
    filename_index = name_line.find('filename=')
    filename = ''
    if filename_index != -1:
        # 从关键字 "filename=" 后面的位置开始查找值的起始位置
        value_start = filename_index + len('filename="')

        # 从起始位置开始查找值的结束位置
        value_end = name_line.find('"', value_start)

        # 提取值
        filename = name_line[value_start:value_end]

    else:
        print("Filename not found.")

    # # 将文件保存到用户目录
    file_path = os.path.join(user_directory, filename)
    with open(file_path, 'wb') as file:
        file.write(content_line.encode('utf-8'))

    response_headers = f'HTTP/1.1 200 OK\r\nSet-Cookie: session-id={000}; Path=/\r\n\r\n'
    client_socket.send(response_headers.encode('utf-8'))
    return

def handle_delete(client_socket, headers, path, request_data):
    return

def handle_post(client_socket, headers, path, request_data):
    try:
        # 解析查询参数
        splited_path = path.split('?')
        if not check_valid_post(path):
            response = 'HTTP/1.1 400 Bad Request\r\n\r\n'
            print('bad 401')
            client_socket.send(response.encode('utf-8'))
            return
        # print('aaa')
        # print(path)
        # print(path.split('?'))
        query_params = path.split('?')[1]
        post_type = path.split('?')[0]
        if post_type == "/upload":
            print('upload')
            handle_upload(client_socket, headers, query_params, request_data)
        elif post_type == "/delete":
            print('delete')
            handle_delete(client_socket, headers, path, request_data)
        else:
            response = 'HTTP/1.1 400 Bad Request\r\n\r\n'
            print('bad 401')
            client_socket.send(response.encode('utf-8'))
            return

    except Exception as e:
        # 处理任何异常并发送适当的响应
        response = 'HTTP/1.1 500 Internal Server Error\r\n\r\n'
        client_socket.send(response.encode('utf-8'))
        print(f"处理POST请求时出错: {e}")


def handle_client(client_socket):
    try:

        while True:
            request_data = client_socket.recv(1024).decode('utf-8')
            #print(request_data)
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
                    print(request_data)
                    handle_get(request_data,client_socket)
                elif method == 'POST':
                    print('get post')
                    print(request_data)
                    handle_post(client_socket, headers, path, request_data)
                else:
                    print('bad request')
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
