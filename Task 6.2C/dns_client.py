# =====================================================
# SIT202 - Task 6.2C - DNS Client
# =====================================================

# We need socket to send and receive messages
# over the network using UDP
# We need struct to pack and unpack binary data
import socket
import struct
import random

# =====================================================
# CLIENT SETTINGS
# =====================================================

# This is the IP address of the DNS server
# We use 127.0.0.1 which means the server is running
# on the same computer as the client
SERVER_IP   = '127.0.0.1'

# Port 53 is the standard DNS port
# This must match the port the server is using
SERVER_PORT = 53

# 512 bytes is the maximum size of a DNS message
BUFFER_SIZE = 512

# How long to wait for a reply from the server
# before giving up — 5 seconds is enough
TIMEOUT = 5


# =====================================================
# FUNCTION: ENCODE HOSTNAME TO DNS FORMAT
# =====================================================

# DNS requires the hostname to be written in a special
# format where each label starts with its length
# for example www.deakin.edu.au becomes
# \x03www\x06deakin\x03edu\x02au\x00
def encode_hostname(hostname):
    result = b''
    for part in hostname.split('.'):
        result += bytes([len(part)]) + part.encode('utf-8')
    result += b'\x00'
    return result


# =====================================================
# FUNCTION: BUILD DNS QUERY
# =====================================================

# This function builds the DNS query message
# that we send to the server asking for a record
def build_dns_query(hostname, query_type):

    # Generate a random transaction ID between 0 and 65535
    # The server will copy this ID in its reply so we
    # can match the reply to our original question
    transaction_id = random.randint(0, 65535)

    # These are the header flags for a standard query
    # QR=0 means this is a query not a response
    # RD=1 means we want recursion if available
    flags = 0x0100

    # Pack the header into 12 bytes
    # 1 question, 0 answers, 0 authority, 0 additional
    header = struct.pack('!HHHHHH',
        transaction_id,
        flags,
        1,
        0,
        0,
        0
    )

    # Encode the hostname into DNS wire format
    question = encode_hostname(hostname)

    # Add the query type and class
    # Type 1 = A record   Type 5 = CNAME record
    # Class 1 = IN which means Internet
    if query_type == 'A':
        question += struct.pack('!HH', 1, 1)
    elif query_type == 'CNAME':
        question += struct.pack('!HH', 5, 1)

    return header + question, transaction_id


# =====================================================
# FUNCTION: PARSE DNS RESPONSE
# =====================================================

# This function reads the raw bytes that came back
# from the server and extracts the answer
def parse_dns_response(data):

    # Read the header to get the important fields
    transaction_id = struct.unpack('!H', data[:2])[0]
    flags          = struct.unpack('!H', data[2:4])[0]
    answer_count   = struct.unpack('!H', data[6:8])[0]

    # Check the RCODE in the flags
    # RCODE = last 4 bits of the flags field
    # RCODE 0 means no error
    # RCODE 3 means the hostname does not exist
    rcode = flags & 0x000F

    if rcode == 3:
        return transaction_id, 'NXDOMAIN', None, None

    if answer_count == 0:
        return transaction_id, 'NOT FOUND', None, None

    # Skip past the header (12 bytes) and the
    # question section to get to the answer section
    i = 12
    while True:
        length = data[i]
        if length == 0:
            i += 1
            break
        i += 1 + length

    # Skip query type and class (4 bytes)
    i += 4

    # Now we are at the start of the answer section
    # Skip the name pointer (2 bytes)
    i += 2

    # Read the answer type
    # 1 = A record   5 = CNAME record
    answer_type = struct.unpack('!H', data[i : i+2])[0]
    i += 2

    # Skip class (2 bytes)
    i += 2

    # Skip TTL (4 bytes)
    i += 4

    # Read the length of the answer data
    data_length = struct.unpack('!H', data[i : i+2])[0]
    i += 2

    # Read the actual answer data
    if answer_type == 1:
        # A record — convert 4 bytes back to IP address
        # for example 4 numbers become 192.168.1.10
        ip_bytes = data[i : i+4]
        resolved = socket.inet_ntoa(ip_bytes)
        return transaction_id, 'A', resolved, None

    elif answer_type == 5:
        # CNAME record — decode the canonical domain name
        # from DNS wire format back to normal text
        cname = ''
        j = i
        while True:
            length = data[j]
            if length == 0:
                break
            if cname:
                cname += '.'
            cname += data[j+1 : j+1+length].decode('utf-8')
            j += 1 + length
        return transaction_id, 'CNAME', cname, None

    return transaction_id, 'UNKNOWN', None, None


# =====================================================
# FUNCTION: SEND DNS QUERY TO SERVER
# =====================================================

# This function creates the UDP socket, sends the
# query to the server and waits for the response
def send_query(hostname, query_type):

    # Create a UDP socket for the client
    client_socket = socket.socket(
        socket.AF_INET,
        socket.SOCK_DGRAM
    )

    # Set a timeout so we do not wait forever
    # if the server does not respond
    client_socket.settimeout(TIMEOUT)

    try:
        # Build the DNS query message
        query, transaction_id = build_dns_query(hostname, query_type)

        # Send the query to the server
        client_socket.sendto(query, (SERVER_IP, SERVER_PORT))
        print(f'\n[SENT] Query sent to server at {SERVER_IP}:{SERVER_PORT}')

        # Wait for the response from the server
        raw_response, server_address = client_socket.recvfrom(BUFFER_SIZE)
        print(f'[RECEIVED] Response received from server')

        # Parse the response and extract the answer
        tid, record_type, resolved, extra = parse_dns_response(raw_response)

        # Display the result to the user in a clean way
        print('\n-----------------------------------------')
        print(f'  Hostname    : {hostname}')
        print(f'  Query type  : {query_type}')

        if record_type == 'A':
            print(f'  Record type : A Record')
            print(f'  IP Address  : {resolved}')
            print(f'  Result      : SUCCESS')

        elif record_type == 'CNAME':
            print(f'  Record type : CNAME Record')
            print(f'  Real domain : {resolved}')
            print(f'  Result      : SUCCESS')

        elif record_type == 'NXDOMAIN':
            print(f'  Result      : NOT FOUND (NXDOMAIN)')
            print(f'  The hostname does not exist on this server')

        else:
            print(f'  Result      : NOT FOUND')

        print('-----------------------------------------')

    except socket.timeout:
        # If we waited too long and got no reply
        # we tell the user the server did not respond
        print('\n[ERROR] No response from server - request timed out')
        print('Make sure the DNS server is running')

    except Exception as e:
        print(f'\n[ERROR] Something went wrong: {e}')

    finally:
        client_socket.close()


# =====================================================
# MAIN CLIENT FUNCTION
# =====================================================

def start_client():

    # Print a welcome message when the client starts
    print('=================================================')
    print('         DNS Client - Task 6.2C')
    print(f'         Server : {SERVER_IP}:{SERVER_PORT}')
    print('=================================================')

    # Keep asking the user for queries until they
    # decide they want to stop
    while True:

        print('\nEnter the hostname or alias you want to look up')
        print('Examples:')
        print('  www.deakin.edu.au      (A record)')
        print('  mail.deakin.edu.au     (A record)')
        print('  learn.deakin.edu.au    (CNAME record)')
        print('  webmail.deakin.edu.au  (CNAME record)')

        # Ask the user to type a hostname
        hostname = input('\nHostname : ').strip().lower()

        # Check the user actually typed something
        if not hostname:
            print('[ERROR] You did not enter a hostname. Please try again.')
            continue

        # Ask the user what type of record they want
        print('\nWhat type of record do you want?')
        print('  1 = A record     (hostname to IP address)')
        print('  2 = CNAME record (alias to real domain)')
        choice = input('Enter 1 or 2 : ').strip()

        if choice == '1':
            query_type = 'A'
        elif choice == '2':
            query_type = 'CNAME'
        else:
            print('[ERROR] Invalid choice. Please enter 1 or 2.')
            continue

        # Send the query to the server
        send_query(hostname, query_type)

        # Ask the user if they want to do another query
        # This is required by the task instructions
        print('\nWould you like to do another DNS query?')
        again = input('Enter yes or no : ').strip().lower()

        if again == 'yes' or again == 'y':
            continue
        else:
            print('\n[GOODBYE] DNS Client closed. Goodbye!')
            break


# =====================================================
# RUN THE CLIENT
# =====================================================

# This starts the client when we run this file
if __name__ == '__main__':
    start_client()