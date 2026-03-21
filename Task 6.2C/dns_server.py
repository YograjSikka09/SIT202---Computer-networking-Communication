# =====================================================
# SIT202 - Task 6.2C - DNS Server
# =====================================================

# We need the socket library to send and receive
# messages over the network using UDP
# We need struct to pack and unpack binary data
import socket
import struct

# =====================================================
# SERVER SETTINGS
# =====================================================

# Port 53 is the standard port for all DNS servers
# Every client in the world sends DNS queries to port 53
SERVER_PORT = 53

# 0.0.0.0 means the server listens on all
# network interfaces so it accepts queries from anywhere
SERVER_IP = '0.0.0.0'

# 512 bytes is the maximum size allowed
# for a DNS message sent over UDP
BUFFER_SIZE = 512


# =====================================================
# DNS RECORDS
# =====================================================

# A records map a hostname directly to an IP address
# When a client asks for www.deakin.edu.au
# the server looks it up here and returns 192.168.1.10
dns_A_records = {
    'www.deakin.edu.au'     : '192.168.1.10',
    'mail.deakin.edu.au'    : '192.168.1.20',
    'library.deakin.edu.au' : '192.168.1.30',
    'portal.deakin.edu.au'  : '192.168.1.40'
}

# CNAME records map an alias name to the real domain
# For example learn.deakin.edu.au is just a shortcut
# that points to portal.deakin.edu.au
dns_CNAME_records = {
    'webmail.deakin.edu.au' : 'mail.deakin.edu.au',
    'learn.deakin.edu.au'   : 'portal.deakin.edu.au'
}


# =====================================================
# FUNCTION: PARSE INCOMING DNS QUERY
# =====================================================

# This function reads the raw bytes that came in
# from the client and extracts the three things we need
# which are the transaction ID, hostname and query type
def parse_dns_query(data):

    # The first two bytes are the transaction ID
    # This is a unique number so the client can match
    # our reply back to their original question
    transaction_id = struct.unpack('!H', data[:2])[0]

    # The hostname is stored after the 12 byte header
    # It is broken into labels separated by their length
    # for example www.deakin.edu.au is stored as
    # 3www6deakin3edu2au0
    hostname = ''
    i = 12

    while True:
        length = data[i]

        # A zero byte means we have reached
        # the end of the hostname so we stop
        if length == 0:
            i += 1
            break

        # Add a dot between each label
        # but not before the very first one
        if hostname:
            hostname += '.'

        # Read the label and add it to the hostname
        hostname += data[i + 1 : i + 1 + length].decode('utf-8')
        i += 1 + length

    # After the hostname the next two bytes tell us
    # what type of record the client is asking for
    # 1 means A record and 5 means CNAME record
    qtype = struct.unpack('!H', data[i : i + 2])[0]

    if qtype == 1:
        query_type = 'A'
    elif qtype == 5:
        query_type = 'CNAME'
    else:
        query_type = 'UNKNOWN'

    return transaction_id, hostname, query_type


# =====================================================
# FUNCTION: ENCODE HOSTNAME TO DNS FORMAT
# =====================================================

# DNS requires hostnames to be written in a special
# format where each label is preceded by its length
# for example www.deakin.edu.au becomes
# \x03www\x06deakin\x03edu\x02au\x00
def encode_hostname(hostname):
    result = b''
    for part in hostname.split('.'):
        result += bytes([len(part)]) + part.encode('utf-8')
    result += b'\x00'
    return result


# =====================================================
# FUNCTION: BUILD DNS RESPONSE
# =====================================================

# This function looks up the record and then builds
# the full DNS response message to send back
def build_dns_response(transaction_id, hostname, query_type):

    resolved_value  = None
    response_status = 'NOT FOUND'

    # Look up the hostname in the correct records table
    # based on what type of record the client asked for
    if query_type == 'A':

        # Client wants an IP address for this hostname
        # so we check our A records dictionary
        if hostname in dns_A_records:
            resolved_value  = dns_A_records[hostname]
            response_status = 'FOUND'
            print(f'    [FOUND] A Record: {hostname} --> {resolved_value}')
        else:
            print(f'    [NOT FOUND] No A record for: {hostname}')

    elif query_type == 'CNAME':

        # Client wants the real domain for this alias
        # so we check our CNAME records dictionary
        if hostname in dns_CNAME_records:
            resolved_value  = dns_CNAME_records[hostname]
            response_status = 'FOUND'
            print(f'    [FOUND] CNAME Record: {hostname} --> {resolved_value}')
        else:
            print(f'    [NOT FOUND] No CNAME record for: {hostname}')

    # Build the response header flags
    # QR=1 means this is a response not a query
    # AA=1 means we are the authoritative server
    # RCODE=0 means no error  RCODE=3 means not found
    if response_status == 'FOUND':
        flags = 0x8180
    else:
        flags = 0x8183

    # Set answer count to 1 if we found the record
    # or 0 if we did not find anything
    answer_count = 1 if response_status == 'FOUND' else 0

    # Pack the header into 12 bytes
    # It contains transaction ID, flags, and counts
    header = struct.pack('!HHHHHH',
        transaction_id,
        flags,
        1,
        answer_count,
        0,
        0
    )

    # Echo the original question back in the response
    # This is required by the DNS protocol standard
    question = encode_hostname(hostname)

    if query_type == 'A':
        question += struct.pack('!HH', 1, 1)
    elif query_type == 'CNAME':
        question += struct.pack('!HH', 5, 1)

    # Build the answer section if we found the record
    answer = b''
    if response_status == 'FOUND':

        # TTL is 300 seconds which means the client
        # can save this answer for 5 minutes
        ttl = 300

        if query_type == 'A':

            # Convert the IP address string into 4 bytes
            # for example 192.168.1.10 becomes 4 numbers
            ip_bytes = socket.inet_aton(resolved_value)

            answer = (
                b'\xc0\x0c' +
                struct.pack('!HHiH', 1, 1, ttl, 4) +
                ip_bytes
            )

        elif query_type == 'CNAME':

            # Encode the canonical domain name into
            # the DNS wire format before sending
            cname_bytes = encode_hostname(resolved_value)

            answer = (
                b'\xc0\x0c' +
                struct.pack('!HHiH', 5, 1, ttl, len(cname_bytes)) +
                cname_bytes
            )

    # Put together the full response message
    # DNS response = header + question + answer
    return header + question + answer


# =====================================================
# MAIN SERVER FUNCTION
# =====================================================

def start_server():

    # Create a UDP socket
    # SOCK_DGRAM means we are using UDP not TCP
    server_socket = socket.socket(
        socket.AF_INET,
        socket.SOCK_DGRAM
    )

    # This option lets the server restart quickly
    # without getting an address already in use error
    server_socket.setsockopt(
        socket.SOL_SOCKET,
        socket.SO_REUSEADDR,
        1
    )

    # Bind the socket to our IP and port
    # This tells the OS to send all port 53
    # traffic to this program
    try:
        server_socket.bind((SERVER_IP, SERVER_PORT))
    except Exception as e:
        print(f'ERROR: Could not start server. {e}')
        print('Try running with sudo or use a port above 1024')
        return

    # Print confirmation that the server has started
    # The task requires this message to be shown
    print('=================================================')
    print('       DNS Server is now running')
    print(f'       Listening on port : {SERVER_PORT}')
    print(f'       A records loaded  : {len(dns_A_records)}')
    print(f'       CNAME records     : {len(dns_CNAME_records)}')
    print('       Waiting for queries...')
    print('=================================================')

    # Keep looping forever and handle one query at a time
    # The server never stops unless the user presses Ctrl+C
    while True:
        try:

            # Wait here until a query arrives from a client
            # raw_data is the message and client_address
            # is who sent it so we know where to reply
            raw_data, client_address = server_socket.recvfrom(BUFFER_SIZE)
            print(f'\n[QUERY] Received from: {client_address}')

            # Check the message is at least 12 bytes
            # because that is the minimum valid DNS size
            if len(raw_data) < 12:
                print('[ERROR] Message too small - ignoring')
                continue

            # Parse the query to extract the three
            # important pieces of information we need
            transaction_id, hostname, query_type = parse_dns_query(raw_data)

            print(f'    Hostname   : {hostname}')
            print(f'    Query type : {query_type}')

            # If the query type is not A or CNAME
            # we cannot handle it so we skip it
            if query_type == 'UNKNOWN':
                print('[ERROR] Unsupported query type - ignoring')
                continue

            # Build the response and send it back
            # to the client over the same UDP socket
            response = build_dns_response(
                transaction_id,
                hostname,
                query_type
            )

            server_socket.sendto(response, client_address)
            print(f'[RESPONSE] Sent to: {client_address}')
            print('-----------------------------------------')

        except KeyboardInterrupt:
            # If the user presses Ctrl+C we stop cleanly
            print('\n[STOPPED] Server shut down by user.')
            break

        except Exception as e:
            # If anything goes wrong we print the error
            # but keep the server running for next query
            print(f'[ERROR] Something went wrong: {e}')
            continue

    server_socket.close()


# =====================================================
# RUN THE SERVER
# =====================================================

# This starts the server when we run this file
if __name__ == '__main__':
    start_server()
