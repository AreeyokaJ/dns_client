import socket
import struct
import random
import json

# Example query spec as JSON
dns_query_spec = {
    "id": random.randint(0, 65535),
    "qr": 0,      # query
    "opcode": 0,  # standard query
    "rd": 1,      # recursion desired
    "questions": [
        {
            "qname": "ilab1.cs.rutgers.edu",
            "qtype": 28,
            "qclass": 1
        }
        # {
        #     "qname": "ilab1.cs.rutgers.edu",
        #     "qtype": 1,   # Arecord
        #     "qclass": 1   # IN
        # }
    ]
}


def build_query(query_spec):
    # Header fields
    ID = query_spec["id"]
    QR = query_spec["qr"] << 15
    OPCODE = query_spec["opcode"] << 11
    AA, TC = 0, 0
    RD = query_spec["rd"] << 8
    RA, Z, RCODE = 0, 0, 0
    flags = QR | OPCODE | AA | TC | RD | RA | Z | RCODE

    QDCOUNT = len(query_spec["questions"])
    ANCOUNT, NSCOUNT, ARCOUNT = 0, 0, 0

    header = struct.pack("!HHHHHH", ID, flags, QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT)

    # Question section
    question_bytes = b""
    for q in query_spec["questions"]:
        labels = q["qname"].split(".")
        for label in labels:
            question_bytes += struct.pack("B", len(label)) + label.encode()
        question_bytes += b"\x00"  # end of qname
        question_bytes += struct.pack("!HH", q["qtype"], q["qclass"])

    return header + question_bytes


def parse_response(data):
    response = {}
    (ID, flags, QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT) = struct.unpack("!HHHHHH", data[:12])

    response["id"] = ID
    response["qr"] = (flags >> 15) & 1
    response["opcode"] = (flags >> 11) & 0xF
    response["aa"] = (flags >> 10) & 1
    response["tc"] = (flags >> 9) & 1
    response["rd"] = (flags >> 8) & 1
    response["ra"] = (flags >> 7) & 1
    response["rcode"] = flags & 0xF
    response["qdcount"] = QDCOUNT
    response["ancount"] = ANCOUNT

    offset = 12
    # Skip questions
    for _ in range(QDCOUNT):
        while data[offset] != 0:
            offset += data[offset] + 1
        offset += 1
        offset += 4  # qtype + qclass

    # Parse answers
    answers = []
    for _ in range(ANCOUNT):
        # name (compression: first two bits 11)
        if (data[offset] & 0xC0) == 0xC0:
            offset += 2
        else:
            while data[offset] != 0:
                offset += data[offset] + 1
            offset += 1

        atype, aclass, ttl, rdlength = struct.unpack("!HHIH", data[offset:offset+10])
        offset += 10
        rdata = data[offset:offset+rdlength]
        offset += rdlength
        print("atype and rdlength",atype,rdlength,type(rdata))
        '''
		 TODO  Add code to extract IPv4 address or IPv6 address based on atype and rdlength
		 Answer should contain three fields "type","ip", and "ttl"
        '''
        
        '''
         for ipv4: there are 4 bytes in 32 bits, ipv4 is 32 bits long the standard ip address is
         each byte represented by one byte 


        '''

        answer_types = {
            "A": {
                "type": 0x0001, 
                "length": 4
            }, 
            "AAAA": {
                "type": 0x001c, 
                "length": 16
            }
        }

        if atype == answer_types["A"]["type"] and rdlength == answer_types["A"]["length"]:
            bytes = [rdata[i] for i in range(rdlength)]
            ip_address = ".".join(str(byte) for byte in bytes)
            answers.append({"type": "A", "ip": ip_address, "ttl": ttl})
        elif atype == answer_types["AAAA"]["type"] and rdlength == answer_types["AAAA"]["length"]:
            segments = []
            for i in range(0, rdlength, 2):
                upper_byte = rdata[i] << 8 
                lower_byte = rdata[i+1]
                combined = upper_byte | lower_byte 

                current_hex = f"{combined: 04x}"
                segments.append(current_hex)
            ip_address = ":".join(segments) 
            answers.append({"type": "AAAA", "ip": ip_address, "ttl":ttl})
          
    response["answers"] = answers
    return response


def dns_query(query_spec, server=("8.8.8.8", 53)):
    query = build_query(query_spec)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5)
    sock.sendto(query, server)
    data, _ = sock.recvfrom(512)
    sock.close()
    result=parse_response(data)
    return result

if __name__ == "__main__":
    with open("Input.json", "r") as f:
        query_json = json.load(f)
    
    #for each question object in input.json create query spec 
    #append each response to output.txt
    for q in query_json:
        #creating query spec
        dns_query_spec = {
            "id": random.randint(0, 65535),
            "qr": 0,      # query
            "opcode": 0,  # standard query
            "rd": 1,      # recursion desired
            "questions": [
                {
                    "qname": q["qname"],
                    "qtype": q["qtype"],
                    "qclass": 1
                }
            ]
        }

        
        response = dns_query(dns_query_spec)

        if response["tc"] == 1: 
            print("Error, response was truncated")   
            sys.exit()

        print(json.dumps(response, indent = 2))

        #clear output.txt file if there is any info in it because a will keep writing
        with open("output.txt", "a") as f:
            f.write(json.dumps(response) + "\n")



