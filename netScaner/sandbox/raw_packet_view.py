import socket
import time

# test file
raw_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
while 1:
    data_all = raw_socket.recvfrom(65535)
    data_inf = data_all[1]
    data = data_all[0]
    print(data)
    print(len(data))
    # print(data_inf)
    print(data[:6])
    print(data[6:12])
    time.sleep(2)

