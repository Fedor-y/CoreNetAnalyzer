import socket
import struct

class EthernetFrame:
    """Класс для обработки кадров канального уровня (Ethernet)"""
    def __init__(self, raw_data):
        self.raw_data = raw_data
        # Распаковываем заголовок
        raw_header = raw_data[:14]
        dest_mac, src_mac, proto = struct.unpack("!6s6sH", raw_header)
        
        # Свойства объекта
        self.dest_mac = self._format_mac(dest_mac)
        self.src_mac = self._format_mac(src_mac)
        self.proto = socket.htons(proto)
        self.payload = raw_data[14:]

    def _format_mac(self, bytes_addr):
        """Внутренний (приватный) метод для форматирования MAC"""
        bytes_str = map("{:02x}".format, bytes_addr)
        return ":".join(bytes_str).upper()


class ARPPacket:
    """Класс для обработки ARP-пакетов"""
    def __init__(self, payload):
        arp_header = payload[:28]
        unpacked = struct.unpack('!HHBBH6s4s6s4s', arp_header)
        
        self.opcode = unpacked[4]
        self.src_mac = EthernetFrame._format_mac(None, unpacked[5]) # Переиспользуем метод форматирования
        self.src_ip = socket.inet_ntoa(unpacked[6])
        self.dst_ip = socket.inet_ntoa(unpacked[8])


class IPv4Packet:
    """Класс для обработки IPv4-пакетов"""
    def __init__(self, payload):
        ip_header = payload[:20]
        unpacked = struct.unpack('!BBHHHBBH4s4s', ip_header)
        
        self.proto = unpacked[6] # Протокол транспортного уровня (TCP/UDP)
        self.src_ip = socket.inet_ntoa(unpacked[8])
        self.dst_ip = socket.inet_ntoa(unpacked[9])
        self.payload = payload[20:]


class TransportSegment:
    """Базовый класс для TCP/UDP сегментов (демонстрация наследования)"""
    def __init__(self, payload):
        self.payload = payload
        self.src_port = None
        self.dst_port = None


class TCPSegment(TransportSegment):
    """Класс для TCP (наследуется от TransportSegment)"""
    def __init__(self, payload):
        super().__init__(payload) # Вызов конструктора родителя
        tcp_header = payload[:20]
        unpacked = struct.unpack('!HHIIBBHHH', tcp_header)
        
        self.src_port = unpacked[0]
        self.dst_port = unpacked[1]
        data_offset = (unpacked[4] >> 4) * 4
        self.user_data = payload[data_offset:]


class UDPSegment(TransportSegment):
    """Класс для UDP (наследуется от TransportSegment)"""
    def __init__(self, payload):
        super().__init__(payload)
        udp_header = payload[:8]
        src_port, dst_port, _, _ = struct.unpack('!HHHH', udp_header)
        
        self.src_port = src_port
        self.dst_port = dst_port
        self.user_data = payload[8:]
