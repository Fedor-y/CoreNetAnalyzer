import socket
# Импортируем наши новые КЛАССЫ вместо функций
from parsers import EthernetFrame, ARPPacket, IPv4Packet, TCPSegment, UDPSegment

class CoreNetAnalyzer:
    def __init__(self):
        # Настройка сокета при инициализации объекта
        self.rs = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        self.known_ports = {22: "SSH", 53: "DNS", 80: "HTTP", 443: "HTTPS", 5353: "mDNS"}

    def _get_service_name(self, port):
        return self.known_ports.get(port, "Unknown App")

    def start_sniffing(self):
        print("[*] ООП-Сниффер запущен. Слушаю интерфейсы...")
        try:
            while True:
                raw_packet, _ = self.rs.recvfrom(65535)
                
                # Создаем объект Ethernet-кадра (Инкапсуляция)
                eth = EthernetFrame(raw_packet)
                
                # Диспетчеризация по объектам
                if eth.proto == 8: # IPv4
                    ip = IPv4Packet(eth.payload)
                    
                    if ip.proto == 6: # TCP внутри IP
                        tcp = TCPSegment(ip.payload)
                        service = self._get_service_name(tcp.dst_port) if tcp.dst_port in self.known_ports else self._get_service_name(tcp.src_port)
                        print(f"[ООП -> TCP] {ip.src_ip}:{tcp.src_port} ──> {ip.dst_ip}:{tcp.dst_port} | {service}")
                        
                    elif ip.proto == 17: # UDP внутри IP
                        udp = UDPSegment(ip.payload)
                        service = self._get_service_name(udp.dst_port) if udp.dst_port in self.known_ports else self._get_service_name(udp.src_port)
                        print(f"[ООП -> UDP] {ip.src_ip}:{udp.src_port} ──> {ip.dst_ip}:{udp.dst_port} | {service}")

                elif eth.proto == 1544: # ARP
                    arp = ARPPacket(eth.payload)
                    if arp.opcode == 1:
                        print(f"[ООП -> ARP] Кто спрашивает {arp.dst_ip}? Ответить на {arp.src_ip}")

        except KeyboardInterrupt:
            print("\n[*] Анализ остановлен пользователем.")

if __name__ == "__main__":
    # Создаем экземпляр нашего анализатора и запускаем его
    analyzer = CoreNetAnalyzer()
    analyzer.start_sniffing()
