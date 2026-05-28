import socket
import threading
import queue
import json
import time
from collections import Counter
from parsers import EthernetFrame, ARPPacket, IPv4Packet, TCPSegment, UDPSegment

class TrafficStats:
    """Класс-Анализатор трафика в оперативной памяти (ООП)"""
    def __init__(self):
        # Используем Counter для сверхбыстрого подсчета
        self.protocols = Counter()
        self.src_ips = Counter()
        self.dst_ips = Counter()
        self.start_time = time.time()

    def analyze(self, packet_info):
        """Мгновенно обновляет счетчики (O(1) по времени)"""
        proto = packet_info.get("proto")
        if proto:
            self.protocols[proto] += 1
        
        if "src_ip" in packet_info:
            self.src_ips[packet_info["src_ip"]] += 1
            
        if "dst_ip" in packet_info:
            self.dst_ips[packet_info["dst_ip"]] += 1

    def print_report(self):
        """Формирует и выводит итоговый отчет с выровненными колонками"""
        elapsed = time.time() - self.start_time
        
        # Делаем шапку чуть шире для красоты
        print(f"\n\n{'='*12} ОТЧЕТ АНАЛИЗАТОРА ТРАФИКА {'='*12}")
        print(f"[*] Время работы сниффера: {elapsed:.1f} сек.\n")
        
        print("[+] Статистика по протоколам:")
        for p, count in self.protocols.most_common():
            # <8 - левое выравнивание на 8 символов
            # >6 - правое выравнивание на 6 символов
            print(f"    - {p:<8} : {count:>6} пакетов")
        
        print("\n[+] Топ-5 активных отправителей (Source IP):")
        for ip, count in self.src_ips.most_common(5):
            # <15 - ровно столько символов занимает самый длинный IPv4 адрес
            print(f"    - {ip:<15} : {count:>6} пакетов")
            
        print("\n[+] Топ-5 частых получателей (Destination IP):")
        for ip, count in self.dst_ips.most_common(5):
            print(f"    - {ip:<15} : {count:>6} пакетов")
            
        print("="*51 + "\n")

class PacketLogger(threading.Thread):
    """Фоновый поток для записи JSONL"""
    def __init__(self, packet_queue, filename="network_traffic.jsonl"):
        super().__init__()
        self.queue = packet_queue
        self.filename = filename
        self.daemon = True

    def run(self):
        with open(self.filename, "a", buffering=1, encoding="utf-8") as f:
            while True:
                packet_data = self.queue.get()
                f.write(json.dumps(packet_data, ensure_ascii=False) + "\n")
                self.queue.task_done()


class CoreNetAnalyzer:
    def __init__(self):
        self.rs = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        self.known_ports = {22: "SSH", 53: "DNS", 80: "HTTP", 443: "HTTPS", 5353: "mDNS"}
        
        self.packet_queue = queue.Queue()
        self.logger = PacketLogger(self.packet_queue)
        self.logger.start()
        
        # Инициализируем наш Анализатор
        self.stats = TrafficStats()

    def _get_service_name(self, port):
        return self.known_ports.get(port, "Unknown App")

    def start_sniffing(self):
        print("[*] ООП-Сниффер запущен.")
        print("[*] Логирование идет в фоне. Для вывода статистики нажмите Ctrl+C...")
        try:
            while True:
                raw_packet, _ = self.rs.recvfrom(65535)
                eth = EthernetFrame(raw_packet)
                
                log_entry = {"timestamp": time.time(), "proto": "Unknown"}

                if eth.proto == 8: # IPv4
                    ip = IPv4Packet(eth.payload)
                    log_entry.update({"proto": "IPv4", "src_ip": ip.src_ip, "dst_ip": ip.dst_ip})
                    
                    if ip.proto == 6: # TCP
                        tcp = TCPSegment(ip.payload)
                        log_entry.update({"proto": "TCP", "src_port": tcp.src_port, "dst_port": tcp.dst_port, "service": self._get_service_name(tcp.dst_port)})
                    elif ip.proto == 17: # UDP
                        udp = UDPSegment(ip.payload)
                        log_entry.update({"proto": "UDP", "src_port": udp.src_port, "dst_port": udp.dst_port, "service": self._get_service_name(udp.dst_port)})

                elif eth.proto == 1544: # ARP
                    arp = ARPPacket(eth.payload)
                    log_entry.update({"proto": "ARP", "src_mac": arp.src_mac, "src_ip": arp.src_ip, "dst_ip": arp.dst_ip})

                if log_entry["proto"] != "Unknown":
                    # 1. Отправляем в очередь на диск (Фоновая задача)
                    self.packet_queue.put(log_entry)
                    # 2. Мгновенно обновляем статистику в памяти (Быстрая задача)
                    self.stats.analyze(log_entry)

        except KeyboardInterrupt:
            print("\n[*] Завершение работы...")
            # Выводим красивый отчет
            self.stats.print_report()
            self.packet_queue.join()
            print("[*] Данные успешно сохранены.")

if __name__ == "__main__":
    analyzer = CoreNetAnalyzer()
    analyzer.start_sniffing()
