import socket
import struct
import textwrap

# Создаем рабочий сырой сокет
rs = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))

# --- ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ ---


def get_mac_addr(bytes_addr):
    """Превращает сырые 6 байт в красивую строку MAC-адреса (AA:BB:CC:DD:EE:FF)"""
    # Преобразуем байты в строку HEX, делаем заглавными
    bytes_str = map("{:02x}".format, bytes_addr)
    return ":".join(bytes_str).upper()


def parse_ethernet_frame(data):
    """Распаковывает заголовок Ethernet (первые 14 байт)"""
    # Забираем первые 14 байт заголовка
    raw_header = data[:14]

    # struct.unpack распаковывает байты по заданному формату.
    # '!6s6sH' означает:
    # ! - Сетевой порядок байт (Big-Endian)
    # 6s - 6 байт (MAC получателя)
    # 6s - 6 байт (MAC отправителя)
    # H - 2 байта (EtherType / Протокол)
    dest_mac, src_mac, proto = struct.unpack("!6s6sH", raw_header)

    # Возвращаем распакованные и отформатированные данные,
    # а также остаток пакета (payload), который пойдет дальше в IPv4
    return get_mac_addr(dest_mac), get_mac_addr(src_mac), socket.htons(proto), data[14:]


# для парсинга ARP пакетов
def parse_arp(payload):
    """Распаковывает заголовок ARP (28 байт)"""
    # Нам нужны первые 28 байт из полезной нагрузки Ethernet
    arp_header = payload[:28]

    # Расшифровка шаблона '!HHBBH6s4s6s4s':
    # ! - Сетевой порядок байт (Big-Endian)
    # H - 2 байта (Hardware type)
    # H - 2 байта (Protocol type)
    # B - 1 байт (Hardware size)
    # B - 1 байт (Protocol size)
    # H - 2 байта (Opcode: 1=запрос, 2=ответ)
    # 6s - 6 байт (MAC отправителя)
    # 4s - 4 байта (IP отправителя)
    # 6s - 6 байт (MAC получателя)
    # 4s - 4 байта (IP получателя / кого ищут)

    unpacked = struct.unpack("!HHBBH6s4s6s4s", arp_header)

    opcode = unpacked[4]
    sender_mac = get_mac_addr(unpacked[5])
    sender_ip = socket.inet_ntoa(unpacked[6])
    target_ip = socket.inet_ntoa(unpacked[8])

    return opcode, sender_mac, sender_ip, target_ip


# --- ОСНОВНАЯ ЛОГИКА ---


def listen():
    print("[*] Сниффер запущен. Ожидание пакетов...")
    while True:
        # Ловим пакет
        all_data = rs.recvfrom(65535)
        main_data = all_data[0]  # Только сырые байты

        # Отдаем байты на парсинг Ethernet-заголовка
        dest_mac, src_mac, eth_proto, payload = parse_ethernet_frame(main_data)

        print("\n=== НОВЫЙ ETHERNET КАДР ===")
        print(f"Откуда (MAC): {src_mac}")
        print(f"Куда (MAC): {dest_mac}")
        print(f"Протокол (EtherType): {eth_proto}")

        # Теперь диспетчеризация (решаем, что делать дальше)
        if eth_proto == 8:  # 8 - это IPv4 (0x0800)
            print("  --> Внутри лежит IPv4 пакет. Нужно парсить дальше!")
            # Здесь потом будет вызов функции parse_ipv4(payload)"""

        if eth_proto == 1544:  # 1544 - это ARP (0x0806)
            print("  --> Внутри лежит ARP запрос.")
            print(f"{parse_arp(payload)[1:3]}")

        elif eth_proto == 56710:  # 56710 - это IPv6 (0x86DD)
            print("  --> Внутри лежит IPv6 пакет.")


# Запуск программы
if __name__ == "__main__":
    listen()
