import tkinter as tk
from tkinter import ttk
import time
import random
import threading
import requests
import dns.message
import dns.query
import string


class TrexTrafficGenerator:
    def __init__(self, destination, port, protocol, duration=60) -> None:
        """
        Инициализация генератора трафика.

        :param destination: Адрес назначения.
        :param port: Порт назначения.
        :param protocol: Протокол передачи (TCP, UDP, HTTP, DNS).
        :param duration: Продолжительность теста в секундах.
        """
        self.destination = destination
        self.port = port
        self.protocol = protocol
        self.duration = duration
        self.stop_event = threading.Event()
        self.packet_size = 64
        self.interval = 0.1

    def set_packet_size(self, packet_size) -> None:
        """
        Устанавливает размер пакета в байтах.

        :param packet_size: Размер пакета в байтах.
        """
        if packet_size < 64:
            print("Minimum packet size is 64 bytes.")
            self.packet_size = 64
        elif packet_size > 1500:
            print("Maximum packet size is 1500 bytes.")
            self.packet_size = 1500
        else:
            self.packet_size = packet_size

    def set_interval(self, interval) -> None:
        """
        Устанавливает интервал между отправкой пакетов.

        :param interval: Интервал в секундах.
        """
        self.interval = interval

    def send_traffic(self) -> None:
        """
        Отправляет трафик.
        """
        while not self.stop_event.is_set():
            if self.protocol == 'TCP':
                print(f"Sending TCP packet to {self.destination}:{
                      self.port}, size: {self.packet_size} bytes")
            elif self.protocol == 'UDP':
                print(f"Sending UDP packet to {self.destination}:{
                      self.port}, size: {self.packet_size} bytes")
            elif self.protocol == 'HTTP':
                print(f"Sending HTTP request to {
                      self.destination}:{self.port}")
                self.send_http_request()
            elif self.protocol == 'DNS':
                print(f"Sending DNS query to {self.destination}:{self.port}")
                self.send_dns_query()
            else:
                print("Unsupported protocol")
                return

            time.sleep(self.interval)

    def send_http_request(self) -> None:
        """
        Отправляет HTTP запрос.
        """
        try:
            method = random.choice(['GET', 'POST', 'PUT', 'DELETE'])
            url = f"http://{self.destination}:{self.port}"
            headers = {'User-Agent': 'TrexTrafficGenerator',
                       'Accept': 'text/plain'}
            data = ''.join(random.choices(
                string.ascii_letters + string.digits, k=16))

            response = requests.request(
                method, url, headers=headers, data=data)
            print(f"Received HTTP response: {response.status_code}")
        except Exception as e:
            print(f"HTTP request failed: {e}")

    def send_dns_query(self) -> None:
        """
        Отправляет DNS запрос.
        """
        try:
            qname = dns.name.from_text(self.destination)  # type: ignore
            qtype = random.choice(
                [dns.rdatatype.A, dns.rdatatype.AAAA,  # type: ignore
                 dns.rdatatype.MX, dns.rdatatype.NS])  # type: ignore
            query = dns.message.make_query(qname, qtype)
            response = dns.query.udp(query, self.destination, timeout=1)
            print(f"Received DNS response: {response}")
        except Exception as e:
            print(f"DNS query failed: {e}")

    def start(self) -> None:
        """
        Запускает генерацию трафика.
        """
        print(f"Starting traffic generation for {self.duration} seconds...")
        thread = threading.Thread(target=self.send_traffic)
        thread.start()

        time.sleep(self.duration)
        self.stop()

    def stop(self) -> None:
        """
        Останавливает генерацию трафика.
        """
        print("Stopping traffic generation...")
        self.stop_event.set()


def start_traffic() -> None:
    destination_ip = destination_ip_entry.get()
    destination_port = int(destination_port_entry.get())
    duration = int(duration_entry.get())
    packet_size = int(packet_size_entry.get())
    interval = float(interval_entry.get())

    if tcp_var.get():
        tcp_generator = TrexTrafficGenerator(
            destination_ip, destination_port, "TCP", duration)
        tcp_generator.set_packet_size(packet_size)
        tcp_generator.set_interval(interval)
        tcp_generator.start()
    if udp_var.get():
        udp_generator = TrexTrafficGenerator(
            destination_ip, destination_port, "UDP", duration)
        udp_generator.set_packet_size(packet_size)
        udp_generator.set_interval(interval)
        udp_generator.start()
    if http_var.get():
        http_generator = TrexTrafficGenerator(
            destination_ip, destination_port, "HTTP", duration)
        http_generator.set_packet_size(packet_size)
        http_generator.set_interval(interval)
        http_generator.start()
    if dns_var.get():
        dns_generator = TrexTrafficGenerator(
            destination_ip, destination_port, "DNS", duration)
        dns_generator.set_packet_size(packet_size)
        dns_generator.set_interval(interval)
        dns_generator.start()


def update_start_button_state(*args) -> None:
    if tcp_var.get() or udp_var.get() or http_var.get() or dns_var.get():
        start_button.state(["!disabled"])
    else:
        start_button.state(["disabled"])


root = tk.Tk()
root.title("Traffic Generator")

protocol_frame = ttk.LabelFrame(root, text="Protocol")
protocol_frame.grid(row=0, column=0, padx=10, pady=5, sticky="w")

tcp_var = tk.BooleanVar()
udp_var = tk.BooleanVar()
http_var = tk.BooleanVar()
dns_var = tk.BooleanVar()

tcp_var.trace_add('write', update_start_button_state)
udp_var.trace_add('write', update_start_button_state)
http_var.trace_add('write', update_start_button_state)
dns_var.trace_add('write', update_start_button_state)

ttk.Checkbutton(protocol_frame, text="TCP", variable=tcp_var).grid(
    row=0, column=0, padx=5, pady=5, sticky="w")
ttk.Checkbutton(protocol_frame, text="UDP", variable=udp_var).grid(
    row=0, column=1, padx=5, pady=5, sticky="w")
ttk.Checkbutton(protocol_frame, text="HTTP", variable=http_var).grid(
    row=0, column=2, padx=5, pady=5, sticky="w")
ttk.Checkbutton(protocol_frame, text="DNS", variable=dns_var).grid(
    row=0, column=3, padx=5, pady=5, sticky="w")

ttk.Label(root, text="Destination IP:").grid(
    row=1, column=0, padx=10, pady=5, sticky="e")
destination_ip_entry = ttk.Entry(root)
destination_ip_entry.grid(row=1, column=1, padx=10, pady=5)
destination_ip_entry.insert(0, "192.168.1.1")

ttk.Label(root, text="Destination Port:").grid(
    row=2, column=0, padx=10, pady=5, sticky="e")
destination_port_entry = ttk.Entry(root)
destination_port_entry.grid(row=2, column=1, padx=10, pady=5)
destination_port_entry.insert(0, "80")

ttk.Label(root, text="Duration (seconds):").grid(
    row=3, column=0, padx=10, pady=5, sticky="e")
duration_entry = ttk.Entry(root)
duration_entry.grid(row=3, column=1, padx=10, pady=5)
duration_entry.insert(0, "60")

ttk.Label(root, text="Packet Size (bytes):").grid(
    row=4, column=0, padx=10, pady=5, sticky="e")
packet_size_entry = ttk.Entry(root)
packet_size_entry.grid(row=4, column=1, padx=10, pady=5)
packet_size_entry.insert(0, "64")

ttk.Label(root, text="Interval (seconds):").grid(
    row=5, column=0, padx=10, pady=5, sticky="e")
interval_entry = ttk.Entry(root)
interval_entry.grid(row=5, column=1, padx=10, pady=5)
interval_entry.insert(0, "0.1")

start_button = ttk.Button(root, text="Start Traffic", command=start_traffic)
start_button.grid(row=6, column=0, columnspan=2, pady=10)

update_start_button_state()

root.mainloop()
