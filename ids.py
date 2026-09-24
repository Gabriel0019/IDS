from scapy.all import sniff, IP, TCP, UDP
from collections import defaultdict
import time

puertos_ip = defaultdict(set)
tiempo_inicio = defaultdict(float)

limite_puertos = 10
ventanas_tiempo = 10

def analizar_paquete(paquete):
    if IP not in paquete:
        return
    ip_origen = paquete[IP].src

    if TCP in paquete:
        puerto_destino = paquete[TCP].dport

    elif UDP in paquete:
        puerto_destino = paquete[UDP].dport

    else:
        return

    ahora = time.time()

    if not tiempo_inicio[ip_origen]:
        tiempo_inicio[ip_origen] = ahora

    tiempo_transcurrido = ahora - tiempo_inicio[ip_origen]

    if tiempo_transcurrido > ventanas_tiempo:
        puertos_ip[ip_origen].clear()
        tiempo_inicio[ip_origen] = ahora

    puertos_ip[ip_origen].add(puerto_destino)

    cantidad = len(puertos_ip[ip_origen])
    print(f"{ip_origen} -> puerto {puerto_destino}" f"| Puertos distintos: {cantidad}")

    if cantidad >= limite_puertos:
        print(f"Alerta: Posible escaneo de puertos desde {ip_origen} (puertos distintos: {cantidad})")
        puertos_ip[ip_origen].clear()
        tiempo_inicio[ip_origen] = ahora

    puertos_ip[ip_origen].clear()

    tiempo_inicio[ip_origen] = ahora


print("IDS iniciado...")
print("Analizando paquetes...")

sniff(prn=analizar_paquete, filter="ip", store=0)
