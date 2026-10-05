from scapy.all import sniff, IP, TCP, UDP
from collections import defaultdict
import time
from datetime import datetime

puertos_ip = defaultdict(set)
tiempo_inicio = defaultdict(float)

limite_puertos = 3
ventanas_tiempo = 10

def registrar_alerta(ip, cantidad):
    fecha_hora = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    with open ("alertas.log", "a") as archivo:
        archivo.write(f"[{fecha_hora}] Alerta: Posible escaneo de puertos desde {ip} (puertos distintos: {cantidad})\n")

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
    print(f"{ip_origen} -> puerto {puerto_destino} | Puertos distintos: {cantidad}")

    if cantidad >= limite_puertos:
        print(f"Alerta: Posible escaneo de puertos desde {ip_origen} (puertos distintos: {cantidad})")
        registrar_alerta(ip_origen, cantidad)
        puertos_ip[ip_origen].clear()
        tiempo_inicio[ip_origen] = ahora


print("IDS iniciado...")
print("Analizando paquetes...")

sniff(prn=analizar_paquete, filter="tcp", store=0)
