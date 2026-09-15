from scapy.all import sniff 

def ver_paquete(paquete): 
    print(paquete.summary()) 

print("IDS iniciado...")
print("Esperando paquetes...")

sniff(prn=ver_paquete, filter="ip", store=0)