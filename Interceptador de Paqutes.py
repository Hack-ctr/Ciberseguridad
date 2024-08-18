from scapy.all import sniff

def procesar_paquete(paquete):
    if paquete.haslayer('IP'):
        ip_src = paquete['IP'].src
        ip_dst = paquete['IP'].dst
        protocolo = paquete['IP'].proto
        print(f"Paquete IP: {ip_src} -> {ip_dst}, Protocolo: {protocolo}")
    elif paquete.haslayer('ARP'):
        print(f"Paquete ARP: {paquete.summary()}")

def capturar_paquetes(interface='Wi-Fi', num_paquetes=10):
    print(f"Capturando {num_paquetes} paquetes en la interfaz {interface}...")
    sniff(iface=interface, prn=procesar_paquete, count=num_paquetes)

# Ajusta la interfaz y el número de paquetes según tu entorno
interface = 'Wi-Fi'  # Cambia esto a la interfaz de red adecuada
num_paquetes = 10

capturar_paquetes(interface, num_paquetes)

# Espera a que el usuario presione una tecla antes de cerrar
input("Presiona Enter para salir...")
