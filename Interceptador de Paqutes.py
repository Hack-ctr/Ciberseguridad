from scapy.all import sniff

# Cargar las asignaciones IP-nombre desde el archivo
def cargar_dns(archivo_dns):
    dns = {}
    try:
        with open(archivo_dns, 'r') as f:
            for linea in f:
                if linea.startswith('ip_'):
                    partes = linea.strip().split('_')
                    if len(partes) == 3:
                        _, ip, nombre = partes
                        dns[ip] = nombre
    except FileNotFoundError:
        print(f"Error: El archivo '{archivo_dns}' no se encuentra.")
    except Exception as e:
        print(f"Se produjo un error al leer el archivo DNS: {e}")
    return dns

def procesar_paquete(paquete, dns):
    if paquete.haslayer('IP'):
        ip_src = paquete['IP'].src
        ip_dst = paquete['IP'].dst
        protocolo = paquete['IP'].proto

        nombre_src = dns.get(ip_src, ip_src)
        nombre_dst = dns.get(ip_dst, ip_dst)

        print(f"Paquete IP: {nombre_src} ({ip_src}) -> {nombre_dst} ({ip_dst}), Protocolo: {protocolo}")
    elif paquete.haslayer('ARP'):
        print(f"Paquete ARP: {paquete.summary()}")

def capturar_paquetes(interface='Wi-Fi', num_paquetes=10):
    print(f"Capturando {num_paquetes} paquetes en la interfaz {interface}...")
    dns = cargar_dns('dns.txt')  # Cargar asignaciones IP-nombre
    sniff(iface=interface, prn=lambda p: procesar_paquete(p, dns), count=num_paquetes)

# Ajusta la interfaz y el número de paquetes según tu entorno
interface = 'Wi-Fi'  # Cambia esto a la interfaz de red adecuada
num_paquetes = 10

capturar_paquetes(interface, num_paquetes)

# Espera a que el usuario presione una tecla antes de cerrar
input("Presiona Enter para salir...")
