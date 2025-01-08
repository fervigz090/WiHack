"""
Autor: Ivan Fernandez Rodriguez
Fecha: 08/01/2025
Descripción: Gestiona el estado de la interfaz que se utiliza para las pruebas.

"""

import subprocess

class Mon_Manage:
    
    def __init__(self, interface):
        self.interface = interface
        
    def enable_monitor_mode(self, interface):
        """
        Activa el modo monitor en la interfaz especificada.
        
        :param interface: Nombre de la interfaz de red (e.g., wlan0).
        :return: Nombre de la interfaz en modo monitor (e.g., wlan0).
        """
        try:
            print(f"[+] Eliminando procesos conflictivos...")
            # Ejecuta airmon-ng check kill
            subprocess.run(["airmon-ng", "check", "kill"], check=True)
            
            print(f"[+] Activando modo monitor en la interfaz {interface}...")
            # Ejecuta airmon-ng start
            subprocess.run(["airmon-ng", "start", interface], check=True)
            
            # Normalmente, el sufifo "mon" se agrega al nombre de la interface.
            monitor_interface = self.check_monitor_interface(interface)
            print(f"[+] Modo monitor activado: {monitor_interface}")
            return monitor_interface
        except Exception as e:
            print(f"[-] Error al activar el modo monitor: {e}")
            return None
    
    def disable_monitor_mode(self, interface):
        """
        Desactiva el modo monitor en la interfaz especificada.
        
        :param interface: Nombre de la interfaz en modo monitor (e.g., wlan0mon).
        """
        try:
            print(f"[+] Desactivando modo monitor en la interface {interface}...")
            # Ejecuta airmon-ng stop (desactivando primero a interfaz)
            subprocess.run(["ifconfig", interface, "down"], check=True)
            subprocess.run(["airmon-ng", "stop", interface], check=True)
            print(f"[+] Modo monitor desactivado.")
        except Exception as e:
            print(f"[-] Error a desactivar el modo monitor: {e}")
    
    def list_interfaces(self):
        """Lista de las interfaces disponibles"""
        try:
            print(f"[+] Listando interfaces de red disponibles...")
            subprocess.run(["iwconfig"], check=True)
        except Exception as e:
            print(f"[-] Error al listar interfaces: {e}")
    
    def capture(self, interface, essid="-"):
        """Inicia la captura de paquetes con la interface en modo monitor"""
        try:
            if essid != "-":
                print(f"[+] Iniciando captura de paquetes con {interface} para el AP {essid}")
                subprocess.run(["airodump-ng", "--essid", essid, interface], check=True)
            else:
                print(f"[+] Iniciando captura de paquetes con {interface} para todos los AP disponibles")
                subprocess.run(["airodump-ng", interface], check=True)
        except Exception as e:
            print(f"[-] Error al inicial la captura con {interface}: {e}")
    
    def stop_capture(self):
        """Detiene la captura de paquetes"""
        try:
            if self.process:
                print(f"[+] Deteniendo la captura de paquetes...")
                self.process.terminate()  # Termina el proceso de captura
                self.process.wait()      # Espera a que el proceso finalice
                print(f"[+] Captura detenida.")
            else:
                print("[-] No hay ninguna captura en curso.")
        except Exception as e:
            print(f"[-] Error al detener la captura: {e}")
    
    def check_monitor_interface(self, interface):
        """
        Comprueba si el nombre de la interfaz ha cambiado después de activar el modo monitor.
        Si el nombre no contiene el sufijo 'mon', lo ajusta automáticamente.

        :param interface: Nombre original de la interfaz.
        :return: Nombre correcto de la interfaz en modo monitor.
        """
        try:
            # Ejecutar el comando `iw dev` para listar las interfaces
            result = subprocess.run(["iw", "dev"], stdout=subprocess.PIPE, text=True, check=True)
            output = result.stdout

            # Buscar todas las interfaces en modo monitor
            if f"Interface {interface}" in output and "monitor" in output:
                # Si la interfaz original ya está en modo monitor, retornar el mismo nombre
                print(f"[+] La interfaz {interface} está en modo monitor.")
                return interface
            elif f"Interface {interface}mon" in output and "monitor" in output:
                # Si existe la interfaz con el sufijo 'mon', retornar ese nombre
                print(f"[+] Cambiando a la interfaz {interface}mon.")
                return f"{interface}mon"
            else:
                print(f"[-] No se pudo detectar la interfaz en modo monitor para {interface}.")
                return None
        except Exception as e:
            print(f"[-] Error verificando la interfaz en modo monitor: {e}")
            return None
                
            