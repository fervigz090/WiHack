# WiHack - Programa para Auditoría de Redes

## Descripción

**WiHack** es un programa diseñado con fines educativos y de auditoría para redes inalámbricas. Su propósito es ayudar a los administradores de redes a identificar vulnerabilidades en sus sistemas Wi-Fi, mediante el análisis de conexiones y la implementación de pruebas controladas.

**IMPORTANTE:** Este programa **no debe** ser utilizado en redes ajenas ni para fines malintencionados. El uso del software en un entorno no autorizado es ilegal y puede acarrear graves consecuencias legales y éticas.

---

## Uso Ético y Legal

Este programa debe ser utilizado únicamente en los siguientes escenarios:

1. **Redes bajo tu control**:
   - Solo puedes auditar redes que poseas o para las que tengas autorización explícita del propietario.

2. **Fines educativos**:
   - Este programa puede ser usado en entornos académicos o de aprendizaje para comprender la seguridad en redes Wi-Fi.

3. **Pruebas en entornos controlados**:
   - Realiza pruebas únicamente en redes de laboratorio o simuladas, creadas específicamente para auditorías.

El uso de este software en redes ajenas sin permiso constituye un **delito** según las leyes de muchos países.

---

## Consecuencias del Uso Indebido

El uso no autorizado del programa puede tener las siguientes consecuencias:

1. **Legales**:
   - Enfrentar cargos por **acceso no autorizado**, **ataques de denegación de servicio** u otros delitos relacionados con la seguridad informática.

2. **Reputación**:
   - Dañar tu reputación personal y profesional.

3. **Responsabilidad ética**:
   - Causar daño a otras personas o instituciones y poner en riesgo su privacidad y seguridad.

---

## Instalación

1. Clona el repositorio:
   ```bash
   git clone https://github.com/tu-usuario/wihack.git
   cd wihack

2. Asegurate de tener las dependencias necesarias instaladas:
    ```bash
    sudo apt install Python3
    sudo apt install aircrack-ng
    sudo apt install airodump-ng
    sudo apt install airmon-ng

3. Activa el entorno .venv:
    ```bash
    source .venv/bin/activate

4. Ejecuta la ayuda del programa:
    ```bash
    sudo python wihack.py --help
