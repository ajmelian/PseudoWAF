# PseudoWAF - Web Application Firewall (Filtro de Aplicaciones Web Pseudo)

PseudoWAF es una implementación básica de un Web Application Firewall (WAF) en PHP, diseñado para detectar y bloquear actividades maliciosas basadas en las reglas OWASP Top 10 más recientes. Este script permite filtrar peticiones HTTP en busca de vulnerabilidades comunes y banea automáticamente las IPs maliciosas usando iptables durante 24 horas.

## Autor
- **Nombre:** AJ Melian
- **Correo Electrónico:** amelian@codesecureforge.com
- **Fecha:** Junio 2024
- **Versión:** 1.0.0

## Instalación y Configuración

### Requisitos Previos

- PHP 7.0 o superior
- Acceso al comando `iptables` en Linux
- Permisos de administrador (`sudo` o equivalente) para configurar `iptables`

### Pasos de Configuración

1. **Descarga del código:** Clona este repositorio o descarga el archivo PHP `PseudoWAF.php`.

2. **Configuración inicial:** Editar los parámetros de configuración en el archivo PHP `PseudoWAF.php` según tus necesidades:
   - `banDuration`: Duración del baneo en segundos (por ejemplo, 86400 para 24 horas).
   - `iptablesCommand`: Ruta al comando iptables (`/sbin/iptables` por defecto).
   - `logFile`: Ruta al archivo de registro para IPs maliciosas (por ejemplo, `/var/log/php_malicious_ips.log`).
3. **Configuración del Servidor:** Asegúrate de que el script PHP tenga permisos de ejecución para iptables. Puedes necesitar dar permisos de sudo sin contraseña para el comando iptables al usuario bajo el cual corre el servidor web (por ejemplo, www-data en Apache). Edita el archivo de sudoers usando visudo y añade la siguiente línea: `www-data ALL=(ALL) NOPASSWD: /sbin/iptables`

### Configuración de iptables

Asegúrate de que el comando `iptables` esté habilitado y configurado correctamente para ejecutarse. Puedes verificar su estado y configurarlo usando los siguientes comandos en un terminal:

```bash
# Verificar si iptables está instalado y accesible
iptables --version

# Configurar iptables para permitir el bloqueo de IPs
sudo iptables -A INPUT -s IP_A_BLOQUEAR -j DROP
```

Reemplaza `IP_A_BLOQUEAR` con la IP específica que deseas bloquear. Asegúrate de que la configuración de `iptables` persista a través de reinicios del sistema si es necesario.

### Ejemplo de Uso

```php
<?php
require_once 'PseudoWAF.php';

// Configuración del WAF
$waf = new PseudoWAF(
    86400,                      // Duración del baneo en segundos (24 horas)
    '/sbin/iptables',           // Ruta al comando iptables
    '/var/log/php_malicious_ips.log'  // Archivo de log para IPs maliciosas
);

// Inspeccionar la solicitud HTTP actual
$waf->inspectRequest();
?>
```

### Métodos Disponibles

- `__construct(int $banDuration, string $iptablesCommand, string $logFile)`: Constructor para inicializar el WAF con configuraciones personalizadas.
  
- `inspectRequest()`: Método principal que inspecciona la solicitud HTTP actual, verifica parámetros GET y POST, cabeceras HTTP y otras vulnerabilidades críticas.

### Vulnerabilidades OWASP Top 10 Detectadas

- **A01:2021 - Broken Access Control**: Control de acceso roto detectado durante la verificación de recursos.
- **A02:2021 - Cryptographic Failures**: Fallas criptográficas detectadas en la transmisión de datos sensibles.
- **A03:2021 - Injection**: Inyecciones SQL detectadas en los parámetros GET y POST.
- **A05:2021 - Security Misconfiguration**: Configuraciones de seguridad inseguras detectadas en la aplicación.
- **A06:2021 - Vulnerable and Outdated Components**: Componentes vulnerables detectados, como versiones desactualizadas de PHP y MySQL.
- **A07:2021 - Identification and Authentication Failures**: Fallos de autenticación detectados durante la verificación de sesiones.
- **A08:2021 - Server-Side Request Forgery (SSRF)**: Intentos de SSRF detectados en las URLs proporcionadas.
- **A10:2021 - Insufficient Logging and Monitoring**: Fallos en el registro y monitoreo de eventos de seguridad detectados.

### Notas

Este es un script de seguridad básico y debe adaptarse y ampliarse según los requisitos específicos de seguridad de tu aplicación y el entorno de ejecución. Asegúrate de seguir las mejores prácticas de seguridad, incluyendo la configuración adecuada de iptables y la gestión de logs, para garantizar la protección efectiva contra vulnerabilidades web.
