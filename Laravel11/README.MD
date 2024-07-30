# PseudoWAF para Laravel 11

## Descripción

Este módulo middleware, denominado PseudoWAFMiddleware, está diseñado para actuar como un Firewall de Aplicaciones Web (WAF) dentro de una aplicación Laravel 11. Su objetivo principal es la autoprotección de la aplicación ante las ciberamenazas comunes que figuran en el OWASP Top 10 mediante la detección y bloqueo automático de actividades maliciosas. 

## Características del Middleware

1. **Inyección SQL (SQL Injection)**   
   - **Descripción**: El middleware escanea los inputs de las solicitudes en busca de patrones comunes de inyección SQL. 
   - **Detección**: Patrón de detección basado en expresiones regulares que identifican comandos SQL maliciosos.
   - **Ejemplo**: Detecta entradas como `' OR 1=1 --`.

2. **Cross-Site Scripting (XSS)**   
   - **Descripción**: Verifica los inputs para identificar intentos de inyección de scripts maliciosos.
   - **Detección**: Uso de patrones que identifican etiquetas `<script>` y otros vectores XSS.
   - **Ejemplo**: Detecta entradas como `<script>alert('XSS');</script>`.

3. **Control de Acceso Roto (Broken Access Control)**   
   - **Descripción**: Verifica que los usuarios tengan los permisos adecuados para acceder a ciertos recursos.
   - **Detección**: Basado en una lista de control de acceso predefinida que mapea roles a recursos.
   - **Ejemplo**: Un usuario con rol `user` intentando acceder a un recurso de `admin`.

4. **Fallas Criptográficas (Cryptographic Failures)**   
   - **Descripción**: Asegura que los datos sensibles se transmitan de manera segura.
   - **Detección**: Verifica la presencia de HTTPS en las solicitudes que contienen datos sensibles.
   - **Ejemplo**: Transmisión de contraseñas sin cifrado.

5. **Errores de Configuración de Seguridad (Security Misconfiguration)**   
   - **Descripción**: Identifica configuraciones inseguras en el servidor.
   - **Detección**: Comprueba configuraciones como la visualización de errores y el registro de errores.
   - **Ejemplo**: `display_errors` habilitado en un entorno de producción.

6. **Componentes Vulnerables y Desactualizados (Vulnerable and Outdated Components)**   
   - **Descripción**: Verifica la versión de componentes del sistema contra una lista de versiones vulnerables conocidas.
   - **Detección**: Comparación de versiones usando `version_compare`.
   - **Ejemplo**: Uso de PHP 7.4 en lugar de una versión más segura y actualizada.

7. **Fallas de Autenticación y Gestión de Sesiones (Identification and Authentication Failures)**   
   - **Descripción**: Verifica la correcta gestión de autenticación y sesiones.
   - **Detección**: Comprobación de variables de sesión como `user` y `csrf_token`.
   - **Ejemplo**: Sesiones sin token CSRF válido.

8. **Fallas de Integridad de Software y Datos (Software and Data Integrity Failures)**   
   - **Descripción**: Asegura la integridad del software y los datos.
   - **Detección**: Mecanismos adicionales que podrían incluir verificaciones de integridad de archivos (no implementados en detalle).
   - **Ejemplo**: No se especifica un caso concreto, pero podría incluir la verificación de sumas de comprobación.

9. **Falta de Registro y Monitoreo de Seguridad (Insufficient Logging and Monitoring)**   
   - **Descripción**: Garantiza que los eventos de seguridad se registren adecuadamente.
   - **Detección**: Verificación de la existencia de un archivo de log.
   - **Ejemplo**: Archivo de log no encontrado en la ubicación especificada.

10. **Server-Side Request Forgery (SSRF)**    
    - **Descripción**: Protege contra solicitudes del lado del servidor a destinos no confiables.
    - **Detección**: Comparación de URLs solicitadas contra una lista de direcciones IP y dominios no confiables.
    - **Ejemplo**: Solicitudes a `localhost` o `127.0.0.1`.

## Implementación en un proyecto

A continuación, se describe el howto o cómo se debe implementar este módulo en un proyecto Laravel 11.un ejemplo de cómo implementar este middleware en una aplicación Laravel 11.

### Paso 1. **Incluir el módulo en la estructura de ficheros**

Guardar el fichero `PseudoWAFMiddleware.php` dentro del directorio `app/Http/Middleware`.

### Paso 2. **Registrar el Middleware en `Kernel.php`**

Abre el archivo `app/Http/Kernel.php` y agrega el middleware al array `$routeMiddleware`:

```php
protected $routeMiddleware = [
   // Otros middlewares
   'pseudo.waf' => \App\Http\Middleware\PseudoWAFMiddleware::class,
];
```

### Paso 3. **Aplicar el Middleware a Rutas**

Abre el archivo `routes/web.php` y aplica el middleware a las rutas que quieres proteger:

```php
use App\Http\Middleware\PseudoWAFMiddleware;

Route::middleware(['pseudo.waf'])->group(function () {
   Route::get('/dashboard', function () {
       // Lógica de la ruta
   });

   Route::post('/submit', function () {
       // Lógica de la ruta
   });
});
```

### Paso 4. **Configuración de Parámetros**

Asegúrate de que el constructor del middleware configure los parámetros necesarios, como la duración del baneo, la ruta al comando `iptables` y el archivo de log:

```php
public function __construct()
{
   $this->banDuration = 86400; // 24 horas
   $this->iptablesCommand = '/sbin/iptables';
   $this->logFile = storage_path('logs/malicious_ips.log');
}
```

### Paso 5. **Conceder permisos de ejecución de IPTables**

Para este paso, deberemos ejecutar, con un usuario con privilegios sudo, el comando `sudo visudo` y añadir la siguiente línea:

```sh
www-data ALL=NOPASSWD: /sbin/iptables
```

## Contribuciones

Las contribuciones son bienvenidas. Si deseas contribuir al proyecto, por favor sigue estos pasos:

1. Haz un fork del repositorio.
2. Crea una nueva rama para tu funcionalidad (`git checkout -b feature/nueva-funcionalidad`).
3. Haz tus cambios y realiza los commits (`git commit -am 'Agrega una nueva funcionalidad'`).
4. Haz push a la rama (`git push origin feature/nueva-funcionalidad`).
5. Crea un pull request.

## Autor

Mi nombre es **Aythami Melián**, Ingeniero de Software Online especialista en PHP, seguridad web y hardenización de aplicaciones PHP.
Como desarrollador apasionado y altamente capacitado en PHP, he creado soluciones innovadoras y seguras que cumplen con los más altos estándares de la industria. Con una sólida experiencia en ciberseguridad y protección de datos, he implementado tecnologías de vanguardia y he sido parte integral de numerosos proyectos exitosos. Mi habilidad para traducir requisitos complejos en soluciones técnicas efectivas ha contribuido al crecimiento y éxito de cada empresa con la que he colaborado. Soy un firme creyente en el poder del trabajo en equipo y la innovación colaborativa, y me comprometo a impulsar la excelencia en cada proyecto. Por ello, he fundado la marca comercial **CodeSecure Forge**, donde colaboro con terceros como socio estratégico dentro del área de Desarrollo y de Ciberseguridad.

**HABILIDADES:**

- **Desarrollo en PHP**: Creación de aplicaciones seguras y eficientes utilizando las mejores prácticas de desarrollo.
- **Ciberseguridad**: Implementación de estrategias avanzadas para la protección de datos y la integridad del sistema.
- **Cumplimiento de normativas de protección de datos**: Prioridad en la privacidad y seguridad.
- **Metodologías DevSecOps y Clean Code**: Integración de prácticas de seguridad en el ciclo de desarrollo de software.
- **Colaboración y Gestión de Proyectos**: Trabajo en equipos de alto rendimiento y liderazgo en iniciativas tecnológicas.

Formas de Contacto:

- **Email**:   
  - Trabajo: [amelian|at|codesecureforge.com](mailto://amelian@codesecureforge.com)
  - Personal: [ajmelper|at|gmail.com](mailto://ajmelper@gmail.com)
- **Telegram**: [@ajmelian](https://t.me/ajmelian)
- **LinkedIn**: [@aythami-melian](https://www.linkedin.com/in/aythami-melian/)

## Licencia

Este proyecto está licenciado bajo la GPL 3.0, por tanto se permite las siguientes acciones:
- Uso libre del software.
- Distribución del software.
- Modificación del software.
- Distribución de versiones modificadas.

No se permite:

- Distribuir software derivado sin el código fuente.
- Usar medidas tecnológicas de protección que restrinjan la libertad de los usuarios.
- Infringir los términos de la licencia.
