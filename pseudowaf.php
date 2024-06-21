<?php

/**
 * Class PseudoWAF
 * 
 * Esta clase implementa un filtro básico de solicitudes HTTP para detectar actividades maliciosas
 * basadas en reglas OWASP y bloquea automáticamente las IPs maliciosas usando iptables durante 24 horas.
 * 
 * @category   Security
 * @package    WebApplicationFirewall
 * @version    1.0.0
 * @date       Junio 2024
 * @license    GPL 3.0
 * @link       https://www.codesecureforge.com/
 * 
 * @author     AJ Melian
 * @contact    amelian@codesecureforge.com
 */
class PseudoWAF {

    /**
     * @var int Duración del baneo en segundos (24 horas).
     */
    private int $banDuration;

    /**
     * @var string Ruta al comando iptables.
     */
    private string $iptablesCommand;

    /**
     * @var string Archivo de log para IPs maliciosas.
     */
    private string $logFile;

    /**
     * PseudoWAF constructor.
     *
     * Inicializa la clase con la duración del baneo, la ruta al comando iptables y el archivo de log.
     *
     * @access public
     * @param int $banDuration Duración del baneo en segundos.
     * @param string $iptablesCommand Ruta al comando iptables.
     * @param string $logFile Archivo de log para IPs maliciosas.
     */
    public function __construct(int $banDuration, string $iptablesCommand, string $logFile) {
        $this->banDuration = $banDuration;
        $this->iptablesCommand = $iptablesCommand;
        $this->logFile = $logFile;
    }

    /**
     * Función para detectar inyecciones SQL (A03:2021 - Injection).
     *
     * Verifica si el input contiene patrones comunes de inyección SQL.
     *
     * @access private
     * @param string $input El input a verificar.
     * @return bool Retorna true si se detecta una inyección SQL, false en caso contrario.
     */
    private function isSqlInjection(string $input): bool {
        // A03:2021 - Injection - Detecta inyecciones SQL
        $patterns = [
            '/select.*from/i',
            '/union.*select/i',
            '/insert.*into/i',
            '/update.*set/i',
            '/delete.*from/i',
            '/drop.*table/i',
            '/;.*--/i'
        ];
        foreach ($patterns as $pattern) {
            if (preg_match($pattern, $input)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Función para detectar XSS (A07:2021 - Cross-Site Scripting (XSS)).
     *
     * Verifica si el input contiene patrones comunes de XSS.
     *
     * @access private
     * @param string $input El input a verificar.
     * @return bool Retorna true si se detecta un intento de XSS, false en caso contrario.
     */
    private function isXss(string $input): bool {
        // A07:2021 - XSS - Detecta intentos de Cross-Site Scripting
        $patterns = [
            '/<script.*?>.*<\/script>/i',
            '/javascript:/i',
            '/on\w+=["\'].*?["\']/i',
            '/<.*?on\w+=.*?>/i'
        ];
        foreach ($patterns as $pattern) {
            if (preg_match($pattern, $input)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Función para detectar Control de Acceso Roto (A01:2021 - Broken Access Control).
     *
     * Verifica si se están intentando acceder a recursos sin autorización.
     *
     * @access private
     * @param string $resource El recurso al que se intenta acceder.
     * @param string $role El rol del usuario que intenta acceder.
     * @return bool Retorna true si se detecta un acceso no autorizado, false en caso contrario.
     */
    private function isBrokenAccessControl(string $resource, string $role): bool {
        // A01:2021 - Broken Access Control - Detecta intentos de acceso no autorizado a recursos
        // Implementación simplificada para demostración
        $accessControlList = [
            'admin' => ['admin_panel', 'user_data', 'config'],
            'user' => ['user_data'],
            'guest' => ['public_content']
        ];

        if (!isset($accessControlList[$role]) || !in_array($resource, $accessControlList[$role])) {
            return true;
        }

        return false;
    }

    /**
     * Función para detectar fallas criptográficas (A02:2021 - Cryptographic Failures).
     *
     * Verifica si los datos sensibles están siendo transmitidos sin cifrado.
     *
     * @access private
     * @param string $input El input a verificar.
     * @return bool Retorna true si se detecta una falla criptográfica, false en caso contrario.
     */
    private function isCryptographicFailure(string $input): bool {
        // A02:2021 - Cryptographic Failures - Detecta fallas criptográficas
        // Simplificado; debería incluir más validaciones en un entorno real
        if (preg_match('/password|creditcard|ssn/', $input) && empty($_SERVER['HTTPS'])) {
            return true;
        }
        return false;
    }

    /**
     * Función para detectar errores de configuración de seguridad (A05:2021 - Security Misconfiguration).
     *
     * Verifica si hay configuraciones inseguras en el servidor.
     *
     * @access private
     * @return bool Retorna true si se detecta una configuración insegura, false en caso contrario.
     */
    private function isSecurityMisconfiguration(): bool {
        // A05:2021 - Security Misconfiguration - Detecta configuraciones inseguras
        // Simplificado; debería incluir más validaciones en un entorno real
        if (ini_get('display_errors') || !ini_get('log_errors')) {
            return true;
        }
        return false;
    }

    /**
     * Función para detectar componentes vulnerables y desactualizados (A06:2021 - Vulnerable and Outdated Components).
     *
     * Verifica si hay componentes con vulnerabilidades conocidas.
     *
     * @access private
     * @return bool Retorna true si se detectan componentes vulnerables, false en caso contrario.
     */
    private function isUsingVulnerableComponents(): bool {
        // A06:2021 - Vulnerable and Outdated Components - Detecta componentes vulnerables
        // Simplificado; debería incluir comparaciones con bases de datos de vulnerabilidades en un entorno real
        $components = [
            'php' => PHP_VERSION,
            'mysql' => '8.0.21' // Ejemplo; debería obtenerse dinámicamente
        ];

        $vulnerableComponents = [
            'php' => '7.4.0', // Ejemplo de versión vulnerable
            'mysql' => '5.7.0' // Ejemplo de versión vulnerable
        ];

        foreach ($components as $component => $version) {
            if (version_compare($version, $vulnerableComponents[$component], '<=')) {
                return true;
            }
        }

        return false;
    }

    /**
     * Función para detectar fallos de autenticación y gestión de sesiones (A07:2021 - Identification and Authentication Failures).
     *
     * Verifica si las sesiones y la autenticación son gestionadas de manera insegura.
     *
     * @access private
     * @return bool Retorna true si se detectan fallos, false en caso contrario.
     */
    private function isAuthenticationFailure(): bool {
        // A07:2021 - Identification and Authentication Failures - Detecta fallos de autenticación
        // Simplificado; debería incluir más validaciones en un entorno real
        if (empty($_SESSION['user']) || empty($_SESSION['csrf_token'])) {
            return true;
        }
        return false;
    }

    /**
     * Función para detectar fallos de integridad de software y datos (A08:2021 - Software and Data Integrity Failures).
     *
     * Verifica la integridad de software y datos.
     *
     * @access private
     * @return bool Retorna true si se detectan fallos, false en caso contrario.
     */
    private function isDataIntegrityFailure(): bool {
        // A08:2021 - Software and Data Integrity Failures - Detecta fallos de integridad de datos
        // Simplificado; debería implementarse hash y verificación de firmas en un entorno real
        return false;
    }

    /**
     * Función para detectar la falta de registro y monitoreo de seguridad (A10:2021 - Insufficient Logging and Monitoring).
     *
     * Verifica si hay fallos en el registro y monitoreo de eventos de seguridad.
     *
     * @access private
     * @return bool Retorna true si se detectan fallos, false en caso contrario.
     */
    private function isLoggingFailure(): bool {
        // A10:2021 - Insufficient Logging and Monitoring - Detecta fallos en el registro de eventos de seguridad
        // Simplificado; debería verificar la existencia y configuración adecuada de registros en un entorno real
        return !file_exists($this->logFile);
    }

    /**
     * Función para detectar Server-Side Request Forgery (SSRF) (A08:2021 - Server-Side Request Forgery (SSRF)).
     *
     * Verifica si se están realizando solicitudes del lado del servidor a destinos no confiables.
     *
     * @access private
     * @param string $url La URL a verificar.
     * @return bool Retorna true si se detecta un SSRF, false en caso contrario.
     */
    private function isSSRF(string $url): bool {
        // A08:2021 - Server-Side Request Forgery (SSRF) - Detecta intentos de SSRF
        // Simplificado; debería validar y sanitizar todas las entradas de URL en un entorno real
        $parsedUrl = parse_url($url);
        if (!in_array($parsedUrl['host'], ['trustedhost.com', 'anothertrustedhost.com'])) {
            return true;
        }
        return false;
    }

    /**
     * Función para bloquear una IP usando iptables.
     *
     * Ejecuta comandos iptables para bloquear la IP y programa su desbloqueo.
     *
     * @access private
     * @param string $ip La IP a bloquear.
     * @return void
     */
    private function blockIP(string $ip): void {
        $banCommand = sprintf('%s -A INPUT -s %s -j DROP', $this->iptablesCommand, escapeshellarg($ip));
        $unbanCommand = sprintf("echo '%s -D INPUT -s %s -j DROP' | at now + %d seconds", 
            $this->iptablesCommand, escapeshellarg($ip), $this->banDuration);

        // Ejecutar comandos
        exec($banCommand);
        exec($unbanCommand);

        // Registrar IP baneada
        file_put_contents($this->logFile, sprintf("%s %s Banned for %d seconds\n", 
            $ip, date('Y-m-d H:i:s'), $this->banDuration), FILE_APPEND);
    }

    /**
     * Función para verificar y bloquear IPs maliciosas.
     *
     * Verifica los datos de entrada y bloquea la IP si se detecta actividad maliciosa.
     *
     * @access private
     * @param array $data Array de datos a verificar (GET, POST o cabeceras).
     * @return void
     */
    private function checkAndBlock(array $data): void {
        foreach ($data as $key => $value) {
            if (!is_string($value)) {
                continue; // Si el valor no es una cadena, omitir
            }
            if ($this->isSqlInjection($value) || $this->isXss($value) || $this->isCryptographicFailure($value)) {
                $this->blockIP($_SERVER['REMOTE_ADDR']);
                exit('Malicious activity detected. Your IP has been banned.');
            }
        }
    }

    /**
     * Función principal para inspeccionar la solicitud HTTP.
     *
     * Inspecciona la solicitud HTTP completa (GET, POST y cabeceras) y bloquea IPs maliciosas si es necesario.
     *
     * @access public
     * @return void
     */
    public function inspectRequest(): void {
        // Verificar parámetros GET
        $this->checkAndBlock($_GET);

        // Verificar parámetros POST
        $this->checkAndBlock($_POST);

        // Verificar cabeceras HTTP
        $headers = getallheaders();
        $this->checkAndBlock($headers);

        // Verificar control de acceso roto
        if ($this->isBrokenAccessControl('admin_panel', 'guest')) {
            $this->blockIP($_SERVER['REMOTE_ADDR']);
            exit('Unauthorized access detected. Your IP has been banned.');
        }

        // Verificar fallos de autenticación
        if ($this->isAuthenticationFailure()) {
            $this->blockIP($_SERVER['REMOTE_ADDR']);
            exit('Authentication failure detected. Your IP has been banned.');
        }

        // Verificar fallos de configuración de seguridad
        if ($this->isSecurityMisconfiguration()) {
            $this->blockIP($_SERVER['REMOTE_ADDR']);
            exit('Security misconfiguration detected. Your IP has been banned.');
        }

        // Verificar componentes vulnerables
        if ($this->isUsingVulnerableComponents()) {
            $this->blockIP($_SERVER['REMOTE_ADDR']);
            exit('Using vulnerable components detected. Your IP has been banned.');
        }

        // Verificar fallos de integridad de datos
        if ($this->isDataIntegrityFailure()) {
            $this->blockIP($_SERVER['REMOTE_ADDR']);
            exit('Data integrity failure detected. Your IP has been banned.');
        }

        // Verificar fallos de registro y monitoreo
        if ($this->isLoggingFailure()) {
            $this->blockIP($_SERVER['REMOTE_ADDR']);
            exit('Logging failure detected. Your IP has been banned.');
        }

        // Verificar SSRF
        if (isset($_GET['url']) && $this->isSSRF($_GET['url'])) {
            $this->blockIP($_SERVER['REMOTE_ADDR']);
            exit('SSRF detected. Your IP has been banned.');
        }

        echo "Request is clean.";
    }
}

// Configuración del WAF
$waf = new PseudoWAF(
    86400, // Duración del baneo en segundos (24 horas)
    '/sbin/iptables', // Ruta al comando iptables
    '/var/log/php_malicious_ips.log' // Archivo de log para IPs maliciosas
);

// Inspeccionar la solicitud HTTP
$waf->inspectRequest();

?>
