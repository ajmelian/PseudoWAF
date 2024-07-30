<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

/**
 * Class PseudoWAFMiddleware
 * 
 * Middleware que implementa un filtro básico de seguridad para detectar actividades maliciosas
 * y bloquear IPs automáticamente usando iptables. Edición para Framework Laravel 11
 * 
 * @category   Security
 * @package    App\Http\Middleware
 * @version    1.0.0
 * @date       Julio 2024
 * @license    GPL 3.0
 * @link       https://www.codesecureforge.com/
 * 
 * @author     AJ Melian
 * @contact    amelian@codesecureforge.com
 */
class PseudoWAFMiddleware
{
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
     * PseudoWAFMiddleware constructor.
     *
     * Inicializa la clase con la duración del baneo, la ruta al comando iptables y el archivo de log.
     *
     * @access public
     * @param int $banDuration Duración del baneo en segundos.
     * @param string $iptablesCommand Ruta al comando iptables.
     * @param string $logFile Archivo de log para IPs maliciosas.
     */
    public function __construct(int $banDuration, string $iptablesCommand, string $logFile)
    {
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
    private function isSqlInjection(string $input): bool
    {
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
    private function isXss(string $input): bool
    {
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
    private function isBrokenAccessControl(string $resource, string $role): bool
    {
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
    private function isCryptographicFailure(string $input): bool
    {
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
    private function isSecurityMisconfiguration(): bool
    {
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
    private function isUsingVulnerableComponents(): bool
    {
        $components = [
            'php' => PHP_VERSION,
            'mysql' => '8.0.21'
        ];

        $vulnerableComponents = [
            'php' => '7.4.0',
            'mysql' => '5.7.0'
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
    private function isAuthenticationFailure(): bool
    {
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
    private function isDataIntegrityFailure(): bool
    {
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
    private function isLoggingFailure(): bool
    {
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
    private function isServerSideRequestForgery(string $url): bool
    {
        $blacklist = [
            'localhost',
            '127.0.0.1',
            '::1'
        ];

        foreach ($blacklist as $block) {
            if (strpos($url, $block) !== false) {
                return true;
            }
        }
        return false;
    }

    /**
     * Maneja la solicitud entrante.
     *
     * @param \Illuminate\Http\Request $request La solicitud HTTP.
     * @param \Closure $next La función a ejecutar después de procesar el middleware.
     * @return \Symfony\Component\HttpFoundation\Response La respuesta HTTP.
     */
    public function handle(Request $request, Closure $next): Response
    {
        $ip = $request->ip();
        $url = $request->url();
        $input = $request->all();

        foreach ($input as $key => $value) {
            if ($this->isSqlInjection($value) || $this->isXss($value) || $this->isCryptographicFailure($value)) {
                file_put_contents($this->logFile, "Malicious input detected from IP $ip\n", FILE_APPEND);
                shell_exec("$this->iptablesCommand -A INPUT -s $ip -j DROP");
                return response()->json(['error' => 'Access denied'], 403);
            }
        }

        if ($this->isBrokenAccessControl($url, 'user') || $this->isUsingVulnerableComponents() || $this->isAuthenticationFailure() || $this->isDataIntegrityFailure() || $this->isLoggingFailure() || $this->isServerSideRequestForgery($url)) {
            file_put_contents($this->logFile, "Security issue detected from IP $ip\n", FILE_APPEND);
            hell_exec("$this->iptablesCommand -A INPUT -s $ip -j DROP");
            return response()->json(['error' => 'Access denied'], 403);
        }

        return $next($request);
    }
}
