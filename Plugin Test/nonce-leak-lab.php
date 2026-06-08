<?php
/**
 * Plugin Name: Nonce Leak Lab (TFG)
 * Description: Plugin vulnerable por diseño para demostración y validación del NonceLeak Scanner en el marco de un Trabajo Fin de Grado (TFG). Expone nonces a través de 3 vectores (Frontend, REST API y Pasivo).
 * Version: 1.2.0
 * Author: Lab TFG NonceLeak
 * License: GPL2
 */

if (!defined('ABSPATH')) {
    exit; // Salir si se accede directamente.
}

/**
 * VECTOR 1: Fuga de Frontend (HTML DOM)
 * Genera un nonce y lo inyecta dentro del HTML público usando etiquetas <script>.
 */
function nll_inject_frontend_nonce()
{
    // Generar un nonce para una acción simulada
    $frontend_nonce = wp_create_nonce('frontend_lab_action');

    // Inyectar en el head del frontend como variable JavaScript
    echo "\n<!-- Nonce Leak Lab - Vector Frontend -->\n";
    echo "<script type='text/javascript'>\n";
    echo "var nll_frontend_config = {\n";
    echo "    'ajax_url': '" . esc_url(admin_url('admin-ajax.php')) . "',\n";
    echo "    'nonce': '" . esc_js($frontend_nonce) . "'\n";
    echo "};\n";
    echo "</script>\n";
}
add_action('wp_head', 'nll_inject_frontend_nonce');


/**
 * VECTOR 2: Fuga en la REST API (JSON)
 * Para que el escáner lo detecte al escanear la raíz /wp-json/, inyectamos
 * el nonce directamente en el índice principal de la API REST mediante un filtro.
 */
function nll_add_nonce_to_rest_index($response)
{
    if (is_a($response, 'WP_REST_Response')) {
        $data = $response->get_data();

        // Generar nonce asociado a la acción de la API
        $api_nonce = wp_create_nonce('api_lab_action');

        // Estructura anidada para validar la recursividad del parser JSON
        $data['nonce_lab_security'] = array(
            'auth_type' => 'none',
            'action_nonce' => $api_nonce,
        );

        $response->set_data($data);
    }
    return $response;
}
add_filter('rest_index', 'nll_add_nonce_to_rest_index');


/**
 * VECTOR 3: Fuga Pasiva - Módulo 1 (Parámetros GET expuestos en enlaces)
 * Genera un enlace en el pie de página que contiene un nonce como parámetro de consulta.
 * El escáner analizará los enlaces del DOM para detectar esta exposición pasiva.
 */
function nll_inject_passive_leak_footer()
{
    $passive_nonce = wp_create_nonce('passive_lab_action');

    // URL que contiene el nonce expuesto en los parámetros GET
    $leak_url = add_query_arg(
        array(
            'action' => 'nll_passive_test',
            '_wpnonce' => $passive_nonce
        ),
        home_url('/')
    );

    echo "\n<!-- Nonce Leak Lab - Vector Pasivo (GET Link) -->\n";
    echo "<div style='text-align: center; margin: 20px auto; padding: 15px; max-width: 800px; background-color: #fff; border: 2px solid #0073aa; border-radius: 4px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); font-family: sans-serif;'>\n";
    echo "  <h3 style='margin-top: 0; color: #0073aa;'>🧪 Nonce Leak Lab - Panel de Control de Pruebas DAST</h3>\n";
    echo "  <p style='font-size: 14px;'>Fugas activadas en esta página principal:</p>\n";
    echo "  <ul style='text-align: left; display: inline-block; font-size: 13px; line-height: 1.6;'>\n";
    echo "    <li><strong>Fuga 1 (Frontend):</strong> Inyectada en el bloque <code>&lt;script&gt;</code> del <code>&lt;head&gt;</code>.</li>\n";
    echo "    <li><strong>Fuga 2 (REST API JSON):</strong> Expuesta en el índice principal de <a href='" . esc_url(home_url('/wp-json/')) . "' target='_blank'><code>/wp-json/</code></a>.</li>\n";
    echo "    <li><strong>Fuga 3 (Pasiva - Parámetro GET):</strong> Inyectada en el enlace de abajo: <br/>";
    echo "        👉 <a href='" . esc_url($leak_url) . "' id='nll-passive-link'>Simular Acción (Enlace con Nonce)</a></li>\n";
    echo "    <li><strong>Fuga 4 (Pasiva - Cabecera Referer):</strong> Enviada automáticamente en las cabeceras HTTP de respuesta de esta página (compruébalo en la pestaña Red de la consola del navegador o con tu escáner).</li>\n";
    echo "  </ul>\n";
    echo "</div>\n";
}
add_action('wp_footer', 'nll_inject_passive_leak_footer');


/**
 * VECTOR 3: Fuga Pasiva - Módulo 2 (Cabecera Referer)
 * Inyecta una cabecera de respuesta "Referer" conteniendo una URL con un nonce
 * en todas las peticiones públicas del frontend.
 */
function nll_add_referer_header_response()
{
    if (!is_admin()) {
        $referer_nonce = wp_create_nonce('referer_lab_action');
        header("Referer: " . home_url('/?_wpnonce=' . $referer_nonce));
    }
}
add_action('send_headers', 'nll_add_referer_header_response');
