<?php
/**
 * Plugin Name: Paisabot Auth
 * Description: Verifies Supabase JWT from pb_session cookie; gates premium content.
 * Version:     1.0.0
 * Author:      Paisabot
 */

defined('ABSPATH') || exit;

define('PB_AUTH_SUPABASE_URL', 'https://kmctuwnhgqgldbkdbwhs.supabase.co');
define('PB_AUTH_JWKS_URL',     PB_AUTH_SUPABASE_URL . '/auth/v1/.well-known/jwks.json');
define('PB_AUTH_COOKIE_NAME',  'sb-kmctuwnhgqgldbkdbwhs-auth-token');  // Supabase SSR cookie name
define('PB_AUTH_CACHE_KEY',    'pb_jwks_cache');
define('PB_AUTH_CACHE_TTL',    3600); // 1 hour

// ── JWKS fetching ─────────────────────────────────────────────────────────────

function pb_auth_get_jwks(): array {
    $cached = get_transient(PB_AUTH_CACHE_KEY);
    if ($cached) return $cached;

    $response = wp_remote_get(PB_AUTH_JWKS_URL, ['timeout' => 5]);
    if (is_wp_error($response)) return [];

    $body = json_decode(wp_remote_retrieve_body($response), true);
    $keys = $body['keys'] ?? [];

    set_transient(PB_AUTH_CACHE_KEY, $keys, PB_AUTH_CACHE_TTL);
    return $keys;
}

// ── JWT verification ──────────────────────────────────────────────────────────

function pb_auth_verify_jwt(string $token): ?array {
    $parts = explode('.', $token);
    if (count($parts) !== 3) return null;

    [$header_b64, $payload_b64, $sig_b64] = $parts;

    $header  = json_decode(base64_decode(strtr($header_b64, '-_', '+/')), true);
    $payload = json_decode(base64_decode(strtr($payload_b64, '-_', '+/')), true);

    if (!$header || !$payload) return null;

    // Check expiry
    if (isset($payload['exp']) && $payload['exp'] < time()) return null;

    // Signature verification via openssl (RS256)
    $kid  = $header['kid'] ?? null;
    $jwks = pb_auth_get_jwks();

    $jwk = null;
    foreach ($jwks as $key) {
        if (!$kid || ($key['kid'] ?? null) === $kid) {
            $jwk = $key;
            break;
        }
    }

    if (!$jwk) return null;

    $public_key = pb_auth_jwk_to_pem($jwk);
    if (!$public_key) return null;

    $signing_input = $header_b64 . '.' . $payload_b64;
    $signature     = base64_decode(strtr($sig_b64, '-_', '+/'));
    $alg           = $header['alg'] ?? 'RS256';

    $algo_map = ['RS256' => OPENSSL_ALGO_SHA256, 'RS384' => OPENSSL_ALGO_SHA384, 'RS512' => OPENSSL_ALGO_SHA512];
    $algo = $algo_map[$alg] ?? OPENSSL_ALGO_SHA256;

    $valid = openssl_verify($signing_input, $signature, $public_key, $algo);
    return ($valid === 1) ? $payload : null;
}

function pb_auth_jwk_to_pem(array $jwk): ?string {
    if (($jwk['kty'] ?? '') !== 'RSA') return null;

    $modulus  = base64_decode(strtr($jwk['n'], '-_', '+/'));
    $exponent = base64_decode(strtr($jwk['e'], '-_', '+/'));

    // Build DER-encoded RSA public key
    $modulus_len  = strlen($modulus);
    $exponent_len = strlen($exponent);

    // Prepend 0x00 if high bit set (to avoid negative number in ASN.1)
    if (ord($modulus[0]) > 0x7f)  $modulus  = "\x00" . $modulus;
    if (ord($exponent[0]) > 0x7f) $exponent = "\x00" . $exponent;

    $modulus_der  = "\x02" . pb_auth_der_length(strlen($modulus)) . $modulus;
    $exponent_der = "\x02" . pb_auth_der_length(strlen($exponent)) . $exponent;

    $sequence = "\x30" . pb_auth_der_length(strlen($modulus_der) + strlen($exponent_der)) . $modulus_der . $exponent_der;

    // RSA OID: 1.2.840.113549.1.1.1
    $oid     = "\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01\x05\x00";
    $bit_str = "\x03" . pb_auth_der_length(strlen($sequence) + 1) . "\x00" . $sequence;
    $der     = "\x30" . pb_auth_der_length(strlen($oid) + strlen($bit_str)) . $oid . $bit_str;

    return "-----BEGIN PUBLIC KEY-----\n" . chunk_split(base64_encode($der), 64, "\n") . "-----END PUBLIC KEY-----\n";
}

function pb_auth_der_length(int $len): string {
    if ($len < 128) return chr($len);
    $bytes = '';
    $tmp = $len;
    while ($tmp > 0) { $bytes = chr($tmp & 0xff) . $bytes; $tmp >>= 8; }
    return chr(0x80 | strlen($bytes)) . $bytes;
}

// ── Current user helper ───────────────────────────────────────────────────────

function pb_auth_get_current_user(): ?array {
    static $cached = false;
    if ($cached !== false) return $cached;

    $cookie_val = $_COOKIE[PB_AUTH_COOKIE_NAME] ?? null;
    if (!$cookie_val) { $cached = null; return null; }

    // Supabase SSR stores JSON: {"access_token":"...","refresh_token":"..."}
    $session = json_decode(stripslashes($cookie_val), true);
    $token   = is_array($session) ? ($session['access_token'] ?? null) : $cookie_val;

    if (!$token) { $cached = null; return null; }

    $payload = pb_auth_verify_jwt($token);
    $cached  = $payload;
    return $payload;
}

function pb_auth_is_logged_in(): bool {
    return pb_auth_get_current_user() !== null;
}

function pb_auth_get_subscription_tier(): string {
    $user = pb_auth_get_current_user();
    if (!$user) return 'free';
    return $user['user_metadata']['subscription_tier'] ?? 'free';
}

// ── Shortcode: [pb_gate tier="pro"] ... [/pb_gate] ───────────────────────────

add_shortcode('pb_gate', function (array $atts, string $content = ''): string {
    $atts     = shortcode_atts(['tier' => 'pro'], $atts);
    $required = $atts['tier'];
    $tiers    = ['free' => 0, 'basic' => 1, 'pro' => 2, 'premium' => 3];

    $user_tier = pb_auth_get_subscription_tier();
    $has_access = ($tiers[$user_tier] ?? 0) >= ($tiers[$required] ?? 1);

    if ($has_access) {
        return do_shortcode($content);
    }

    ob_start();
    ?>
    <div class="pb-gate-wall">
        <p>This content is available to <strong><?php echo esc_html(ucfirst($required)); ?></strong> subscribers.</p>
        <a href="https://auth.paisabot.com/auth/google?next=<?php echo urlencode(get_permalink()); ?>" class="pb-login-btn pb-login-google">
            Sign in with Google
        </a>
        <a href="https://auth.paisabot.com/auth/facebook?next=<?php echo urlencode(get_permalink()); ?>" class="pb-login-btn pb-login-facebook">
            Sign in with Facebook
        </a>
    </div>
    <?php
    return ob_get_clean();
});

// ── Toolbar: show login/logout link ──────────────────────────────────────────

add_action('wp_footer', function () {
    $user = pb_auth_get_current_user();
    if ($user) {
        $name = esc_html($user['user_metadata']['full_name'] ?? $user['email'] ?? 'Account');
        echo '<div id="pb-auth-bar" class="pb-auth-bar pb-auth-bar--logged-in">';
        echo '<span class="pb-auth-name">' . $name . '</span>';
        echo '<a href="https://auth.paisabot.com/auth/logout?next=' . urlencode(home_url('/')) . '" class="pb-auth-logout">Sign out</a>';
        echo '</div>';
    }
});
