<?php
/**
 * Plugin Name: Paisabot Auth
 * Description: Verifies pb_session JWT from auth.paisabot.com; Phase 1 helper functions.
 * Version:     2.0.0
 * Author:      Paisabot
 */

defined('ABSPATH') || exit;

define('PB_AUTH_SERVICE',   'https://auth.paisabot.com');
define('PB_AUTH_JWKS_URL',  PB_AUTH_SERVICE . '/.well-known/jwks.json');
define('PB_SESSION_COOKIE', 'pb_session');
define('PB_LANG_COOKIE',    'pb_lang');
define('PB_JWKS_CACHE_KEY', 'pb_jwks_v2');
define('PB_JWKS_CACHE_TTL', 86400); // 24h; refetched on kid miss

// ── JWKS fetching ─────────────────────────────────────────────────────────────

function pb_auth_get_jwks(): array {
    $cached = get_transient(PB_JWKS_CACHE_KEY);
    if ($cached) return $cached;
    return pb_auth_refresh_jwks();
}

function pb_auth_refresh_jwks(): array {
    $response = wp_remote_get(PB_AUTH_JWKS_URL, ['timeout' => 5]);
    if (is_wp_error($response)) return [];
    $body = json_decode(wp_remote_retrieve_body($response), true);
    $keys = $body['keys'] ?? [];
    if ($keys) set_transient(PB_JWKS_CACHE_KEY, $keys, PB_JWKS_CACHE_TTL);
    return $keys;
}

// ── JWT verification (RS256) ──────────────────────────────────────────────────

function pb_auth_verify_jwt(string $token): ?array {
    $parts = explode('.', $token);
    if (count($parts) !== 3) return null;

    [$header_b64, $payload_b64, $sig_b64] = $parts;

    $header  = json_decode(pb_auth_b64url_decode($header_b64), true);
    $payload = json_decode(pb_auth_b64url_decode($payload_b64), true);
    if (!$header || !$payload) return null;

    if (isset($payload['exp']) && $payload['exp'] < time()) return null;
    if (($payload['iss'] ?? '') !== PB_AUTH_SERVICE) return null;

    $kid  = $header['kid'] ?? null;
    $jwks = pb_auth_get_jwks();

    $jwk = null;
    foreach ($jwks as $key) {
        if (!$kid || ($key['kid'] ?? null) === $kid) { $jwk = $key; break; }
    }

    // kid miss — try a fresh fetch once
    if (!$jwk) {
        $jwks = pb_auth_refresh_jwks();
        foreach ($jwks as $key) {
            if (!$kid || ($key['kid'] ?? null) === $kid) { $jwk = $key; break; }
        }
    }

    if (!$jwk) return null;

    $public_key = pb_auth_jwk_to_pem($jwk);
    if (!$public_key) return null;

    $signing_input = $header_b64 . '.' . $payload_b64;
    $signature     = pb_auth_b64url_decode($sig_b64);

    $valid = openssl_verify($signing_input, $signature, $public_key, OPENSSL_ALGO_SHA256);
    return ($valid === 1) ? $payload : null;
}

function pb_auth_b64url_decode(string $input): string {
    return base64_decode(strtr($input, '-_', '+/') . str_repeat('=', (4 - strlen($input) % 4) % 4));
}

function pb_auth_jwk_to_pem(array $jwk): ?string {
    if (($jwk['kty'] ?? '') !== 'RSA') return null;

    $n = pb_auth_b64url_decode($jwk['n']);
    $e = pb_auth_b64url_decode($jwk['e']);

    if (ord($n[0]) > 0x7f) $n = "\x00" . $n;
    if (ord($e[0]) > 0x7f) $e = "\x00" . $e;

    $n_der   = "\x02" . pb_auth_asn1_len(strlen($n)) . $n;
    $e_der   = "\x02" . pb_auth_asn1_len(strlen($e)) . $e;
    $seq     = "\x30" . pb_auth_asn1_len(strlen($n_der) + strlen($e_der)) . $n_der . $e_der;
    $oid     = "\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01\x05\x00";
    $bit_str = "\x03" . pb_auth_asn1_len(strlen($seq) + 1) . "\x00" . $seq;
    $der     = "\x30" . pb_auth_asn1_len(strlen($oid) + strlen($bit_str)) . $oid . $bit_str;

    return "-----BEGIN PUBLIC KEY-----\n" . chunk_split(base64_encode($der), 64, "\n") . "-----END PUBLIC KEY-----\n";
}

function pb_auth_asn1_len(int $len): string {
    if ($len < 128) return chr($len);
    $b = '';
    $t = $len;
    while ($t > 0) { $b = chr($t & 0xff) . $b; $t >>= 8; }
    return chr(0x80 | strlen($b)) . $b;
}

// ── Current user helper ───────────────────────────────────────────────────────

function pb_auth_get_current_user(): ?array {
    static $cached = false;
    if ($cached !== false) return $cached;

    $token = $_COOKIE[PB_SESSION_COOKIE] ?? null;
    if (!$token) { $cached = null; return null; }

    $payload = pb_auth_verify_jwt($token);
    $cached  = $payload;
    return $payload;
}

function pb_auth_is_logged_in(): bool {
    return pb_auth_get_current_user() !== null;
}

function pb_auth_get_lang(): string {
    // pb_lang is non-HttpOnly and directly readable; fall back to JWT claim
    $lang = $_COOKIE[PB_LANG_COOKIE] ?? null;
    if ($lang) return $lang;
    $user = pb_auth_get_current_user();
    return $user['lang'] ?? 'en';
}

function pb_auth_login_url(string $return_url = ''): string {
    $return = $return_url ?: (is_ssl() ? 'https://' : 'http://') . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'];
    return PB_AUTH_SERVICE . '/login?return=' . rawurlencode($return);
}

function pb_auth_guest_url(string $return_url = ''): string {
    $return = $return_url ?: (is_ssl() ? 'https://' : 'http://') . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'];
    return PB_AUTH_SERVICE . '/guest?return=' . rawurlencode($return);
}

function pb_auth_logout_url(string $return_url = ''): string {
    $return = $return_url ?: home_url('/');
    return PB_AUTH_SERVICE . '/logout?return=' . rawurlencode($return);
}
