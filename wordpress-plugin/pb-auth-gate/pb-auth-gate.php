<?php
/**
 * Plugin Name: Paisabot Auth Gate
 * Description: Soft login gate for all Paisabot sites. Verifies pb_session JWT
 *              locally (RS256 via JWKS), supports metered/immediate mode, silent
 *              device re-auth via pb_refresh, Google + guest actions.
 * Version:     1.0.0
 * Author:      Paisabot
 */

defined('ABSPATH') || exit;

// ── Config (override via wp-config.php if needed) ────────────────────────────

if (!defined('PB_AUTH_SERVICE'))    define('PB_AUTH_SERVICE',    'https://auth.paisabot.com');
if (!defined('PB_GATE_MODE'))       define('PB_GATE_MODE',       'metered');   // 'metered' | 'immediate'
if (!defined('PB_GATE_FREE_READS')) define('PB_GATE_FREE_READS', 1);
if (!defined('PB_PRIVACY_URL'))     define('PB_PRIVACY_URL',     'https://paisabot.com/privacy/');
if (!defined('PB_TERMS_URL'))       define('PB_TERMS_URL',       'https://paisabot.com/terms/');

// lang → subdomain map (te is the trap: lang=te, sub=tel)
const PB_LANG_SUBDOMAIN = [
    'en' => 'www', 'hi' => 'hi', 'bn' => 'bn', 'mr' => 'mr',
    'te' => 'tel', 'ta' => 'ta', 'gu' => 'gu', 'kn' => 'kn',
    'ml' => 'ml',  'or' => 'or',
];

// ── JWKS + JWT (pure PHP, no Composer) ───────────────────────────────────────

function pb_get_jwks(): array {
    $cached = get_transient('pb_jwks_v2');
    if ($cached) return $cached;
    return pb_refresh_jwks();
}

function pb_refresh_jwks(): array {
    $r = wp_remote_get(PB_AUTH_SERVICE . '/.well-known/jwks.json', ['timeout' => 5]);
    if (is_wp_error($r)) return [];
    $keys = json_decode(wp_remote_retrieve_body($r), true)['keys'] ?? [];
    if ($keys) set_transient('pb_jwks_v2', $keys, 86400);
    return $keys;
}

function pb_b64url(string $s): string {
    return base64_decode(strtr($s, '-_', '+/') . str_repeat('=', (4 - strlen($s) % 4) % 4));
}

function pb_jwk_to_pem(array $jwk): ?string {
    if (($jwk['kty'] ?? '') !== 'RSA') return null;
    $n = pb_b64url($jwk['n']);
    $e = pb_b64url($jwk['e']);
    if (ord($n[0]) > 0x7f) $n = "\x00$n";
    if (ord($e[0]) > 0x7f) $e = "\x00$e";
    $nd   = "\x02" . pb_asn1len(strlen($n)) . $n;
    $ed   = "\x02" . pb_asn1len(strlen($e)) . $e;
    $seq  = "\x30" . pb_asn1len(strlen($nd) + strlen($ed)) . $nd . $ed;
    $oid  = "\x30\x0d\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01\x05\x00";
    $bits = "\x03" . pb_asn1len(strlen($seq) + 1) . "\x00" . $seq;
    $der  = "\x30" . pb_asn1len(strlen($oid) + strlen($bits)) . $oid . $bits;
    return "-----BEGIN PUBLIC KEY-----\n" . chunk_split(base64_encode($der), 64, "\n") . "-----END PUBLIC KEY-----\n";
}

function pb_asn1len(int $n): string {
    if ($n < 128) return chr($n);
    $b = ''; $t = $n;
    while ($t > 0) { $b = chr($t & 0xff) . $b; $t >>= 8; }
    return chr(0x80 | strlen($b)) . $b;
}

function pb_verify_jwt(string $token): ?array {
    $p = explode('.', $token);
    if (count($p) !== 3) return null;
    [$hb, $pb, $sb] = $p;
    $header  = json_decode(pb_b64url($hb), true);
    $payload = json_decode(pb_b64url($pb), true);
    if (!$header || !$payload) return null;
    if (($payload['exp'] ?? 0) < time()) return null;
    if (($payload['iss'] ?? '') !== PB_AUTH_SERVICE) return null;

    $kid  = $header['kid'] ?? null;
    $jwks = pb_get_jwks();
    $jwk  = null;
    foreach ($jwks as $k) {
        if (!$kid || ($k['kid'] ?? null) === $kid) { $jwk = $k; break; }
    }
    if (!$jwk) {
        $jwks = pb_refresh_jwks();
        foreach ($jwks as $k) {
            if (!$kid || ($k['kid'] ?? null) === $kid) { $jwk = $k; break; }
        }
    }
    if (!$jwk) return null;

    $pem = pb_jwk_to_pem($jwk);
    if (!$pem) return null;

    $ok = openssl_verify("$hb.$pb", pb_b64url($sb), $pem, OPENSSL_ALGO_SHA256);
    return ($ok === 1) ? $payload : null;
}

// ── Current user (cached per request) ────────────────────────────────────────

function pb_current_user(): ?array {
    static $cache = false;
    if ($cache !== false) return $cache;
    $token = $_COOKIE['pb_session'] ?? null;
    $cache = $token ? pb_verify_jwt($token) : null;
    return $cache;
}

function pb_is_authed(): bool { return pb_current_user() !== null; }

function pb_login_url(): string {
    $here = (is_ssl() ? 'https' : 'http') . '://' . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'];
    return PB_AUTH_SERVICE . '/login?return=' . rawurlencode($here);
}

function pb_guest_url(): string {
    $here = (is_ssl() ? 'https' : 'http') . '://' . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'];
    return PB_AUTH_SERVICE . '/guest?return=' . rawurlencode($here);
}

function pb_logout_url(): string {
    $home = (is_ssl() ? 'https' : 'http') . '://' . $_SERVER['HTTP_HOST'] . '/';
    return PB_AUTH_SERVICE . '/logout?return=' . rawurlencode($home);
}

// ── SEO: NewsArticle structured data ─────────────────────────────────────────
// The gate is soft (full article stays in the DOM, crawlers are exempt), but
// emitting JSON-LD makes the gated content unambiguous to search engines and
// enables rich results. isAccessibleForFree=True + hasPart marks the metered
// model honestly per Google's paywalled-content guidance.

add_action('wp_head', function () {
    if (!is_single()) return;

    $post = get_post();
    if (!$post) return;

    $title   = get_the_title($post);
    $excerpt = wp_strip_all_tags(get_the_excerpt($post));
    $url     = get_permalink($post);
    $pub     = get_the_date('c', $post);
    $mod     = get_the_modified_date('c', $post);
    $img     = get_the_post_thumbnail_url($post, 'full') ?: '';
    $author  = get_the_author_meta('display_name', $post->post_author) ?: 'Paisabot';

    $data = [
        '@context' => 'https://schema.org',
        '@type'    => 'NewsArticle',
        'headline' => $title,
        'description' => $excerpt,
        'mainEntityOfPage' => ['@type' => 'WebPage', '@id' => $url],
        'datePublished' => $pub,
        'dateModified'  => $mod,
        'author'    => ['@type' => 'Organization', 'name' => $author],
        'publisher' => [
            '@type' => 'Organization',
            'name'  => 'Paisabot',
            'logo'  => [
                '@type' => 'ImageObject',
                'url'   => 'https://paisabot.com/wp-content/uploads/logo.png',
            ],
        ],
        // Metered paywall honesty: the article body is the gated part.
        'isAccessibleForFree' => true,
        'hasPart' => [
            '@type' => 'WebPageElement',
            'isAccessibleForFree' => true,
            'cssSelector' => '.entry-content',
        ],
    ];
    if ($img) $data['image'] = [$img];

    echo "\n<script type=\"application/ld+json\">"
       . wp_json_encode($data, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE)
       . "</script>\n";
}, 5);

// ── Account / sessions UI — [pb_account] shortcode ───────────────────────────
// Renders a self-service panel: profile, active sessions (revoke), logout
// everywhere, and DPDP account deletion. All actions call the auth service
// with credentials; this shortcode only ships the container + assets.

add_shortcode('pb_account', function () {
    $uri = plugin_dir_url(__FILE__);
    wp_enqueue_style('pb-account', $uri . 'account.css', [], '1.0.0');
    wp_enqueue_script('pb-account', $uri . 'account.js', [], '1.0.0', true);
    wp_localize_script('pb-account', 'PB_ACCOUNT', [
        'authService' => PB_AUTH_SERVICE,
        'loginUrl'    => pb_login_url(),
        'logoutUrl'   => pb_logout_url(),
    ]);
    return '<div id="pb-account-root" class="pb-account">Loading your account…</div>';
});

// ── Crawler detection (reverse-DNS, not just UA) ──────────────────────────────

function pb_is_verified_crawler(): bool {
    // Verify Googlebot/Bingbot by reverse + forward DNS, as Google recommends.
    // UA check alone is spoofable; this is not.
    $ip = $_SERVER['REMOTE_ADDR'] ?? '';
    if (!$ip) return false;

    static $cache = [];
    if (isset($cache[$ip])) return $cache[$ip];

    $host = gethostbyaddr($ip);
    if ($host === $ip) { $cache[$ip] = false; return false; } // no PTR

    $is_google = preg_match('/\.googlebot\.com$/', $host)
              || preg_match('/\.google\.com$/', $host);
    $is_bing   = preg_match('/\.search\.msn\.com$/', $host);

    if ($is_google || $is_bing) {
        // Forward DNS confirm
        $resolved = gethostbyname($host);
        $cache[$ip] = ($resolved === $ip);
    } else {
        $cache[$ip] = false;
    }
    return $cache[$ip];
}

// ── Metered gate counter (signed cookie, no server state) ────────────────────

function pb_metered_increment(): int {
    $secret = defined('AUTH_KEY') ? AUTH_KEY : 'pb_fallback';
    $cookie = $_COOKIE['pb_reads'] ?? '';
    $count  = 0;

    if ($cookie) {
        $parts = explode('.', $cookie, 2);
        if (count($parts) === 2) {
            [$data, $sig] = $parts;
            if (hash_equals(hash_hmac('sha256', $data, $secret), $sig)) {
                $count = (int) base64_decode($data);
            }
        }
    }

    $count++;
    $data = base64_encode((string) $count);
    $sig  = hash_hmac('sha256', $data, $secret);
    setcookie('pb_reads', "$data.$sig", [
        'expires'  => time() + 86400,
        'path'     => '/',
        'secure'   => is_ssl(),
        'httponly' => false,
        'samesite' => 'Lax',
    ]);
    return $count;
}

// ── Gate decision ─────────────────────────────────────────────────────────────

function pb_should_gate(): bool {
    if (pb_is_authed())          return false;
    if (pb_is_verified_crawler()) return false;
    if (PB_GATE_MODE === 'metered') {
        return pb_metered_increment() > PB_GATE_FREE_READS;
    }
    return true; // immediate
}

// Body class is no longer set server-side — JS adds pb-gated-visible after
// evaluating the localStorage counter, which works on cached pages.

// ── Enqueue gate overlay assets ───────────────────────────────────────────────
// Always load on single posts — JS owns the gate decision so it works even
// when LiteSpeed/CDN serves a cached page (PHP cookies don't fire on cache).

// CSS and JS are INLINED into the page (not enqueued as files) so the
// Hostinger CDN (hcdn) — which caches static assets and ignores ?ver= query
// strings — can never serve a stale gate. The HTML carries the current code.
add_action('wp_enqueue_scripts', function () {
    if (!is_singular()) return;
    if (pb_is_verified_crawler()) return;

    $dir = plugin_dir_path(__FILE__);
    $css = @file_get_contents($dir . 'gate.css');
    $js  = @file_get_contents($dir . 'gate.js');

    // Register handle-less style/script so we can attach inline content.
    wp_register_style('pb-gate', false);
    wp_enqueue_style('pb-gate');
    if ($css) wp_add_inline_style('pb-gate', $css);

    wp_register_script('pb-gate', false, [], null, true);
    wp_enqueue_script('pb-gate');
    $cfg = wp_json_encode([
        'authService' => PB_AUTH_SERVICE,
        'loginUrl'    => pb_login_url(),
        'guestUrl'    => pb_guest_url(),
        'gateMode'    => PB_GATE_MODE,
        'freeReads'   => PB_GATE_FREE_READS,
    ]);
    if ($js) wp_add_inline_script('pb-gate', "window.PB_GATE=$cfg;\n$js");
});

// ── Gate overlay HTML (injected into footer) ──────────────────────────────────

// ── Phase 5: Cross-language interstitial ──────────────────────────────────────

// Reverse PB_LANG_SUBDOMAIN: subdomain → lang code.
function pb_site_lang(): string {
    $host = strtolower($_SERVER['HTTP_HOST'] ?? '');
    $sub  = explode('.', $host)[0];
    foreach (PB_LANG_SUBDOMAIN as $lang => $s) {
        if ($s === $sub) return $lang;
    }
    // 'paisabot' (apex) and 'www' are both English
    return 'en';
}

// Native language names for the interstitial UI.
const PB_LANG_NAMES = [
    'en' => 'English', 'hi' => 'हिंदी',   'bn' => 'বাংলা',
    'mr' => 'मराठी',   'te' => 'తెలుగు',  'ta' => 'தமிழ்',
    'gu' => 'ગુજરાતી', 'kn' => 'ಕನ್ನಡ',   'ml' => 'മലയാളം',
    'or' => 'ଓଡ଼ିଆ',
];

function pb_get_variants(string $cluster_id): array {
    $key    = 'pb_variants_' . substr(str_replace('-', '', $cluster_id), 0, 12);
    $cached = get_transient($key);
    if ($cached !== false) return (array) $cached;

    $url = PB_AUTH_SERVICE . '/api/v1/story/' . rawurlencode($cluster_id) . '/variants';
    $r   = wp_remote_get($url, ['timeout' => 3]);
    if (is_wp_error($r)) return [];

    $data     = json_decode(wp_remote_retrieve_body($r), true);
    $variants = $data['variants'] ?? [];
    set_transient($key, $variants, 3600);
    return $variants;
}

// template_redirect fires before output → safe to wp_redirect() for 'always'.
add_action('template_redirect', function () {
    if (!is_single())            return;
    if (pb_is_verified_crawler()) return;

    $user = pb_current_user();
    if (!$user) return;

    $pref_lang = $_COOKIE['pb_lang'] ?? null;
    $site_lang = pb_site_lang();
    if (!$pref_lang || $pref_lang === $site_lang) return;

    $routing = $user['cross_lang_routing'] ?? 'ask';
    if ($routing === 'never') return;

    $cluster_id = get_post_meta(get_the_ID(), 'paisabot_cluster_id', true);
    if (!$cluster_id) return;

    $variants     = pb_get_variants($cluster_id);
    $pref_variant = null;
    foreach ($variants as $v) {
        if (($v['lang'] ?? '') === $pref_lang && !empty($v['wp_url'])) {
            $pref_variant = $v;
            break;
        }
    }
    if (!$pref_variant) return;

    if ($routing === 'always') {
        wp_redirect(esc_url_raw($pref_variant['wp_url']), 302);
        exit;
    }

    // 'ask' → hand off to JS via localized script data
    global $pb_interstitial_data;
    $pb_interstitial_data = [
        'prefLang'    => $pref_lang,
        'siteLang'    => $site_lang,
        'prefName'    => PB_LANG_NAMES[$pref_lang]  ?? $pref_lang,
        'siteName'    => PB_LANG_NAMES[$site_lang]  ?? $site_lang,
        'variantUrl'  => $pref_variant['wp_url'],
        'clusterId'   => $cluster_id,
        'authService' => PB_AUTH_SERVICE,
    ];
});

add_action('wp_enqueue_scripts', function () {
    global $pb_interstitial_data;
    if (empty($pb_interstitial_data)) return;

    $uri = plugin_dir_url(__FILE__);
    wp_enqueue_style('pb-interstitial',  $uri . 'interstitial.css', [], '1.0.0');
    wp_enqueue_script('pb-interstitial', $uri . 'interstitial.js',  [],          '1.0.0', true);
    wp_localize_script('pb-interstitial', 'PB_INTERSTITIAL', $pb_interstitial_data);
}, 11); // after the gate enqueue at priority 10

add_action('wp_footer', function () {
    if (!is_singular()) return;
    if (pb_is_verified_crawler()) return;
    // Gate HTML always present; gate.js decides whether to show it based on
    // localStorage read count and pb_session cookie — works on cached pages.

    $login_url = esc_url(pb_login_url());
    $guest_url = esc_url(pb_guest_url());
    $privacy   = esc_url(PB_PRIVACY_URL);
    $terms     = esc_url(PB_TERMS_URL);

    // Logo mark SVG (inline, no external request)
    $logo_svg = '<svg viewBox="0 0 40 40" width="50" height="50" fill="none" aria-hidden="true">
        <rect width="40" height="40" rx="9" fill="#1B2E45"/>
        <rect x="7"  y="22" width="5" height="12" rx="2" fill="#C4820A"/>
        <rect x="14" y="15" width="5" height="19" rx="2" fill="#C4820A" opacity=".75"/>
        <rect x="21" y="9"  width="5" height="25" rx="2" fill="#C4820A" opacity=".5"/>
        <rect x="28" y="5"  width="5" height="29" rx="2" fill="#C4820A" opacity=".3"/>
        <path d="M9.5 19 L17 12 L24 8 L31.5 4.5" stroke="white" stroke-width="1.5" stroke-linecap="round" opacity=".35"/>
    </svg>';

    // Google G SVG
    $google_svg = '<svg width="20" height="20" viewBox="0 0 24 24" aria-hidden="true">
        <path d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z" fill="#4285F4"/>
        <path d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" fill="#34A853"/>
        <path d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l3.66-2.84z" fill="#FBBC05"/>
        <path d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" fill="#EA4335"/>
    </svg>';

    // Arrow right SVG
    $arrow_svg = '<svg width="17" height="17" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
        <path d="M5 12h14M12 5l7 7-7 7"/>
    </svg>';

    // Check SVG for perks
    $check_svg = '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">
        <path d="M20 6L9 17l-5-5"/>
    </svg>';

    echo <<<HTML
<div id="pb-gate-root" class="pb-gate-wrap" role="dialog" aria-modal="true" aria-label="Sign in to continue reading">
  <div class="pb-gate-fade" aria-hidden="true"></div>
  <div class="pb-gate">
    <div class="pb-gate-card">
      <div class="pb-gate-mark">{$logo_svg}</div>
      <span class="pb-gate-kicker"><span class="pb-ln"></span>Free account<span class="pb-ln"></span></span>
      <h2>Read the markets — and <em>join the conversation.</em></h2>
      <p class="pb-deck">You've reached today's free limit. Create a Paisabot account to keep reading, follow India's sharpest market voices, and share your own takes.</p>

      <div class="pb-gate-actions">
        <a href="{$login_url}" class="pb-btn-google">
          {$google_svg} Continue with Google
        </a>
        <a href="{$guest_url}" class="pb-btn-guest">
          Continue as guest {$arrow_svg}
        </a>
      </div>

      <p class="pb-gate-fine">No credit card. Free forever for readers.<br>By continuing you agree to our <a href="{$terms}">Terms</a> &amp; <a href="{$privacy}">Privacy Policy</a>.</p>

      <div class="pb-gate-perks">
        <span class="pb-perk">{$check_svg} Unlimited stories</span>
        <span class="pb-perk">{$check_svg} Follow analysts</span>
        <span class="pb-perk">{$check_svg} Post your takes</span>
      </div>
    </div>
  </div>
  <div id="pb-gate-spinner" class="pb-gate-spinner" aria-hidden="true"></div>
</div>
HTML;
});
