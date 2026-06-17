import { Router } from 'express'
import { requireAuth } from '../middleware/requireAuth.js'
import { signSessionToken } from '../lib/jwt.js'
import { query } from '../lib/db.js'
import config, { isSafeReturn, langToOrigin, LANG_SUBDOMAIN } from '../config.js'

const router = Router()

const VALID_LANGS = new Set(Object.keys(LANG_SUBDOMAIN))

const SESSION_COOKIE_OPTS = {
  httpOnly: true,
  secure:   config.cookie.secure,
  sameSite: 'lax',
  domain:   config.cookie.domain,
  path:     '/',
  maxAge:   config.jwt.sessionTtlSeconds * 1000,
}

const LANG_COOKIE_OPTS = {
  secure:   config.cookie.secure,
  sameSite: 'lax',
  domain:   config.cookie.domain,
  path:     '/',
  maxAge:   config.jwt.refreshTtlDays * 24 * 60 * 60 * 1000,
}

// Resolve where to redirect after lang selection.
// If returnUrl is a different-lang site from chosen lang, redirect to the
// chosen lang's home (Phase 5 will make this story-aware).
function resolveRedirect(returnUrl, lang) {
  const chosenOrigin = langToOrigin(lang)
  if (!returnUrl || !isSafeReturn(returnUrl)) return chosenOrigin || config.defaultRedirect

  try {
    const url = new URL(returnUrl)
    // If the origin already matches the chosen lang's origin, go straight back
    if (chosenOrigin && url.origin === chosenOrigin) return returnUrl
    // Different-lang site — send to chosen lang's home for now
    return chosenOrigin || config.defaultRedirect
  } catch {
    return chosenOrigin || config.defaultRedirect
  }
}

// Derive site lang from hostname so we can preselect on skip
function siteHintFromReturn(returnUrl) {
  if (!returnUrl) return null
  try {
    const { hostname } = new URL(returnUrl)
    // www.paisabot.com or paisabot.com → en
    if (hostname === 'paisabot.com' || hostname === 'www.paisabot.com') return 'en'
    // sub.paisabot.com → map subdomain → lang code
    const sub = hostname.split('.')[0]
    // reverse LANG_SUBDOMAIN map
    for (const [lang, s] of Object.entries(LANG_SUBDOMAIN)) {
      if (s === sub) return lang
    }
  } catch {}
  return null
}

// ── GET /language — render the picker ────────────────────────────────────────

router.get('/', requireAuth, (req, res) => {
  const returnUrl = isSafeReturn(req.query.return) ? req.query.return : ''
  const currentLang = req.user.lang || ''
  res.setHeader('Content-Type', 'text/html; charset=utf-8')
  res.send(renderPage({ returnUrl, currentLang, nonce: res.locals.cspNonce }))
})

// ── POST /language — save selection, re-mint cookies, redirect ────────────────

router.post('/', requireAuth, async (req, res, next) => {
  try {
    const { lang, return: rawReturn, skip } = req.body
    const returnUrl = isSafeReturn(rawReturn) ? rawReturn : ''

    let finalLang = lang
    if (skip === '1' || !lang) {
      // Skip: default to site hint or 'en'
      finalLang = siteHintFromReturn(returnUrl) || req.user.lang || 'en'
    }

    if (!VALID_LANGS.has(finalLang)) finalLang = 'en'

    await query('UPDATE users SET lang = $1 WHERE id = $2', [finalLang, req.user.id])

    const { rows: [u] } = await query(
      'SELECT id, email, name, picture_url, lang, role FROM users WHERE id = $1',
      [req.user.id]
    )

    const sessionToken = signSessionToken({
      sub: u.id, email: u.email, name: u.name,
      picture: u.picture_url, lang: u.lang, role: u.role,
    })

    res.cookie('pb_session', sessionToken, SESSION_COOKIE_OPTS)
    res.cookie('pb_lang', u.lang, LANG_COOKIE_OPTS)

    const dest = resolveRedirect(returnUrl, finalLang)
    res.redirect(dest)
  } catch (err) {
    next(err)
  }
})

// ── HTML renderer ─────────────────────────────────────────────────────────────

function renderPage({ returnUrl, currentLang, nonce = '' }) {
  const returnEsc = returnUrl.replace(/"/g, '&quot;')
  const nonceAttr = nonce ? ` nonce="${nonce}"` : ''

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Choose your language · Paisabot</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800;900&family=Source+Serif+4:ital,opsz,wght@1,8..60,400;1,8..60,700&family=JetBrains+Mono:wght@400;500&family=Noto+Sans+Devanagari:wght@400;600;700&family=Noto+Sans+Malayalam:wght@400;600;700&family=Noto+Sans+Telugu:wght@400;600;700&family=Noto+Sans+Tamil:wght@400;600;700&family=Noto+Sans+Kannada:wght@400;600;700&family=Noto+Sans+Gujarati:wght@400;600;700&family=Noto+Sans+Bengali:wght@400;600;700&family=Noto+Sans+Oriya:wght@400;600;700&display=swap" rel="stylesheet">
<style>
:root {
  --cream:#FFF9F4;--cream-2:#FFF3E6;--navy:#0F1E33;--navy-2:#1B2E45;--navy-3:#2E4D6B;--navy-4:#4A6F8E;
  --amber:#C4820A;--amber-2:#E0A030;--amber-3:#9E6808;--amber-soft:#FFF3DC;
  --up:#1A7A4A;--bg:#FFF9F4;--surface:#FFFFFF;--surface-hover:#FFF3E6;
  --border:#E8D8C4;--border-strong:#D4BFA5;
  --fg:#0F1E33;--fg-2:#2C3E50;--fg-3:#4A6070;--fg-muted:#7A93A3;--fg-on-dark:rgba(255,255,255,0.92);
  --font-sans:'Inter',system-ui,sans-serif;
  --font-serif:'Source Serif 4','Georgia',serif;
  --font-mono:'JetBrains Mono','Courier New',monospace;
  --font-hi:'Noto Sans Devanagari',var(--font-sans);
  --font-ml:'Noto Sans Malayalam',var(--font-sans);
  --font-te:'Noto Sans Telugu',var(--font-sans);
  --t-xs:11px;--t-sm:13px;--t-base:15px;--t-lg:19px;--t-5xl:52px;
  --sp-2:8px;--sp-3:12px;--sp-4:16px;--sp-5:20px;--sp-6:24px;--sp-7:32px;--sp-8:40px;--sp-9:56px;
  --r-sm:6px;--r-lg:16px;--r-full:9999px;
  --s-sm:0 2px 8px rgba(15,30,51,.07);--s:0 4px 16px rgba(15,30,51,.09);--s-lg:0 8px 32px rgba(15,30,51,.12);
  --t-fast:120ms ease;--t-med:200ms ease;--t-out:300ms cubic-bezier(.2,0,0,1);
  --max-w:1240px;
}
*{box-sizing:border-box;margin:0;padding:0}
html,body{min-height:100%}
body{background:var(--bg);color:var(--fg);font-family:var(--font-sans);-webkit-font-smoothing:antialiased;display:flex;flex-direction:column;min-height:100vh}

.topbar{height:62px;flex:0 0 auto;background:var(--surface);border-bottom:1px solid var(--border);display:flex;align-items:center;padding:0 var(--sp-7)}
.brand{display:flex;align-items:center;gap:10px;text-decoration:none}
.brand .name{font-size:21px;font-weight:900;color:var(--navy);letter-spacing:-.04em;line-height:1}
.brand .name em{color:var(--amber);font-style:italic;font-family:var(--font-serif);font-weight:700}
.brand .sub{font-size:9px;color:var(--fg-muted);letter-spacing:.16em;text-transform:uppercase;font-weight:700;margin-top:4px}
.brand .stack{display:flex;flex-direction:column;line-height:1}
.steps{margin-left:auto;display:flex;align-items:center;gap:8px}
.step-dot{width:7px;height:7px;border-radius:var(--r-full);background:var(--border-strong)}
.step-dot.on{background:var(--amber);width:22px}
.steps .lbl{font-size:var(--t-xs);font-weight:800;letter-spacing:.1em;text-transform:uppercase;color:var(--fg-muted);margin-right:6px;white-space:nowrap}

main{flex:1 1 auto;overflow-y:auto;padding:var(--sp-9) var(--sp-7) 140px}
.wrap{max-width:var(--max-w);margin:0 auto}
.intro{max-width:640px;margin-bottom:var(--sp-8)}
.kicker{display:inline-flex;align-items:center;gap:8px;margin-bottom:var(--sp-4);font-size:var(--t-xs);font-weight:800;letter-spacing:.09em;text-transform:uppercase;color:var(--navy)}
.kicker .dot{width:6px;height:6px;border-radius:var(--r-full);background:var(--amber)}
.intro h1{font-size:clamp(34px,4.4vw,var(--t-5xl));line-height:1.05;letter-spacing:-.035em;font-weight:900;margin-bottom:var(--sp-4)}
.intro h1 em{font-family:var(--font-serif);font-style:italic;font-weight:700;color:var(--amber-3)}
.intro .deck{font-family:var(--font-serif);font-size:var(--t-lg);line-height:1.55;color:var(--fg-3);font-style:italic}

.grid{display:grid;grid-template-columns:repeat(5,1fr);gap:var(--sp-4)}
@media(max-width:1100px){.grid{grid-template-columns:repeat(4,1fr)}}
@media(max-width:880px){.grid{grid-template-columns:repeat(3,1fr)}}
@media(max-width:620px){.grid{grid-template-columns:repeat(2,1fr)}}

.lang{position:relative;text-align:left;background:var(--surface);border:1.5px solid var(--border);border-radius:var(--r-lg);padding:var(--sp-5) var(--sp-5) var(--sp-4);cursor:pointer;transition:border-color var(--t-fast),box-shadow var(--t-med),transform var(--t-med),background var(--t-fast);display:flex;flex-direction:column;gap:var(--sp-2);min-height:128px;font-family:var(--font-sans)}
.lang:hover{border-color:var(--border-strong);box-shadow:var(--s-sm);transform:translateY(-2px)}
.lang:focus-visible{outline:none;border-color:var(--amber);box-shadow:0 0 0 3px var(--amber-soft)}
.native{font-size:30px;line-height:1.1;font-weight:600;color:var(--navy);letter-spacing:-.01em}
.meta{display:flex;flex-direction:column;gap:2px;margin-top:auto}
.en-name{font-size:var(--t-base);font-weight:700;color:var(--fg-2)}
.region{font-family:var(--font-mono);font-size:10px;font-weight:500;letter-spacing:.04em;text-transform:uppercase;color:var(--fg-muted)}
.tick{position:absolute;top:14px;right:14px;width:24px;height:24px;border-radius:var(--r-full);border:1.5px solid var(--border-strong);background:var(--surface);display:flex;align-items:center;justify-content:center;transition:all var(--t-med)}
.tick svg{width:13px;height:13px;stroke:#fff;stroke-width:3;fill:none;opacity:0;transform:scale(.5);transition:all var(--t-med)}
.lang[aria-pressed="true"]{border-color:var(--navy);box-shadow:var(--s)}
.lang[aria-pressed="true"] .tick{background:var(--amber);border-color:var(--amber)}
.lang[aria-pressed="true"] .tick svg{opacity:1;transform:scale(1)}
.native[lang="hi"],.native[lang="mr"]{font-family:var(--font-hi)}
.native[lang="ta"]{font-family:'Noto Sans Tamil',var(--font-sans)}
.native[lang="kn"]{font-family:'Noto Sans Kannada',var(--font-sans)}
.native[lang="te"]{font-family:var(--font-te)}
.native[lang="ml"]{font-family:var(--font-ml)}
.native[lang="gu"]{font-family:'Noto Sans Gujarati',var(--font-sans)}
.native[lang="bn"]{font-family:'Noto Sans Bengali',var(--font-sans)}
.native[lang="or"]{font-family:'Noto Sans Oriya',var(--font-sans)}

.actionbar{position:fixed;left:0;right:0;bottom:0;background:rgba(255,249,244,.88);backdrop-filter:blur(12px);border-top:1px solid var(--border);padding:var(--sp-4) var(--sp-7)}
.actionbar .inner{max-width:var(--max-w);margin:0 auto;display:flex;align-items:center;gap:var(--sp-5)}
.selnote{display:flex;flex-direction:column;gap:2px;min-width:0}
.selnote .l1{font-size:var(--t-sm);color:var(--fg-3)}
.selnote .l1 b{color:var(--navy);font-weight:800}
.selnote .l2{font-family:var(--font-mono);font-size:10px;letter-spacing:.04em;text-transform:uppercase;color:var(--fg-muted)}
.cta-group{margin-left:auto;display:flex;align-items:center;gap:var(--sp-3)}
.btn-skip{height:44px;padding:0 18px;border:none;background:transparent;color:var(--fg-3);font-family:var(--font-sans);font-size:var(--t-sm);font-weight:700;border-radius:var(--r-sm);cursor:pointer;white-space:nowrap;transition:background var(--t-fast),color var(--t-fast)}
.btn-skip:hover{background:var(--surface-hover);color:var(--navy)}
.btn-continue{height:44px;padding:0 26px;border:none;background:var(--amber);color:#fff;font-family:var(--font-sans);font-size:var(--t-base);font-weight:800;letter-spacing:.01em;border-radius:var(--r-full);cursor:pointer;display:inline-flex;align-items:center;gap:8px;box-shadow:var(--s-sm);transition:background var(--t-fast),opacity var(--t-fast),transform var(--t-fast)}
.btn-continue svg{width:16px;height:16px;stroke:#fff;stroke-width:2.4;fill:none}
.btn-continue:hover:not(:disabled){background:var(--amber-3);transform:translateX(1px)}
.btn-continue:disabled{opacity:.4;cursor:not-allowed;background:var(--navy-4);box-shadow:none}
.toast{position:fixed;left:50%;bottom:96px;transform:translate(-50%,16px);background:var(--navy);color:var(--fg-on-dark);padding:12px 18px;border-radius:var(--r-full);font-size:var(--t-sm);font-weight:600;box-shadow:var(--s-lg);display:flex;align-items:center;gap:10px;opacity:0;pointer-events:none;transition:all var(--t-out);z-index:20}
.toast.show{opacity:1;transform:translate(-50%,0)}
.toast .chk{width:18px;height:18px;border-radius:var(--r-full);background:var(--up);display:flex;align-items:center;justify-content:center}
.toast .chk svg{width:10px;height:10px;stroke:#fff;stroke-width:3;fill:none}
</style>
</head>
<body>

<header class="topbar">
  <a class="brand" href="https://paisabot.com">
    <svg viewBox="0 0 40 40" width="36" height="36" fill="none" aria-hidden="true">
      <rect width="40" height="40" rx="9" fill="#1B2E45"/>
      <rect x="7"  y="22" width="5" height="12" rx="2" fill="#C4820A"/>
      <rect x="14" y="15" width="5" height="19" rx="2" fill="#C4820A" opacity=".75"/>
      <rect x="21" y="9"  width="5" height="25" rx="2" fill="#C4820A" opacity=".5"/>
      <rect x="28" y="5"  width="5" height="29" rx="2" fill="#C4820A" opacity=".3"/>
      <path d="M9.5 19 L17 12 L24 8 L31.5 4.5" stroke="white" stroke-width="1.5" stroke-linecap="round" opacity=".35"/>
    </svg>
    <span class="stack">
      <span class="name">Paisa<em>bot</em></span>
      <span class="sub">Economic Intelligence</span>
    </span>
  </a>
  <div class="steps">
    <span class="lbl">Step 1 of 3</span>
    <span class="step-dot on"></span>
    <span class="step-dot"></span>
    <span class="step-dot"></span>
  </div>
</header>

<main>
  <div class="wrap">
    <section class="intro">
      <span class="kicker"><span class="dot"></span><span>Personalise your briefing</span></span>
      <h1>Read the markets in <em>your language.</em></h1>
      <p class="deck">Choose the language for your headlines, market briefings and alerts. You can switch anytime from Settings.</p>
    </section>
    <div class="grid" id="grid" role="radiogroup" aria-label="Choose your news language"></div>
  </div>
</main>

<div class="actionbar">
  <div class="inner">
    <div class="selnote">
      <span class="l1" id="selL1">No language selected yet</span>
      <span class="l2" id="selL2">Select one to continue</span>
    </div>
    <div class="cta-group">
      <button class="btn-skip" id="btnSkip" type="button">Skip for now</button>
      <button class="btn-continue" id="btnContinue" type="button" disabled>
        Continue
        <svg viewBox="0 0 24 24"><path d="M5 12h14M12 5l7 7-7 7" stroke-linecap="round" stroke-linejoin="round"/></svg>
      </button>
    </div>
  </div>
</div>

<div class="toast" id="toast">
  <span class="chk"><svg viewBox="0 0 24 24"><path d="M5 12l5 5L20 7" stroke-linecap="round" stroke-linejoin="round"/></svg></span>
  <span id="toastText">Language saved</span>
</div>

<!-- Hidden form — submitted by JS -->
<form id="langForm" method="POST" action="/language" style="display:none">
  <input type="hidden" name="lang"   id="fLang">
  <input type="hidden" name="skip"   id="fSkip"   value="0">
  <input type="hidden" name="return" id="fReturn"  value="${returnEsc}">
</form>

<script${nonceAttr}>
const LANGS = [
  { code:'en', native:'English',   en:'English',   region:'Pan-India' },
  { code:'hi', native:'हिन्दी', en:'Hindi', region:'North India' },
  { code:'bn', native:'বাংলা', en:'Bengali', region:'West Bengal' },
  { code:'mr', native:'मराठी', en:'Marathi', region:'Maharashtra' },
  { code:'te', native:'తెలుగు', en:'Telugu', region:'Andhra · Telangana' },
  { code:'ta', native:'தமிழ்', en:'Tamil', region:'Tamil Nadu' },
  { code:'gu', native:'ગુજરાતી', en:'Gujarati', region:'Gujarat' },
  { code:'kn', native:'ಕನ್ನಡ', en:'Kannada', region:'Karnataka' },
  { code:'ml', native:'മലയാളം', en:'Malayalam', region:'Kerala' },
  { code:'or', native:'ଓଡ଼ିଆ', en:'Odia', region:'Odisha' },
];

const SAVED_LANG = ${JSON.stringify(currentLang)};

const grid    = document.getElementById('grid');
const btnCont = document.getElementById('btnContinue');
const btnSkip = document.getElementById('btnSkip');
const selL1   = document.getElementById('selL1');
const selL2   = document.getElementById('selL2');
const toast   = document.getElementById('toast');
const toastT  = document.getElementById('toastText');
const fLang   = document.getElementById('fLang');
const fSkip   = document.getElementById('fSkip');
const form    = document.getElementById('langForm');

let selected = null;

const tickSVG = '<span class="tick"><svg viewBox="0 0 24 24"><path d="M5 12l5 5L20 7" stroke-linecap="round" stroke-linejoin="round"/></svg></span>';

LANGS.forEach(L => {
  const b = document.createElement('button');
  b.className = 'lang';
  b.type = 'button';
  b.setAttribute('role', 'radio');
  b.setAttribute('aria-pressed', 'false');
  b.dataset.code = L.code;
  b.innerHTML =
    tickSVG +
    '<span class="native" lang="' + L.code + '">' + L.native + '</span>' +
    '<span class="meta"><span class="en-name">' + L.en + '</span>' +
    '<span class="region">' + L.region + '</span></span>';
  b.addEventListener('click', () => choose(L, b));
  grid.appendChild(b);
});

function choose(L, btn) {
  [...grid.children].forEach(c => c.setAttribute('aria-pressed', c === btn ? 'true' : 'false'));
  selected = L;
  selL1.innerHTML = 'Your news language: <b>' + L.en + ' &middot; ' + L.native + '</b>';
  selL2.textContent = 'Tap Continue to confirm';
  btnCont.disabled = false;
  try { localStorage.setItem('paisabot.lang', L.code); } catch(e) {}
}

btnCont.addEventListener('click', () => {
  if (!selected) return;
  toastT.textContent = 'Reading in ' + selected.en + ' — ' + selected.native;
  toast.classList.add('show');
  fLang.value = selected.code;
  fSkip.value = '0';
  setTimeout(() => form.submit(), 700);
});

btnSkip.addEventListener('click', () => {
  fLang.value = selected ? selected.code : '';
  fSkip.value = '1';
  form.submit();
});

// Preselect saved lang
if (SAVED_LANG) {
  const L = LANGS.find(x => x.code === SAVED_LANG);
  const btn = L ? grid.querySelector('[data-code="' + SAVED_LANG + '"]') : null;
  if (L && btn) choose(L, btn);
}
</script>
</body>
</html>`
}

export default router
