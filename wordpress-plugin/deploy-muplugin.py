#!/usr/bin/env python3
"""
deploy-muplugin.py — Deploy pb-auth-gate mu-plugin to Paisabot WP sites via FTP.

Usage:
    python3 deploy-muplugin.py                   # deploy to all sites
    python3 deploy-muplugin.py qa                # deploy to qa only (recommended first)
    python3 deploy-muplugin.py qa hi ml tel      # specific sites

Rollback:
    Delete the mu-plugin via FTP or SSH:
        rm -rf /public_html/wp-content/mu-plugins/pb-auth-gate/
    Sites revert to open (ungated) immediately — no theme change needed.

Adding a new language site:
    1. Add an entry to SITES below (copy an existing Indic site entry).
    2. Add the lang→subdomain mapping to PB_LANG_SUBDOMAIN in pb-auth-gate.php.
    3. Run: python3 deploy-muplugin.py <new-site-key>
    4. Verify the gate appears on qa equivalent first.
"""

import ftplib
import os
import ssl
import sys
import time

# ── Config ──────────────────────────────────────────────────────────────────

FTP_HOST = "217.21.85.66"
FTP_PORT = 21

LOCAL_PLUGIN = os.path.join(os.path.dirname(__file__), "pb-auth-gate")
REMOTE_DIR   = "wp-content/mu-plugins/pb-auth-gate"

# WordPress only auto-loads .php files at the mu-plugins ROOT (not subdirs), so a
# one-line loader stub is required alongside the plugin directory.
LOADER_REMOTE = "wp-content/mu-plugins/pb-auth-gate.php"
LOADER_BODY   = b"<?php require_once __DIR__ . '/pb-auth-gate/pb-auth-gate.php';\n"

# Docroot base per FTP account. Subdomain FTP users land directly in their
# docroot (base ""). The MAIN account (u928714162) lands in the home dir whose
# `cwd public_html` FAILS — its real docroot is domains/paisabot.com/public_html.

SITES = {
    "qa": {
        "label": "qa.paisabot.com",
        "user":  "u928714162.qa.paisabot.com",
    },
    "paisabot": {
        "label": "paisabot.com",
        "user":  "u928714162",
        "base":  "domains/paisabot.com/public_html",
    },
    "hi": {
        "label": "hi.paisabot.com",
        "user":  "u928714162.hi.paisabot.com",
    },
    "ml": {
        "label": "ml.paisabot.com",
        "user":  "u928714162.ml.paisabot.com",
    },
    "tel": {
        "label": "tel.paisabot.com",
        "user":  "u928714162.tel.paisabot.com",
    },
    # ta/mr/gu/kn/bn/or were re-created as SUBDOMAINS of paisabot.com (not addon
    # sites) to dodge a broken addon-vhost mapping that served the parking page.
    # They live as subdirectories under the MAIN account's docroot, so deploy via
    # the main FTP user (u928714162) with base domains/paisabot.com/public_html/<sub>.
    "ta": {
        "label": "ta.paisabot.com",
        "user":  "u928714162",
        "base":  "domains/paisabot.com/public_html/ta",
    },
    "mr": {
        "label": "mr.paisabot.com",
        "user":  "u928714162",
        "base":  "domains/paisabot.com/public_html/mr",
    },
    "gu": {
        "label": "gu.paisabot.com",
        "user":  "u928714162",
        "base":  "domains/paisabot.com/public_html/gu",
    },
    "kn": {
        "label": "kn.paisabot.com",
        "user":  "u928714162",
        "base":  "domains/paisabot.com/public_html/kn",
    },
    "bn": {
        "label": "bn.paisabot.com",
        "user":  "u928714162",
        "base":  "domains/paisabot.com/public_html/bn",
    },
    "or": {
        "label": "or.paisabot.com",
        "user":  "u928714162",
        "base":  "domains/paisabot.com/public_html/or",
    },
}

EXCLUDE_FILES = {".DS_Store", ".gitignore", "__pycache__"}

# ── Helpers ──────────────────────────────────────────────────────────────────

def ftp_mkdir_p(ftp, path):
    """Create remote directory tree, ignoring already-exists errors."""
    parts = path.strip("/").split("/")
    current = ""
    for part in parts:
        current = f"{current}/{part}" if current else part
        try:
            ftp.mkd(current)
        except ftplib.error_perm:
            pass  # already exists


def upload_dir(ftp, local_dir, remote_dir):
    ftp_mkdir_p(ftp, remote_dir)
    total = 0
    for entry in sorted(os.listdir(local_dir)):
        if entry in EXCLUDE_FILES:
            continue
        local_path  = os.path.join(local_dir, entry)
        remote_path = f"{remote_dir}/{entry}"
        if os.path.isdir(local_path):
            sub_total = upload_dir(ftp, local_path, remote_path)
            total += sub_total
        else:
            with open(local_path, "rb") as f:
                ftp.storbinary(f"STOR {remote_path}", f)
            print(f"    ✓ {entry}")
            total += 1
    return total


def _ftp_connect(user, password):
    """Try explicit FTPS first, fall back to plain FTP."""
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ftp = ftplib.FTP_TLS(context=ctx)
        ftp.connect(FTP_HOST, FTP_PORT, timeout=30)
        ftp.auth()
        ftp.login(user, password)
        ftp.prot_p()
        ftp.set_pasv(True)
        return ftp
    except Exception:
        ftp = ftplib.FTP()
        ftp.connect(FTP_HOST, FTP_PORT, timeout=30)
        ftp.login(user, password)
        ftp.set_pasv(True)
        return ftp


def deploy_site(key, cfg, password):
    label = cfg["label"]
    user  = cfg["user"]
    base  = cfg.get("base", "")
    print(f"\n{'─'*60}")
    print(f"  → {label}")
    print(f"{'─'*60}")

    ftp = _ftp_connect(user, password)

    # cd into the account's docroot. Explicit `base` (e.g. the main account's
    # domains/paisabot.com/public_html) wins; otherwise try public_html and
    # ignore failure — subdomain users already land in their docroot.
    if base:
        ftp_mkdir_p(ftp, base)
        ftp.cwd(base)
    else:
        try:
            ftp.cwd("public_html")
        except ftplib.error_perm:
            pass

    start = time.time()
    # Loader stub at mu-plugins root (WP ignores subdir-only plugins).
    ftp_mkdir_p(ftp, "wp-content/mu-plugins")
    from io import BytesIO
    ftp.storbinary(f"STOR {LOADER_REMOTE}", BytesIO(LOADER_BODY))
    count = 1 + upload_dir(ftp, LOCAL_PLUGIN, REMOTE_DIR)
    ftp.quit()

    elapsed = time.time() - start
    print(f"  ✅ {count} files in {elapsed:.1f}s")
    return True


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    targets = sys.argv[1:] if len(sys.argv) > 1 else list(SITES.keys())

    unknown = [t for t in targets if t not in SITES]
    if unknown:
        print(f"Unknown site(s): {', '.join(unknown)}")
        print(f"Valid: {', '.join(SITES.keys())}")
        sys.exit(1)

    print(f"\nDeploying pb-auth-gate mu-plugin to: {', '.join(targets)}")
    print(f"Local source: {LOCAL_PLUGIN}")

    if not os.path.isdir(LOCAL_PLUGIN):
        print(f"ERROR: plugin directory not found: {LOCAL_PLUGIN}")
        sys.exit(1)

    import getpass
    password = getpass.getpass("\nFTP password (shared across all sites): ")

    results = {}
    for key in targets:
        try:
            results[key] = deploy_site(key, SITES[key], password)
        except Exception as e:
            print(f"  ❌ FAILED: {e}")
            results[key] = False

    print(f"\n{'═'*60}")
    print("  SUMMARY")
    print(f"{'═'*60}")
    for key, ok in results.items():
        status = "✅" if ok else "❌"
        print(f"  {status}  {SITES[key]['label']}")

    failed = [k for k, ok in results.items() if not ok]
    if failed:
        print(f"\nFailed: {', '.join(failed)}")
        sys.exit(1)
    else:
        print("\nAll sites deployed successfully.")
        print("\nVerify at: https://qa.paisabot.com (open a new incognito window)")
        print("Rollback:  Delete wp-content/mu-plugins/pb-auth-gate/ via FTP on any site")


if __name__ == "__main__":
    main()
