#!/usr/bin/env python3
"""CLI: examine the ClearPass certificate trust list and selectively remove SHA-1 certificates."""

import argparse
import json
import os
import sys

from app.clearpass import (
    ClearPassConfig,
    fetch_all_trust_list,
    identify_sha1_certs,
    make_login,
    remove_cert,
)


def build_config(args) -> ClearPassConfig:
    server = args.server or os.environ.get("CLEARPASS_SERVER")
    if not server:
        sys.exit("Error: ClearPass server URL is required (--server or CLEARPASS_SERVER env var).")

    verify_ssl_env = os.environ.get("CLEARPASS_VERIFY_SSL", "true").lower()
    verify_ssl = args.verify_ssl and verify_ssl_env not in ("false", "0", "no")

    api_token     = args.api_token     or os.environ.get("CLEARPASS_API_TOKEN")
    client_id     = args.client_id     or os.environ.get("CLEARPASS_CLIENT_ID")
    client_secret = args.client_secret or os.environ.get("CLEARPASS_CLIENT_SECRET")

    if not api_token and not (client_id and client_secret):
        sys.exit(
            "Error: Provide authentication via --api-token, or both --client-id and --client-secret "
            "(or the corresponding environment variables)."
        )

    return ClearPassConfig(
        server=server,
        api_token=api_token or None,
        client_id=client_id or None,
        client_secret=client_secret or None,
        verify_ssl=verify_ssl,
    )


def format_cert_entry(entry: dict, index: int) -> str:
    return (
        f"  [{index}] ID: {entry.get('id', 'N/A')}\n"
        f"      Subject : {entry.get('subject') or entry.get('subject_dn') or entry.get('common_name') or 'Unknown'}\n"
        f"      Issuer  : {entry.get('issuer') or entry.get('issuer_dn') or 'Unknown'}\n"
        f"      Expires : {entry.get('not_after') or entry.get('valid_until') or entry.get('expiry_date') or 'Unknown'}\n"
        f"      Usage   : {entry.get('cert_usage') or entry.get('usage') or 'Unknown'}\n"
        f"      Detected: {entry.get('_detected_by', 'unknown')}"
    )


def cli_remove(login, cert_id, dry_run: bool = False) -> bool:
    if dry_run:
        print(f"  [dry-run] Would delete cert ID {cert_id}")
        return True
    try:
        remove_cert(login, cert_id)
        print(f"  Deleted cert ID {cert_id}")
        return True
    except Exception as exc:
        print(f"  Failed to delete cert ID {cert_id}: {exc}")
        return False


def run(login, dry_run: bool, auto_remove: bool, output_json: bool) -> None:
    print("Fetching certificate trust list from ClearPass...")
    all_entries = fetch_all_trust_list(login)
    print(f"Found {len(all_entries)} total trust list entries.")

    if not all_entries:
        print("No entries to examine.")
        return

    print("Checking for SHA-1 signed certificates...")
    sha1_certs = identify_sha1_certs(login, all_entries)

    if not sha1_certs:
        print("No SHA-1 certificates found in the trust list.")
        return

    print(f"\nFound {len(sha1_certs)} SHA-1 certificate(s):\n")

    if output_json:
        safe = [{k: v for k, v in c.items() if k != "_detected_by"} for c in sha1_certs]
        print(json.dumps(safe, indent=2, default=str))
        return

    for i, cert in enumerate(sha1_certs, start=1):
        print(format_cert_entry(cert, i))
        print()

    if dry_run:
        print("Dry-run mode: no certificates will be deleted.")
        for cert in sha1_certs:
            cli_remove(login, cert["id"], dry_run=True)
        return

    if auto_remove:
        print("Auto-remove mode: deleting all SHA-1 certificates...")
        removed = sum(1 for c in sha1_certs if cli_remove(login, c["id"]))
        print(f"\nRemoved {removed}/{len(sha1_certs)} certificate(s).")
        return

    # Interactive mode
    print("Select certificates to remove.")
    print("Enter comma-separated numbers (e.g. 1,3), 'all' to remove all, or 'none' to exit.\n")

    while True:
        choice = input("Your selection: ").strip().lower()

        if choice in ("none", "q", "quit", "exit", ""):
            print("No certificates removed.")
            return

        if choice == "all":
            selected = sha1_certs
        else:
            try:
                indices = [int(x.strip()) for x in choice.split(",")]
                if any(i < 1 or i > len(sha1_certs) for i in indices):
                    print(f"  Please enter numbers between 1 and {len(sha1_certs)}.")
                    continue
                selected = [sha1_certs[i - 1] for i in indices]
            except ValueError:
                print("  Invalid input. Use numbers, 'all', or 'none'.")
                continue

        print(f"\nAbout to delete {len(selected)} certificate(s):")
        for cert in selected:
            print(f"  - ID {cert.get('id')}: {cert.get('subject') or cert.get('common_name', 'Unknown')}")

        confirm = input("\nConfirm deletion? [y/N]: ").strip().lower()
        if confirm not in ("y", "yes"):
            print("Cancelled.")
            continue

        removed = sum(1 for c in selected if cli_remove(login, c["id"]))
        print(f"\nRemoved {removed}/{len(selected)} certificate(s).")
        return


def main():
    parser = argparse.ArgumentParser(
        description="List and remove SHA-1 certificates from the ClearPass trust list."
    )
    parser.add_argument("--server",        help="ClearPass server URL (e.g. https://cppm.example.com/api)")
    parser.add_argument("--api-token",     help="ClearPass API token")
    parser.add_argument("--client-id",     help="OAuth2 client ID")
    parser.add_argument("--client-secret", help="OAuth2 client secret")
    parser.add_argument("--no-verify-ssl", dest="verify_ssl", action="store_false", default=True,
                        help="Disable SSL certificate verification")
    parser.add_argument("--dry-run",    action="store_true", help="List SHA-1 certs but do not delete")
    parser.add_argument("--auto-remove", action="store_true", help="Remove all SHA-1 certs without prompting")
    parser.add_argument("--json", dest="output_json", action="store_true",
                        help="Output SHA-1 cert list as JSON (implies --dry-run)")
    args = parser.parse_args()

    if args.output_json:
        args.dry_run = True

    config = build_config(args)
    try:
        login = make_login(config)
    except ValueError as exc:
        sys.exit(f"Error: {exc}")

    run(login, dry_run=args.dry_run, auto_remove=args.auto_remove, output_json=args.output_json)


if __name__ == "__main__":
    main()
