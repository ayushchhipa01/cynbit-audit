import time
import re
from urllib.parse import urlparse, parse_qs
from playwright.sync_api import sync_playwright

BASE_URL = "https://www.cynbit.in"
OUTPUT_FILE = "audit_report.txt"

# Reset/clear previous report file
with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
    f.write(f"=== AUDIT REPORT FOR {BASE_URL} ===\n\n")

def log(message: str):
    """Prints to console and appends to the log file."""
    print(message)
    with open(OUTPUT_FILE, "a", encoding="utf-8") as f:
        f.write(message + "\n")

SENSITIVE_PATTERNS = [
    re.compile(r'("_id"\s*:\s*"[^"]+")', re.IGNORECASE),
    re.compile(r'("email"\s*:\s*"[^"]+@[^"]+")', re.IGNORECASE),
    re.compile(r'("(secret|token|password|apiKey|internalStatus)"\s*:\s*"[^"]+")', re.IGNORECASE),
]

def on_response(response):
    url = response.url
    status = response.status
    headers = response.headers
    timing = response.request.timing

    # 1. Header fingerprinting
    for header in ["x-powered-by", "x-nextjs-cache", "x-vercel-id", "server"]:
        if header in headers:
            log(f"[HEADER EXPOSED] {url[:60]}... -> {header}: {headers[header]}")

    # 2. RSC Payload & Data Over-fetching check
    if "_rsc=" in url:
        duration = timing.get("responseEnd", 0) - timing.get("requestStart", 0)
        log(f"[RSC PREFETCH] Status: {status} | Duration: {duration:.1f}ms | URL: {url.split('?')[0]}")
        try:
            text_body = response.text()
            for pattern in SENSITIVE_PATTERNS:
                matches = pattern.findall(text_body)
                if matches:
                    log(f"  [DATA LEAK ALERT] Found potential sensitive key: {matches[:2]}")
        except Exception:
            pass

    # 3. Image Optimization & Placeholder Checks
    if "image" in url or "_next/image" in url:
        parsed = urlparse(url)
        params = parse_qs(parsed.query)

        if "w" in params and params["w"][0] == "1920":
            log(f"[IMAGE AUDIT] Over-sized width (w=1920) requested: {url[:80]}...")

        if "url" in params:
            img_src = params["url"][0]
            if "pravatar.cc" in img_src:
                log(f"[MOCK DATA DETECTED] Production asset proxying mock avatar: {img_src}")

def run_audit():
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        )
        page = context.new_page()
        page.on("response", on_response)

        log(f"=== [1] PASSIVE AUDIT: {BASE_URL} ===\n")
        page.goto(BASE_URL, wait_until="networkidle")
        time.sleep(2)

        log("\n=== [2] CLIENT INPUT VALIDATION AUDITS ===")
        test_routes = [
            f"{BASE_URL}/bitelevate/paths",
            f"{BASE_URL}/services",
            f"{BASE_URL}/products"
        ]

        for route in test_routes:
            try:
                log(f"\nTesting route: {route}")
                page.goto(route, wait_until="domcontentloaded")
                time.sleep(1)

                email_inputs = page.locator('input[type="email"], input[name*="email"]').all()
                name_inputs = page.locator('input[name*="name"], input[placeholder*="Name"]').all()

                for field in email_inputs:
                    field.fill("999@r")
                    field.press("Tab")
                    is_valid = field.evaluate("el => el.checkValidity()")
                    msg = field.evaluate("el => el.validationMessage")
                    log(f"  [EMAIL INPUT] Value: '999@r' | Browser Valid: {is_valid} | Message: '{msg}'")

                for field in name_inputs:
                    field.fill("9999")
                    field.press("Tab")
                    val = field.input_value()
                    log(f"  [NAME INPUT] Value accepted: '{val}'")

            except Exception as e:
                log(f"  [ERROR] Route check failed: {e}")

        browser.close()
        log("\n=== AUDIT COMPLETED ===")

if __name__ == "__main__":
    run_audit()
    print(f"\nAudit complete! The results are saved in '{OUTPUT_FILE}'.")