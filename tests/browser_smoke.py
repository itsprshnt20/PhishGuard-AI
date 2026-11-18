
"""Exercise the running app with local Chromium and block external page requests.

Install the optional Playwright test dependency before running this script.
"""
from pathlib import Path
import sys

from playwright.sync_api import expect, sync_playwright

URL = sys.argv[1] if len(sys.argv) > 1 else "http://127.0.0.1:8501"
SAMPLES = Path(__file__).resolve().parents[1] / "samples"


def main():
    expect.set_options(timeout=45000)
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        context = browser.new_context(accept_downloads=True, service_workers="block")
        external = []

        def local_only(route):
            if route.request.url.startswith(URL + "/"):
                route.continue_()
            else:
                external.append(route.request.url)
                route.abort()

        context.route("**/*", local_only)
        page = context.new_page()
        page.goto(URL)
        expect(page.get_by_text("Choose a synthetic example", exact=False)).to_be_visible()
        for name, level in (("Normal", "Low"), ("Suspicious", "High"), ("Ambiguous", "Review")):
            page.get_by_role("button", name=name, exact=True).click()
            expect(page.get_by_role("heading", name=f"{level} triage assessment")).to_be_visible()
            if name == "Suspicious":
                expect(page.get_by_text("Visible URL / destination mismatch", exact=True)).to_be_visible()
                expect(page.locator("code").filter(has_text="https://studio.example/review").first).to_be_visible()
                expect(page.locator("a[href*='support.example']")).to_have_count(0)
            if name == "Ambiguous":
                expect(page.locator("code").filter(has_text="From: Unknown")).to_be_visible()
                expect(page.get_by_text("No configured rule fired.")).to_be_visible()
        print("PASS: all three demos, uncertainty, and inert mismatch evidence")

        page.get_by_role("textbox", name="Email text").fill("Can you review the meeting notes?")
        page.get_by_role("button", name="Analyze email").click()
        expect(page.get_by_text("Pasted email", exact=True)).to_be_visible()
        expect(page.get_by_role("heading", name="Review triage assessment")).to_be_visible()
        print("PASS: pasted text")

        page.get_by_text("Upload .eml", exact=True).click()
        uploader = page.locator('input[type="file"]')
        uploader.set_input_files(SAMPLES / "suspicious.eml")
        page.get_by_role("button", name="Analyze email").click()
        expect(page.get_by_text("Uploaded email", exact=True)).to_be_visible()
        expect(page.get_by_role("heading", name="High triage assessment")).to_be_visible()
        expect(page.get_by_text("Running...", exact=True)).to_be_hidden()
        with page.expect_download() as downloaded:
            page.get_by_role("button", name="Download Markdown report").click()
        document = downloaded.value.path().read_text(encoding="utf-8")
        assert "https://studio.example/review" in document
        assert "https://support.example:8443/review" in document
        assert "to keep access" not in document
        print("PASS: multipart upload and Markdown download")

        uploader.set_input_files({"name": "bad.eml", "mimeType": "message/rfc822",
                                  "buffer": b"Content-Type: multipart/mixed\n\nMissing boundary"})
        page.get_by_role("button", name="Analyze email").click()
        expect(page.get_by_text("Malformed MIME", exact=False)).to_be_visible()
        uploader.set_input_files({"name": "large.eml", "mimeType": "message/rfc822",
                                  "buffer": b"x" * (1024 * 1024 + 1)})
        expect(page.get_by_text("1MB", exact=False).last).to_be_visible()
        expect(page.get_by_text("large.eml", exact=True)).to_be_visible()
        print("PASS: malformed MIME and oversized upload validation")
        assert not external, external
        print("PASS: no external browser HTTP requests")
        browser.close()


if __name__ == "__main__":
    main()
