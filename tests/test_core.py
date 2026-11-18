
import unittest
from pathlib import Path

from analysis_core import MAX_BYTES, InputError, assess, parse, report
from model import load_split, score, train_model

SAMPLES = Path(__file__).resolve().parents[1] / "samples"


def sample(name):
    filename = name + ".eml"
    return parse((SAMPLES / filename).read_bytes(), filename)


class ParsingTests(unittest.TestCase):
    def test_plain_paste(self):
        email = parse(b"Please look at https://files.example/a, thanks!")
        self.assertEqual(email.links[0].destination, "https://files.example/a")
        self.assertEqual(assess(email)[0], "Review")

    def test_paste_with_headers(self):
        email = parse(b"From: a@team.example\nReply-To: a@team.example\nSubject: Hi\n\nBody")
        self.assertEqual(email.domains["From"], "team.example")
        self.assertEqual(assess(email)[0], "Low")

    def test_multipart_mismatch(self):
        email = sample("suspicious")
        self.assertEqual(len(email.links), 1)
        result = assess(email)
        self.assertEqual(result[:2], ("High", 12))
        self.assertIn("Visible: https://studio.example/review", result[2][1].observed)
        self.assertIn("Destination: https://support.example:8443/review", result[2][1].observed)

    def test_missing_claims_are_uncertainty(self):
        result = assess(sample("ambiguous"))
        self.assertEqual(result, ("Review", 0, [], ["From", "Reply-To"], []))

    def test_normal_sample(self):
        self.assertEqual(assess(sample("normal"))[:2], ("Low", 0))

    def test_malformed_mime(self):
        with self.assertRaisesRegex(InputError, "Malformed MIME"):
            parse(b"From: a@example.com\nContent-Type: multipart/mixed\n\nNo boundary", "bad.eml")

    def test_size_and_type(self):
        with self.assertRaisesRegex(InputError, "1 MiB"):
            parse(b"x" * (MAX_BYTES + 1), "large.eml")
        with self.assertRaisesRegex(InputError, "Upload an .eml"):
            parse(b"Body", "wrong.txt")

    def test_inert_content_and_report(self):
        raw = (b"Content-Type: text/html\n\n"
               b"<img src='https://tracker.example/pixel'><script>untrusted()</script>"
               b"<p>Body marker</p><a href='https://two.example'>https://one.example</a>")
        email = parse(raw, "html.eml")
        self.assertNotIn("tracker", str(email.links))
        self.assertNotIn("untrusted", email.body)
        document = report(email, assess(email))
        self.assertIn("    Destination: https://two.example", document)
        self.assertNotIn("Body marker", document)

    def test_repeat_points_capped(self):
        email = parse(b"Visit http://127.0.0.1 and http://192.0.2.1")
        _, points, findings, *_ = assess(email)
        self.assertEqual(len(findings), 2)
        self.assertEqual(points, 2)

    def test_unsupported_body(self):
        with self.assertRaisesRegex(InputError, "No readable body"):
            parse(b"Content-Type: application/octet-stream\n\nabc", "data.eml")


class ModelTests(unittest.TestCase):
    def test_grouped_split_and_score(self):
        train, evaluation = load_split()
        self.assertEqual(len(evaluation), 6)
        self.assertFalse({row["family"] for row in train} & {row["family"] for row in evaluation})
        model = train_model()
        self.assertTrue(0 <= score(model, sample("normal")) <= 1)
