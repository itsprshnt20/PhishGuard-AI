
"""Streamlit entry point for PhishGuard AI."""
from pathlib import Path

import streamlit as st

from analysis_core import CLAIMS, InputError, assess, parse, report
from model import score, train_model

SAMPLES = Path(__file__).resolve().parent / "samples"
STYLES = """<style>
.stApp, [data-testid="stHeader"] { background: #000; }
.stMainBlockContainer { max-width: 59rem; padding-top: 3.8rem; padding-bottom: 4rem; }
.st-key-hero {
    padding: clamp(1.3rem, 4vw, 2.65rem);
    border: 1px solid #27332d;
    border-radius: 1.4rem;
    background: radial-gradient(ellipse at 95% 0%, #142b21 0%, #090e0b 36%, #050605 72%);
    box-shadow: 0 12px 45px #000;
}
.st-key-hero h1 { font-size: clamp(2.55rem, 7vw, 4.75rem); letter-spacing: -.065em; line-height: 1; }
.st-key-hero [data-testid="stCaptionContainer"] { color: #a7b7ae; }
.st-key-intake, .st-key-results {
    background: #080a09;
    border: 1px solid #252f2a;
    border-radius: 1.25rem;
    padding: clamp(1rem, 3vw, 1.65rem);
}
.st-key-intake [data-testid="stForm"] { border: 0; padding: 0; }
.st-key-examples button, [data-testid="stDownloadButton"] button {
    border: 1px solid #303c35;
    background: #101411;
    min-height: 2.75rem;
    border-radius: .8rem;
}
.st-key-examples button:hover, [data-testid="stDownloadButton"] button:hover {
    background: #14231b;
    border-color: #8af0b8;
    color: #a7f5c8;
}
[data-testid="stBaseButton-primary"] {
    color: #06150e;
    background: #8af0b8;
    border-color: #8af0b8;
    border-radius: .75rem;
    font-weight: 700;
}
[data-testid="stBaseButton-primary"]:hover { color: #06150e; background: #b2ffd5; }
button:focus-visible, textarea:focus-visible { outline: 2px solid #a7f5c8; outline-offset: 3px; }
[data-testid="stMetric"] {
    background: #101411;
    border: 1px solid #26322a;
    border-radius: .85rem;
    padding: .9rem 1rem;
}
[data-testid="stMetricValue"] { font-variant-numeric: tabular-nums; font-weight: 680; }
.st-key-risk_high h2 { color: #ff9eaa; }
.st-key-risk_review h2 { color: #ffd18b; }
.st-key-risk_low h2 { color: #8af0b8; }
[data-testid="stCode"] pre { background: #0f1411; border: 1px solid #26322a; }
[data-testid="stExpander"] details { background: #0b100d; border-color: #29362d; }
@media (max-width: 600px) {
    .stMainBlockContainer { padding-top: 3rem; }
}
</style>"""


@st.cache_resource(show_spinner=False)
def local_model():
    return train_model()


def render(email):
    assessment = assess(email)
    level, points, findings, unknown, uncertain = assessment
    try:
        model_score = score(local_model(), email)
    except (ImportError, OSError, ValueError, RuntimeError):
        model_score = None

    with st.container(key=f"risk_{level.lower()}"):
        st.header(f"{level} triage assessment")
    left, right = st.columns(2)
    left.metric("Rule points · deterministic checks", points)
    right.metric("Local classifier score", "Unknown" if model_score is None else f"{model_score:.1%}")
    st.caption("The classifier uses TF-IDF and logistic regression on synthetic text. "
               "Its score is separate from triage and is not a real-world phishing probability.")
    st.subheader("Claimed headers")
    st.caption("These values are claims from the email. Sender identity is unverified.")
    st.code("\n".join(f"{name}: {email.headers.get(name) or 'Unknown'}" for name in CLAIMS),
            language=None)
    if unknown or uncertain:
        st.info("Missing headers: " + (", ".join(unknown) or "None") +
                ". Unusable address claims: " + (", ".join(uncertain) or "None") + ".")
    st.subheader("Evidence")
    if not findings:
        st.write("No configured rule fired.")
    for finding in findings:
        st.markdown(f"**{finding.title}** · +{finding.points}")
        st.write(finding.reason)
        st.code(finding.observed, language=None)
    with st.expander(f"Extracted links ({len(email.links)})"):
        if not email.links:
            st.write("No links extracted.")
        for link in email.links:
            st.code(f"Visible: {link.visible or '(empty)'}\nDestination: {link.destination}",
                    language=None)
    with st.expander("Email body preview"):
        st.code(email.body, language=None)
    st.download_button("Download Markdown report", report(email, assessment, model_score),
                       "phishguard-report.md", "text/markdown", on_click="ignore")


st.set_page_config(page_title="PhishGuard AI", layout="wide")
st.html(STYLES)
with st.container(key="hero"):
    st.title("PhishGuard AI")
    st.write("Review a suspicious email locally. Try a synthetic example or provide an email to inspect.")
    st.caption("Created and maintained by Prashant Chauhan")

with st.container(key="examples"):
    st.subheader("Synthetic examples")
    for column, name in zip(st.columns(3), ("Normal", "Suspicious", "Ambiguous")):
        if column.button(name, key=f"demo_{name.lower()}", use_container_width=True):
            filename = name.lower() + ".eml"
            st.session_state.input = ((SAMPLES / filename).read_bytes(), filename, f"Synthetic · {name}")

with st.container(key="intake"):
    st.subheader("Review an email")
    source = st.radio("Input type", ["Paste text", "Upload .eml"], horizontal=True)
    with st.form("email_input"):
        if source == "Paste text":
            pasted = st.text_area("Email text", height=155,
                                  placeholder="Paste the email body, or include its original headers.")
        else:
            upload = st.file_uploader("Email file (up to 1 MiB)", type=["eml"])
        if st.form_submit_button("Analyze email", type="primary"):
            if source == "Paste text":
                st.session_state.input = (pasted.encode("utf-8"), None, "Pasted email")
            else:
                st.session_state.input = (upload.getvalue() if upload else b"",
                                          upload.name if upload else "missing.eml", "Uploaded email")

with st.container(key="results"):
    if "input" in st.session_state:
        raw, filename, label = st.session_state.input
        st.divider()
        st.caption(label)
        try:
            with st.spinner("Analyzing email locally…"):
                render(parse(raw, filename))
        except InputError as error:
            st.error(str(error))
    else:
        st.info("Choose a synthetic example or submit an email to see its assessment.")
