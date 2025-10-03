from pathlib import Path

def getVerifyPrompt(batch, filename):
    path = Path(__file__).parent / "prompts" / filename
    text = path.read_text(encoding="utf-8")

    for c in batch:
        c_text = " ".join(f"{k}={v}" for k, v in c.items())
        text += c_text
        text += "\n\n"

    return text

