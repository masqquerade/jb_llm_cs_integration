import json
import os

from src.cli.cli import CLI
from src.core.regex import Regex
from src.core.repository import Repository, iter_added_lines
from src.core.llm.llm import LLM
from dotenv import load_dotenv
from src.cli.args import args
from src.helpers.parallel_helper import verify_batches_parallel
from src.core.llm.schemas.verifySecretsSchema import verifySecretsSchema
from src.core.llm.schemas.verifySensitiveSchema import verifySensitiveSchema

load_dotenv()

SECRETS_VERIFY_PROMPT_NAME = "secretsDataVerifyPrompt.txt"
SENSITIVE_VERIFY_PROMPT_NAME = "sensitiveDataVerifyPrompt.txt"

# Helper function to build llm-context dictionary for secrets
def get_secrets_llm_context_obj(candidate):
    return {
        "id": candidate["id"],
        "rule": candidate["rule"],
        "value": candidate["value"],
        "file": candidate["file"],
        "line": candidate["line"],
        "entropy": candidate["entropy"],
        "context": candidate["context"],
        "commit_message": candidate["commit"]["message"],
        "uri_detected": candidate["uri_detected"],
    }

def save_result(filename: str, result):
    with open(filename, "w") as f:
        json.dump(result, f, indent=4)

def form_llm_output(item, mapping):
    _id = item["id"]
    msg = mapping[_id]["commit"]["message"]
    file_name = mapping[_id]["file"]
    line = mapping[_id]["line"]
    reason = item["reason"]
    value = mapping[_id]["value"]
    _hash = mapping[_id]["commit"]["hash"]
    rule = mapping[_id]["rule"]
    text = f"[LLM][{file_name}][msg: {msg}]: Line {line}: ${reason} | {value}"

    return {
        "commit_hash": _hash,
        "commit_message": msg,
        "file_path": file_name,
        "line": line,
        "finding_type": rule,
        "rationale": f"{reason} | {item["label"]}",
        "snippet": value,
        "readable": text
    }

def parse_response(allowedValues, responses, map):
    tmp = []

    for response in responses:
        for item in response["items"]:
            if item["label"] == "secret" or item["label"] == "likely_secret":
                tmp.append(form_llm_output(item, map))

    return tmp


# Initiates heuristic and LLM (if needed) analysis of diffs
def analyse_secrets(repo, cli, regex, llm):
    commits = repo.get_last_commits(cli.get_arg("n"))

    llm_reports_map = {}
    llm_reports_list = []
    results = []

    for commit in commits:
        for diff in commit["diffs"]:
            for line in iter_added_lines(diff["patch"]):
                candidate = regex.detect_secret(line, diff["file"], commit)

                if candidate is not None:
                    llm_context_obj = get_secrets_llm_context_obj(candidate)

                    if candidate["kind"] == "LLM":
                        llm_reports_map[candidate["id"]] = candidate
                        llm_reports_list.append(llm_context_obj)
                    else:
                        results.append({
                            "commit_hash": candidate["commit"]["hash"],
                            "commit_message": candidate["commit"]["message"],
                            "file_path": candidate["file"],
                            "line": candidate["line"],
                            "finding_type": candidate["rule"],
                            "rationale": "Heuristic detection",
                            "snippet": candidate["value"],
                            "readable":
                                f"[HEURISTIC][{candidate["file"]}][msg: {candidate["commit"]["message"]}]: Line {candidate["line"]}: ${candidate["rule"]} | {candidate["value"]}"
                        })

    batch_responses = verify_batches_parallel(
        llm,
        schema=verifySecretsSchema,
        items=llm_reports_list,
        prompt_filename=SECRETS_VERIFY_PROMPT_NAME
    )

    results.extend(parse_response(["secret", "likely_secret"], batch_responses, llm_reports_map))
    save_result(cli.get_arg("out"), results)


def analyze_sensitive(repo, cli, regex, llm):
    commits = repo.get_last_commits(cli.get_arg("n"))

    llm_reports_list = []
    llm_reports_map = {}
    results = []

    for commit in commits:
        for diff in commit["diffs"]:
            for line in iter_added_lines(diff["patch"]):
                candidate = regex.detect_sensitive(line, diff["file"], commit)
                if candidate is not None:
                    llm_reports_list.append({
                        "id": candidate["id"],
                        "rule": candidate["rule"],
                        "file_name": candidate["file"],
                        "value": candidate["value"],
                        "commit_message": candidate["commit"]["message"],
                        "context": candidate["context"]
                    })
                    llm_reports_map[candidate["id"]] = candidate

    batch_responses = verify_batches_parallel(
        llm,
        items=llm_reports_list,
        schema=verifySensitiveSchema,
        prompt_filename=SENSITIVE_VERIFY_PROMPT_NAME
    )

    for response in batch_responses:
        for item in response["items"]:
            if item["label"] == "sensitive" or item["label"] == "likely_sensitive":
                results.append(form_llm_output(item, llm_reports_map))

    results.extend(parse_response(["sensitive", "likely_sensitive"], batch_responses, llm_reports_map))
    save_result(cli.get_arg("out"), results)

def main():
    # Initialize main instances
    cli = CLI(args, "Secrets seeker", "Find secrets (tokens, passwords, etc.) in your GitHub repository")
    repo = Repository(cli.get_arg("repo"))
    regex = Regex()
    llm = LLM(os.getenv("API_TOKEN"), os.getenv("LLM_MODEL"))

    sensitive_mode = cli.get_arg("sensitive")
    if sensitive_mode:
        # Run sensitivity analysis
        analyze_sensitive(repo, cli, regex, llm)
    else:
        # Run secrets analysis
        analyse_secrets(repo, cli, regex, llm)

    return

if __name__ == "__main__":
    main()