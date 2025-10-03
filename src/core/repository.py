import re
import shutil
from hashlib import sha256
import os.path
from collections import deque

from git import Repo, NULL_TREE

TMP_FOLDER = "../../seeker_tmp/"

HUNK_HEADER_REGEX = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")

# Generator function that generates (number of line, line itself, context) triple.
def iter_added_lines(patch: str):
    new_line = None
    in_hunk = False
    lines = patch.splitlines()

    for i, line in enumerate(lines):
        match = HUNK_HEADER_REGEX.match(line)
        if match:
            in_hunk = True
            new_start = int(match.group(3))
            new_line = new_start
            continue

        if not in_hunk:
            continue

        if line.startswith("+") and not line.startswith("+++"):
            start = max(0, i - 3)
            end = min(len(lines), i + 4)
            yield new_line, line[1:], lines[start:end]
            new_line += 1
        elif line.startswith("-") or line.startswith("+"):
            pass
        else:
            if not line.startswith("\\"):
                new_line += 1

class Repository:
    def __init__(self, url_or_path: str):
        tmp_folder = os.path.abspath(TMP_FOLDER)
        os.makedirs(tmp_folder, exist_ok=True)

        if os.path.exists(url_or_path):
            self.repo = Repo(url_or_path)
            self.repo_name = os.path.basename(os.path.normpath(url_or_path))
            return

        self.repo_name = os.path.basename(re.sub(r"\.git$", "", url_or_path.rstrip("/")))
        repo_path = os.path.join(tmp_folder, self.repo_name)

        if os.path.exists(repo_path):
            self.repo = Repo(repo_path)
            self.repo.remotes.origin.fetch(prune=True)
        else:
            self.repo = Repo.clone_from(url_or_path, repo_path)

    # Returns last n commits from the local/remote repository
    def get_last_commits(self, n: int):
        commits = []

        for commit in list(self.repo.iter_commits(all=True, max_count=n)):
            # Retrieve changes
            if commit.parents:
                diffs = commit.parents[0].diff(commit, create_patch=True)
            else:
                diffs = commit.diff(NULL_TREE, create_patch=True)

            # Collect all useful information in commit_data
            commit_data = {
                "hash": commit.hexsha,
                "message": commit.message.strip(),
                "diffs": [
                    {
                        "file": d.b_path,
                        "patch": d.diff.decode("utf-8", errors="ignore")
                    }
                    for d in diffs
                ]
            }

            commits.append(commit_data)

        return commits
