# CLI args and their parameters
args = [
    {
        "name": "--repo",
        "type": str,
        "required": True,
        "help": "Repository path or GitHub URL"
    },
    {
        "name": "--n",
        "type": int,
        "required": True,
        "help": "Number of last commits to be scanned"
    },
    {
        "name": "--out",
        "type": str,
        "required": True,
        "help": "Path to output report (JSON)"
    },
    {
        "name": "--sensitive",
        "action": "store_true",
        "required": False,
        "help": "Scan for sensitive data and not for secrets."
    }
]