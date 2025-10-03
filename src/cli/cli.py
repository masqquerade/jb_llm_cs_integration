import argparse
from typing import List, Dict, Any

class CLI:
    def __init__(self, args: List[Dict[str, Any]], programName: str, description: str):
        self.parser = argparse.ArgumentParser(
            prog=programName,
            description=description,
        )

        for arg in args:
            arg = dict(arg)

            flags = arg.pop("flags", None)
            name = arg.pop("name", None)

            if flags is None:
                if name is None:
                    raise ValueError("Each arg must have either name of flags")
                flags = [name]

            self.parser.add_argument(*flags, **arg)

        self.args = self.parser.parse_args()

    # Simple by-name get method
    def get_arg(self, name: str):
        return getattr(self.args, name)