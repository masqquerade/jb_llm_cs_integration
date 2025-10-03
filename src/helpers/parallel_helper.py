import json
from concurrent.futures import as_completed
from concurrent.futures.thread import ThreadPoolExecutor
from typing import Iterable, List

# Batches generator function
def chunked(seq: List, size: int) -> Iterable[List]:
    for i in range(0, len(seq), size):
        yield seq[i:i+size]

# Run LLM requests using Threads for speedup
def verify_batches_parallel(
        llm,
        schema,
        items: List[dict],
        prompt_filename: str,
        batch_size: int = 15,
        max_workers: int = 9,
):
    batches = list(chunked(items, batch_size))
    results = []

    with ThreadPoolExecutor(max_workers=max_workers) as ex:
        future_to_idx = {
            ex.submit(llm.verifyBatch, batch, schema, prompt_filename): idx for idx, batch in enumerate(batches)
        }

        for fut in as_completed(future_to_idx):
            try:
                content = fut.result()
                parsed = json.loads(content)
                results.append(parsed)
            except Exception as e:
                print(e)

    return results