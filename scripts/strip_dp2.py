import json

lines = [
    json.loads(l)
    for l in open(
        "scenarios/colonial-pipeline/grader/canonical_events.ndjson", encoding="utf-8"
    )
]
for l in lines:
    l["phase"] = "unknown"
    l["attack"] = []
    l["actor"] = "unknown"

with open("stripped.ndjson", "w", encoding="utf-8") as f:
    f.write("\n".join(json.dumps(l) for l in lines))