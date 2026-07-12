import json
from datetime import datetime

events = {
    e["evidence_id"]: e
    for e in [
        json.loads(l)
        for l in open(
            "output/retail-test/grader/canonical_events.ndjson", encoding="utf-8"
        )
    ]
}
d = json.load(open("output/retail-test/grader/tiger.json", encoding="utf-8"))

violations = 0
for e in d["edges"]:
    if e["rule"] == "sequential_tools_same_host":
        a, b = e["evidence_ids"]
        ta = datetime.fromisoformat(events[a]["ts"].replace("Z", "+00:00"))
        tb = datetime.fromisoformat(events[b]["ts"].replace("Z", "+00:00"))
        delta = abs((tb - ta).total_seconds()) / 60
        if delta > 15:
            print("VIOLATION", a, b, round(delta, 1), "min")
            violations += 1

print("Total violations:", violations)