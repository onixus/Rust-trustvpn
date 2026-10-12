"""Freeze an explicit immutable Git commit into an empty Jenkins workspace."""
import argparse
import json
from source_provenance import snapshot

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('destination')
    parser.add_argument('--source', required=True)
    parser.add_argument('--sha', required=True)
    args = parser.parse_args()
    print(json.dumps(snapshot(args.source, args.sha, args.destination), sort_keys=True))
