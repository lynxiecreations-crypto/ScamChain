"""Train and persist ScamChain's synthetic demonstration model."""
import argparse
import json
from ml import ensure_model_artifact, MODEL_PATH, MODEL_META_PATH

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--force", action="store_true", help="retrain and overwrite the artifact")
    args = parser.parse_args()
    _, metadata = ensure_model_artifact(force_retrain=args.force)
    print(json.dumps({"status": "ready", "artifact_path": str(MODEL_PATH),
                      "metadata_path": str(MODEL_META_PATH), "metadata": metadata}, indent=2))

if __name__ == "__main__":
    main()
