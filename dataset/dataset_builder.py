"""
dataset/dataset_builder.py

Semantic Feature Extraction Pipeline for Text-Only Phishing Corpora.
Extracts psychological threat vectors using an LLM gateway (AICredits)
to generate structured tabular inputs for XGBoost classification:
  - urgency_score
  - financial_request_score
  - authority_impersonation_score
  - grammar_anomaly_score
"""

import asyncio
import json
from pathlib import Path

import pandas as pd
from openai import AsyncOpenAI
from tqdm.asyncio import tqdm

from api_key_fetcher import get_ai_credits_key

# ======================================================================
# CONFIGURATION & PATH RESOLUTION
# ======================================================================

DATASET_DIR = Path(__file__).resolve().parent

# Auto-detect singular or plural dataset file naming
if (DATASET_DIR / "phishing_email.csv").is_file():
    INPUT_CSV = DATASET_DIR / "phishing_email.csv"
elif (DATASET_DIR / "phishing_emails.csv").is_file():
    INPUT_CSV = DATASET_DIR / "phishing_emails.csv"
else:
    raise FileNotFoundError(
        f"Neither phishing_email.csv nor phishing_emails.csv found inside {DATASET_DIR}"
    )

OUTPUT_CSV = DATASET_DIR / "phishing_emails_features.csv"
CHECKPOINT_JSONL = DATASET_DIR / "features_checkpoint.jsonl"

MODEL_ID = "openai/gpt-4o-mini"

# Target: 1500 phishing + 1500 safe = 3000 total samples
TOTAL_ROWS = 3000
SAMPLES_PER_CLASS = TOTAL_ROWS // 2

# Controlled concurrency to respect gateway rate limits
MAX_CONCURRENCY = 15
semaphore = asyncio.Semaphore(MAX_CONCURRENCY)

SYSTEM_PROMPT = """You are a cybersecurity intent analyzer. Analyze the provided email body and score these four psychological manipulation tactics from 0.0 to 1.0.
Respond ONLY with a valid JSON object matching this exact schema:
{
    "urgency_score": 0.0,
    "financial_request_score": 0.0,
    "authority_impersonation_score": 0.0,
    "grammar_anomaly_score": 0.0
}
"""

_client: AsyncOpenAI | None = None


def get_client() -> AsyncOpenAI:
    global _client
    if _client is None:
        key = get_ai_credits_key()
        if not key:
            raise ValueError(
                "AI_CREDITS_KEY is missing or empty. Check your .env file."
            )
        _client = AsyncOpenAI(
            base_url="https://api.aicredits.in/v1",
            api_key=key,
        )
    return _client


# ======================================================================
# COLUMN & TEXT EXTRACTION UTILITIES
# ======================================================================

def resolve_column(df: pd.DataFrame, candidates: list[str]) -> str:
    """Finds the first existing column matching candidate names."""
    for col in candidates:
        if col in df.columns:
            return col
    raise KeyError(
        f"None of {candidates} found in dataset. Existing columns: {df.columns.tolist()}"
    )


def extract_body(val) -> str:
    """Cleans body values and rejects NaN/empty strings."""
    if pd.isna(val) or val is None:
        return ""
    text_str = str(val).strip()
    if text_str.lower() in {"nan", "none", ""}:
        return ""
    return text_str


def normalize_label(val) -> int:
    """Normalizes various label representations into integer 0 (safe) or 1 (phishing)."""
    if pd.isna(val):
        return 0
    str_val = str(val).strip().lower()
    if str_val in {"1", "1.0", "phishing", "phishing email", "spam", "true"}:
        return 1
    return 0


# ======================================================================
# WORKER
# ======================================================================

async def process_single_row(
    row_dict: dict,
    index: int,
    text_col: str,
    label_col: str,
) -> dict | None:
    client = get_client()
    raw_text = extract_body(row_dict.get(text_col))
    norm_label = normalize_label(row_dict.get(label_col))

    # Bounded length to preserve token budget and reduce inference latency
    truncated_text = raw_text[:3500]

    base_feature_record = {
        "sample_id": index,
        "label": norm_label,
        "body_length": len(raw_text),
    }

    if not truncated_text:
        base_feature_record.update({
            "urgency_score": 0.0,
            "financial_request_score": 0.0,
            "authority_impersonation_score": 0.0,
            "grammar_anomaly_score": 0.0,
        })
        return base_feature_record

    async with semaphore:
        for attempt in range(3):
            try:
                response = await client.chat.completions.create(
                    model=MODEL_ID,
                    messages=[
                        {"role": "system", "content": SYSTEM_PROMPT},
                        {
                            "role": "user",
                            "content": f"Email text:\n{truncated_text}",
                        },
                    ],
                    response_format={"type": "json_object"},
                    temperature=0.1,
                    timeout=20.0,
                )

                content = response.choices[0].message.content
                if not content:
                    raise ValueError("Empty completion payload received.")

                scores = json.loads(content)

                base_feature_record.update({
                    "urgency_score": float(scores.get("urgency_score", 0.0)),
                    "financial_request_score": float(scores.get("financial_request_score", 0.0)),
                    "authority_impersonation_score": float(scores.get("authority_impersonation_score", 0.0)),
                    "grammar_anomaly_score": float(scores.get("grammar_anomaly_score", 0.0)),
                })
                return base_feature_record

            except Exception as exc:
                if attempt == 2:
                    print(f"[-] Dropping record index {index} after 3 attempts: {exc}")
                    return None
                await asyncio.sleep(1.5 * (attempt + 1))

    return None


# ======================================================================
# BATCH EXECUTION & CHECKPOINTING
# ======================================================================

async def main():
    print(f"[*] Reading dataset: {INPUT_CSV}")
    df = pd.read_csv(INPUT_CSV)
    print(f"[*] Loaded records: {len(df)}")

    text_col = resolve_column(
        df,
        ["text_combined", "text", "Email Text", "Email_Text", "content", "Message", "mail"],
    )
    label_col = resolve_column(
        df,
        ["label", "Email Type", "Email_Type", "Class", "target", "spam"],
    )
    print(f"[*] Target columns identified -> text: '{text_col}', label: '{label_col}'")

    # Filter invalid/empty email bodies
    df["_cleaned_body"] = df[text_col].apply(extract_body)
    df = df[df["_cleaned_body"] != ""].copy()
    df["_norm_label"] = df[label_col].apply(normalize_label)

    # Stratified balance: 1500 safe and 1500 phishing samples
    phishing_subset = df[df["_norm_label"] == 1].head(SAMPLES_PER_CLASS)
    safe_subset = df[df["_norm_label"] == 0].head(SAMPLES_PER_CLASS)

    balanced_df = (
        pd.concat([phishing_subset, safe_subset])
        .sample(frac=1.0, random_state=42)
        .reset_index(drop=True)
    )

    total_selected = len(balanced_df)
    print(
        f"[*] Selected {total_selected} balanced samples "
        f"({len(phishing_subset)} phishing, {len(safe_subset)} safe)"
    )

    records = balanced_df.to_dict(orient="records")

    # Load existing checkpoint if resuming an interrupted run
    processed_ids = set()
    collected_results = []

    if CHECKPOINT_JSONL.exists():
        with open(CHECKPOINT_JSONL, "r", encoding="utf-8") as f:
            for line in f:
                if line.strip():
                    item = json.loads(line)
                    processed_ids.add(item["sample_id"])
                    collected_results.append(item)
        print(f"[*] Found checkpoint with {len(processed_ids)} already-scored records. Resuming...")

    remaining_tasks = [
        (idx, row) for idx, row in enumerate(records) if idx not in processed_ids
    ]

    # Pre-flight check on the first pending item
    if remaining_tasks:
        print("[*] Running pre-flight request for sanity check...")
        first_idx, first_row = remaining_tasks[0]
        test_res = await process_single_row(first_row, first_idx, text_col, label_col)
        if test_res:
            print(
                f"[+] Pre-flight OK -> urgency: {test_res['urgency_score']}, "
                f"financial: {test_res['financial_request_score']}, "
                f"authority: {test_res['authority_impersonation_score']}, "
                f"grammar: {test_res['grammar_anomaly_score']}"
            )
            collected_results.append(test_res)
            processed_ids.add(first_idx)
            with open(CHECKPOINT_JSONL, "a", encoding="utf-8") as f:
                f.write(json.dumps(test_res) + "\n")
            remaining_tasks.pop(0)

    # Run remaining rows concurrently
    if remaining_tasks:
        print(f"[*] Queueing {len(remaining_tasks)} items with concurrency {MAX_CONCURRENCY}...")

        with open(CHECKPOINT_JSONL, "a", encoding="utf-8") as chk_file:
            tasks = [
                process_single_row(row, idx, text_col, label_col)
                for idx, row in remaining_tasks
            ]

            for future in tqdm.as_completed(tasks, desc="Scoring Semantics"):
                res = await future
                if res is not None:
                    collected_results.append(res)
                    chk_file.write(json.dumps(res) + "\n")
                    chk_file.flush()

    print(f"[+] Processing finished. Writing structured tabular file to {OUTPUT_CSV}...")
    final_df = pd.DataFrame(collected_results)

    # Export structured feature columns
    export_columns = [
        "sample_id",
        "urgency_score",
        "financial_request_score",
        "authority_impersonation_score",
        "grammar_anomaly_score",
        "body_length",
        "label",
    ]
    final_df = final_df[export_columns]
    final_df.to_csv(OUTPUT_CSV, index=False)

    print(f"[✔] Successfully exported {len(final_df)} rows to {OUTPUT_CSV}")


if __name__ == "__main__":
    asyncio.run(main())