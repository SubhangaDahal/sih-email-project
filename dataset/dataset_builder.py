import pandas as pd
import asyncio
import json
from openai import AsyncOpenAI
from api_key_fetcher import get_ai_credits_key

client = AsyncOpenAI(
    base_url='http://https://api.aicredits.in/v1',
    api_key=get_ai_credits_key(),
)

MODEL_ID = "openai/gpt-4o-mini"
INPUT_CSV = "./phishing_emails.csv"
OUTPUT_CSV = "./phishing_emails_features.csv"

# Balanced split: 1500 phishing + 1500 legitimate = 3000 total
TOTAL_ROWS = 3000
SAMPLES_PER_CLASS = TOTAL_ROWS // 2

MAX_CONCURRENCY_REQUESTS = 50
semaphore = asyncio.Semaphore(MAX_CONCURRENCY_REQUESTS)

SYSTEM_PROMPT = """You are a cybersecurity intent analyzer. Analyze the following email body and score these four psychological manipulation tactics from 0.0 to 1.0.
Respond ONLY with a valid JSON object matching this exact schema:
{
    "urgency_score": 0.0,
    "financial_request_score": 0.0,
    "authority_impersonation_score": 0.0,
    "grammar_anomaly_score": 0.0
}
"""


# ======================================================================
# ASYNC WORKER
# ======================================================================

async def process_single_row(row_dict: dict, index: int) -> dict | None:
    """Processes a single row while respecting the semaphore limit."""
    body_text = str(row_dict.get("body", row_dict.get("text", ""))).strip()

    # Truncate overly long bodies to bound token consumption and latency
    truncated_body = body_text[:4000]

    if not truncated_body:
        row_dict["urgency_score"] = 0.0
        row_dict["financial_request_score"] = 0.0
        row_dict["authority_impersonation_score"] = 0.0
        row_dict["grammar_anomaly_score"] = 0.0
        return row_dict

    async with semaphore:
        for attempt in range(3):
            try:
                response = await client.chat.completions.create(
                    model=MODEL_ID,
                    messages=[
                        {"role": "system", "content": SYSTEM_PROMPT},
                        {"role": "user", "content": f"Email text:\n{truncated_body}"}
                    ],
                    response_format={"type": "json_object"},
                    temperature=0.1,
                    timeout=15.0
                )

                content = response.choices[0].message.content
                if not content:
                    continue

                result = json.loads(content)

                # Map extracted scores back to the row
                row_dict["urgency_score"] = float(result.get("urgency_score", 0.0))
                row_dict["financial_request_score"] = float(result.get("financial_request_score", 0.0))
                row_dict["authority_impersonation_score"] = float(result.get("authority_impersonation_score", 0.0))
                row_dict["grammar_anomaly_score"] = float(result.get("grammar_anomaly_score", 0.0))

                return row_dict

            except Exception as e:
                if attempt == 2:
                    print(f"[-] Failed row {index} after 3 attempts: {e}")
                    return None
                await asyncio.sleep(1 + attempt)

    return None


# ======================================================================
# MAIN EXECUTION PIPELINE
# ======================================================================

async def main():
    print(f"[*] Loading dataset from {INPUT_CSV}...")
    df = pd.read_csv(INPUT_CSV)

    # Detect label column name ('label', 'Email Type', 'target', etc.)
    label_col = next((col for col in ["label", "Email Type", "Class", "target"] if col in df.columns), None)
    if not label_col:
        raise ValueError(f"Could not identify a label column in {df.columns.tolist()}")

    # Stratified balance: pull 1500 safe and 1500 phishing samples
    phishing_df = df[df[label_col].isin([1, "Phishing Email", "1"])].head(SAMPLES_PER_CLASS)
    safe_df = df[df[label_col].isin([0, "Safe Email", "0"])].head(SAMPLES_PER_CLASS)

    selected_df = pd.concat([phishing_df, safe_df]).sample(frac=1, random_state=42).reset_index(drop=True)
    print(f"[*] Prepared {len(selected_df)} rows ({len(phishing_df)} phishing, {len(safe_df)} safe)")

    rows = selected_df.to_dict(orient="records")

    print(f"[*] Dispatching requests with concurrency limit = {MAX_CONCURRENCY_REQUESTS}...")
    tasks = [process_single_row(row, idx) for idx, row in enumerate(rows)]

    results = await tqdm.gather(*tasks, desc="Extracting features")

    # Filter out dropped / failed rows
    successful_rows = [r for r in results if r is not None]
    print(f"[+] Successfully scored {len(successful_rows)} / {len(rows)} emails.")

    out_df = pd.DataFrame(successful_rows)
    out_df.to_csv(OUTPUT_CSV, index=False)
    print(f"[+] Saved enriched features dataset to {OUTPUT_CSV}")


if __name__ == "__main__":
    asyncio.run(main())