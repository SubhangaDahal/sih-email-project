"""
main.py

FastAPI delivery layer exposing the unified threat engine results to the frontend.
Engines: Auth (SPF/DKIM/DMARC), IOC (VirusTotal/Safe Browsing), Text AI + ML Model.
"""

from typing import Any, Dict, List, Literal, Optional
from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

# Engine imports
from engines.run_auth_checks import run_auth_checks
from engines.ioc_engine import run_ioc_intel
from engines.run_text_ai import run_text_ai
from svm_model import PhishingSVMPredictor

app = FastAPI(
    title="Email Threat Intelligence API",
    version="1.0.0",
    description="Multi-engine threat detection combining Auth, IOCs, and ML.",
)

# Enable CORS for frontend development (e.g. Next.js / React)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Load the trained ML threat model on startup
predictor: Optional[PhishingSVMPredictor] = None

@app.on_event("startup")
def load_model():
    global predictor
    try:
        predictor = PhishingSVMPredictor()
        print("[+] Machine learning threat predictor loaded successfully.")
    except Exception as exc:
        print(f"[!] Warning: ML model failed to load ({exc}). Fallbacks will be active.")


# ======================================================================
# PYDANTIC SCHEMAS (Request & Response)
# ======================================================================

class EmailAnalysisRequest(BaseModel):
    id: str
    thread_id: str
    timestamp: str
    sender: str = Field(..., alias="from")
    to: str
    subject: str
    snippet: str
    body: str
    headers: Dict[str, Any] = Field(default_factory=dict)
    urls: List[str] = Field(default_factory=list)
    attachments: List[Dict[str, Any]] = Field(default_factory=list)

    class Config:
        populate_by_name = True


class VerdictSchema(BaseModel):
    overall_score: float
    status: Literal["SAFE", "SUSPICIOUS", "MALICIOUS"]
    confidence: float
    primary_threat: str
    action_recommended: Literal["INBOX", "WARNING_BANNER", "QUARANTINE"]


class AuthEngineDetails(BaseModel):
    score: float
    status: str
    details: Dict[str, Any]
    reason: str


class IOCEngineDetails(BaseModel):
    score: float
    hits: int
    urls_checked: int
    malicious_urls: List[str]
    attachments_checked: int
    malicious_files: List[str]


class TextAIEngineDetails(BaseModel):
    score: float
    tactics: List[str]
    reasoning: str
    flagged_phrases: List[str]


class EnginesBreakdown(BaseModel):
    auth: AuthEngineDetails
    ioc: IOCEngineDetails
    text_ai: TextAIEngineDetails


class EmailThreatResponse(BaseModel):
    id: str
    thread_id: str
    timestamp: str
    sender: str = Field(..., serialization_alias="from")
    to: str
    subject: str
    snippet: str
    sanitized_body: str
    verdict: VerdictSchema
    engines: EnginesBreakdown


# ======================================================================
# FUSION & OVERRIDE LOGIC
# ======================================================================

def compute_composite_verdict(
    auth_res: Dict[str, Any],
    ioc_res: Dict[str, Any],
    text_res: Dict[str, Any],
    ml_score: float,
) -> VerdictSchema:
    """
    Computes final fused score applying deterministic hard-overrides first,
    then defaulting to calibrated ML semantic probability.
    """
    # 1. Hard Override: Confirmed Malicious Indicators (VirusTotal / Safe Browsing)
    if len(ioc_res.get("malicious_urls", [])) > 0 or len(ioc_res.get("malicious_files", [])) > 0:
        return VerdictSchema(
            overall_score=1.0,
            status="MALICIOUS",
            confidence=0.98,
            primary_threat="Malicious Payload / Known IOC",
            action_recommended="QUARANTINE",
        )

    # 2. Hard Override: DMARC Authentication Failure & Spoofing
    auth_details = auth_res.get("details", {})
    if auth_details.get("dmarc") == "fail" and auth_details.get("alignment") == "unaligned":
        return VerdictSchema(
            overall_score=0.95,
            status="MALICIOUS",
            confidence=0.95,
            primary_threat="Domain Spoofing / Impersonation",
            action_recommended="QUARANTINE",
        )

    # 3. Gating Thresholds Based on ML Semantic Score
    if ml_score >= 0.70:
        return VerdictSchema(
            overall_score=round(ml_score, 2),
            status="MALICIOUS",
            confidence=round(max(0.75, ml_score), 2),
            primary_threat=text_res.get("tactics", ["Social Engineering"])[0] if text_res.get("tactics") else "Phishing",
            action_recommended="QUARANTINE",
        )
    elif ml_score >= 0.35:
        return VerdictSchema(
            overall_score=round(ml_score, 2),
            status="SUSPICIOUS",
            confidence=0.80,
            primary_threat="Suspicious Urgency or Intent",
            action_recommended="WARNING_BANNER",
        )
    else:
        return VerdictSchema(
            overall_score=round(ml_score, 2),
            status="SAFE",
            confidence=0.90,
            primary_threat="None",
            action_recommended="INBOX",
        )


# ======================================================================
# API ENDPOINTS
# ======================================================================

@app.post(
    "/api/v1/emails/analyze",
    response_model=EmailThreatResponse,
    status_code=status.HTTP_200_OK,
    response_model_by_alias=True,
)
async def analyze_email(email_req: EmailAnalysisRequest):
    """
    Executes all detection engines in parallel and delivers the normalized 
    threat payload formatted for the frontend dashboard.
    """
    try:
        # 1. Deterministic Engines
        auth_res = run_auth_checks(email_req.headers)
        ioc_res = await run_ioc_intel(email_req.urls, email_req.attachments)

        # 2. Text AI Semantic Extraction
        text_res = await run_text_ai(email_req.body)

        # 3. Infer using trained ML pipeline (falls back safely if not loaded)
        if predictor:
            ml_score = predictor.predict_threat_score(
                urgency=float(text_res.get("urgency_score", 0.0)),
                financial=float(text_res.get("financial_request_score", 0.0)),
                authority=float(text_res.get("authority_impersonation_score", 0.0)),
                grammar=float(text_res.get("grammar_anomaly_score", 0.0)),
                body_length=len(email_req.body),
            )
        else:
            ml_score = float(text_res.get("score", 0.0))

        # 4. Compile Composite Verdict
        verdict = compute_composite_verdict(auth_res, ioc_res, text_res, ml_score)

        return EmailThreatResponse(
            id=email_req.id,
            thread_id=email_req.thread_id,
            timestamp=email_req.timestamp,
            sender=email_req.sender,
            to=email_req.to,
            subject=email_req.subject,
            snippet=email_req.snippet,
            sanitized_body=email_req.body,
            verdict=verdict,
            engines=EnginesBreakdown(
                auth=AuthEngineDetails(
                    score=auth_res.get("score", 0.0),
                    status=auth_res.get("status", "UNKNOWN"),
                    details=auth_res.get("details", {}),
                    reason=auth_res.get("reason", "No flags detected"),
                ),
                ioc=IOCEngineDetails(
                    score=ioc_res.get("score", 0.0),
                    hits=ioc_res.get("hits", 0),
                    urls_checked=ioc_res.get("urls_checked", len(email_req.urls)),
                    malicious_urls=ioc_res.get("malicious_urls", []),
                    attachments_checked=ioc_res.get("attachments_checked", len(email_req.attachments)),
                    malicious_files=ioc_res.get("malicious_files", []),
                ),
                text_ai=TextAIEngineDetails(
                    score=float(text_res.get("score", ml_score)),
                    tactics=text_res.get("tactics", []),
                    reasoning=text_res.get("reasoning", "Semantic scan complete."),
                    flagged_phrases=text_res.get("flagged_phrases", []),
                ),
            ),
        )

    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error executing security pipelines: {str(exc)}",
        )


@app.get("/health", status_code=status.HTTP_200_OK)
def health_check():
    return {"status": "ok", "model_loaded": predictor is not None}