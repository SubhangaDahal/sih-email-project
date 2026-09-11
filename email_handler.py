import asyncio
import base64
import json
import threading
from concurrent.futures import ThreadPoolExecutor
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials

from google.cloud import pubsub_v1
from googleapiclient.discovery import build
from engines import run_auth_checks, ioc_engine, run_text_ai

from setup import SCOPES

# ======================================================================
# CONFIGURATION
# ======================================================================

PROJECT_ID = "pristine-atom-497215-c2"
SUBSCRIPTION_ID = "gmail-notifications"

# IMPORTANT:
#
# Ideally, set this to the historyId returned when you created the
# Gmail watch.
#
# Example:
#
# INITIAL_HISTORY_ID = "123456"
#
# If None, the first Pub/Sub notification will establish the baseline.
# That fallback means events that happened BEFORE the daemon started
# cannot be recovered by this process.
INITIAL_HISTORY_ID = 6685


# Number of detection tasks that can run concurrently.
DETECTION_WORKERS = 8


# ======================================================================
# GLOBAL STATE
# ======================================================================

# Gmail history IDs MUST be processed sequentially.
#
# We therefore serialize the entire Gmail delta processing path rather
# than allowing multiple Pub/Sub callbacks to modify the checkpoint
# concurrently.
history_lock = threading.Lock()

last_history_id = INITIAL_HISTORY_ID


# Detection work can be parallel.
executor = ThreadPoolExecutor(
    max_workers=DETECTION_WORKERS,
)

def get_gmail_credentials():
    creds = Credentials.from_authorized_user_file(
        "token.json",
        SCOPES,
    )

    if creds.expired and creds.refresh_token:
        creds.refresh(Request())

    if not creds.valid:
        raise RuntimeError("Gmail credentials are invalid.")

    print(f"[AUTH] Gmail scopes: {creds.scopes}")

    return creds


# ======================================================================
# 1. DETECTION ENGINES
# ======================================================================



async def run_geo_engine(headers: list) -> dict:
    """
    Geographic anomaly engine.
    """
    return {
        "score": 0.4,
        "country": "RU",
    }


# ======================================================================
# 2. EMAIL BODY EXTRACTION
# ======================================================================

def decode_body_data(data: str) -> str:
    """
    Gmail uses URL-safe base64 for message bodies.
    """
    try:
        decoded = base64.urlsafe_b64decode(data)
        return decoded.decode("utf-8", errors="ignore")

    except Exception as exc:
        print(
            f"[PARSER] Failed to decode body: "
            f"{type(exc).__name__}: {exc}"
        )
        return ""


def extract_body(payload: dict) -> str:
    """
    Recursively extract a text/plain or text/html body from a Gmail
    message payload.

    Preference:
        text/plain
        then text/html
    """

    if not payload:
        return ""

    # --------------------------------------------------------------
    # Direct body
    # --------------------------------------------------------------

    body = payload.get("body", {})

    if body.get("data"):
        mime_type = payload.get("mimeType")

        if mime_type in ("text/plain", "text/html"):
            return decode_body_data(body["data"])

    # --------------------------------------------------------------
    # Multipart body
    # --------------------------------------------------------------

    parts = payload.get("parts", [])

    # First pass: prefer text/plain.
    for part in parts:
        if part.get("mimeType") == "text/plain":
            part_body = part.get("body", {})

            if part_body.get("data"):
                return decode_body_data(part_body["data"])

    # --------------------------------------------------------------
    # Second pass: text/html.
    # --------------------------------------------------------------

    for part in parts:
        if part.get("mimeType") == "text/html":
            part_body = part.get("body", {})

            if part_body.get("data"):
                return decode_body_data(part_body["data"])

    # --------------------------------------------------------------
    # Recursive search through nested multipart structures.
    # --------------------------------------------------------------

    for part in parts:
        nested_body = extract_body(part)

        if nested_body:
            return nested_body

    return ""


# ======================================================================
# 3. DETECTION DISPATCHER
# ======================================================================

async def dispatch_engines(msg_payload: dict):
    """
    Run all detection engines concurrently for one Gmail message.
    """

    payload = msg_payload.get("payload", {})

    body = extract_body(payload)
    headers = payload.get("headers", [])

    print(
        f"[DETECTION] Starting engines "
        f"for message={msg_payload.get('id')}"
    )

    try:
        (
            text_res,
            auth_res,
            ioc_res,
            geo_res,
        ) = await asyncio.gather(
            run_text_ai(body),
            run_auth_checks(headers),
            ioc_engine(body, headers),
            run_geo_engine(headers),
        )

    except Exception as exc:
        print(
            f"[DETECTION] Engine failure: "
            f"{type(exc).__name__}: {exc}"
        )
        raise

    engine_outputs = {
        "text": text_res,
        "auth": auth_res,
        "ioc": ioc_res,
        "geo": geo_res,
    }

    print(
        "\n[+] Engine outputs collected:",
        engine_outputs,
    )

    return engine_outputs


# ======================================================================
# 4. GMAIL HISTORY FETCHING
# ======================================================================

def fetch_history_delta(
    gmail_service,
    start_history_id: str,
):
    """
    Fetch ALL Gmail history records after start_history_id.

    Gmail history.list is paginated, so we continue until there is
    no nextPageToken.

    Returns:
        list of messagesAdded entries.
    """

    all_messages_added = []

    page_token = None

    while True:

        print(
            f"[GMAIL] history.list("
            f"startHistoryId={start_history_id}, "
            f"pageToken={page_token}"
            f")"
        )

        request = gmail_service.users().history().list(
            userId="me",
            startHistoryId=start_history_id,
            historyTypes=["messageAdded"],
            pageToken=page_token,
        )

        response = request.execute()

        history_records = response.get("history", [])

        print(
            f"[GMAIL] Received "
            f"{len(history_records)} history records"
        )

        for record in history_records:

            messages_added = record.get(
                "messagesAdded",
                [],
            )

            all_messages_added.extend(messages_added)

        page_token = response.get("nextPageToken")

        if not page_token:
            break

    return all_messages_added


# ======================================================================
# 5. PROCESS ONE GMAIL DELTA
# ======================================================================

def process_gmail_delta(
    notification_history_id: str,
    message: pubsub_v1.subscriber.message.Message,
    loop: asyncio.AbstractEventLoop,
):
    """
    Process one Gmail Pub/Sub notification.

    IMPORTANT CHECKPOINT SEMANTICS:

        Pub/Sub notification
                ↓
        fetch Gmail history
                ↓
        fetch every affected message
                ↓
        run detection engines
                ↓
        ONLY AFTER SUCCESS
                ↓
        update last_history_id
                ↓
        ACK Pub/Sub message

    If anything fails before the checkpoint update, the Pub/Sub message
    is NACKed and the checkpoint remains unchanged.
    """

    global last_history_id

    print(
        f"\n[GMAIL] Processing notification "
        f"historyId={notification_history_id}"
    )

    try:

        # --------------------------------------------------------------
        # Create Gmail client inside the worker thread.
        # --------------------------------------------------------------
        creds = get_gmail_credentials()
        gmail_service = build(
            "gmail",
            "v1",
            credentials=creds
        )

        # --------------------------------------------------------------
        # Serialize Gmail history processing.
        #
        # This prevents:
        #
        # notification A → history 100 → 110
        # notification B → history 110 → 120
        #
        # from being processed concurrently/out of order.
        # --------------------------------------------------------------

        with history_lock:

            print(
                f"[GMAIL] Current checkpoint="
                f"{last_history_id}"
            )

            # ----------------------------------------------------------
            # No checkpoint yet.
            #
            # This is only the fallback case where the daemon was
            # started without INITIAL_HISTORY_ID.
            # ----------------------------------------------------------

            if last_history_id is None:

                last_history_id = notification_history_id

                print(
                    f"[GMAIL] No initial history ID supplied."
                )

                print(
                    f"[GMAIL] Established baseline="
                    f"{last_history_id}"
                )

                # There is no older checkpoint from which we can safely
                # reconstruct the delta.
                #
                # We ACK this notification because it has now become
                # our baseline.
                message.ack()

                return

            current_start_id = last_history_id

            print(
                f"[GMAIL] Fetching delta "
                f"{current_start_id} → "
                f"{notification_history_id}"
            )

            # ----------------------------------------------------------
            # Fetch history.
            # ----------------------------------------------------------

            messages_added = fetch_history_delta(
                gmail_service,
                current_start_id,
            )

            print(
                f"[GMAIL] Messages added in delta: "
                f"{len(messages_added)}"
            )

            # ----------------------------------------------------------
            # Deduplicate message IDs.
            #
            # The same message can potentially occur in multiple
            # history records.
            # ----------------------------------------------------------

            message_ids = {
                entry["message"]["id"]
                for entry in messages_added
                if entry.get("message", {}).get("id")
            }

            print(
                f"[GMAIL] Unique message IDs: "
                f"{len(message_ids)}"
            )

            # ----------------------------------------------------------
            # Fetch and process every email.
            #
            # We wait for each detection coroutine to finish before
            # committing the Gmail checkpoint.
            # ----------------------------------------------------------

            detection_futures = []

            for msg_id in message_ids:

                print(
                    f"[GMAIL] Fetching message={msg_id}"
                )

                msg = gmail_service.users().messages().get(
                    userId="me",
                    id=msg_id,
                    format="full",
                ).execute()

                print(
                    f"[GMAIL] Retrieved message={msg_id}"
                )

                future = asyncio.run_coroutine_threadsafe(
                    dispatch_engines(msg),
                    loop,
                )

                detection_futures.append(
                    future
                )

            # ----------------------------------------------------------
            # Wait for every detection pipeline to finish.
            #
            # This is important.
            #
            # Previously, run_coroutine_threadsafe() was called but
            # nothing waited for the resulting Future. Therefore a
            # detection exception could occur after the Pub/Sub message
            # was already ACKed.
            # ----------------------------------------------------------

            for future in detection_futures:

                future.result()

            print(
                "[GMAIL] All detection pipelines completed"
            )

            # ----------------------------------------------------------
            # ONLY NOW advance the checkpoint.
            # ----------------------------------------------------------

            last_history_id = notification_history_id

            print(
                f"[GMAIL] Checkpoint advanced to "
                f"{last_history_id}"
            )

            # ----------------------------------------------------------
            # ONLY NOW ACK Pub/Sub.
            # ----------------------------------------------------------

            message.ack()

            print(
                f"[PUBSUB] ACK "
                f"message_id={message.message_id}"
            )

    except Exception as exc:

        print(
            f"[-] Error processing Gmail delta: "
            f"{type(exc).__name__}: {exc}"
        )

        print(
            f"[GMAIL] Checkpoint remains "
            f"{last_history_id}"
        )

        # --------------------------------------------------------------
        # Do NOT advance the checkpoint.
        #
        # NACK causes Pub/Sub to redeliver the notification.
        # --------------------------------------------------------------

        message.nack()

        print(
            f"[PUBSUB] NACK "
            f"message_id={message.message_id}"
        )

        # Re-raise so ThreadPoolExecutor's Future also records the
        # exception and thread_done_callback can see it.
        raise


# ======================================================================
# 6. THREADPOOL CALLBACK
# ======================================================================

def thread_done_callback(future):
    """
    Surface exceptions that occur inside process_gmail_delta().
    """

    try:
        future.result()

    except Exception as exc:

        print(
            f"[-] Unhandled exception in Gmail worker: "
            f"{type(exc).__name__}: {exc}"
        )

    else:

        print(
            "[THREAD] Gmail worker completed successfully"
        )


# ======================================================================
# 7. PUB/SUB CALLBACK
# ======================================================================

def pubsub_callback(
    message: pubsub_v1.subscriber.message.Message,
    loop: asyncio.AbstractEventLoop,
):
    """
    Called by Google Pub/Sub whenever a notification arrives.
    """

    print(
        "\n[PUBSUB] Callback received"
    )

    try:

        print(
            f"[PUBSUB] message_id="
            f"{message.message_id}"
        )

        print(
            f"[PUBSUB] data="
            f"{message.data!r}"
        )

        # --------------------------------------------------------------
        # Gmail notification payload.
        # --------------------------------------------------------------

        raw_data = message.data.decode(
            "utf-8"
        )

        event = json.loads(raw_data)

        print(
            f"[PUBSUB] event={event}"
        )

        history_id = event.get(
            "historyId"
        )

        # --------------------------------------------------------------
        # Gmail should provide historyId.
        # --------------------------------------------------------------

        if not history_id:

            print(
                "[PUBSUB] No historyId in notification"
            )

            # This isn't a Gmail notification we can process.
            message.ack()

            print(
                f"[PUBSUB] ACK invalid/non-Gmail "
                f"message={message.message_id}"
            )

            return

        print(
            f"[PUBSUB] historyId={history_id}"
        )

        # --------------------------------------------------------------
        # Hand Gmail processing to the worker thread.
        # --------------------------------------------------------------

        future = executor.submit(
            process_gmail_delta,
            history_id,
            message,
            loop,
        )

        future.add_done_callback(
            thread_done_callback
        )

        print(
            "[PUBSUB] Gmail delta submitted "
            "to worker"
        )

    except Exception as exc:

        print(
            f"[-] Pub/Sub callback exception: "
            f"{type(exc).__name__}: {exc}"
        )

        message.nack()


# ======================================================================
# 8. PUB/SUB STREAMING PULL WORKER
# ======================================================================

def start_worker():

    # --------------------------------------------------------------
    # Create asyncio event loop.
    # --------------------------------------------------------------

    loop = asyncio.new_event_loop()

    asyncio.set_event_loop(loop)

    # --------------------------------------------------------------
    # Create Pub/Sub client.
    # --------------------------------------------------------------

    subscriber = pubsub_v1.SubscriberClient()

    sub_path = subscriber.subscription_path(
        PROJECT_ID,
        SUBSCRIPTION_ID,
    )

    print(
        "[*] Starting subscriber..."
    )

    print(
        f"[*] Project: {PROJECT_ID}"
    )

    print(
        f"[*] Subscription: {sub_path}"
    )

    # --------------------------------------------------------------
    # Pub/Sub streaming pull.
    # --------------------------------------------------------------

    streaming_pull = subscriber.subscribe(
        sub_path,
        callback=lambda msg: pubsub_callback(
            msg,
            loop,
        ),
    )

    # --------------------------------------------------------------
    # Monitor the streaming pull itself.
    #
    # Without this, the Python process can remain alive even if the
    # Pub/Sub streaming connection has terminated.
    # --------------------------------------------------------------

    def subscriber_done(future):

        try:

            future.result()

        except Exception as exc:

            print(
                f"[PUBSUB] Streaming pull died: "
                f"{type(exc).__name__}: {exc}"
            )

        else:

            print(
                "[PUBSUB] Streaming pull terminated"
            )

    streaming_pull.add_done_callback(
        subscriber_done
    )

    print(
        f"[*] Ingestion daemon listening on "
        f"{sub_path}..."
    )

    # --------------------------------------------------------------
    # Keep asyncio loop alive.
    # --------------------------------------------------------------

    try:

        loop.run_forever()

    except KeyboardInterrupt:

        print(
            "[*] KeyboardInterrupt received"
        )

    finally:

        print(
            "[*] Shutting down..."
        )

        # ----------------------------------------------------------
        # Stop Pub/Sub streaming pull.
        # ----------------------------------------------------------

        streaming_pull.cancel()

        # ----------------------------------------------------------
        # Close Pub/Sub client.
        # ----------------------------------------------------------

        subscriber.close()

        # ----------------------------------------------------------
        # Stop asyncio.
        # ----------------------------------------------------------

        loop.stop()

        loop.close()

        # ----------------------------------------------------------
        # Wait for Gmail worker threads.
        # ----------------------------------------------------------

        executor.shutdown(
            wait=True
        )

        print(
            "[*] Shutdown complete"
        )


# ======================================================================
# ENTRY POINT
# ======================================================================

if __name__ == "__main__":
    start_worker()