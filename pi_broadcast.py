#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os, sys, json, time, urllib.parse, urllib.request, shlex, subprocess, pathlib, wave, signal, threading
import boto3
from botocore.exceptions import ClientError
from botocore.config import Config as BotoConfig

# ===============================
# Configuration (via environment)
# ===============================
AWS_REGION         = os.getenv("AWS_REGION", "us-east-1")
QUEUE_URL          = os.environ["QUEUE_URL"]  # required
DOWNLOAD_DIR       = os.getenv("DOWNLOAD_DIR", "/home/rpibroadcaster/wav")

# BROADCAST_CMD is now *dynamic*; we bootstrap from env, and can hot-reload from ENV_FILE on SIGHUP/SIGUSR2
BROADCAST_CMD      = os.getenv("BROADCAST_CMD", "aplay -q {file}")

# Where to reload BROADCAST_CMD from on SIGHUP/SIGUSR2:
ENV_FILE           = os.getenv("ENV_FILE", "/home/rpibroadcaster/broadcast.env")

VISIBILITY         = int(os.getenv("VISIBILITY", "300"))         # seconds
HEARTBEAT          = int(os.getenv("HEARTBEAT_SEC", "5"))        # seconds between visibility extensions
MAX_PLAYBACK_SECS  = int(os.getenv("MAX_PLAYBACK_SECS", "1800")) # kill player after this (default 30m)

# Whole-message timeout & DLQ
MESSAGE_TIMEOUT_SECS = int(os.getenv("MESSAGE_TIMEOUT_SECS", "2400"))  # download+playback wall clock (default 40m)
MAX_RECEIVE_COUNT    = int(os.getenv("MAX_RECEIVE_COUNT", "5"))        # after this, send to DLQ (if configured)
DLQ_URL              = os.getenv("DLQ_URL", "")                        # optional FIFO DLQ

# Idle "silence" carrier
SILENCE_FILE = os.getenv("SILENCE_FILE", "")
SILENCE_SECS = int(os.getenv("SILENCE_SECS", "600"))

# Robust AWS client timeouts & retries
_boto_cfg = BotoConfig(
    connect_timeout=5,
    read_timeout=60,
    retries={"max_attempts": 5, "mode": "standard"},
)

sqs = boto3.client("sqs", region_name=AWS_REGION, config=_boto_cfg)
s3  = boto3.client("s3",  region_name=AWS_REGION, config=_boto_cfg)

def log(*a): print(time.strftime("[%Y-%m-%d %H:%M:%S]"), *a, flush=True)
def ensure_dir(p: str): pathlib.Path(p).mkdir(parents=True, exist_ok=True)

# ===============================
# Hot-reload / interrupt controls
# ===============================
_ctrl_lock = threading.Lock()
_reload_requested     = False  # SIGHUP: reload env & cmd, restart silence
_interrupt_requested  = False  # SIGUSR2: abort current playback, requeue message, then reload

_current_receipt_handle = None
_player_proc            = None

def _set_reload():
    global _reload_requested
    with _ctrl_lock:
        _reload_requested = True

def _consume_reload_flag() -> bool:
    global _reload_requested
    with _ctrl_lock:
        v = _reload_requested
        _reload_requested = False
        return v

def _request_interrupt():
    global _interrupt_requested
    with _ctrl_lock:
        _interrupt_requested = True

def _consume_interrupt_flag() -> bool:
    global _interrupt_requested
    with _ctrl_lock:
        v = _interrupt_requested
        _interrupt_requested = False
        return v

def _load_env_file(path: str) -> dict:
    env = {}
    if not os.path.exists(path):
        return env
    import re
    line_re = re.compile(r"""
        ^\s*
        (?:export\s+)?              
        (?P<key>[A-Za-z_][A-Za-z0-9_]*)
        \s*=\s*
        (?P<val>.*?)
        \s*$
    """, re.X)
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        for raw in f:
            s = raw.strip().rstrip("\r")
            if not s or s.startswith("#"):
                continue
            m = line_re.match(s)
            if not m:
                continue
            key = m.group("key")
            val = m.group("val")
            if (len(val) >= 2) and (val[0] == val[-1]) and val[0] in ("'", '"'):
                val = val[1:-1]
            env[key] = val
    return env

def _render_cmd_with_current_freq(tmpl: str) -> str:
    # Allow the template to contain {freq} or <num>, but if missing we just return tmpl.
    # We do NOT know the freq directly here; we assume tmpl already has the right one.
    return tmpl

def _reload_broadcast_cmd_from_file():
    """Reload BROADCAST_CMD from ENV_FILE; restart silence with new command."""
    global BROADCAST_CMD
    env = _load_env_file(ENV_FILE)
    new_cmd = env.get("BROADCAST_CMD", BROADCAST_CMD)
    if new_cmd != BROADCAST_CMD:
        log(f"Reloading BROADCAST_CMD -> {new_cmd}")
    BROADCAST_CMD = _render_cmd_with_current_freq(new_cmd)
    # restart idle carrier at new freq
    stop_silence()
    start_silence_now()

def _handle_sighup(_signum, _frame):
    log("Received SIGHUP: scheduling hot-reload")
    _set_reload()

def _handle_sigusr2(_signum, _frame):
    log("Received SIGUSR2: scheduling immediate interrupt + reload")
    _request_interrupt()
    _set_reload()

signal.signal(signal.SIGHUP, _handle_sighup)
signal.signal(signal.SIGUSR2, _handle_sigusr2)

# ===============================
# Payload helpers
# ===============================
def parse_payload(msg_body: str) -> dict:
    body = json.loads(msg_body)
    if isinstance(body, dict) and "Message" in body:
        try:
            return json.loads(body["Message"])
        except Exception:
            return {"message": body["Message"]}
    return body

def extract_s3_info(payload: dict):
    if "url" in payload:
        return None, None, payload["url"]
    if "bucket" in payload and "key" in payload:
        return payload["bucket"], payload["key"], None
    if "Records" in payload and payload["Records"]:
        r = payload["Records"][0]
        return r["s3"]["bucket"]["name"], urllib.parse.unquote_plus(r["s3"]["object"]["key"]), None
    raise ValueError("No S3 info in message")

def download_wav(bucket: str, key: str, out_dir: str) -> str:
    ensure_dir(out_dir)
    dest = os.path.join(out_dir, os.path.basename(key) or "audio.wav")
    log(f"Downloading s3://{bucket}/{key} -> {dest}")
    s3.download_file(bucket, key, dest)
    return dest

def download_url(url: str, out_dir: str) -> str:
    ensure_dir(out_dir)
    name = os.path.basename(urllib.parse.urlparse(url).path) or "audio.wav"
    if not name.lower().endswith(".wav"):
        name += ".wav"
    dest = os.path.join(out_dir, name)
    log(f"Downloading {url} -> {dest}")
    with urllib.request.urlopen(url, timeout=60) as r, open(dest, "wb") as f:
        while True:
            chunk = r.read(1024 * 64)
            if not chunk:
                break
            f.write(chunk)
    return dest

# ===============================
# Broadcast with timeout/heartbeat + interrupt
# ===============================
def broadcast(path: str, receipt_handle: str):
    """Run the broadcast command with a hard timeout, keep SQS visibility alive, and support SIGUSR2 interrupt."""
    global _player_proc, _current_receipt_handle
    _current_receipt_handle = receipt_handle

    cmd = BROADCAST_CMD.format(file=shlex.quote(path))
    log(f"Broadcasting with: {cmd}")

    proc = subprocess.Popen(cmd, shell=True)
    _player_proc = proc

    start = time.time()
    last_extend = 0.0

    try:
        while True:
            # Interrupt requested?
            if _consume_interrupt_flag():
                try:
                    # Make the message visible immediately so it requeues to the head of its group
                    sqs.change_message_visibility(
                        QueueUrl=QUEUE_URL,
                        ReceiptHandle=receipt_handle,
                        VisibilityTimeout=0
                    )
                    log("Interrupted current playback: visibility set to 0 (requeued)")
                except ClientError as e:
                    log(f"WARN: change_message_visibility(0) failed: {e}")
                try:
                    proc.kill()
                except Exception:
                    pass
                raise RuntimeError("Playback interrupted by SIGUSR2")

            ret = proc.poll()
            if ret is not None:
                if ret != 0:
                    raise RuntimeError(f"Broadcast command exited with {ret}")
                return  # success

            now = time.time()
            elapsed = int(now - start)

            # Kill player if it runs too long
            if elapsed >= MAX_PLAYBACK_SECS:
                try:
                    proc.kill()
                except Exception:
                    pass
                raise RuntimeError(f"Playback exceeded MAX_PLAYBACK_SECS ({MAX_PLAYBACK_SECS}s); killed")

            # Extend visibility periodically
            if now - last_extend >= HEARTBEAT:
                try:
                    sqs.change_message_visibility(
                        QueueUrl=QUEUE_URL,
                        ReceiptHandle=receipt_handle,
                        VisibilityTimeout=min(VISIBILITY, 43200),
                    )
                    log(f"Extended visibility (t+{elapsed}s)")
                except ClientError as e:
                    log(f"WARN: change_message_visibility failed: {e}")
                last_extend = now

            time.sleep(0.2)
    finally:
        try:
            if proc and proc.poll() is None:
                proc.terminate()
                try:
                    proc.wait(timeout=1.5)
                except Exception:
                    proc.kill()
        except Exception:
            pass
        _player_proc = None
        _current_receipt_handle = None

# ===============================
# Idle silence management
# ===============================
_silence_proc = None

def _silence_path() -> str:
    return SILENCE_FILE or os.path.join(DOWNLOAD_DIR, "silence_10min.wav")

def _ensure_silence_file_exists():
    path = _silence_path()
    if os.path.exists(path):
        return path
    ensure_dir(os.path.dirname(path))
    log(f"Creating silent WAV: {path} ({SILENCE_SECS}s @ 16kHz mono 16-bit)")
    with wave.open(path, "wb") as w:
        w.setnchannels(1); w.setsampwidth(2); w.setframerate(16000)
        w.writeframes(b"\x00\x00" * 16000 * SILENCE_SECS)
    return path

def ensure_silence_playing():
    """Start (or keep) a silence carrier when idle."""
    global _silence_proc
    path = _silence_path()
    if not os.path.exists(path):
        _ensure_silence_file_exists()
    if _silence_proc and _silence_proc.poll() is None:
        return
    cmd = BROADCAST_CMD.format(file=shlex.quote(path))
    log(f"Idle: starting silence with: {cmd}")
    _silence_proc = subprocess.Popen(cmd, shell=True)

def start_silence_now(retries: int = 10, delay: float = 0.8) -> bool:
    """Start the idle silence now, retry briefly if /dev/mem still busy."""
    global _silence_proc
    stop_silence()
    path = _silence_path()
    if not os.path.exists(path):
        _ensure_silence_file_exists()
    for i in range(retries):
        cmd = BROADCAST_CMD.format(file=shlex.quote(path))
        log(f"Idle: starting silence (try {i+1}/{retries}) with: {cmd}")
        p = subprocess.Popen(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(0.25)
        if p.poll() is None:
            _silence_proc = p
            return True
        time.sleep(delay)
    log("WARN: could not keep silence running; will retry on next loop")
    return False

def stop_silence():
    """Stop silence before real broadcast (pifm needs /dev/mem exclusively)."""
    global _silence_proc
    if _silence_proc and _silence_proc.poll() is None:
        try:
            _silence_proc.terminate()
            try:
                _silence_proc.wait(timeout=2)
            except Exception:
                _silence_proc.kill()
        except Exception:
            pass
    _silence_proc = None
    time.sleep(0.2)

# ===============================
# DLQ helpers & message handling
# ===============================
def safe_delete(receipt_handle: str) -> bool:
    try:
        sqs.delete_message(QueueUrl=QUEUE_URL, ReceiptHandle=receipt_handle)
        return True
    except ClientError as e:
        log(f"WARN: delete_message failed: {e}")
        return False

def send_to_dlq(msg: dict) -> bool:
    """Move the message to DLQ (if configured) and delete from main queue."""
    if not DLQ_URL:
        return False
    try:
        attrs   = msg.get("Attributes", {}) or {}
        groupid = attrs.get("MessageGroupId")
        dedup   = msg.get("MessageId")  # safe unique fallback
        kwargs = {"QueueUrl": DLQ_URL, "MessageBody": msg["Body"]}
        if groupid: kwargs["MessageGroupId"] = groupid
        if dedup:   kwargs["MessageDeduplicationId"] = dedup
        sqs.send_message(**kwargs)
        sqs.delete_message(QueueUrl=QUEUE_URL, ReceiptHandle=msg["ReceiptHandle"])
        log(f"Moved MessageId={msg.get('MessageId','?')} to DLQ")
        return True
    except ClientError as e:
        log(f"WARN: failed to send to DLQ: {e}")
        return False

def process_message(msg: dict):
    start_ts = time.time()

    rh      = msg["ReceiptHandle"]
    msg_id  = msg.get("MessageId", "?")
    attrs   = msg.get("Attributes", {}) or {}
    group   = attrs.get("MessageGroupId", "(n/a)")
    rcnt    = int(attrs.get("ApproximateReceiveCount", "1"))
    log(f"Processing MessageId={msg_id} GroupId={group} ReceiveCount={rcnt}")

    # Too many attempts? -> DLQ (if configured)
    if DLQ_URL and rcnt >= MAX_RECEIVE_COUNT:
        moved = send_to_dlq(msg)
        if not moved:
            log("Could not move to DLQ; leaving for retry")
        return

    # Parse
    try:
        payload = parse_payload(msg["Body"])
    except Exception as e:
        log(f"ERROR: invalid JSON body for MessageId={msg_id}: {e}")
        return  # leave for retry / DLQ later

    # Skip obvious non-wav keys
    if isinstance(payload, dict) and "key" in payload and not payload["key"].lower().endswith(".wav"):
        log(f"Skipping non-wav key: {payload['key']}")
        safe_delete(rh); return

    ensure_dir(DOWNLOAD_DIR)

    # Extract source
    try:
        bucket, key, url = extract_s3_info(payload)
    except Exception as e:
        log(f"ERROR: payload missing S3 info: {e}")
        return  # retry / DLQ later

    # Download (bounded by urllib/boto timeouts)
    try:
        path = download_url(url, DOWNLOAD_DIR) if url else download_wav(bucket, key, DOWNLOAD_DIR)
    except Exception as e:
        log(f"ERROR downloading: {e}")
        return  # retry later; receive count will increase

    # Wall-clock before playback
    if time.time() - start_ts >= MESSAGE_TIMEOUT_SECS:
        log(f"MessageId={msg_id} exceeded MESSAGE_TIMEOUT_SECS before playback; aborting")
        return

    # Playback (bounded by MAX_PLAYBACK_SECS inside broadcast)
    try:
        stop_silence()
        broadcast(path, rh)
    except Exception as e:
        log(f"ERROR during playback: {e}")
        start_silence_now()
        return

    # Wall-clock after playback
    if time.time() - start_ts >= MESSAGE_TIMEOUT_SECS:
        log(f"MessageId={msg_id} exceeded MESSAGE_TIMEOUT_SECS after playback; not deleting (will retry/DLQ)")
        start_silence_now()
        return

    # Success
    if safe_delete(rh):
        log(f"Message processed and deleted. MessageId={msg_id}")
    start_silence_now()

# ===============================
# Main loop
# ===============================
def main():
    log("Starting SQS broadcaster")
    log(f"Queue: {QUEUE_URL}")
    log(f"Download dir: {DOWNLOAD_DIR}")
    log(f"Initial Command: {BROADCAST_CMD}")
    log(f"Visibility={VISIBILITY}s  Heartbeat={HEARTBEAT}s  MaxPlayback={MAX_PLAYBACK_SECS}s  MsgTimeout={MESSAGE_TIMEOUT_SECS}s")
    log(f"ENV_FILE for reload: {ENV_FILE}")

    _ensure_silence_file_exists()
    start_silence_now()

    while True:
        try:
            # Handle a pending reload request even when idle
            if _consume_reload_flag():
                _reload_broadcast_cmd_from_file()

            resp = sqs.receive_message(
                QueueUrl=QUEUE_URL,
                MaxNumberOfMessages=1,
                WaitTimeSeconds=20,          # long polling
                VisibilityTimeout=VISIBILITY,
                AttributeNames=["All"],
                MessageAttributeNames=["All"]
            )
            msgs = resp.get("Messages", [])
            if not msgs:
                ensure_silence_playing()
                continue

            for m in msgs:
                # If we got an interrupt signal just before processing, handle it:
                if _consume_interrupt_flag():
                    # Requeue the *next* message immediately and reload
                    try:
                        sqs.change_message_visibility(
                            QueueUrl=QUEUE_URL,
                            ReceiptHandle=m["ReceiptHandle"],
                            VisibilityTimeout=0
                        )
                        log("Interrupt before playback: set visibility 0 for next message")
                    except ClientError as e:
                        log(f"WARN: change_message_visibility(0) failed: {e}")
                    _reload_broadcast_cmd_from_file()
                    continue

                process_message(m)

        except KeyboardInterrupt:
            log("Exiting...")
            stop_silence()
            break
        except Exception as e:
            log("WARN receive loop:", e); time.sleep(2)

if __name__ == "__main__":
    main()
