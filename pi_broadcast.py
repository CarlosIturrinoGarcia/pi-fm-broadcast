
import os, json, time, urllib.parse, urllib.request, shlex, subprocess, pathlib, wave
import boto3
from botocore.exceptions import ClientError

AWS_REGION   = os.getenv("AWS_REGION", "us-east-1")
QUEUE_URL    = os.environ["QUEUE_URL"]  # required
DOWNLOAD_DIR = os.getenv("DOWNLOAD_DIR", "/home/rpibroadcaster/wav")
BROADCAST_CMD= os.getenv("BROADCAST_CMD", "aplay -q {file}")
VISIBILITY   = int(os.getenv("VISIBILITY", "300"))
HEARTBEAT    = int(os.getenv("HEARTBEAT_SEC", "2"))

SILENCE_FILE = os.getenv("SILENCE_FILE", "")  
SILENCE_SECS = int(os.getenv("SILENCE_SECS", "600"))  

sqs = boto3.client("sqs", region_name=AWS_REGION)
s3  = boto3.client("s3", region_name=AWS_REGION)

def log(*a): print(time.strftime("[%Y-%m-%d %H:%M:%S]"), *a, flush=True)
def ensure_dir(p: str): pathlib.Path(p).mkdir(parents=True, exist_ok=True)

def parse_payload(msg_body: str) -> dict:
    body = json.loads(msg_body)
    if isinstance(body, dict) and "Message" in body:
        try: return json.loads(body["Message"])
        except Exception: return {"message": body["Message"]}
    return body

def extract_s3_info(payload: dict):
    if "url" in payload: return None, None, payload["url"]
    if "bucket" in payload and "key" in payload: return payload["bucket"], payload["key"], None
    if "Records" in payload and payload["Records"]:
        r = payload["Records"][0]
        return r["s3"]["bucket"]["name"], urllib.parse.unquote_plus(r["s3"]["object"]["key"]), None
    raise ValueError("No S3 info in message")

def download_wav(bucket: str, key: str, out_dir: str) -> str:
    dest = os.path.join(out_dir, os.path.basename(key) or "audio.wav")
    log(f"Downloading s3://{bucket}/{key} -> {dest}")
    s3.download_file(bucket, key, dest)
    return dest

def download_url(url: str, out_dir: str) -> str:
    name = os.path.basename(urllib.parse.urlparse(url).path) or "audio.wav"
    if not name.lower().endswith(".wav"): name += ".wav"
    dest = os.path.join(out_dir, name)
    log(f"Downloading {url} -> {dest}")
    with urllib.request.urlopen(url, timeout=60) as r, open(dest, "wb") as f:
        while True:
            chunk = r.read(1024 * 64)
            if not chunk: break
            f.write(chunk)
    return dest

def broadcast(path: str, receipt_handle: str):
    cmd = BROADCAST_CMD.format(file=shlex.quote(path))
    log(f"Broadcasting with: {cmd}")
    proc = subprocess.Popen(cmd, shell=True)
    elapsed = 0
    while True:
        ret = proc.poll()
        if ret is not None:
            if ret != 0: raise RuntimeError(f"Broadcast command exited with {ret}")
            return
        time.sleep(HEARTBEAT)
        elapsed += HEARTBEAT
        try:
            sqs.change_message_visibility(QueueUrl=QUEUE_URL, ReceiptHandle=receipt_handle, VisibilityTimeout=min(VISIBILITY, 43200))
            log(f"Extended visibility (t+{elapsed}s)")
        except ClientError as e:
            log(f"WARN: change_message_visibility failed: {e}")
            
            
_silence_proc = None

def _silence_path() -> str:
    # use explicit env path or default to <DOWNLOAD_DIR>/silence_10min.wav
    return SILENCE_FILE or os.path.join(DOWNLOAD_DIR, "silence_10min.wav")

def _ensure_silence_file_exists():
    path = _silence_path()
    if os.path.exists(path): return path
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
    # already running?
    if _silence_proc and _silence_proc.poll() is None:
        return
    cmd = BROADCAST_CMD.format(file=shlex.quote(path))
    log(f"Idle: starting silence with: {cmd}")
    _silence_proc = subprocess.Popen(cmd, shell=True)
    
def start_silence_now(retries: int = 10, delay: float = 0.8) -> bool:
    """Start the idle silence right now and retry briefly if pifm is still releasing /dev/mem."""
    global _silence_proc
    stop_silence()  # make sure no old one is lingering
    path = _silence_path()
    if not os.path.exists(path):
        _ensure_silence_file_exists()
    for i in range(retries):
        cmd = BROADCAST_CMD.format(file=shlex.quote(path))
        log(f"Idle: starting silence (try {i+1}/{retries}) with: {cmd}")
        p = subprocess.Popen(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(0.25)  # give it time to grab /dev/mem
        if p.poll() is None:
            _silence_proc = p
            return True
        time.sleep(delay)  # likely /dev/mem still busy; try again
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
    time.sleep(0.2)  # small pause so device/file is free

def process_message(msg: dict):
    rh = msg["ReceiptHandle"]
    payload = parse_payload(msg["Body"])
    if isinstance(payload, dict) and "key" in payload and not payload["key"].lower().endswith(".wav"):
        log(f"Skipping non-wav key: {payload['key']}")
        sqs.delete_message(QueueUrl=QUEUE_URL, ReceiptHandle=rh); return
    ensure_dir(DOWNLOAD_DIR)
    bucket, key, url = extract_s3_info(payload)
    try:
        path = download_url(url, DOWNLOAD_DIR) if url else download_wav(bucket, key, DOWNLOAD_DIR)
        stop_silence()
        broadcast(path, rh)
        sqs.delete_message(QueueUrl=QUEUE_URL, ReceiptHandle=rh)
        log("Message processed and deleted.")
    except Exception as e:
        log("ERROR processing message:", e)
        time.sleep(1)
    finally:
        start_silence_now()

def main():
	log("Starting SQS broadcaster")
	log(f"Queue: {QUEUE_URL}")
	log(f"Download dir: {DOWNLOAD_DIR}")
	log(f"Command: {BROADCAST_CMD}")
	# ensure silence file exists & start idle carrier
	_ensure_silence_file_exists()
	start_silence_now()

	while True:
		try:
			resp = sqs.receive_message(
				QueueUrl=QUEUE_URL,
				MaxNumberOfMessages=1,
				WaitTimeSeconds=2,
				VisibilityTimeout=VISIBILITY
			)
			msgs = resp.get("Messages", [])
			if not msgs:
				# keep silence alive on idle polls (restarts if it finished)
				ensure_silence_playing()
			for m in msgs:
				process_message(m)
		except KeyboardInterrupt:
			log("Exiting...")
			stop_silence()
			break
		except Exception as e:
			log("WARN receive loop:", e); time.sleep(2)

if __name__ == "__main__":
    main()
