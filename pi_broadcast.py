
import os, json, time, urllib.parse, urllib.request, shlex, subprocess, pathlib
import boto3
from botocore.exceptions import ClientError

AWS_REGION   = os.getenv("AWS_REGION", "us-east-1")
QUEUE_URL    = os.environ["QUEUE_URL"]  # required
DOWNLOAD_DIR = os.getenv("DOWNLOAD_DIR", "/home/rpibroadcaster/wav")
BROADCAST_CMD= os.getenv("BROADCAST_CMD", "aplay -q {file}")
VISIBILITY   = int(os.getenv("VISIBILITY", "300"))
HEARTBEAT    = int(os.getenv("HEARTBEAT_SEC", "25"))

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
        broadcast(path, rh)
        sqs.delete_message(QueueUrl=QUEUE_URL, ReceiptHandle=rh)
        log("Message processed and deleted.")
    except Exception as e:
        log("ERROR processing message:", e)
        time.sleep(1)

def main():
    log("Starting SQS broadcaster")
    log(f"Queue: {QUEUE_URL}")
    log(f"Download dir: {DOWNLOAD_DIR}")
    log(f"Command: {BROADCAST_CMD}")
    while True:
        try:
            resp = sqs.receive_message(QueueUrl=QUEUE_URL, MaxNumberOfMessages=1, WaitTimeSeconds=20, VisibilityTimeout=VISIBILITY)
            for m in resp.get("Messages", []): process_message(m)
        except KeyboardInterrupt:
            log("Exiting..."); break
        except Exception as e:
            log("WARN receive loop:", e); time.sleep(2)

if __name__ == "__main__":
    main()
