# FM Broadcast

Raspberry Pi FM broadcaster project.


# Pi FM Broadcast

Small Raspberry Pi service that plays WAV files over FM using `pifm` and pulls work from an SQS queue.

---

## Environment

Create an env file (e.g., `~/broadcast.env`) and add:

```bash
# Path: ~/broadcast.env  (not committed; see .gitignore)

# Command template used to broadcast a WAV file.
# {file} will be replaced by the WAV file path at runtime.
export BROADCAST_CMD="/usr/bin/sudo /home/rpibroadcaster/fm_transmitter/pifm {file} -f 91.0"

# AWS SQS queue URL to poll for jobs
export QUEUE_URL="<sqs-url>"

# AWS region (e.g., us-east-1)
export AWS_REGION=<AWS region>

# SQS message visibility timeout (seconds)
export VISIBILITY=300
