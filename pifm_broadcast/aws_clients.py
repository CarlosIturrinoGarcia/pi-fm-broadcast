"""AWS client wrappers for SQS and S3 operations."""

import logging
from typing import Optional, List, Dict, Any
import boto3
from botocore.config import Config as BotoConfig
from botocore.exceptions import ClientError, BotoCoreError

from .exceptions import DownloadError, MessageProcessingError


logger = logging.getLogger(__name__)


class SQSClient:
    """Thread-safe SQS client wrapper."""

    def __init__(
        self,
        queue_url: str,
        region_name: str = "us-east-1",
        dlq_url: Optional[str] = None
    ):
        """Initialize SQS client.

        Args:
            queue_url: SQS queue URL
            region_name: AWS region
            dlq_url: Dead letter queue URL (optional)
        """
        self.queue_url = queue_url
        self.dlq_url = dlq_url

        # Configure client with timeouts and retries
        boto_config = BotoConfig(
            connect_timeout=5,
            read_timeout=60,
            retries={"max_attempts": 5, "mode": "standard"},
            region_name=region_name,
        )

        self.client = boto3.client("sqs", config=boto_config)
        logger.info(f"SQSClient initialized: queue={queue_url}, region={region_name}")

    def receive_messages(
        self,
        max_messages: int = 1,
        wait_time: int = 20,
        visibility_timeout: int = 300
    ) -> List[Dict[str, Any]]:
        """Receive messages from queue.

        Args:
            max_messages: Maximum number of messages to receive
            wait_time: Long polling wait time in seconds
            visibility_timeout: Visibility timeout in seconds

        Returns:
            List of messages

        Raises:
            MessageProcessingError: If receive operation fails
        """
        try:
            response = self.client.receive_message(
                QueueUrl=self.queue_url,
                MaxNumberOfMessages=max_messages,
                WaitTimeSeconds=wait_time,
                VisibilityTimeout=visibility_timeout,
                AttributeNames=["All"],
                MessageAttributeNames=["All"],
            )
            return response.get("Messages", [])

        except (ClientError, BotoCoreError) as e:
            raise MessageProcessingError(f"Failed to receive messages: {e}")

    def delete_message(self, receipt_handle: str) -> bool:
        """Delete message from queue.

        Args:
            receipt_handle: Message receipt handle

        Returns:
            True if successful, False otherwise
        """
        try:
            self.client.delete_message(
                QueueUrl=self.queue_url,
                ReceiptHandle=receipt_handle
            )
            logger.debug(f"Deleted message: {receipt_handle[:20]}...")
            return True

        except ClientError as e:
            logger.warning(f"Failed to delete message: {e}")
            return False

    def change_visibility(
        self,
        receipt_handle: str,
        timeout: int
    ) -> bool:
        """Change message visibility timeout.

        Args:
            receipt_handle: Message receipt handle
            timeout: New visibility timeout in seconds (0-43200)

        Returns:
            True if successful, False otherwise
        """
        try:
            # Ensure timeout is within SQS limits
            timeout = max(0, min(timeout, 43200))

            self.client.change_message_visibility(
                QueueUrl=self.queue_url,
                ReceiptHandle=receipt_handle,
                VisibilityTimeout=timeout
            )
            logger.debug(f"Changed visibility to {timeout}s: {receipt_handle[:20]}...")
            return True

        except ClientError as e:
            logger.warning(f"Failed to change visibility: {e}")
            return False

    def send_to_dlq(
        self,
        message_body: str,
        message_id: str,
        group_id: Optional[str] = None,
        attributes: Optional[Dict] = None
    ) -> bool:
        """Send message to dead letter queue.

        Args:
            message_body: Message body
            message_id: Message ID (used for deduplication)
            group_id: Message group ID for FIFO queues
            attributes: Additional message attributes

        Returns:
            True if successful, False otherwise
        """
        if not self.dlq_url:
            logger.warning("DLQ not configured, cannot send message")
            return False

        try:
            kwargs = {
                "QueueUrl": self.dlq_url,
                "MessageBody": message_body,
            }

            if group_id:
                kwargs["MessageGroupId"] = group_id

            if message_id:
                kwargs["MessageDeduplicationId"] = message_id

            if attributes:
                kwargs["MessageAttributes"] = attributes

            self.client.send_message(**kwargs)
            logger.info(f"Sent message to DLQ: {message_id}")
            return True

        except ClientError as e:
            logger.error(f"Failed to send to DLQ: {e}")
            return False


class S3Client:
    """Thread-safe S3 client wrapper."""

    def __init__(self, region_name: str = "us-east-1"):
        """Initialize S3 client.

        Args:
            region_name: AWS region
        """
        # Configure client with timeouts and retries
        boto_config = BotoConfig(
            connect_timeout=5,
            read_timeout=60,
            retries={"max_attempts": 5, "mode": "standard"},
            region_name=region_name,
        )

        self.client = boto3.client("s3", config=boto_config)
        logger.info(f"S3Client initialized: region={region_name}")

    def download_file(self, bucket: str, key: str, local_path: str) -> str:
        """Download file from S3.

        Args:
            bucket: S3 bucket name
            key: S3 object key
            local_path: Local file path to save to

        Returns:
            Local file path

        Raises:
            DownloadError: If download fails
        """
        try:
            logger.info(f"Downloading s3://{bucket}/{key} -> {local_path}")
            self.client.download_file(bucket, key, local_path)
            logger.debug(f"Download complete: {local_path}")
            return local_path

        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', 'Unknown')
            if error_code == 'NoSuchKey':
                raise DownloadError(f"S3 object not found: s3://{bucket}/{key}")
            elif error_code == 'NoSuchBucket':
                raise DownloadError(f"S3 bucket not found: {bucket}")
            elif error_code == '403':
                raise DownloadError(f"Access denied to s3://{bucket}/{key}")
            else:
                raise DownloadError(f"S3 download failed: {e}")

        except BotoCoreError as e:
            raise DownloadError(f"S3 download failed: {e}")

    def head_object(self, bucket: str, key: str) -> Dict[str, Any]:
        """Get object metadata without downloading.

        Args:
            bucket: S3 bucket name
            key: S3 object key

        Returns:
            Object metadata dictionary

        Raises:
            DownloadError: If operation fails
        """
        try:
            response = self.client.head_object(Bucket=bucket, Key=key)
            return response

        except ClientError as e:
            error_code = e.response.get('Error', {}).get('Code', 'Unknown')
            if error_code == '404':
                raise DownloadError(f"S3 object not found: s3://{bucket}/{key}")
            else:
                raise DownloadError(f"S3 head_object failed: {e}")
