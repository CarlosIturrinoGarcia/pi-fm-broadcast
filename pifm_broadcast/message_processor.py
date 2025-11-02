"""Message processing with DLQ handling and timeout management."""

import time
import logging
from typing import Optional

from .config import Config
from .aws_clients import SQSClient
from .downloader import Downloader
from .broadcaster import Broadcaster
from .silence import SilenceManager
from .file_manager import FileManager
from .logger import correlation_context
from .exceptions import (
    DownloadError,
    ValidationError,
    PlaybackError,
    PlaybackTimeout,
    PlaybackInterrupted,
    MessageProcessingError
)


logger = logging.getLogger(__name__)


class MessageProcessor:
    """Processes SQS messages with error handling and DLQ support."""

    def __init__(
        self,
        config: Config,
        sqs_client: SQSClient,
        downloader: Downloader,
        broadcaster: Broadcaster,
        silence_manager: SilenceManager,
        file_manager: FileManager
    ):
        """Initialize message processor.

        Args:
            config: Application configuration
            sqs_client: SQS client
            downloader: File downloader
            broadcaster: Broadcaster
            silence_manager: Silence manager
            file_manager: File manager
        """
        self.config = config
        self.sqs = sqs_client
        self.downloader = downloader
        self.broadcaster = broadcaster
        self.silence = silence_manager
        self.file_manager = file_manager

        logger.info("MessageProcessor initialized")

    def process_message(self, message: dict) -> bool:
        """Process a single SQS message.

        Args:
            message: SQS message dictionary

        Returns:
            True if message was processed successfully (should be deleted)
            False if message should be retried (left in queue)
        """
        start_time = time.time()

        # Extract message metadata
        receipt_handle = message.get("ReceiptHandle", "")
        message_id = message.get("MessageId", "unknown")
        attributes = message.get("Attributes", {}) or {}
        group_id = attributes.get("MessageGroupId", "n/a")
        receive_count = int(attributes.get("ApproximateReceiveCount", "1"))

        # Use message ID as correlation ID for logging
        with correlation_context(message_id):
            logger.info(
                f"Processing message: id={message_id}, "
                f"group={group_id}, "
                f"receive_count={receive_count}"
            )

            # Check if message should go to DLQ
            if receive_count >= self.config.max_receive_count:
                logger.warning(
                    f"Message exceeded max receive count ({self.config.max_receive_count}), "
                    "sending to DLQ"
                )
                if self._send_to_dlq(message):
                    return True  # Successfully moved to DLQ, delete from main queue
                else:
                    logger.error("Failed to send to DLQ, leaving in queue")
                    return False  # Leave in queue for retry

            # Process message with timeout
            try:
                return self._process_with_timeout(
                    message,
                    receipt_handle,
                    message_id,
                    start_time
                )

            except PlaybackInterrupted:
                # Interrupt was requested, message already requeued
                logger.info("Playback interrupted, message requeued")
                return False  # Don't delete, already requeued

            except (ValidationError, DownloadError) as e:
                # These are likely permanent errors, don't retry
                logger.error(f"Validation/download error (permanent): {e}")
                if self._send_to_dlq(message):
                    return True  # Moved to DLQ
                return False  # Leave for retry if DLQ send failed

            except PlaybackTimeout as e:
                # Playback took too long, might be a problem with the file
                logger.error(f"Playback timeout: {e}")
                if self._send_to_dlq(message):
                    return True
                return False

            except PlaybackError as e:
                # Playback error, might be transient
                logger.error(f"Playback error (will retry): {e}")
                return False  # Leave in queue for retry

            except Exception as e:
                # Unexpected error, log and retry
                logger.error(f"Unexpected error processing message: {e}", exc_info=True)
                return False  # Leave in queue for retry

    def _process_with_timeout(
        self,
        message: dict,
        receipt_handle: str,
        message_id: str,
        start_time: float
    ) -> bool:
        """Process message with overall timeout.

        Args:
            message: SQS message
            receipt_handle: Receipt handle
            message_id: Message ID
            start_time: Processing start time

        Returns:
            True if message should be deleted, False otherwise
        """
        # Download file
        logger.info("Downloading file...")
        try:
            file_path = self.downloader.download(message["Body"])
        except (DownloadError, ValidationError):
            raise  # Re-raise for outer handler

        # Check timeout before playback
        elapsed = time.time() - start_time
        if elapsed >= self.config.message_timeout_secs:
            logger.error(
                f"Message timeout before playback ({elapsed:.1f}s >= "
                f"{self.config.message_timeout_secs}s)"
            )
            # Clean up downloaded file
            self.file_manager.delete_file(file_path)
            return False  # Retry

        # Stop silence and broadcast
        logger.info(f"Broadcasting {file_path}...")
        self.silence.stop()

        try:
            # Create visibility callback
            def extend_visibility(elapsed_secs: int) -> bool:
                success = self.sqs.change_visibility(
                    receipt_handle,
                    min(self.config.visibility_timeout, Config.MAX_VISIBILITY_TIMEOUT)
                )
                if success:
                    logger.debug(f"Extended visibility (elapsed={elapsed_secs}s)")
                return success

            # Broadcast with timeout and visibility extension
            self.broadcaster.broadcast(
                file_path,
                correlation_id=message_id,
            )

            # Manually extend visibility during broadcast
            # (Note: In production, this should be done in the broadcaster's monitoring loop)

        finally:
            # Always restart silence after broadcast (success or failure)
            self.silence.ensure_playing()

        # Check timeout after playback
        elapsed = time.time() - start_time
        if elapsed >= self.config.message_timeout_secs:
            logger.error(
                f"Message timeout after playback ({elapsed:.1f}s >= "
                f"{self.config.message_timeout_secs}s)"
            )
            return False  # Don't delete, will retry

        # Success!
        logger.info(f"Message processed successfully in {elapsed:.1f}s")
        return True

    def _send_to_dlq(self, message: dict) -> bool:
        """Send message to DLQ.

        Args:
            message: SQS message

        Returns:
            True if sent successfully
        """
        if not self.sqs.dlq_url:
            logger.warning("DLQ not configured, cannot send message")
            return False

        message_id = message.get("MessageId", "unknown")
        attributes = message.get("Attributes", {}) or {}
        group_id = attributes.get("MessageGroupId")

        success = self.sqs.send_to_dlq(
            message_body=message["Body"],
            message_id=message_id,
            group_id=group_id
        )

        if success:
            # Delete from main queue
            self.sqs.delete_message(message["ReceiptHandle"])
            logger.info(f"Message sent to DLQ: {message_id}")

        return success

    def handle_interrupt_before_processing(self, receipt_handle: str) -> None:
        """Handle interrupt signal received before message processing.

        Args:
            receipt_handle: Receipt handle of message to requeue
        """
        logger.info("Interrupt received before processing, requeuing message")
        self.sqs.change_visibility(receipt_handle, 0)
