#!/usr/bin/env python3
"""
Pi FM Broadcast - Production-ready FM broadcasting service.

This application polls an AWS SQS queue for audio broadcast jobs,
downloads WAV files from S3 or URLs, and broadcasts them via FM
using the pifm transmitter.
"""

import sys
import time
import logging
from pathlib import Path

from .config import Config
from .logger import setup_logger
from .aws_clients import SQSClient, S3Client
from .file_manager import FileManager
from .broadcaster import Broadcaster
from .silence import SilenceManager
from .downloader import Downloader
from .message_processor import MessageProcessor
from .signal_handler import SignalHandler
from .health import HealthMonitor
from .exceptions import ConfigurationError, MessageProcessingError


logger = logging.getLogger(__name__)


class FMBroadcastService:
    """Main FM broadcast service."""

    def __init__(self, config: Config):
        """Initialize service with configuration.

        Args:
            config: Application configuration
        """
        self.config = config

        # Initialize AWS clients
        self.sqs_client = SQSClient(
            queue_url=config.queue_url,
            region_name=config.aws_region,
            dlq_url=config.dlq_url
        )
        self.s3_client = S3Client(region_name=config.aws_region)

        # Initialize file manager
        self.file_manager = FileManager(
            download_dir=config.download_dir,
            max_stored_files=config.max_stored_files,
            cleanup_interval=config.cleanup_interval
        )

        # Initialize broadcaster
        self.broadcaster = Broadcaster(config=config)

        # Initialize silence manager
        self.silence_manager = SilenceManager(config=config)

        # Initialize downloader
        self.downloader = Downloader(
            config=config,
            s3_client=self.s3_client,
            file_manager=self.file_manager
        )

        # Initialize message processor
        self.message_processor = MessageProcessor(
            config=config,
            sqs_client=self.sqs_client,
            downloader=self.downloader,
            broadcaster=self.broadcaster,
            silence_manager=self.silence_manager,
            file_manager=self.file_manager
        )

        # Initialize signal handler
        self.signal_handler = SignalHandler(
            config=config,
            broadcaster=self.broadcaster,
            silence_manager=self.silence_manager
        )

        # Initialize health monitor
        self.health_monitor = HealthMonitor()

        logger.info("FMBroadcastService initialized")

    def startup(self) -> None:
        """Perform startup procedures."""
        logger.info("=" * 60)
        logger.info("Pi FM Broadcast Service Starting")
        logger.info("=" * 60)
        logger.info(f"Queue: {self.config.queue_url}")
        logger.info(f"Download dir: {self.config.download_dir}")
        logger.info(f"Broadcast command: {self.config.broadcast_cmd_template}")
        logger.info(f"Visibility: {self.config.visibility_timeout}s")
        logger.info(f"Heartbeat: {self.config.heartbeat_interval}s")
        logger.info(f"Max playback: {self.config.max_playback_secs}s")
        logger.info(f"Message timeout: {self.config.message_timeout_secs}s")
        logger.info(f"Max receive count: {self.config.max_receive_count}")
        if self.config.dlq_url:
            logger.info(f"DLQ: {self.config.dlq_url}")
        logger.info("=" * 60)

        # Setup signal handlers
        self.signal_handler.setup_handlers()

        # Ensure silence file exists
        self.silence_manager.ensure_silence_file_exists()

        # Start silence carrier
        logger.info("Starting idle silence carrier...")
        if self.silence_manager.start():
            logger.info("Silence carrier started successfully")
        else:
            logger.warning("Failed to start silence carrier, will retry")

        logger.info("Service startup complete, entering main loop")

    def shutdown(self) -> None:
        """Perform graceful shutdown."""
        logger.info("=" * 60)
        logger.info("Graceful Shutdown Initiated")
        logger.info("=" * 60)

        # Stop current broadcast
        if self.broadcaster.is_playing():
            logger.info("Stopping current broadcast...")
            self.broadcaster.stop_current()

        # Stop silence carrier
        logger.info("Stopping silence carrier...")
        self.silence_manager.stop()

        # Log final metrics
        logger.info("Final metrics:")
        self.health_monitor.log_metrics()

        # Log file stats
        file_stats = self.file_manager.get_stats()
        logger.info(
            f"File stats: {file_stats['file_count']} files, "
            f"{file_stats['total_size_bytes'] / 1024 / 1024:.1f} MB"
        )

        logger.info("Shutdown complete")

    def run_once(self) -> bool:
        """Run one iteration of the main loop.

        Returns:
            True to continue, False to exit
        """
        # Check for shutdown signal
        if self.signal_handler.should_shutdown():
            return False

        # Check for reload signal
        if self.signal_handler.should_reload():
            self.signal_handler.handle_reload()

        # Perform automatic file cleanup
        self.file_manager.auto_cleanup()

        # Receive messages from SQS
        try:
            messages = self.sqs_client.receive_messages(
                max_messages=1,
                wait_time=self.config.sqs_wait_time,
                visibility_timeout=self.config.visibility_timeout
            )

        except MessageProcessingError as e:
            logger.error(f"Failed to receive messages: {e}")
            time.sleep(2)
            return True

        # No messages, ensure silence is playing
        if not messages:
            self.silence_manager.ensure_playing()
            return True

        # Process each message
        for message in messages:
            # Check for interrupt before processing
            if self.signal_handler.should_reload():
                self.message_processor.handle_interrupt_before_processing(
                    message["ReceiptHandle"]
                )
                self.signal_handler.handle_reload()
                continue

            # Process message
            try:
                should_delete = self.message_processor.process_message(message)

                # Record metrics
                self.health_monitor.record_message_processed(should_delete)

                # Delete message if successful
                if should_delete:
                    self.sqs_client.delete_message(message["ReceiptHandle"])

            except Exception as e:
                logger.error(
                    f"Unexpected error processing message {message.get('MessageId', '?')}: {e}",
                    exc_info=True
                )
                self.health_monitor.record_message_processed(False)

        return True

    def run(self) -> int:
        """Run the main service loop.

        Returns:
            Exit code (0 for success, non-zero for error)
        """
        try:
            self.startup()

            # Main loop
            while True:
                try:
                    if not self.run_once():
                        break

                except KeyboardInterrupt:
                    logger.info("Received KeyboardInterrupt")
                    break

                except Exception as e:
                    logger.error(f"Error in main loop: {e}", exc_info=True)
                    time.sleep(2)

            self.shutdown()
            return 0

        except Exception as e:
            logger.critical(f"Fatal error: {e}", exc_info=True)
            return 1


def main() -> int:
    """Main entry point.

    Returns:
        Exit code
    """
    # Setup logging
    log_level = "INFO"
    structured = False

    logger_instance = setup_logger(
        name="pifm_broadcast",
        level=log_level,
        structured=structured
    )

    try:
        # Load configuration
        logger.info("Loading configuration...")
        config = Config()
        logger.info("Configuration loaded successfully")

        # Create and run service
        service = FMBroadcastService(config)
        return service.run()

    except ConfigurationError as e:
        logger.critical(f"Configuration error: {e}")
        return 2

    except Exception as e:
        logger.critical(f"Fatal startup error: {e}", exc_info=True)
        return 1


if __name__ == "__main__":
    sys.exit(main())
