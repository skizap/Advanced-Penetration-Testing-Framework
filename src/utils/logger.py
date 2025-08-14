"""
Logging Configuration Module
Sets up structured logging for the framework
"""

import sys
from pathlib import Path
from loguru import logger
from core.config import config_manager


def setup_logging():
    """Configure logging for the framework"""
    # Remove default logger
    logger.remove()

    # Get logging configuration
    log_level = config_manager.get('logging.level', 'INFO')
    log_file = config_manager.get('logging.file', 'logs/framework.log')
    max_size = config_manager.get('logging.max_size', '100MB')
    backup_count = config_manager.get('logging.backup_count', 5)

    # Ensure log directory exists
    log_path = Path(log_file)
    log_path.parent.mkdir(parents=True, exist_ok=True)

    # Console logging with colors
    logger.add(
        sys.stderr,
        level=log_level,
        format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | "
               "<level>{level: <8}</level> | "
               "<cyan>{name}</cyan>:<cyan>{function}</cyan>:<cyan>{line}</cyan> | "
               "<level>{message}</level>",
        colorize=True
    )

    # File logging with rotation
    logger.add(
        log_file,
        level=log_level,
        format="{time:YYYY-MM-DD HH:mm:ss} | {level: <8} | {name}:{function}:{line} | {message}",
        rotation=max_size,
        retention=backup_count,
        compression="zip"
    )

    logger.info("Logging system initialized")


def get_logger(name: str):
    """Get a logger instance for a specific module"""
    return logger.bind(name=name)