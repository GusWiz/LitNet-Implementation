from loguru import logger

logger.remove()

logger.add(
    "litsune_runtime.log",
    format="{time:YYYY-MM-DD HH:mm:ss} | {level} | {message}",
    level="DEBUG",
    rotation="10 MB",
    retention="10 days",
    compression="zip",
    backtrace=True,
    diagnose=True,
)