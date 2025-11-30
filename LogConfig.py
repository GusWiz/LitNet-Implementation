from loguru import logger
import datetime
logger.remove()

# Create a timestamp for this run
timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")

logger.add(
    f"litsune_runtime_{timestamp}.log",
    format="{time:YYYY-MM-DD HH:mm:ss} | {level} | {message}",
    level="DEBUG",
    rotation="10 MB",
    retention="10 days",
    compression="zip",
    backtrace=True,
    diagnose=True,
)