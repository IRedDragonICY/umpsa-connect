import logging
from threading import Lock

logger = logging.getLogger(__name__)


class Counter:
    def __init__(self, total: int):
        logger.debug("Initializing Counter with total: %d", total)
        self.total = total
        self.completed = 0
        self.lock = Lock()

    def increment(self) -> None:
        with self.lock:
            self.completed += 1
            logger.info("Incremented counter: %d/%d", self.completed, self.total)

    def get_progress(self) -> str:
        with self.lock:
            percentage = (self.completed / self.total) * 100 if self.total else 0.0
            progress = f"{self.completed}/{self.total} ({percentage:.2f}%)"
            logger.debug("Current progress: %s", progress)
            return progress