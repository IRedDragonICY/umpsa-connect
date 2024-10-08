import logging
import sys
from pathlib import Path

from ui import UMPSAConnectApp
from webdriver_utils import ensure_connected_to_umspa_id

BASE_PATH = Path(getattr(sys, '_MEIPASS', Path.cwd()))
LOG_FILE = BASE_PATH / "app.log"

logging.basicConfig(
    level=logging.INFO,
    format='[%(asctime)s] %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(str(LOG_FILE)),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)

if __name__ == "__main__":
    ensure_connected_to_umspa_id()
    app = UMPSAConnectApp()
    app.run()