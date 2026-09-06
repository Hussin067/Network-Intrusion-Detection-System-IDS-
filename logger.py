from pathlib import Path

LOG_FILE = Path(__file__).resolve().parent / "ids.log"


def write_log(message):
    with open(LOG_FILE, "a") as log_file:
        log_file.write(message + "\n")


def read_logs():
    if not LOG_FILE.exists():
        return []

    with open(LOG_FILE, "r") as log_file:
        return log_file.readlines()