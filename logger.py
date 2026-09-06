LOG_FILE = "/home/hussin/ids-project/ids.log"

def write_log(message):
    with open(LOG_FILE, "a") as log_file:
        log_file.write(message + "\n")

def read_logs():
    try:
        with open(LOG_FILE, "r") as log_file:
            return log_file.readlines()
    except FileNotFoundError:
        return []