import time
import threading
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from hashing import compute_hashes
from vt import check_filehash_virustotal
from event_store import add_event
from logger import log_event
from notifier import notify
from watcher_config import WATCH_FOLDERS

class ThreatWatchHandler(FileSystemEventHandler):
    def on_created(self, event):
        if event.is_directory:
            return

        file_path = event.src_path
        print(f"[Watchdog] New file detected: {file_path}")

        # Compute hashes
        hashes = compute_hashes(file_path)

        # VT Check
        vt_result = check_filehash_virustotal(hashes["sha256"])

        # Store in event_store
        add_event(
            event_type="file_created",
            file_path=file_path,
            hashes=hashes,
            vt_result=vt_result
        )

        # Log
        log_event(
            event_type="watchdog_file_created",
            file_path=file_path,
            hashes=hashes,
            vt_result=vt_result
        )

        # Notify
        notify(
            event_type="watchdog_file_created",
            file_path=file_path,
            hashes=hashes,
            vt_result=vt_result
        )

def start_watcher(folder):
    observer = Observer()
    handler = ThreatWatchHandler()
    observer.schedule(handler, folder, recursive=False)
    observer.start()
    print(f"[Watchdog] Monitoring: {folder}")
    observer.join()


threads = []
for folder in WATCH_FOLDERS:
    t = threading.Thread(target=start_watcher, args=(folder,), daemon=True)
    t.start()
    threads.append(t)

try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    print("[Watchdog] Stopping all observers...")