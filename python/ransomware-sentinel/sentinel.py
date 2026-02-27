import time
import math
import os
import shutil
import psutil
import logging
from collections import Counter
from watchdog.observers.polling import PollingObserver as Observer
from watchdog.events import FileSystemEventHandler


# ---------------- CONFIG ----------------

WATCH_PATH = r"C:\Users\DHARUN\python\my_data_folder"
QUARANTINE_PATH = r"C:\Users\DHARUN\python\quarantine"

TEXT_ENTROPY_LIMIT = 5.8
BINARY_ENTROPY_LIMIT = 7.5
SPIKE_THRESHOLD = 2.5

MODIFICATION_WINDOW = 5
MODIFICATION_THRESHOLD = 20

RENAME_WINDOW = 5
RENAME_THRESHOLD = 10

SAFE_EXTENSIONS = ['.png', '.jpg', '.jpeg', '.zip', '.7z', '.mp4', '.pdf']

LOG_FILE = "sentinel_log.txt"

# ---------------- LOGGING ----------------

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s"
)

logging.info("Sentinel started.")


os.makedirs(WATCH_PATH, exist_ok=True)
os.makedirs(QUARANTINE_PATH, exist_ok=True)


class RansomwareSentinel(FileSystemEventHandler):

    def __init__(self):
        self.modification_times = []
        self.rename_times = []
        self.file_entropy_map = {}

    # -------- ENTROPY --------
    def calculate_entropy(self, data):
        if not data:
            return 0
        counts = Counter(data)
        length = len(data)
        entropy = 0
        for count in counts.values():
            p = count / length
            entropy -= p * math.log2(p)
        return entropy

    # -------- PROCESS KILL --------
    def kill_suspicious_process(self, file_path):
        try:
            target = os.path.abspath(file_path).lower()

            for proc in psutil.process_iter(['pid', 'name', 'open_files']):
                try:
                    files = proc.info['open_files']
                    if not files:
                        continue

                    for f in files:
                        if f.path and os.path.abspath(f.path).lower() == target:
                            logging.warning(f"PROCESS KILLED | {proc.info['name']} | PID {proc.info['pid']}")
                            print(f"🛑 Killing Process: {proc.info['name']} (PID {proc.info['pid']})")
                            proc.kill()
                            return True

                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue

        except Exception as e:
            logging.error(f"Process kill error: {e}")

        return False

    # -------- QUARANTINE --------
    def quarantine_file(self, file_path, reason):
        try:
            if not os.path.exists(file_path):
                return

            logging.warning(f"ATTACK DETECTED | {file_path} | {reason}")
            print(f"\n🚨 ATTACK DETECTED: {reason}")

            killed = self.kill_suspicious_process(file_path)

            if killed:
                print("✅ Suspicious process terminated.")
            else:
                print("⚠ No process found holding file.")

            time.sleep(0.2)

            filename = os.path.basename(file_path)
            name, ext = os.path.splitext(filename)
            dest = os.path.join(QUARANTINE_PATH, filename)

            if os.path.exists(dest):
                dest = os.path.join(
                    QUARANTINE_PATH,
                    f"{name}_{int(time.time())}{ext}"
                )

            shutil.move(file_path, dest)

            logging.warning(f"FILE QUARANTINED | {dest}")
            print(f"🔒 MOVED TO QUARANTINE: {dest}\n")

        except Exception as e:
            logging.error(f"Quarantine failed: {e}")
            print(f"❌ Quarantine failed: {e}")

    # -------- MASS MOD --------
    def detect_mass_modification(self):
        current_time = time.time()
        self.modification_times.append(current_time)

        self.modification_times = [
            t for t in self.modification_times
            if current_time - t <= MODIFICATION_WINDOW
        ]

        return len(self.modification_times) >= MODIFICATION_THRESHOLD

    # -------- RENAME DETECTION --------
    def detect_rapid_rename(self):
        current_time = time.time()
        self.rename_times.append(current_time)

        self.rename_times = [
            t for t in self.rename_times
            if current_time - t <= RENAME_WINDOW
        ]

        return len(self.rename_times) >= RENAME_THRESHOLD

    # -------- MAIN CHECK --------
    def process_check(self, file_path):

        if QUARANTINE_PATH in file_path:
            return

        if not os.path.exists(file_path):
            return

        filename = os.path.basename(file_path)

        if self.detect_mass_modification():
            self.quarantine_file(file_path, "Mass File Encryption Behavior")
            return

        if filename.count('.') > 1:
            self.quarantine_file(file_path, "Multiple Extensions Detected")
            return

        _, ext = os.path.splitext(filename.lower())

        if ext in SAFE_EXTENSIONS:
            return

        try:
            with open(file_path, "rb") as f:
                data = f.read(4096)

            new_entropy = self.calculate_entropy(data)
            old_entropy = self.file_entropy_map.get(file_path)
            self.file_entropy_map[file_path] = new_entropy

            if old_entropy is not None:
                if new_entropy - old_entropy > SPIKE_THRESHOLD:
                    self.quarantine_file(file_path,
                        f"Entropy Spike ({old_entropy:.2f} → {new_entropy:.2f})")
                    return

            limit = TEXT_ENTROPY_LIMIT if ext == ".txt" else BINARY_ENTROPY_LIMIT

            if new_entropy > limit:
                self.quarantine_file(file_path,
                        f"High Entropy ({new_entropy:.2f})")
            else:
                logging.info(f"SAFE | {filename} | Entropy {new_entropy:.2f}")
                print(f"✅ Safe: {filename} (Entropy: {new_entropy:.2f})")

        except Exception as e:
            logging.error(f"File read error: {e}")
            print(f"❌ Error reading {filename}: {e}")

    # -------- WATCHDOG EVENTS --------
    def on_created(self, event):
        if not event.is_directory:
            self.process_check(event.src_path)

    def on_modified(self, event):
        if not event.is_directory:
            self.process_check(event.src_path)

    def on_moved(self, event):
        if event.is_directory:
            return

        old_ext = os.path.splitext(event.src_path)[1].lower()
        new_ext = os.path.splitext(event.dest_path)[1].lower()

        if old_ext != new_ext:
            if self.detect_rapid_rename():
                self.quarantine_file(event.dest_path, "Rapid Extension Change")
            else:
                logging.info(f"Extension changed: {old_ext} → {new_ext}")
                print(f"⚠ Extension changed: {old_ext} → {new_ext}")


# -------- START OBSERVER --------

observer = Observer()
sentinel = RansomwareSentinel()

observer.schedule(sentinel, path=WATCH_PATH, recursive=False)
observer.start()

print(f"🛡️ Sentinel Active - Watching: {WATCH_PATH}")

try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    observer.stop()

observer.join()


