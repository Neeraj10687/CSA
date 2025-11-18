import os

for folder in WATCH_FOLDERS:
    os.makedirs(folder, exist_ok=True)


WATCH_FOLDERS = [
    "watch_folder_1",
    "watch_folder_2",
    "watch_folder_3"
]