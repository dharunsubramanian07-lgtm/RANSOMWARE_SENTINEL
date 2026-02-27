import os

path = r"C:\Users\DHARUN\python\my_data_folder"

for i in range(15):
    old = os.path.join(path, f"file{i}.txt")
    new = os.path.join(path, f"file{i}.locked")

    with open(old, "w") as f:
        f.write("hello")

    os.rename(old, new)
