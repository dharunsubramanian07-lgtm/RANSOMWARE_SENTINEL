import os

path = r"C:\Users\DHARUN\python\my_data_folder"

for i in range(30):
    with open(os.path.join(path, f"file{i}.txt"), "w") as f:
        f.write("hello world")

