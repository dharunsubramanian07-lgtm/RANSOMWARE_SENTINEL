import os
import time

path = r"C:\Users\DHARUN\python\my_data_folder\victim.txt"

with open(path, "w") as f:
    f.write("This is normal readable text file.")

time.sleep(2)

with open(path, "wb") as f:
    f.write(os.urandom(10000))
