import time

f = open(r"C:\Users\DHARUN\python\my_data_folder\loop.txt", "w")

while True:
    f.write("writing...\n")
    f.flush()
    time.sleep(0.1)

