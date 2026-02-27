import os

with open("attack_test.txt", "wb") as f:
    f.write(os.urandom(10000))
