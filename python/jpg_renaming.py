from glob import glob
import os

path = "./cmmc/*"
list = glob(path)
i = 0
for file in list:
    i += 1
    os.rename(file, f"module3-{i}.jpg")
print(list)