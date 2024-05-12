import os
import subprocess


def system_tracerout():
    # output = os.popen("tracert ya.ru", "r").readlines().encode("cp1251").decode("cp866")
    # output = subprocess.check_output(["echo", "ya.ru"], encoding='cp866')
    # for line in output:
    #     print(line)
    output = os.popen("tracert google.com", "r")
    for line in output:
        line = line.split(" ")
        if len(line) > 2:
            if line[2].isdigit() or line[1].isdigit() or line[0].isdigit():
                if line[-1] == "\n":
                    print(line[-2].strip("[]"))
                    print("bebra")
        print(line)
    pass


# process = subprocess.run(["tracert", "ya.ru"], shell=True, encoding="cp866")

system_tracerout()
