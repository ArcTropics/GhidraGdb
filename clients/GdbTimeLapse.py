import os
import sys
import subprocess
import time
import ast


import termios, fcntl, sys, os


class GdbTimeLapse:


    def __init__(self):
        self.tl = []

    def append(self, frame):
        self.tl.append(frame)

    def view(self):
        file = open("/tmp/tmpfile", 'w')
        file.write(str(self.tl))
        file.close()
        self.process = subprocess.Popen("xfce4-terminal -e '" + str(sys.executable) + " " + str(os.path.realpath(__file__)) + "'", shell=True)
        #print("writing into stdin: " +  str(str(self.tl).replace("\"", "'").join("\n").encode('utf-8')))
        #self.process.stdin.write(str(self.tl).replace("\"", "'").join("\n").encode('utf-8'))

        print("writing done")


    
class TimeLapseViever:
    
    def __init__(self, data):
        pass
        
if __name__ == "__main__":

    try:
        print("hello world in timelapse")
        #time.sleep(5)
        rf = open("/tmp/tmpfile", 'r')
        line = rf.readline() 
        total = ""
        while line:
            total += line

            line = rf.readline() 

        
        arr= ast.literal_eval(total)

        fd = sys.stdin.fileno()

        oldterm = termios.tcgetattr(fd)
        newattr = termios.tcgetattr(fd)
        newattr[3] = newattr[3] & ~termios.ICANON & ~termios.ECHO
        termios.tcsetattr(fd, termios.TCSANOW, newattr)

        oldflags = fcntl.fcntl(fd, fcntl.F_GETFL)
        fcntl.fcntl(fd, fcntl.F_SETFL, oldflags | os.O_NONBLOCK)

        cnt = 0
        print("Frame " + str(cnt+1) + "/" + str(len(arr)) + "\n")
        print(arr[cnt])
        
        lastTrig = False
        while 1:
            try:
                c = sys.stdin.read(1)
                if c:


                    if lastTrig:
                        if str(c) == 'C':
                            #Right Arrow
                            cnt+=1
                            if cnt >= len(arr) -1:
                                cnt = len(arr) -1

                            os.system('clear')
                            print("Frame " + str(cnt+1) + "/" + str(len(arr)) + "\n")
                            print(arr[cnt])
                        if str(c) == 'D':
                            #Left Arrow
                            cnt-=1
                            if cnt < 0:
                                cnt = 0

                            os.system('clear')
                            print("Frame " + str(cnt+1) + "/" + str(len(arr)) + "\n")
                            print(arr[cnt])


                    if str(c) == '[':
                        lastTrig = True
                    else:
                        lastTrig = False

            except IOError:
                pass
        time.sleep(15)
    except Exception as e:
        print(e)
        time.sleep(5)
    
 
    
