from pwn import *
import sys
import os

from threading import Thread

from clients.GhidraCommandClient import GhidraCommandClient

class GhidraGdb:

    FIFO = "/tmp/gdbPipe"
    
    def __init__(self, process):
        self.fifo = None
        if not process:
            return

        self.process = process
        
        try:
            os.mkfifo(self.FIFO)
        except Exception as e:
            print(e)
            if not "File exists" in str(e):
                print("sys.exit")
                return

        self.client = GhidraCommandClient(self)
        self.parserMode = None
        self.breakpointAddr = None
        self.currRet = None


    def excAndGet(self, exc):

        self.currRet = ""
        self.parserMode = "GETDAT"

        
        self.gdb.execute(exc.split("\n")[0])
        self.gdb.execute("print \"ggdb__EOF\"")
        while self.parserMode == "GETDAT":
            time.sleep(0.01)

        return self.currRet.split("\n$")[0]

    ### Todo: The upper one of these solutions did not work to enumerate Breakpoints - find out why
    def excAndGet2(self, exc):

        self.currRet = ""
        self.parserMode = "GETDAT"

        self.gdb.execute(exc.split("\n")[0])

        self.gdb.execute("print \"ggdb__EOF\"")

        while self.parserMode == "GETDAT":
            time.sleep(0.01)

        return self.currRet
        
    def readFifo(self, fifo):
        while True:
            #time.sleep(0.05)
            line = fifo.readline()
            if len(line) > 2:
                line = line.replace("\n", "")
                if self.parserMode == "WAITBP":
                    if "Breakpoint" in line:
                        for part in line.split(" "):
                            if "0x" in part:
                                self.breakpointAddr = part.split("x")[1]
                                #print("found Breakpoint Address: " + self.breakpointAddr)

                                
                elif self.parserMode == "GETDAT":
                    self.currRet = self.currRet + line + "\n"
                    if "ggdb__EOF" in line:
                        self.parserMode = "WAITBP"

    def setupFifo(self, FIFO):
        print("setting up fifo now: " + str(FIFO))
        with open(FIFO, 'r') as fifo:
            self.fifo = fifo
            print("fiifo opened")
            self.readFifo(fifo)

    def setupFifoNonBlock(self, Fifo):
        Thread(target=self.setupFifo, args=(Fifo,), daemon=True).start()


    def setupGdbInteractive(self):
        Thread(target=self.process.interactive).start()
        
    def setupGdb(self, interactive=True, startCommands=""):

        #connect reader thread to read gdb pipe
        self.setupFifoNonBlock(self.FIFO)

        self.pid, self.gdb = gdb.attach(self.process, '''
        set logging file /tmp/gdbPipe
        set logging on
        info functions
        #continue
        ''' + startCommands, api=True)

        if interactive:
            self.setupGdbInteractive()


        self.runtimeAnalysisNonBlock()
            
    def analyze(self, funcs):
        self.client.analyze(funcs)
        


    def runtimeAnalysis(self):

        #the first breakpoint has to install the other breakpoints - then continue ...
        while self.checkThreadRunning():
            time.sleep(0.05)

        print("EXECUTING GDB BP SETUP")
            
        for bp in self.client.breakpoints:
            print("ADDING BP")
            self.gdb.execute(str(bp.setup))

        self.gdb.execute(str("continue"))

        self.parserMode = "WAITBP"

        while True:

            time.sleep(0.05)
            while self.checkThreadRunning():
                time.sleep(0.05)

                
            finBp = None
            try:
                if self.breakpointAddr:
                    #print("BREAKPOINT HIT")
                    for bp in self.client.breakpoints:
                        if bp.lineNr in self.breakpointAddr:
                            #print("BREAKPOINT FOUND")
                            finBp = bp
                            self.breakpointAddr = None
                            break
            except:
                continue
            
            if not finBp:
                continue

            finBp.activate()

            #todo - this has to be in parallel
            for line in finBp.pyExc.split("\n"):
                if len(line) > 1:
                    try:
                        finBp.exec_(line)
                    except Exception as e:
                        print("Exception during code execution: " + str(line))
                        print(str(e))
            
            for line in finBp.dbExc.split("\n"):
                if len(line) > 0:
                    try:
                        self.gdb.execute(line)
                        if line[0] == "c" or "continue" in line:
                            finBp.deactivate()
                            
                    except Exception as e:
                        print("Error in GDB execution of:" + str(line))
                        print("Exception: " + str(e))
                        


        

    def runtimeAnalysisNonBlock(self):
        Thread(target=self.runtimeAnalysis, daemon=True).start()

    #check if current thread is running ... (if gdb hits breakpoint ...)
    def checkThreadRunning(self):
        if self.gdb.conn.root.gdb.selected_inferior().threads()[0].is_running():
            return True
        else:
            return False

        


