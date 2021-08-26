from pwn import *
import sys
import os
from pathlib import Path

from threading import Thread

from clients.GhidraCommandClient import GhidraCommandClient

class GhidraGdb:

    FIFO = "/tmp/gdbPipe"
    
    def __init__(self, process=None):
        self.fifo = None

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
        self.removals = []


    def removeBpByPattern(self, pattern):
        self.removals.append(pattern)
        
        

    def excAndGet(self, exc):

        self.currRet = ""
        self.parserMode = "GETDAT"

        
        self.gdb.execute(exc.split("\n")[0])
        self.gdb.execute("print \"ggdb__EOF\"")
        while self.parserMode == "GETDAT":
            time.sleep(0.01)

        return self.currRet.split("$")[0]


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


    def getProcOffset(self, procName):

        print("waiting for thread")
        while self.checkThreadRunning():
            time.sleep(0.05)

        print("getting proc mapping")
        #get the proc mappings from gdb
        procMappings = self.excAndGet("i proc mappings")
        
        proc_maps = []

        #get and format the memory mappings which are mapping the main executable
        for line in procMappings.split("\n"):

            if procName in line:
                ln = line.replace("\t", " ")
                
                #turn multiple whitespaces into single whitespaces
                while "  " in ln:
                    ln = ln.replace("  ", " ")

                #create an array, containing the different columns
                arr = ln.split(" ")
                if len(arr[0]) < 2:
                    arr.pop(0)

                proc_maps.append(arr)

        ## get the lowest Start Address
        offset = 0
        procStartAddresss = 0
        for i, map in enumerate(proc_maps):
            if i == 0 or offset > int(map[3].split("x")[1],16) :
                offset = int(map[3].split("x")[1],16)
                procStartAddresss = map[0]

        return procStartAddresss
    
    def run(self, cmd, interactive=True, startCommands="", args=""):

        #connect reader thread to read gdb pipe
        self.setupFifoNonBlock(self.FIFO)

        self.process = gdb.debug(cmd, '''
        set logging file /tmp/gdbPipe
        set logging on
        starti'''  + str(args) + "\n" + startCommands, api=True)

        self.gdb = self.process.gdb
        #self
        
        if interactive:
            self.setupGdbInteractive()

        self.runtimeAnalysisNonBlock()

        #we need to calculate the offset between Ghidra and the process mapping here (Because of ...)
        imageBase = self.client.br.remote_eval("str(getState().getCurrentProgram().getAddressMap().getImageBase())") 

        procOffset = self.getProcOffset(Path(cmd).name)


        if procOffset == 0:
            return self.process, False
        
        print("Found proc offset: " + str(procOffset))
        #calculate final dynamic offset
        self.procOffset = str(hex(int(procOffset.split("x")[1],16) - int(imageBase,16)))
        print("final offset: " + str(self.procOffset))

        
        print("EXECUTING GDB BP SETUP")

        for bp in self.client.breakpoints:
            skip = False
            for line in bp.pyExc.split("\n"):
                for line2 in self.removals:
                    if line2 in line:
                        skip = True

            if skip:
                continue
            print("ADDING BP")
            bp.rebuiltWithOffset(self.procOffset)

            bp.setHitLimit(0)
            ret  = self.excAndGet(str(bp.setup))

            #we parse the number of the breakpoint (in gdb)
            parts = ret.split(" ")
            parse = False
            number = 0
            for part in parts:

                if parse:
                    try:
                        number = int(part)
                    except:
                        pass
                
                if "Breakpoint" in part:
                    parse = True
                    
            bp.number = number
                    
            print("return from setup: " + str(ret))
            #self.gdb.execute(str(bp.setup))

            
        self.gdb.execute(str("continue"))
        return self.process, True

    def setupGdb(self, interactive=True, startCommands=""):

        #connect reader thread to read gdb pipe
        self.setupFifoNonBlock(self.FIFO)

        self.pid, self.gdb = gdb.attach(self.process, '''
        set logging file /tmp/gdbPipe
        set logging on
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

            #time.sleep(5)
        
        print("CONTINUE")

        self.parserMode = "WAITBP"

        while True:

            time.sleep(0.05)
            while self.checkThreadRunning():
                time.sleep(0.05)

                
            finBp = None
            try:
                if self.breakpointAddr:
                    #print("breakpoint hit")
                    for bp in self.client.breakpoints:
                        if bp.address.split("x")[1] in self.breakpointAddr:
                            finBp = bp
                            self.breakpointAddr = None
                            break
            except:
                continue
            
            if not finBp:
                continue

            finBp.hit()

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
        #Todo -- check this
        try:

            #print(dir(self.gdb.conn.root.gdb))#.selected_inferior().threads())
            #print(dir(self.gdb.conn.root.gdb.InferiorThread))
            #print(self.gdb.conn.root.gdb.selected_thread().is_running())

            
            #if self.gdb.conn.root.gdb.selected_inferior().threads()[0].is_running():
            if self.gdb.conn.root.gdb.selected_thread().is_running():
                
                return True
            else:
                return False
        except Exception as e:
            return True 
        


