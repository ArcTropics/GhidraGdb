import ghidra_bridge
from clients.GdbTimeLapse import GdbTimeLapse
import time

import traceback

import clients.GhidraGdbOutput as otp
otp.init_()
#from ghidra.app.decompiler import DecompileOptions
#from ghidra.app.decompiler import DecompInterface
#from ghidra.util.task import ConsoleTaskMonitor



class GhidraFunction:
    
    def __init__(self):
        self.vars = []
        self.currentBreakpoint = None


class RegisterVal:

    def __init__(self, name, val):
        self.name = name
        self.val = val
        
class GhidraBreakpoint:
    
    def __init__(self, lineNr, func, offset = 0):
        tl = GdbTimeLapse()
        self.func = func
        self.lineNr = lineNr
        self.address = self.getAddress(lineNr, offset)
        self.setup = "b *" + str(self.address)
        self.dbExc = ""
        self.pyExc = ""
        self.stack = GhidraStack(self.func.client.ggdb)
        self.currentRegisters = ""
        self.offset = offset
        self.hitLimit = 0
        self.hitCount = 0
        self.number = 0
        self.otp = otp


    def rebuiltWithOffset(self, offset):
        self.address = self.getAddress(self.lineNr, offset)
        self.setup = "b *" + str(self.address)


    def find(self, lineNr):
        return self.getAddress(lineNr, self.offset)


    def getAddress(self, lineNr, offset):

        self.offset = offset

        arr = str(offset).split("x")
        if len(arr) > 1:
            offset = int(arr[1], 16)

        if offset == 0:
            return "0x" + lineNr
        else:
            return  str(hex(int(lineNr, 16) + offset))



    def c(self):
        self.deactivate()
        self.func.client.ggdb.gdb.execute("c")


    def getRegisterVal(self, reg, ggdb):

        #print("GET REG VAL: " + str(reg))
        #check if this register has already been read for this breakpoint

        fin = ""
        ##Toodo: get this right:
        if len(self.currentRegisters) > 2:
            retur = self.currentRegisters
            print("using old value")
            #retur = ggdb.excAndGet("info registers")
        else:
            retur = ggdb.excAndGet("info registers")


        for line in retur.split("\n"):
            if reg in line:
                self.currentRegisters = retur
                ebpStr = line
                while "  " in ebpStr:
                    ebpStr = ebpStr.replace("  ", " ")

                splt = ebpStr.split(" ")
                #print("Found EBP String: " + str(line) + " fin " + str(splt[1]))
                fin = splt[1].split("x")[1]
                #self.currentRegisters.append(RegisterVal(reg, fin))
                return fin

    def setHitLimit(self, limit=100):
        self.hitLimit = limit


    def getRegisterValInt(self, reg):
        try:
            ret = self.getRegisterVal(reg, self.func.client.ggdb)
            return int(str(ret), 16)
        except:
            traceback.print_exc()
            return None

    def disable(self):
        print(self.gdbGet("d " + str(self.number)))
        self.gdbGet("i b")



    def hit(self):

        self.func.currentBreakpoint = self

        self.hitCount += 1
        if self.hitLimit > 0 and self.hitLimit < self.hitCount:
            print("call deact")
            self.disable()

    def deactivate(self):
        self.currentRegisters = ""

    def dbAppend(self, db):
        self.dbExc = self.dbExc + str(db) + "\n"

    def getRegisterValX(self, reg):
        ggdb = self.func.client.ggdb
        return "0x" + self.getRegisterVal(reg, ggdb)

    def getWordX(self, addr):
        ggdb = self.func.client.ggdb
        result = ggdb.excAndGet("x/1wx "+str(addr))
        return result.split('\t')[1]

    def getLongX(self, addr):
        ggdb = self.func.client.ggdb
        result = ggdb.excAndGet("x/1g "+str(addr))
        return result.split('\t')[1]

    def pyExec(self, exc):
        self.pyExc = self.pyExc + exc + "\n"

    def gdbGet(self, exc, prnt=False):
        if prnt:
            print("gdbPrint(" + str(exc) + ")")

        ggdb = self.func.client.ggdb
        result = ggdb.excAndGet(exc)
        if prnt:
            print(result)
        return result

    def gdbGet2(self, exc, prnt=False):
        if prnt:
            print("gdbPrint(" + str(exc) + ")")

        ggdb = self.func.client.ggdb
        result = ggdb.excAndGet2(exc)
        if prnt:
            print(result)
        return result


    def gdbPrint(self, exc, prnt=True):
        if prnt:
            print("gdbPrint(" + str(exc) + ")")

        ggdb = self.func.client.ggdb
        result = ggdb.excAndGet(exc)
        if prnt:
            print(result)
        return result

    def exec_(self, exc):
        try:
            exec(exc)
        except Exception as e:
            print("Error in execution of line " + str(exc))
            print("error during gdb execution: " + str(e))
            traceback.print_exc()

    def stackPrint(self, size):
        ggdb = self.func.client.ggdb
        stk = self.getRegisterValInt("rbp")#TODO: switch this to ebp for 32bit architecture
        stk = stk - size
        result = ggdb.excAndGet("x/"+str(size) + "x " + str(hex(stk)))
        print(result)
        return result

    def stackAddFuncVars(self, funcName):

        for func in self.func.client.functions:
            if funcName in func.name:
                for var in func.vars:
                    self.stack.addVar(var, func)

    def stackAddAllVars(self):
        for var in self.func.vars:
            #print("adding var" + var.name + "at address: " +  var.getVariablePosition())
            self.stack.addVar(var, self.func)

    def stackAddLabel(self, label, address):
        self.stack.addLabel(label,address)

#could have Auto  Add
class GhidraStack:

    def __init__(self, ggdb):
        self.stackString = ""
        self.varPositions = []
        self.varNames = []
        self.ggdb = ggdb

    def addVar(self, var, func = None):
        #first we get the position of the variable
        self.varPositions.append(var.getVariablePosition())
        try:
            cv = str(hex(var.getVariablePosition()))
        except:
            cv = "none"
        print("adding var: "+ str(var.name) + " pos " + cv)
        if func:
            self.varNames.append(func.name + "." +var.name)
        else:
            self.varNames.append(var.name)

    def addLabel(self, label, address):
        self.varPositions.append(address)
        self.varNames.append(label)

    #todo - integer conversion not yet working
    def examine(self, baseAddr, numWords, verbose = False):

        #convert to integer if it is hex
        if len(str(baseAddr).split("x")) > 1:
            try:
                baseAddr = int(baseAddr.split("x")[1], 16)
            except Exception as e:
                print("Exception in examine Stack:" + str(e))
                print("inputs - baseAddr: " +  str(baseAddr) + " numWords " + str(numWords))

        ret = self.ggdb.excAndGet("x/" + str(numWords) + "wx " + str(baseAddr))
        rm = ""
        rets = ret.replace("\t", "\n").split('\n')
        cnt = 0

        if verbose:
            print("variables to be marked int the stack: ")
            for i, pos in enumerate(self.varPositions):
                try:
                    print(str(hex(pos))+ " |--| " + str(self.varNames[i]))
                except:
                    pass

        for line in rets:
            if len(line) > 2:
                if not ":" in line:

                    #check if any variable matches the current offset

                    for i, var in enumerate(self.varPositions):
                        try:
                            if var >= baseAddr + cnt * 4 and var < baseAddr + (cnt + 1) * 4:
                                rm = rm + str(self.varNames[i])+"\n"
                                otp.printG(str(self.varNames[i]))
                        except Exception as e:
                            pass
                    print(str(hex(baseAddr + cnt * 4)) + "   " + line)
                    rm = rm + str(hex(baseAddr + cnt * 4)) + "   " + line  + "\n"
                    cnt+=1
        return rm


class GhidraVar:

    def __init__(self):
        self.addr_ = 0


    def getVariablePosition(self):

        if self.addr_ != 0:
            print("returning right awaz")
            #return self.addr_


        parts = self.storage.replace("[", "]").split("]")
        #print(parts)
        if len(parts) == 3:
            for i, part in enumerate(parts):
                if i == 1:
                    try:
                        num = int(part.split("x")[1], 16)
                        ebp = self.func.currentBreakpoint.getRegisterValInt("rbp")

                    #ggdb.datPos
                    except Exception as e:
                        print("exception getting var pos: ")
                        print(e)
                        return None
                    finally:
                        #Todo: WHY??? + 4?????
                        addr = ebp - num + int(self.size)
                        self.addr_ = addr
                        return addr




    def x(self, prnt = False):


        ##getting ebp register
        ggdb = self.func.client.ggdb
        addr = self.getVariablePosition()

        if addr:


            if int(self.size) == 8:
                #print("printing a double word")
                tmp = ggdb.excAndGet("x/g "+str(hex(addr)))
            else:
                tmp = ggdb.excAndGet("x "+str(hex(addr)))

            #print(tmp)
            tmp = tmp.split("0x")[2]

            #print(tmp)
            if prnt:
                print(self.name + " = 0x" + str(tmp))
            return("0x" + str(tmp))

    def addr(self):
        return self.getVariablePosition()

    def addrX(self):
        return "0x" + str(hex(self.addr()))

    def d(self):
        return int(self.x().split("x")[1], 16)


class GhidraGlobals:
    pass



class GhidraCommandClient:

    #class GhidraComment:
    def __init__(self, ggdb):

        self.ggdb = ggdb

        #create Ghidra Bridge
        self.br = ghidra_bridge.GhidraBridge(namespace=globals())

        #append path for Ghidra CmdServer
        #Todo: this has to be generic
        self.br.remote_exec("import sys")
        self.br.remote_exec("sys.path.append(\"/media/simon/tools/ghidra/plugins\")")

        #import Ghidra CmdServer
        self.br.remote_exec("from GhidraCommandServer import GhidraCommandServer")

        #reload Ghidra Command Server
        self.br.remote_exec("reload(sys.modules[\"GhidraCommandServer\"])")
        self.br.remote_exec("from GhidraCommandServer import GhidraCommandServer")

        #
        self.br.remote_exec("cmds = GhidraCommandServer(getState())")

        self.globals = GhidraGlobals()
        self.functions = []

        # symbols = self.br.remote_eval("cmds.getVars()")
        # print(symbols)

        # for i, symbol in enumerate(symbols):
        #     try:
        #         print(str(symbol))
        #     except:
        #         pass

        # self.br.remote_eval("cmds.getComments()")




        #self.state = getState()
        #self.currentProgram = getState().getCurrentProgram()
        #self.functionManager = self.currentProgram.getFunctionManager()
        #self.funcs = self.functionManager.getFunctions(True) # True means 'forward'

        #if not self.br:
        #    int("ghidra bridge instantiate error")



    def addBp(self, function, cmd):
        for func in self.functions:
            if func.name == function:
                print("Adding breakpoint to function: " + str(function))
                bp = GhidraBreakpoint(function, func, 0)
                bp.setup = "b " + function
                bp.globals = self.globals
                self.breakpoints.append(bp)


    def analyzeComment(self, comment, func):
        print("ANALYZING COMMENT")
        breakpoints = []
        for i, line in enumerate(comment[0].split("\n")):
            if i == 0:
                try:
                    bp = GhidraBreakpoint(comment[1], func)
                    if line[0] != "$":
                        print("returning none")
                        return None
                    else:
                        bp.dbAppend(line.replace("$", ""))
                except Exception as e:
                    print("exception prim -- returning none" + str(e))
                    return None

            else:
                try:
                    if line[0] != "$":
                        bp.pyExec(line)
                    else:
                        bp.dbAppend(line.replace("$", ""))
                except:
                    continue
        try:
            print("returning bp: ")
            return bp
        except:
            print("exception -- returning none")
            return None


    def analyze(self, functions):


        #self.allFuncs = self.br.remote_exec("cmds.enumerateFunctions()")
        #for func in self.allfuncs:

        self.breakpoints = []

        for function in functions:
            exec("self." + str(function) + " = GhidraFunction()")
            exec("self.func = self." + str(function))
            exec("self.func.name = \"" + str(function) + "\"")
            print(self.func)
            self.func.client=self

            self.functions.append(self.func)

            symbols = self.br.remote_eval("cmds.getVars(\"" + str(function) + "\")")

            for i, symbol in enumerate(symbols):
                try:

                    if False:
                        otp.printR(symbol[0])
                        for j, sm in enumerate(symbol):
                            print(str(j) + str(sm))

                    name = symbol[0]
                    exec("self.func." + str(name) + " = GhidraVar()")
                    exec("self.var = self.func." + str(name))
                    self.var.name = symbol[0]
                    self.var.dataType = symbol[1]
                    self.var.pcAdress = symbol[2]
                    self.var.size = symbol[3]
                    self.var.storage = symbol[4]
                    self.var.parameter = symbol[5]
                    self.var.readOnly = symbol[6]
                    self.var.typeLocked = symbol[7]
                    self.var.nameLocked = symbol[8]
                    self.var.func = self.func
                    self.func.vars.append(self.var)
                except Exception as e:
                    print("Error here")
                    print(e)
                    pass
                #print(self.var)

            comments = self.br.remote_eval("cmds.getComments(\"" + str(function) + "\")")
            print(comments)
            for comment in comments:
                bp = self.analyzeComment(comment, self.func)
                if bp:
                    bp.globals = self.globals
                    self.breakpoints.append(bp)

            print("created breakpoints: ")
            print(self.breakpoints)

    def enumerateFunctions2(self):

        print("enumerate functions now")
        func = getFirstFunction()
        while func is not None:
            print("Function: {} @ 0x{}".format(func.getName(), func.getEntryPoint()))
            func = getFunctionAfter(func)


    def enumerateFunctions2(self):
        currentProgram = getState.getCurrentProgram()

        fm = currentProgram.getFunctionManager()
        funcs = fm.getFunctions(True) # True means 'forward'
        for func in funcs:
            print("Function: {} @ 0x{}".format(func.getName(), func.getEntryPoint()))


    def getFunc(self, name):

        for func in self.funcs:
            #print("Function: {} @ 0x{}".format(func.getName(), func.getEntryPoint()))
            if name in func.getName():
                return func

        return None


    def getFunc2(self, name):
        name_list = self.br.remote_eval("[ f for f in currentProgram.getFunctionManager().getFunctions(True)]")
        #print(name_list)
        for name2 in name_list:
            if name in name2.getName():
                return name2

        return None

    def getVars(self):

        func_name = "DoMainStuff"
        for i in range(2):
            func = self.getFunc2(func_name)
            print(func)

        options = DecompileOptions()
        monitor = ConsoleTaskMonitor()
        ifc = DecompInterface()
        ifc.setOptions(options)
        ifc.openProgram(func.getProgram())
        res = ifc.decompileFunction(func, 60, monitor)
        high_func = res.getHighFunction()
        lsm = high_func.getLocalSymbolMap()
        symbols = lsm.getSymbols()

        for i, symbol in enumerate(symbols):
            try:
                print("\nSymbol {}:".format(i+1))
                print("  name:         {}".format(symbol.name))
                print("  dataType:     {}".format(symbol.dataType))
                print("  getPCAddress: 0x{}".format(symbol.getPCAddress()))
                print("  size:         {}".format(symbol.size))
                print("  storage:      {}".format(symbol.storage))
                print("  parameter:    {}".format(symbol.parameter))
                print("  readOnly:     {}".format(symbol.readOnly))
                print("  typeLocked:   {}".format(symbol.typeLocked))
                print("  nameLocked:   {}".format(symbol.nameLocked))
                print("  slot:         {}".format(symbol.slot))
            except:
                pass
