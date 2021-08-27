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

    """A function of Type Ghidra function - can hold several GhidraVariables, Breakpoints and other classes
    """
    
    def __init__(self):
        self.vars = []
        self.currentBreakpoint = None

        
class GhidraBreakpoint:

    """A class representing a breakpoint in Ghidra. This class might hold several different attributes, such as:
    - the address in the code where the Breakpoint is located ad
    - A function to which this breakpoint belongs
    - a stack object representing the current stack state
    - executable instructions for GDB or python which are executed once the breakpoint is hit
    """
    
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

        """Recalculate the offset of the breakpoint based on a given offset

        :param Hex,String offset: the offset to 0 which the main executable holds in the memory map
        :return: Nobe
        """

        self.address = self.getAddress(self.lineNr, offset)
        self.setup = "b *" + str(self.address)


    def find(self, lineNr):

        """Find the total Address of a line Nr in the given function

        :param Int lineNr: the line number in Ghidra
        :return: The Address of the position
        """

        return self.getAddress(lineNr, self.offset)


    def getAddress(self, lineNr, offset):

        """ Get the address of a line Nr taking in account the current offset

        :param Int lineNr: The line number in Ghidra
        :param offset: The offset of the main executable in the proc mappings
        :return: Hex value of the Address
        """

        self.offset = offset

        arr = str(offset).split("x")
        if len(arr) > 1:
            offset = int(arr[1], 16)

        if offset == 0:
            return "0x" + lineNr
        else:
            return str(hex(int(lineNr, 16) + offset))



    def c(self):

        """Continue Execution

        :return: None
        """

        #Todo: why deactivate
        self.deactivate()
        self.func.client.ggdb.gdb.execute("c")


    def getRegisterVal(self, reg, ggdb):

        """Get the value of a register

        :param String reg: The name of the register to get the value from, e.g "ebp"
        :param ggdb: the ggdb instance
        :return: Hex value contained in the register
        """

        #Todo: do we really need the ggdb parameter?

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

                #Todo: ebp is not generic
                ebpStr = line
                while "  " in ebpStr:
                    ebpStr = ebpStr.replace("  ", " ")

                splt = ebpStr.split(" ")
                #print("Found EBP String: " + str(line) + " fin " + str(splt[1]))
                fin = splt[1].split("x")[1]
                #self.currentRegisters.append(RegisterVal(reg, fin))
                return fin

    def setHitLimit(self, limit=100):

        """Set a Limit to this breapoint after which the breakpoint gets deactivated

        :param Int limit: The maximum amount of hits the breakpoint will get
        :return: None
        """

        self.hitLimit = limit


    def getRegisterValInt(self, reg):

        """Get the value of a register as int

        :param String reg: The name of the register to get the value from, e.g "ebp"
        :return: Integer value contained in the register
        """

        try:
            ret = self.getRegisterVal(reg, self.func.client.ggdb)
            return int(str(ret), 16)
        except:
            traceback.print_exc()
            return None

    def disable(self):

        """ Disables the breakpoint - Not yet implemented!!!

        :return: None
        """

        #Todo: implement this!
        print(self.gdbGet("d " + str(self.number)))
        self.gdbGet("i b")



    def hit(self):

        """Call this function when breakpoint is hit

        :return:
        """

        self.func.currentBreakpoint = self

        self.hitCount += 1
        if self.hitLimit > 0 and self.hitLimit < self.hitCount:
            print("call deact")
            self.disable()


    #Todo ... Naming ... !
    def deactivate(self):

        """ Called after breakpoint execution is done

        :return: None
        """

        self.currentRegisters = ""

    def dbAppend(self, db):

        """Appends a debugger command

        :param String db: the debugger command
        :return: None
        """

        self.dbExc = self.dbExc + str(db) + "\n"

    def getRegisterValX(self, reg):

        """Get the value of a register as Hex

        :param String reg: The name of the register to get the value from, e.g "ebp"
        :return: Integer value contained in the register
        """

        ggdb = self.func.client.ggdb
        return "0x" + self.getRegisterVal(reg, ggdb)

    def getWordX(self, addr):

        """Get a word (32 bit) of data from the memory

        :param addr: The Address from where to read
        :return: The Word as Hex
        """

        ggdb = self.func.client.ggdb
        result = ggdb.excAndGet("x/1wx "+str(addr))
        return result.split('\t')[1]

    def getLongX(self, addr):

        """Get a Long (64 bit) of data from the memory

        :param addr: The Address from where to read
        :return: The Long as Hex
        """

        ggdb = self.func.client.ggdb
        result = ggdb.excAndGet("x/1g "+str(addr))
        return result.split('\t')[1]

    def pyExec(self, exc):

        """Append python command to be executed when this breakpoint is hit

        :param String exc: The command
        :return: Nonw
        """

        self.pyExc = self.pyExc + exc + "\n"

    def gdbGet(self, exc, prnt=False):

        """Execute a a command in Gdb and return the resulting output

        :param String exc: The GDB Command
        :param Boolean prnt: optional print the command before executing it - default: False
        :return: The result of the GDB call as String
        """

        if prnt:
            print("gdbPrint(" + str(exc) + ")")

        ggdb = self.func.client.ggdb
        result = ggdb.excAndGet(exc)
        if prnt:
            print(result)
        return result

    #Todo: Why 2??
    def gdbGet2(self, exc, prnt=False):

        """Execute a a command in Gdb and return the resulting output

        :param String exc: The GDB Command
        :param Boolean prnt: optional print the command before executing it - default: False
        :return: The result of the GDB call as String
        """

        if prnt:
            print("gdbPrint(" + str(exc) + ")")

        ggdb = self.func.client.ggdb
        result = ggdb.excAndGet2(exc)
        if prnt:
            print(result)
        return result


    def gdbPrint(self, exc, prnt=True):

        """ Execute a GDB Command and print the result

        :param String exc: The GDB Command
        :param Boolean prnt: optional print the command before executing it - default: False
        :return: The result of the GDB call as String
        """

        if prnt:
            print("gdbPrint(" + str(exc) + ")")

        ggdb = self.func.client.ggdb
        result = ggdb.excAndGet(exc)
        if prnt:
            print(result)
        return result

    def exec_(self, exc):

        """Executes code in the context of this module

        :param exc: the command to be executed
        :return: None
        """

        try:
            exec(exc)
        except Exception as e:
            print("Error in execution of line " + str(exc))
            print("error during gdb execution: " + str(e))
            traceback.print_exc()

    def stackPrint(self, size):

        """Prints current stack
        Note: This is a very basic stack print - for more specific results use the class GhidraStack
        - you can add the variables to the stack and examine them
        - does very well in combination with a timelapse

        :param Int size: The size of the stack to be printed
        :return: The resulting stack as String
        """

        ggdb = self.func.client.ggdb
        stk = self.getRegisterValInt("rbp")#TODO: switch this to ebp for 32bit architecture
        stk = stk - size
        result = ggdb.excAndGet("x/"+str(size) + "x " + str(hex(stk)))
        print(result)
        return result

    def stackAddFuncVars(self, funcName):

        """Add a function name to the current stack frame

        :param String funcName: the name of the function to add to the stack
        :return: None
        """

        for func in self.func.client.functions:
            if funcName in func.name:
                for var in func.vars:
                    self.stack.addVar(var, func)

    def stackAddAllVars(self):

        """ Add all known Variables of the current function to the stack

        :return: None
        """

        for var in self.func.vars:
            #print("adding var" + var.name + "at address: " +  var.getVariablePosition())
            self.stack.addVar(var, self.func)

    def stackAddLabel(self, label, address):

        """Add a label for the stack

        :param Sting label: The name of the label
        :param address: The address where the Label is located
        :return: None
        """

        self.stack.addLabel(label,address)

#could have Auto  Add
class GhidraStack:

    """This class may be used to analyze the stack state"""

    def __init__(self, ggdb):
        self.stackString = ""
        self.varPositions = []
        self.varNames = []
        self.ggdb = ggdb

    def addVar(self, var, func = None):

        """Add Variable to the current state

        :param GhidraVar var: The Variable to add to the stack
        :param GhidraFunc func: The function in which the Variable is defined
        :return: None
        """

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

        """Add a custom label to the stack

        :param String label: The name of the label to be added
        :param address: The address of the label
        :return: None
        """

        self.varPositions.append(address)
        self.varNames.append(label)

    #todo - integer conversion not yet working
    #Todo - implement for 64 bit also
    def examine(self, baseAddr, numWords, verbose = False):

        """Print a detailed overview of the stack - outlining all the variables that have been added for stack examination

        :param baseAddr: The address from where the stack is to be examined
        :param numWords: The number of words to be examined
        :param Boolean verbose: print verbose logs(for debugging)
        :return: The resulting stack snapsot as string
        """


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

    """This class represents a Variable in Ghidra"""

    def __init__(self):
        self.addr_ = 0


    def getVariablePosition(self):

        """Get the position of the variable

        :return: None
        """

        #Todo full 32bit - 64bit support

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

        """Get the position of the variable as hex

        :param prnt: print details - debugging
        :return: String representation of hex number
        """

        #Todo: check for 32bit - 64b it support

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
        #Todo - why two functions
        return self.getVariablePosition()

    def addrX(self):
        # Todo - why two functions
        return "0x" + str(hex(self.addr()))

    def d(self):
        # Todo - again - overthink this
        return int(self.x().split("x")[1], 16)


class GhidraGlobals:
    #Todd: Needed?
    pass



class GhidraCommandClient:

    """The Ghidra Command Client acts as a bridge between python and a Ghidra instance"""

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



    def addBp(self, function):

        """Add a breakpoint

        :param function: kp
        :return:
        """

        #Todo: is this needed?

        for func in self.functions:
            if func.name == function:
                print("Adding breakpoint to function: " + str(function))
                bp = GhidraBreakpoint(function, func, 0)
                bp.setup = "b " + function
                bp.globals = self.globals
                self.breakpoints.append(bp)


    def analyzeComment(self, comment, func):

        """Analyze Comment and extract breakpoints if needed

        :param String comment: The PRE comment, coming from Ghidra
        :param GhidraFunction func: the function from which the Breakpoint has been created
        :return: The Breakpoint of type GhidraBreakpoint - if created - otherwise None
        """

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

        """Analyze a given set of function and generate the breakpoints that are found

        :param [String] functions: Array giving the function names to be analyzed
        :return: None
        """

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

        #Todo: in use?

        print("enumerate functions now")
        func = getFirstFunction()
        while func is not None:
            print("Function: {} @ 0x{}".format(func.getName(), func.getEntryPoint()))
            func = getFunctionAfter(func)


    def enumerateFunctions2(self):

        # Todo: in use?
        currentProgram = getState.getCurrentProgram()

        fm = currentProgram.getFunctionManager()
        funcs = fm.getFunctions(True) # True means 'forward'
        for func in funcs:
            print("Function: {} @ 0x{}".format(func.getName(), func.getEntryPoint()))


    def getFunc(self, name):

        # Todo: in use?

        for func in self.funcs:
            #print("Function: {} @ 0x{}".format(func.getName(), func.getEntryPoint()))
            if name in func.getName():
                return func

        return None


    def getFunc2(self, name):

        # Todo: in use?
        name_list = self.br.remote_eval("[ f for f in currentProgram.getFunctionManager().getFunctions(True)]")
        #print(name_list)
        for name2 in name_list:
            if name in name2.getName():
                return name2

        return None

    def getVars(self):
        # Todo: in use?
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
