from ghidra.app.decompiler import DecompileOptions
from ghidra.app.decompiler import DecompInterface
from ghidra.util.task import ConsoleTaskMonitor


# Method 1:
class CmdServer():

    def __init__(self, state):
        self.state = state


        
    
    def enumerateFunctions(self):

        print("enumerate functions now")
        func = getFirstFunction()
        while func is not None:
            print("Function: {} @ 0x{}".format(func.getName(), func.getEntryPoint()))
            func = getFunctionAfter(func)


    def enumerateFunctions2(self):
        currentProgram = self.state.getCurrentProgram()
        
        fm = currentProgram.getFunctionManager()
        funcs = fm.getFunctions(True) # True means 'forward'
        for func in funcs: 
            print("Function: {} @ 0x{}".format(func.getName(), func.getEntryPoint()))
        

    def getFunc(self, name):
        currentProgram = self.state.getCurrentProgram()
        
        fm = currentProgram.getFunctionManager()
        funcs = fm.getFunctions(True) # True means 'forward'
        for func in funcs: 
            #print("Function: {} @ 0x{}".format(func.getName(), func.getEntryPoint()))
            if name in func.getName():
                return func

        return None

            

    def getVars(self):

        print("hello world from getVars")
        func_name = "DoMainStuff"
        func = self.getFunc(func_name)
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

        print("habe fertig")
        return "test"
