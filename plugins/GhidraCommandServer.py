
#Note:
# This is unconventional, however,  this is running as a remote module WITHIN Ghidra.
# These module are not available in a local python environment
# this is why the documentation generation through sphinx will fail. The try catch statement here avoids this

try:
    from ghidra.app.decompiler import DecompileOptions
    from ghidra.app.decompiler import DecompInterface
    from ghidra.util.task import ConsoleTaskMonitor
    from ghidra.program.model.listing import CodeUnit
except:
    pass

# Method 1:
class GhidraCommandServer:

    def __init__(self, state):
        self.state = state

        
    
    def enumerateFunctions2(self):

        """Enumerates all existing functions that are known to ghidra

        :return: None
        """

        print("enumerate functions now")
        func = getFirstFunction()
        while func is not None:
            print("Function: {} @ 0x{}".format(func.getName(), func.getEntryPoint()))
            func = getFunctionAfter(func)


    def enumerateFunctions(self):

        """Enumerates all existing functions that are known to ghidra

        :return: None
        """

        currentProgram = getState().getCurrentProgram()
        
        fm = currentProgram.getFunctionManager()
        funcs = fm.getFunctions(True) # True means 'forward'
        for func in funcs: 
            print("Function: {} @ 0x{}".format(func.getName(), func.getEntryPoint()))
        

    def getFunc(self, name):

        """Iterates through all the existing functions that are known to Ghidra and returns the match

        :param String name: The Name of the function to get
        :return: The Object of Type GhidraFunction
        """

        currentProgram = self.state.getCurrentProgram()
        
        fm = currentProgram.getFunctionManager()
        funcs = fm.getFunctions(True) # True means 'forward'
        for func in funcs: 
            #print("Function: {} @ 0x{}".format(func.getName(), func.getEntryPoint()))
            if name in func.getName():
                return func

        return None

            

    def getVars(self, funcName):

        """ Get all the Variables from a function with the given name

        :param String funcName: The name of the target function
        :return: An Array of Arrays containing all the known Attributes for each GhidraVar
        """


        print("hello world from getVars")
        func = self.getFunc(funcName)
        options = DecompileOptions()
        monitor = ConsoleTaskMonitor()
        ifc = DecompInterface()
        ifc.setOptions(options)
        ifc.openProgram(func.getProgram())
        res = ifc.decompileFunction(func, 60, monitor)
        high_func = res.getHighFunction()
        lsm = high_func.getLocalSymbolMap()
        symbols = lsm.getSymbols()

        temp = []
        
        for i, symbol in enumerate(symbols):
            try:
                #temp.append("".format(symbol.name) + "123 ".format(symbol.dataType))
                temp.append([symbol.name, str(symbol.dataType), symbol.getPCAddress(), symbol.size, str(symbol.storage), symbol.parameter, symbol.readOnly, symbol.typeLocked, symbol.nameLocked])
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

        return temp


    def getComments(self, funcName):

        """Get all the PRE-Comments for a given Function name

        :param String funcName: The name of the target function
        :return: Array of strings containing the comments
        """

        currentProgram = self.state.getCurrentProgram()

        listing = currentProgram.getListing()
        func = self.getFunc(funcName)
        addrSet = func.getBody()
        codeUnits = listing.getCodeUnits(addrSet, True)

        comments = []
        for codeUnit in codeUnits:

            if codeUnit.getComment(CodeUnit.PRE_COMMENT):
                
                comments.append([codeUnit.getComment(CodeUnit.PRE_COMMENT), str(codeUnit.getMinAddress()), str(codeUnit.getMaxAddress())])
                print(codeUnit.getComment(CodeUnit.PRE_COMMENT) + " " + str(codeUnit.getMinAddress()) + " " + str(codeUnit.getMaxAddress()))

        return comments
                
	    #deol = DisplayableEol(codeUnit, True, True, True, True, 5, True)
	    #if deol.hasAutomatic():
	    #ac = deol.getAutomaticComment()
	    #print(type(ac))
	    #print(ac)
	    #print(ac[0])

    
