import colorama 
from colorama import init
from colorama import Fore, Back, Style



def init_():
    init(autoreset=True)

def printG(txt):
    print(Fore.GREEN + txt)

def printB(txt):
    print(Fore.BLUE + txt)
    
def printR(txt):
    print(Fore.RED + txt)

def printM(txt):
    print(Fore.MAGENTA + txt)

def printY(txt):
    print(Fore.YELLOW + txt)


def printC(txt):
    print(Fore.CYAN + txt)

def cleanup():
    deinit()
