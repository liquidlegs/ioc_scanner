import os, json, re, enum, platform, sys
from platform import system
import colorama as cl
from colorama import Fore, Back, Style
cl.init(autoreset=True)

CONFIG_ENV = "IOC_SCANNER_CONFIG"
VIRUS_TOTAL_KEY = "vt_api_key"
ALIEN_VAULT_KEY = "otx_api_key"
VIRUS_TOTAL_DISABLED = "disable_vt"
ALIEN_VAULT_DISABLED = "disable_otx"
D_CRLF = "\r\n"
D_LF = "\n"
D_LIST = ","


class Item(enum.Enum):
  Ip = 0
  Hash = 1
  Url = 2


class NameType(enum.Enum):
  Nan = 0
  Directory = 1
  File = 2


def validate_ip(ip: str) -> str:
  '''# Function checks that the provided string is a IPv4 address.'''
  try:
    out = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", ip).group(0)
    return out
  except AttributeError:
    return None


def validate_url(url: str) -> str:
  '''# Function checks if the provided string is a valid url.'''
  try:
    out = re.search(r"(\w+://\S+\.\w+\S+)", url).group(0)
    return out
  except AttributeError:
    domain = validate_domain(url)
    
    if domain != None:
      return f"http://{domain}"
    
    return None


def validate_domain(domain: str) -> str:
  '''# Function checks if the provided string is a valid domain.'''
  try:
    out = re.search(r"(\S+\.\S{2,})", domain).group(0)
    return out
  except AttributeError:
    return None


def get_items_from_cmd(istring: str, delim: str, cmd_item: Item) -> list[str]:
  '''Splits ip address received from the commandline and returns them as a list.'''
  out = []
  temp_items = istring.split(delim)

  if cmd_item == Item.Ip:
    for ip in temp_items:
      result = validate_ip(ip)
      out.append(result)

  
  elif cmd_item == Item.Hash:
    out.extend(temp_items)
  
  
  elif cmd_item == Item.Url:
    for url in temp_items:
      result = validate_url(url)
      out.append(result)

  return out


def get_items_from_list(content: list[str], file_item: Item) -> list[str]:
  '''Splits ip addresses contained in a string, like read from a file and returns it as a list.'''
  out = []
  
  if file_item == Item.Ip:
    for line in content:
      ip = validate_ip(line)
      out.append(ip)


  elif file_item == Item.Url:
    for line in content:
      url = validate_url(line)
      out.append(url)


  elif file_item == Item.Hash:
    for line in content:
      out.append(line)


  return out


def get_file_contents(filepath: str, delim: str) -> list[str]:
  '''Reads the contents of a file and returns it as a list of lines.'''
  path = ""
  slash = ""

  # Get the correct slash for the correct system
  if platform.system == "windows":
    slash = "\\"
  else:
    slash = "/"
  
  # Fix the path if not absolute
  if os.path.exists(filepath):
    if os.path.abspath(filepath) == False:
      path = f"{os.getcwd}{slash}{filepath}"
    else:
      path = filepath

  # Read the file into a buffer and split each line by the specified delimiter
  buffer = ""
  with open(path, "r") as f:
    buffer = f.read()

  output = buffer.split(delim)
  return output


def is_arg_list(string: str) -> bool:
  '''Function checks if there is a list of items supplied from the commandline seprated by commas'''
  chk = string.split(D_LIST)
  
  if len(chk) > 1:
    return True
  else:
    return False


def get_file_delim(data: str) -> str:
  '''Function checks what the delimter is between in line in a file and returns it.'''
  chk = data.split(D_LF)
  if len(chk) > 1:
    return D_LF
  
  chk = data.split(D_CRLF)
  if len(chk) > 1:
    return D_CRLF


def load_config() -> str:
  '''Function loads the config file from the root of the project directory.'''
  buffer = ""
  delim = "/"

  operating_sys = system()
  if operating_sys == "Windows":
    delim = "\\"

  # Attempts to load the config file from an environment variable
  filepath = os.environ.get(CONFIG_ENV)
  if filepath != None:
    try:
      with open(filepath, "r") as f:
        buffer = f.read()
    except FileNotFoundError:
      pass

  if len(buffer) < 1:
    pwd = os.getcwd()
    script = sys.argv[0]
    filename = get_script_name(pwd, script, delim)
    filepath = f"{pwd}{delim}config.json"

    # Loads the config file from the current directory.
    try:
      with open(filepath, "r") as f:
        buffer = f.read()
    except FileNotFoundError:
      # print(f"File not found: {filepath}")
      filepath = f"{pwd}{delim}{script}".replace(filename, "")

    # Attempts to find the config file by combining the current directory with the first argument supplied to the command line.
    try:
      with open(filepath, "r") as f:
        buffer = f.read()
    except FileNotFoundError:
      # print(f"File not found: {filepath}")
      filepath = search_scanner_path(filename, filepath, delim) + "config.json"
      
    # Attempts to find the config file by working out how many directories the script needs to go back to get back to the root of the project.
    try:
      with open(filepath, "r") as f:
        buffer = f.read()
    except FileNotFoundError:
      # print(f"File not found: {filepath}")
      pass

  data = None

  try:
    data = json.loads(buffer)
  except json.decoder.JSONDecodeError:
    print(f"{Colour.f_red('Error')} Unable to read config file.")
  
  return data


def get_script_name(pwd: str, arg: str, delim: str):
  '''Gets the name of the python script supplied in the first argument.'''
  path = f"{pwd}{delim}{arg}".split(delim)
  dec = 1
  
  check_len = len(path)-dec

  if check_len < 0:
    return
  
  return path[len(path)-dec]


def search_scanner_path(filename: str, filepath: str, delim: str):
  ''''Function works out the name of the root of the project'''
  file_name = ""
  root = ""

  # Gets the name of the current directory by taking the name of the script and removing the ext.
  if len(filename) > 3:
    file_name = filename[0:len(filename)-3] + delim
  
  regex = fr"({file_name}{delim}.+)"
  
  # Gets the root of the project and all sub directory names.
  try:
    out = re.search(regex, filepath).groups(0)
    root = out[0]
  except AttributeError:
    pass
  
  # Counts how many subdirectories need to be removed.
  split_root = root.split(delim)
  if split_root[len(split_root)-1] == "":
    split_root.pop()
  
  # Counts the chats to remove.
  chars = 0
  for i in range(len(split_root)):
    if i > 0:
      chars += len(split_root[i])+1

  root = filepath[0:len(filepath)-chars]
  return root


def parse_config_file(data: str) -> str:
  '''Makes sure that there is a value in the config file for specified key.
     Function will return expanded environment variable for any values that begin with \'$\'.'''
  dt = data
  output = ""

  if type(data) == str:
    if len(data) == 0:
      return None

    if dt[0] == '$':
      env = dt[1:len(dt)]
      expanded_env = os.environ.get(env)
      
      if expanded_env == None:
        return None

      if len(expanded_env) > 0:
        output += expanded_env

    else:
      output = dt

  if type(data) == bool:
    if bool(dt) == True:
      output = dt
  
  return output


class ArgType(enum.Enum):
  Nan = 0
  File = 1
  Cmd = 2


class Colour:
  '''Returns the colour of your desires'''

  def f_blue(text: str) -> str:
    return f"{Fore.BLUE}{Style.BRIGHT}{text}{Fore.RESET}{Style.NORMAL}"

  def f_red(text: str) -> str:
    return f"{Fore.RED}{Style.BRIGHT}{text}{Fore.RESET}{Style.NORMAL}"

  def f_green(text: str) -> str:
    return f"{Fore.GREEN}{Style.BRIGHT}{text}{Fore.RESET}{Style.NORMAL}"

  def f_yellow(text: str) -> str:
    return f"{Fore.YELLOW}{Style.BRIGHT}{text}{Fore.RESET}{Style.NORMAL}"

  def f_cyan(text: str) -> str:
    return f"{Fore.CYAN}{Style.BRIGHT}{text}{Fore.RESET}{Style.NORMAL}"

  def f_magenta(text: str) -> str:
    return f"{Fore.MAGENTA}{Style.BRIGHT}{text}{Fore.RESET}{Style.NORMAL}"

  def f_white(text: str) -> str:
    return f"{Fore.WHITE}{Style.BRIGHT}{text}{Fore.RESET}{Style.NORMAL}"

  def fd_blue(text: str) -> str:
    return f"{Fore.BLUE}{Style.NORMAL}{text}{Fore.RESET}{Style.NORMAL}"

  def fd_red(text: str) -> str:
    return f"{Fore.RED}{Style.NORMAL}{text}{Fore.RESET}{Style.NORMAL}"

  def fd_green(text: str) -> str:
    return f"{Fore.GREEN}{Style.NORMAL}{text}{Fore.RESET}{Style.NORMAL}"

  def fd_yellow(text: str) -> str:
    return f"{Fore.YELLOW}{Style.NORMAL}{text}{Fore.RESET}{Style.NORMAL}"

  def fd_cyan(text: str) -> str:
    return f"{Fore.CYAN}{Style.NORMAL}{text}{Fore.RESET}{Style.NORMAL}"

  def fd_magenta(text: str) -> str:
    return f"{Fore.MAGENTA}{Style.NORMAL}{text}{Fore.RESET}{Style.NORMAL}"

  def fd_white(text: str) -> str:
    return f"{Fore.WHITE}{Style.NORMAL}{text}{Fore.RESET}{Style.NORMAL}"
  
  def b_blue(text: str) -> str:
    return f"{Back.BLUE}{Style.BRIGHT}{text}{Back.RESET}{Style.NORMAL}"

  def b_red(text: str) -> str:
    return f"{Back.RED}{Style.BRIGHT}{text}{Back.RESET}{Style.NORMAL}"

  def b_green(text: str) -> str:
    return f"{Back.GREEN}{Style.BRIGHT}{text}{Back.RESET}{Style.NORMAL}"

  def b_yellow(text: str) -> str:
    return f"{Back.YELLOW}{Style.BRIGHT}{text}{Back.RESET}{Style.NORMAL}"

  def b_cyan(text: str) -> str:
    return f"{Back.CYAN}{Style.BRIGHT}{text}{Back.RESET}{Style.NORMAL}"

  def b_magenta(text: str) -> str:
    return f"{Back.MAGENTA}{Style.BRIGHT}{text}{Back.RESET}{Style.NORMAL}"

  def b_white(text: str) -> str:
    return f"{Back.WHITE}{Style.BRIGHT}{text}{Back.RESET}{Style.NORMAL}"

  def bd_blue(text: str) -> str:
    return f"{Back.BLUE}{Style.NORMAL}{text}{Back.RESET}{Style.NORMAL}"

  def bd_red(text: str) -> str:
    return f"{Back.RED}{Style.NORMAL}{text}{Back.RESET}{Style.NORMAL}"

  def bd_green(text: str) -> str:
    return f"{Back.GREEN}{Style.NORMAL}{text}{Back.RESET}{Style.NORMAL}"

  def bd_yellow(text: str) -> str:
    return f"{Back.YELLOW}{Style.NORMAL}{text}{Back.RESET}{Style.NORMAL}"

  def bd_cyan(text: str) -> str:
    return f"{Back.CYAN}{Style.NORMAL}{text}{Back.RESET}{Style.NORMAL}"

  def bd_magenta(text: str) -> str:
    return f"{Back.MAGENTA}{Style.NORMAL}{text}{Back.RESET}{Style.NORMAL}"

  def bd_white(text: str) -> str:
    return f"{Back.WHITE}{Style.NORMAL}{text}{Back.RESET}{Style.NORMAL}"
  

class Dbg:

  def __init__(self, debug=False):
    self.debug = debug

  def dprint(self, text: str):
    if self.debug == True:
      print(f"{Colour.f_red('Debug')} {Colour.fd_cyan('=>')} {Colour.fd_yellow(text)}")
        
  def _dprint(text: str):
    print(f"{Colour.f_red('Debug')} {Colour.fd_cyan('=>')} {Colour.fd_yellow(text)}")
