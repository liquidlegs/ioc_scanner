import os, json, re, enum, platform
from platform import system
import colorama as cl
from colorama import Fore, Back, Style
cl.init(autoreset=True)

VIRUS_TOTAL_KEY = "vt_api_key"
ALIEN_VAULT_KEY = "otx_api_key"
D_CRLF = "\r\n"
D_LF = "\n"
D_LIST = ","


class Item(enum.Enum):
  Ip = 0
  Hash = 1
  Url = 2


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


def re_contains(regex: str, text: str) -> str:
  try:
    out = re.search(regex, text).group(0)
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

  filepath = f"{os.getcwd()}{delim}config.json"
  with open(filepath, "r") as f:
    buffer = f.read()

  data = json.loads(buffer)
  return data


def parse_config_file(data: str) -> str:
  '''Makes sure that there is a value in the config file for specified key.
     Function will return expanded environment variable for any values that begin with \'$\'.'''
  dt = data
  output = ""

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
