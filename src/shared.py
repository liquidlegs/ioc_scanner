import os, json, re
from platform import system
import colorama as cl
from colorama import Fore, Back, Style
cl.init(autoreset=True)

VIRUS_TOTAL_KEY = "vt_api_key"
ALIEN_VAULT_KEY = "avl_api_key"
D_CRLF = "\r\n"
D_LF = "\n"
D_LIST = ","


# Function checks that the provided string is a IPv4 address.
def validate_ip(ip: str) -> str:
  try:
    out = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", ip).group(0)
    return out
  except AttributeError:
    return None


# Function checks if the provided string is a valid url.
def validate_url(url: str) -> str:
  try:
    out = re.search(r"(\w+://\S+\.\w+\S+)", url).group(0)
    return out
  except AttributeError:
    return None


# Function checks if there is a list of items supplied from the commandline seprated by commas
def is_arg_list(string: str) -> bool:
  chk = string.split(D_LIST)
  
  if len(chk) > 1:
    return True
  else:
    return False


# Function checks what the delimter is between in line in a file and returns it.
def get_file_delim(data: str) -> str:
  chk = data.split(D_LF)
  if len(chk) > 1:
    return D_LF
  
  chk = data.split(D_CRLF)
  if len(chk) > 1:
    return D_CRLF


# Function loads the config file from the root of the project directory.
def load_config() -> str:
  buffer = ""
  delim = "/"

  operating_sys = system()
  if operating_sys == "Windows":
    delim = "\\"

  filepath = f"{os.getcwd()}{delim}..{delim}config.json"
  with open(filepath, "r") as f:
    buffer = f.read()

  data = json.loads(buffer)
  return data


# Makes sure that there is a value in the config file for specified key.
# Function will return expanded environment variable for any values that begin with '$'
def parse_config_file(data: str) -> str:
  dt = data
  output = ""

  if dt[0] == '$':
    env = dt[1:len(dt)]
    expanded_env = os.environ.get(env)
    
    if len(expanded_env) > 0:
      output += expanded_env

  else:
    output = dt
  
  return output


class Colour:

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