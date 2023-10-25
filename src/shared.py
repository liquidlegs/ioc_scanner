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
METADF_KEY = "md_api_key"
METADF_DISABLED = "disable_md"
SUPRESS_WARNINGS = "supress_warnings"
THREAT_FOX_KEY = "tfx_api_key"
THREAT_FOX_DISABLED = "disable_tfx"
D_CRLF = "\r\n"
D_LF = "\n"
D_LIST = ","


class FeatureList(enum.Enum):
  Nan = 0
  Vt = 1
  Otx = 2
  Md = 3
  Tfx = 4
  Warnings = 5


class FeatureState(enum.Enum):
  Enabled = 1
  Disabled = 2
  Toggle = 3


class Dbg:

  def __init__(self, debug=False):
    self.debug = debug

  def dprint(self, text: str):
    if self.debug == True:
      print(f"{Colour.f_red('Debug')} {Colour.fd_cyan('=>')} {Colour.fd_yellow(text)}")
        
  def _dprint(text: str):
    print(f"{Colour.f_red('Debug')} {Colour.fd_cyan('=>')} {Colour.fd_yellow(text)}")


class Item(enum.Enum):
  Ip = 0
  Hash = 1
  Url = 2
  Domain = 3


class NameType(enum.Enum):
  Nan = 0
  Directory = 1
  File = 2


def validate_hash(hash: str) -> str:
  '''Function checks that the provided string is an MD5, SHA1, or SHA256 hash.'''
  try:
    out = re.search(r"(^[a-fA-f0-9]{64}$|^[a-fA-f0-9]{40}$|^[a-fA-f0-9]{32}$)", hash).group(0)
    return out
  except AttributeError:
    return None


def validate_ip(ip: str) -> str:
  '''Function checks that the provided string is a IPv4 address.'''
  try:
    out = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", ip).group(0)
    return out
  except AttributeError:
    return None


def validate_url(url: str) -> str:
  '''Function checks if the provided string is a valid url.'''
  try:
    out = re.search(r"(\w+://\S+\.\w+\S+|.+/\S+)", url).group(0)
    
    if out.startswith("http") == False:
      out = f"https://{out}"

    return out
  except AttributeError:
    return None


def validate_domain(domain: str) -> str:
  '''Function checks if the provided string is a valid domain.'''
  try:
    out = re.search(r"(^\w+[a-zA-Z0-9.-]+\.\w+$)", domain).group(0)
    return out
  except AttributeError:
    return None


def extract_date(date: str) -> str:
  '''Function checks if the provided string is a valid domain.'''
  try:
    out = re.search(r"(\d{4}-\d{2}-\d{2})", date).group(0)
    return out
  except AttributeError:
    return None


def get_items_from_cmd(debug: bool, istring: str, delim: str, cmd_item: Item) -> list[str]:
  '''Splits ip address received from the commandline and returns them as a list.'''
  dbg = Dbg(debug)
  out = {
    "ioc": [],
    "domain": []
  }

  temp_items = istring.split(delim)
  dbg.dprint(f"Attempting to split commandline items {temp_items}")

  if cmd_item == Item.Ip:
    for ip in temp_items:
      result = validate_ip(ip)
      
      if result != None:
        out["ioc"].append(result)
  
  elif cmd_item == Item.Hash:
    out["ioc"].extend(temp_items)
  
  
  elif cmd_item == Item.Url:
    for url in temp_items:
      result = validate_url(url)

      if result == None:
        result = validate_domain(url)
        out["domain"].append(result)
      
      if result != None:
        out["ioc"].append(result)


  out["ioc"] = list(set(out["ioc"]))
  out["domain"] = list(set(out["domain"]))
  return out


def get_items_from_list(content: list[str], file_item: Item) -> list[str]:
  '''Splits ip addresses contained in a string, like read from a file and returns it as a list.'''
  out = []
  
  if file_item == Item.Ip:
    for line in content:
      ip = validate_ip(line)
      
      if ip != None:
        out.append(ip)


  elif file_item == Item.Url:
    for line in content:
      url = validate_url(line)

      if url != None:
        out.append(url)


  elif file_item == Item.Domain:
    for line in content:
      domain = validate_domain(line)
      
      if domain != None:
        out.append(domain)


  elif file_item == Item.Hash:
    for line in content:
      out.append(line)


  return list(set(out))


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


def load_config() -> (str):
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
      filepath = f"{pwd}{delim}{script}".replace(filename, "")

    # Attempts to find the config file by combining the current directory with the first argument supplied to the command line.
    try:
      with open(filepath, "r") as f:
        buffer = f.read()
    except FileNotFoundError:
      filepath = search_scanner_path(filename, filepath, delim) + "config.json"
      
    # Attempts to find the config file by working out how many directories the script needs to go back to get back to the root of the project.
    try:
      with open(filepath, "r") as f:
        buffer = f.read()
    except FileNotFoundError:
      pass

  data = None

  try:
    data = json.loads(buffer)
  except json.decoder.JSONDecodeError:
    print(f"{Colour.f_red('Error')} Unable to read config file.")
  
  return (data, filepath)


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


def get_feature_status(key: str, feature: FeatureList):
  '''Function reads each key in the config file and will display the value depending on whether it is true or false.'''
  
  if feature == FeatureList.Vt:
    value = bool(check_json_error(key, VIRUS_TOTAL_DISABLED))

    if value == False:
      print(f"{Colour.f_green('[+]')} Virus Total enabled")
    else:
      print(f"{Colour.f_red('[-]')} Virus Total disabled")
  
  elif feature == FeatureList.Otx:
    value = bool(check_json_error(key, ALIEN_VAULT_DISABLED))

    if value == False:
      print(f"{Colour.f_green('[+]')} Alien Vault enabled")
    else:
      print(f"{Colour.f_red('[-]')} Alien Vault disabled")
  
  elif feature == FeatureList.Md:
    value = bool(check_json_error(key, METADF_DISABLED))

    if value == False:
      print(f"{Colour.f_green('[+]')} MetaDefender enabled")
    else:
      print(f"{Colour.f_red('[-]')} MetaDefender disabled")
  
  elif feature == FeatureList.Tfx:
    value = bool(check_json_error(key, THREAT_FOX_DISABLED))

    if value == False:
      print(f"{Colour.f_green('[+]')} Threat Fox enabled")
    else:
      print(f"{Colour.f_red('[-]')} Threat Fox disabled")
  
  elif feature == FeatureList.Warnings:
    value = bool(check_json_error(key, SUPRESS_WARNINGS))

    if value == False:
      print(f"{Colour.f_green('[+]')} Warnings enabled")
    else:
      print(f"{Colour.f_red('[-]')} Warnings disabled")


def save_config_file(debug: bool, feature: FeatureList, state: FeatureState):
  '''Function will modify the boolean values for each feature that has been specified by the user to be enabled or disabled.
  Once compete, the new data will be written to the file and the changes to the config file will be verified to determine if successful.'''
  
  dbg = Dbg(debug)
  data_pair = load_config()
  config = data_pair[0]
  file_path = data_pair[1]

  if state == FeatureState.Toggle:
    if feature == FeatureList.Vt:
      
      value = bool(check_json_error(config, VIRUS_TOTAL_DISABLED))
      if value == True:
        config[VIRUS_TOTAL_DISABLED] = False
      elif value == False:
        config[VIRUS_TOTAL_DISABLED] = True

    if feature == FeatureList.Otx:
      
      value = bool(check_json_error(config, ALIEN_VAULT_DISABLED))
      if value == True:
        config[ALIEN_VAULT_DISABLED] = False
      elif value == False:
        config[ALIEN_VAULT_DISABLED] = True

    if feature == FeatureList.Tfx:
      
      value = bool(check_json_error(config, THREAT_FOX_DISABLED))
      if value == True:
        config[THREAT_FOX_DISABLED] = False
      elif value == False:
        config[THREAT_FOX_DISABLED] = True

    if feature == FeatureList.Warnings:
      
      value = bool(check_json_error(config, SUPRESS_WARNINGS))
      if value == True:
        config[SUPRESS_WARNINGS] = False
      elif value == False:
        config[SUPRESS_WARNINGS] = True

  elif state == FeatureState.Enabled:
    config[VIRUS_TOTAL_DISABLED] = False
    config[ALIEN_VAULT_DISABLED] = False
    config[THREAT_FOX_DISABLED] = False
    config[SUPRESS_WARNINGS] = False

  elif state == FeatureState.Disabled:
    config[VIRUS_TOTAL_DISABLED] = True
    config[ALIEN_VAULT_DISABLED] = True
    config[THREAT_FOX_DISABLED] = True
    config[SUPRESS_WARNINGS] = True

  new_config = json.dumps(config, indent=4)
  with open(file_path, "w") as f:
    b = f.write(new_config)

    dbg.dprint(f"Successfully wrote {Colour.fd_cyan(b)} {Colour.fd_yellow('bytes to the config file at')} {Colour.fd_cyan(file_path)}")
    temp_data = json.loads(new_config)
    get_feature_status(temp_data, feature)

    if state == FeatureState.Enabled:
      print(f"{Colour.f_green('[+]')} all features are enabled")
    elif state == FeatureState.Disabled:
      print(f"{Colour.f_red('[-]')} all features are disabled")


def check_json_error(data: str, key: str) -> str:
  '''Function will attempt to retrieve the data from a json field and key that is specified by the user.
  This is all to prevent python crashing so that even if a value can't be extracted, information can still be displayed.'''
  
  try:
    out = data[key]
    return out
  except KeyError:
    return ""
  except TypeError:
    return ""


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