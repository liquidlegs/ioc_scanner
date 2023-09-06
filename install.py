import os, platform, argparse
from src.shared import Colour as C

def windows_install():
  pass


def linux_install(args):
  vt_key = None
  config_path = "/opt/ioc_scanner/config.json"
  full_path = "/opt/ioc_scanner"

  if args.vt_key != None:
    vt_key = args.vt_key
  if args.config_path != None:
    config_path = args.config_path
  if args.full_path != None:
    full_path = args.full_path

  username = os.environ.get("USER")
  print(f"{C.f_yellow('Info')}: Installing ioc_scanner for {C.f_blue(username)}")

  home_path = os.path.exists(f"/home/{username}")
  if home_path == True:
    print(f"{C.f_green('[+]')} Successfully found {username}s home directory at {home_path}")

    bashrc = os.path.exists(f"/home/{username}/.bashrc")
    if bashrc == True:

      err = os.system(f"echo 'export PATH=\"$PATH:{full_path}\"' >> /home/{username}/.bashrc")
      if err == 0:  print(f"{C.f_green('[+]')} successfully added ioc_scanner to PATH")
      else:         print(f"{C.f_red('[-]')} failed to add ioc_scanner to PATH")
      
      err = os.system(f"echo 'export IOC_SCANNER_CONFIG={config_path}' >> /home/{username}/.bashrc")
      if err == 0:  print(f"{C.f_green('[+]')} successfully configured the ioc_scanner config path")
      else:         print(f"{C.f_red('[-]')} failed to add the ioc_scanner config path")
      
      if vt_key != None:
        
        err = os.system(f"echo 'export VT_KEY={vt_key}' >> /home/{username}/.bashrc")
        if err == 0:  print(f"{C.f_green('[+]')} successfully added the Virus Total API key to bashrc")
        else:         print(f"{C.f_red('[-]')} failed to add the Virus Total API key to bashrc")
      else:
        print(f"{C.f_red('[-]')} failed to configure Virus Total API key as no value was provided")

    else:
      print(f"{C.f_red('Error')}: .bashrc does not exist")
      print(f"{C.f_red('[-]')} installation failed")
      exit(1)

  pass


def main():
  parser = argparse.ArgumentParser(description="none")
  
  parser.add_argument("-c", "--config-path", action="store", help="The path to the ioc_scanner config file")
  parser.add_argument("-V", "--vt-key", action="store", help="The Virus Total API key")
  parser.add_argument("-p", "--full-path", action="store", help="The full path to the ioc_scanner directory")
  args = parser.parse_args()

  operating_sys = platform.system()

  if operating_sys == "Windows":
    pass
  elif operating_sys == "Linux":
    linux_install(args)


if __name__ == "__main__":
  main()