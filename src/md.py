from src.shared import load_config, parse_config_file, METADF_KEY, METADF_DISABLED, SUPRESS_WARNINGS
from src.shared import Dbg, Colour as C
import requests, time, json, enum
from prettytable.colortable import ColorTable


class NbrItems(enum.Enum):
  SINGLE = 0
  BULK = 1


class ItemType(enum.Enum):
  IP = 0
  HASH = 1
  URL = 3
  DOMAIN = 4


class MdfApiErr(enum.Enum):
  Nan = 0
  MaxObservables = 1
  InvalidApiKey = 2
  EndpointNotFound = 3


class MetaDefenderCloud:
  
  BASE_IP_PTH_SINGLE = "https://api.metadefender.com/v4/ip/{ip}"
  BASE_IP_PTH_BULK = "https://api.metadefender.com/v4/ip/"
  BASE_URL_PTH_SINGLE = "https://api.metadefender.com/v4/url/{url}"
  BASE_URL_PTH_BULK = "https://api.metadefender.com/v4/url/"
  BASE_DOM_PTH_SINGLE = "https://api.metadefender.com/v4/domain/{domain}"
  BASE_DOM_PTH_BULK = "https://api.metadefender.com/v4/domain/"
  BASE_HASH_PTH_SINGLE = "https://api.metadefender.com/v4/hash/{hash}"
  BASE_HASH_PTH_BULK = "https://api.metadefender.com/v4/hash/"
  BASE_APIKEY_INFO = "https://api.metadefender.com/v4/apikey"

  JSON_HDR = ["accept", "application/json"]

  def init(self):
    '''Reads the config file and parses the json to retrieve the VT API key.'''
    data = load_config()
    key = parse_config_file(data[METADF_KEY])
    disable_md = parse_config_file(data[METADF_DISABLED])
    warnings = parse_config_file(data[SUPRESS_WARNINGS])

    if key != None:
      self.api_key[1] = key

    if disable_md != None:
      self.disabled = bool(disable_md)

    if warnings != None:
      self.supress_warnings = bool(warnings)


  def is_apikey_loaded(self) -> bool:
    length = len(self.api_key[1])
    if length > 0:
      return True
    else:
      return False


  def __init__(self, debug=False, raw_json=False, disabled=False):
    self.debug = debug
    self.raw_json = raw_json
    self.disabled = disabled
    self.supress_warnings = False
    self.api_key = ["apikey", ""]

  
  def dprint(self, text: str):
    if self.debug == True:
      Dbg._dprint(text)


  def get_error_code(code: int) -> MdfApiErr:
    if code == 100484:
      return MdfApiErr.MaxObservables
    if code == 401006:
      return MdfApiErr.InvalidApiKey
    
    return MdfApiErr.Nan


  def handle_api_error(self, data: str) -> MdfApiErr:
    err = MdfApiErr.Nan

    if self.raw_json == True:
      print(data)
      exit(1)

    try:
      dt = json.loads(data)
      error = dt["error"]

      if len(error) > 0:
        messages = error["messages"]
        err = MetaDefenderCloud.get_error_code(int(error["code"]))
        print(f"{C.f_red('Error')}: ({C.f_magenta('MetaDefenderCloud')}) {C.fd_yellow(messages[0])}")
    
      return err
    except KeyError:
      return err


  def get_apikey_info(self) -> str:
    start = time.time()
    base = self.BASE_APIKEY_INFO
    
    header = {
      self.JSON_HDR[0]: self.JSON_HDR[1],
      self.api_key[0]: self.api_key[1]
    }

    resp = requests.get(base, headers=header)
    end = time.time()
    self.dprint(f"Took {end - start}s to query file attributes and receive a response")

    text = resp.text
    return text


  def get_ip_rep_bulk(self, ips: list) -> (str, NbrItems):
    start = time.time()
    base = self.BASE_IP_PTH_BULK

    header = {
      self.JSON_HDR[0]: self.JSON_HDR[1],
      self.api_key[0]: self.api_key[1]
    }

    payload = {"address": ips}
    resp = requests.post(base, headers=header, data=json.dumps(payload))

    end = time.time()
    self.dprint(f"Took {end - start}s to query file attributes and receive a response")

    text = resp.text
    return (text, NbrItems.BULK)


  def get_ip_rep(self, ip: str) -> (str, NbrItems):
    start = time.time()
    base = self.BASE_IP_PTH_SINGLE

    header = {
      self.JSON_HDR[0]: self.JSON_HDR[1],
      self.api_key[0]: self.api_key[1]
    }

    base = base.replace("{ip}", ip)
    resp = requests.get(base, headers=header)

    end = time.time()
    self.dprint(f"Took {end - start}s to query file attributes and receive a response")

    text = resp.text
    return (text, NbrItems.SINGLE)


  def get_hash_rep_bulk(self, hashes: list) -> (str, NbrItems):
    start = time.time()
    base = self.BASE_HASH_PTH_BULK

    header = {
      self.JSON_HDR[0]: self.JSON_HDR[1],
      self.api_key[0]: self.api_key[1],
      "includescandetails": "1"
    }
    
    payload = {"hash": hashes}
    resp = requests.post(base, headers=header, data=json.dumps(payload))

    end = time.time()
    self.dprint(f"Took {end - start}s to query file attributes and receive a response")

    text = resp.text
    return (text, NbrItems.BULK)


  def get_hash_rep(self, hash: str) -> (str, NbrItems):
    start = time.time()
    base = self.BASE_HASH_PTH_SINGLE

    header = {
      self.JSON_HDR[0]: self.JSON_HDR[1],
      self.api_key[0]: self.api_key[1]
    }
    
    base = base.replace("{hash}", hash)
    resp = requests.get(base, headers=header)

    end = time.time()
    self.dprint(f"Took {end - start}s to query file attributes and receive a response")

    text = resp.text
    return (text, NbrItems.SINGLE)


  def get_url_rep_bulk(self, urls: list, i_type: ItemType) -> (str, NbrItems):
    start = time.time()
    base = self.BASE_URL_PTH_BULK

    header = {
      self.JSON_HDR[0]: self.JSON_HDR[1],
      self.api_key[0]: self.api_key[1]
    }
    
    payload = {"url": urls}
    resp = requests.post(base, headers=header, data=json.dumps(payload))

    end = time.time()
    self.dprint(f"Took {end - start}s to query file attributes and receive a response")

    text = resp.text
    return (text, NbrItems.BULK)


  def get_url_rep(self, url: str, i_type: ItemType) -> (str, NbrItems):
    start = time.time()
    base = self.BASE_URL_PTH_SINGLE

    header = {
      self.JSON_HDR[0]: self.JSON_HDR[1],
      self.api_key[0]: self.api_key[1]
    }
    
    base = base.replace("{url}", url)
    resp = requests.get(base, headers=header)

    end = time.time()
    self.dprint(f"Took {end - start}s to query file attributes and receive a response")

    text = resp.text
    return (text, NbrItems.SINGLE)
  

  def get_quickscan_ip(ips: str, nbr: NbrItems):
    ip_json = json.loads(ips)

    table = ColorTable()
    table.align = "l"
    table.field_names = [
      C.f_yellow("IP Address"),
      C.f_yellow("Detections"),
      C.f_yellow("Country"),
      C.f_yellow("City"),
      C.f_yellow("Subdivisions")
    ]

    rows = 0
    data = None

    if nbr == NbrItems.SINGLE:
      try:
        data = ip_json

        address = C.f_green(data["address"])
        detections = data["lookup_results"]["detected_by"]

        if int(detections) > 0:
            detections = C.b_red(C.f_white(detections))
        elif int(detections) < 1:
          detections = C.f_green(detections)

        geo = data["geo_info"]
        country = geo["country"]["name"]
        city = geo["city"]["name"]

        subdiv_names = ""  
        for i in geo["subdivisions"]:
          subdiv_names += i["name"]
      
        table.add_row([address, detections, country, city, subdiv_names])
        rows += 1
      except KeyError:
        pass

      if rows > 0:
        print(table)
      else:
        print("Nothing to display")

    elif nbr == NbrItems.BULK:
      
      try:
        data = ip_json["data"]
      except KeyError:
        pass

      for idx in data:
        try:
          address = C.f_green(idx["address"])
          detections = idx["lookup_results"]["detected_by"]

          if int(detections) > 0:
            detections = C.b_red(C.f_white(detections))
          elif int(detections) < 1:
            detections = C.f_green(detections)

          geo = idx["geo_info"]
          country = geo["country"]["name"]
          city = geo["city"]["name"]

          subdiv_names = ""  
          for i in geo["subdivisions"]:
            subdiv_names += i["name"]

          table.add_row([address, detections, country, city, subdiv_names])
          rows += 1
        except KeyError:
          continue
      
      if rows > 0:
        print(table)
      else:
        print("Nothing to display")


  def get_detection_keys():
    pass


  def get_quickscan_hash(json_hash: str, nbr: NbrItems):
    
    table = ColorTable()
    table.align = "l"
    table.field_names = [
      "Hash",
      "Detections"
      "Verdict",
      "threat"
    ]

    json_data = json.loads(json_hash)
    rows = 0

    for i in json_data["data"]:
      scan_result = int(i["scan_result_i"])
      hash_v = C.f_green(i["hash"])
      threats = ""

      verdict = C.f_green("Clean")
      if scan_result > 0:
        veridct = C.f_red("Malicious")

      scan_deets =            i["scan_details"]
      super_anti_spyware =    scan_deets["SUPERAntiSpyware"]["threat_found"]
      super_anti_spyware_l =  scan_deets["SUPERAntiSpyware"]["scan_result_i"]
      
      jiangmin =              scan_deets["Jiangmin"]["threat_found"]
      jiangmin_l =            scan_deets["Jiangmin"]["scan_result_i"]
      
      baidu =                 scan_deets["Baidu"]["threat_found"]
      baidu_l =               scan_deets["Baidu"]["scan_result_i"]
      
      vir_IT_ex =             scan_deets["Vir_IT eXplorer"]["threat_found"]
      vir_IT_ex_l =           scan_deets["Vir_IT eXplorer"]["scan_result_i"]
      
      vir_IT_ml =             scan_deets["Vir_IT ML"]["threat_found"]
      vir_IT_ml_l =           scan_deets["Vir_IT ML"]["scan_result_i"]
      
      zillya =                scan_deets["Zillya!"]["threat_found"]
      zillya_l =              scan_deets["Zillya!"]["scan_result_i"]
      
      xvirus =                scan_deets["Xvirus Personal Guard"]["threat_found"]
      xvirus_l =              scan_deets["Xvirus Personal Guard"]["scan_result_i"]
      
      vBlokAda =              scan_deets["VirusBlokAda"]["threat_found"]
      vBlokAda_l =            scan_deets["VirusBlokAda"]["scan_result_i"]
      
      TrendMicro_H =          scan_deets["TrendMicro House Call"]["threat_found"]
      TrendMicro_H_l =        scan_deets["TrendMicro House Call"]["scan_result_i"]
      
      TrendMicro =            scan_deets["TrendMicro"]["threat_found"]
      TrendMicro_l =          scan_deets["TrendMicro"]["scan_result_i"]
      
      total_Def =             scan_deets["Total Defense"]["threat_found"]
      total_Def_l =           scan_deets["Total Defense"]["scan_result_i"]
      
      threatTrack =           scan_deets["ThreatTrack"]["threat_found"]
      threatTrack_l =         scan_deets["ThreatTrack"]["scan_result_i"]
      
      tachyon =               scan_deets["TACHYON"]["threat_found"]
      tachyon_l =             scan_deets["TACHYON"]["scan_result_i"]
      
      sophos =                scan_deets["Sophos"]["threat_found"]
      sophos_l =              scan_deets["Sophos"]["scan_result_i"]
      
      quick_heal =            scan_deets["Quick Heal"]["threat_found"]
      quick_heal_l =          scan_deets["Quick Heal"]["scan_result_i"]
      
      preventon =             scan_deets["Preventon"]["threat_found"]
      preventon_l =           scan_deets["Preventon"]["scan_result_i"]
      
      nanoav =                scan_deets["NANOAV"]["threat_found"]
      nanoav_l =              scan_deets["NANOAV"]["scan_result_i"]
      
      mcAfee =                scan_deets["McAfee"]["threat_found"]
      mcAfee_l =              scan_deets["McAfee"]["scan_result_i"]
      
      k7 =                    scan_deets["K7"]["threat_found"]
      k7_l =                  scan_deets["K7"]["scan_result_i"]
      
      ikarus =                scan_deets["Ikarus"]["threat_found"]
      ikarus_l =              scan_deets["Ikarus"]["scan_result_i"]
      
      huorong =               scan_deets["Huorong"]["threat_found"]
      huorong_l =             scan_deets["Huorong"]["scan_result_i"]
      
      hauri =                 scan_deets["Hauri"]["threat_found"]
      hauri_l =               scan_deets["Hauri"]["scan_result_i"]
      
      fortinet =              scan_deets["Fortinet"]["threat_found"]
      fortinet_l =            scan_deets["Fortinet"]["scan_result_i"]
      
      filseclab =             scan_deets["Filseclab"]["threat_found"]
      filseclab_l =           scan_deets["Filseclab"]["scan_result_i"]
      
      f_secure =              scan_deets["F-secure"]["threat_found"]
      f_secure_l =            scan_deets["F-secure"]["scan_result_i"]
      
      f_prot =                scan_deets["F-prot"]["threat_found"]
      f_prot_l =              scan_deets["F-prot"]["scan_result_i"]
      
      emsisoft =              scan_deets["Emsisoft"]["threat_found"]
      emsisoft_l =            scan_deets["Emsisoft"]["scan_result_i"]
      
      eset =                  scan_deets["ESET"]["threat_found"]
      eset_l =                scan_deets["ESET"]["scan_result_i"]
      
      cyren =                 scan_deets["Cyren"]["threat_found"]
      cyren_l =               scan_deets["Cyren"]["scan_result_i"]
      
      clamAV =                scan_deets["ClamAV"]["threat_found"]
      clamAV_l =              scan_deets["ClamAV"]["scan_result_i"]
      
      byteH =                 scan_deets["ByteHero"]["threat_found"]
      byteH_l =               scan_deets["ByteHero"]["scan_result_i"]
      
      bit_Def =               scan_deets["BitDefender"]["threat_found"]
      bit_Def_l =             scan_deets["BitDefender"]["scan_result_i"]
      
      avira =                 scan_deets["Avira"]["threat_found"]
      avira_l =               scan_deets["Avira"]["scan_result_i"]
      
      antiy =                 scan_deets["Antiy"]["threat_found"]
      antiy_l =               scan_deets["Antiy"]["scan_result_i"]
      
      ahn_lab =               scan_deets["Ahnlab"]["threat_found"]
      ahn_lab_l =             scan_deets["Ahnlab"]["scan_result_i"]
      
      agnitum =               scan_deets["Agnitum"]["threat_found"]
      agnitum_l =             scan_deets["Agnitum"]["scan_result_i"]
      
      aegis_Lab =             scan_deets["AegisLab"]["threat_found"]
      aegis_Lab_l =           scan_deets["AegisLab"]["scan_result_i"]
      
      detections = 0
      detections += super_anti_spyware_l + jiangmin_l + vir_IT_ex_l + vir_IT_ml_l + zillya_l +  xvirus_l + vBlokAda_l + TrendMicro_H_l
      detections += TrendMicro_l + total_Def_l + baidu_l + threatTrack_l + tachyon_l + sophos_l + quick_heal_l + preventon_l
      detections += nanoav_l + mcAfee_l + k7_l + ikarus_l + huorong_l + hauri_l + fortinet_l + filseclab_l + f_secure_l + f_prot_l
      detections += emsisoft_l + eset_l + cyren_l + clamAV_l + bit_Def_l + byteH_l + avira_l + antiy_l + ahn_lab_l + agnitum_l + aegis_Lab_l

      # threats += f"{super_anti_spyware}\n{jiangmin}\n{vir_IT_ex}\n{vir_IT_ml}\n{zillya}\n{xvirus}\n"
      # threats += f"{vBlokAda}\n{TrendMicro_H}\n{preventon}\n{f_secure}\n{f_prot}\n{ahn_lab}\n{agnitum}\n"
      # threats += f"{TrendMicro}\n{total_Def}\n{baidu}\n{threatTrack}\n{tachyon}\n{sophos}\n{quick_heal}\n"
      # threats += f"{nanoav}\n{mcAfee}\n{k7}\n{ikarus}\n{huorong}\n{hauri}\n{fortinet}\n{filseclab}\n"
      # threats += f"{emsisoft}\n{eset}\n{cyren}\n{clamAV}\n{bit_Def}\n{byteH}\n{avira}\n{antiy}\n{aegis_Lab}"

      if detections > 0:
        detections = C.b_red(C.f_white(detections))

      table.add_row([hash_v, veridct, detections, "None for now"])
      rows += 1
    
    if rows > 0:
      print(table)
    else:
      print("Nothing to display")


  def get_quickscan_url():
    pass


  def show_apikey_info(info: str):
    
    table = ColorTable()
    table.align = "l"
    table.field_names = [
      C.f_yellow("Key"),
      C.f_yellow("Value"),
    ]

    data = json.loads(info)
    m_file_download =     C.fd_yellow(data["max_file_download"])
    m_upload_file_size =  C.fd_yellow(data["max_upload_file_size"])
    ma_file_depth =       C.fd_yellow(data["max_archive_file_depth"])
    ma_file_size =        C.fd_yellow(data["max_archive_file_size"])
    ma_file_number =      C.fd_yellow(data["max_archive_file_number"])
    l_prevention =        C.fd_yellow(data["limit_prevention"])
    l_reputation =        C.fd_yellow(data["limit_reputation"])
    l_threat_intel =      C.fd_yellow(data["limit_threat_intel_search"])
    l_sandbox =           C.fd_yellow(data["limit_sandbox"])
    l_feed =              C.fd_yellow(data["limit_feed"])
    throttle =            C.fd_yellow(data["throttling_limit"])
    workflow =            C.fd_yellow(data["workflow_rule"])
    e_private_scan =      C.f_red(data["enforce_private_scan"])
    blk_avs =             C.f_magenta(data["blocked_avs"])
    partner =             C.fd_yellow(data["partner"])
    t_interval =          C.fd_yellow(data["time_interval"])
    qos_scan =            C.f_green(data["qos_scan"])
    created_at =          C.fd_yellow(data["created_at"])
    nickname =            C.f_green(data["nickname"])
    sandbox_qscan =       C.f_green(data["sandbox_qos_scan"])
    exp_date =            C.fd_yellow(data["expiration_date"])
    vuln_submissions =    C.f_magenta(data["vulnerability_submissions"])
    is_enterprise =       C.f_red(data["is_enterprise"])
    mtls_only =           C.f_red(data["mtls_only"])
    is_encrypt_enable =   C.f_red(data["is_encrypt_enable"])
    source =              C.f_green(data["source"])
    sso_user_id =         C.f_cyan(data["sso_user_id"])
    userid =              C.f_cyan(data["userid"])
    l_change_note =       C.f_green(data["license_change_note"])
    mdc_license_type =    C.f_green(data["mdc_license_type"])
    updated_at =          C.fd_yellow(data["updated_at"])
    paid_user =           C.fd_yellow(data["paid_user"])

    label = ""
    values = ""

    label += C.f_yellow("max_file_download") + "\n" + C.f_yellow("max_upload_file_size") + "\n" + C.f_yellow("max_archive_file_depth") + "\n"
    label += C.f_yellow("max_archive_file_size") + "\n" + C.f_yellow("max_archive_file_number") + "\n" + C.f_yellow("limit_prevention") + "\n"
    label += C.f_yellow("limit_reputation") + "\n" + C.f_yellow("limit_threat_intel_search") + "\n" + C.f_yellow("limit_sandbox") + "\n" + C.f_yellow("limit_feed") + "\n"
    label += C.f_yellow("throttling_limit") + "\n" + C.f_yellow("workflow_rule") + "\n" + C.f_yellow("enforce_private_scan") + "\n" + C.f_yellow("blocked_avs") + "\n"
    label += C.f_yellow("partner") + "\n" + C.f_yellow("time_interval") + "\n" + C.f_yellow("qos_scan") + "\n" + C.f_yellow("portal_api_key") + "\n"
    label += C.f_yellow("created_at") + "\n" + C.f_yellow("nickname") + "\n" + C.f_yellow("sandbox_qos_scan") + "\n" + C.f_yellow("expiration_date") + "\n"
    label += C.f_yellow("vulnerability_submissions") + "\n" + C.f_yellow("is_enterprise") + "\n" + C.f_yellow("mtls_only") + "\n" + C.f_yellow("is_encrypt_enable") + "\n"
    label += C.f_yellow("source") + "\n" + C.f_yellow("sso_user_id") + "\n" + C.f_yellow("userid") + "\n" + C.f_yellow("license_change_note") + "\n"
    label += C.f_yellow("mdc_license_type") + "\n" + C.f_yellow("updated_at") + "\n" + C.f_yellow("paid_user")

    values += m_file_download + "\n" + m_upload_file_size + "\n" + ma_file_depth + "\n" + ma_file_size + "\n" + ma_file_number + "\n" + l_prevention + "\n"
    values += l_reputation + "\n" + l_threat_intel + "\n" + l_sandbox + "\n" + l_feed + "\n" + throttle + "\n" + workflow + "\n" + e_private_scan + "\n" 
    values += blk_avs + "\n" + partner + "\n" + t_interval + "\n" + qos_scan + "\n" + created_at + "\n" + nickname + "\n" + sandbox_qscan + "\n"
    values += exp_date + "\n" + vuln_submissions + "\n" + is_enterprise + "\n" + mtls_only + "\n" + is_encrypt_enable + "\n" + source + "\n" + sso_user_id + "\n"
    values += userid + "\n" + l_change_note + "\n" + mdc_license_type + "\n" + updated_at + "\n" + paid_user
    
    table.add_row([label, values])
    print(table)