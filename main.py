'''
coding:utf-8
@Software:PyCharm
@Time:2022/12/22 15:46
@Author:尘心||rocky
'''
import json
import os
import re
from string import Template

import requests
from dotenv import find_dotenv, load_dotenv

load_dotenv(find_dotenv('envs/.env'))  # 此处填写需要使用的漏洞配置文件
env_dist = os.environ
serverlist = json.load(open('conf/server.json', "r"))


# 从内部漏洞库中获取漏洞编号对应漏洞的详细信息
def get_info_from_online_service():
    global vul_id
    global searchlist
    global searchres
    global param
    global informationlist
    global vul_detail
    global className
    global vul_date
    global create_date
    global update_date
    global app_name
    global vul_name
    global vul_num
    global cve_num
    global cnvd_num
    global vul_type
    global poc_category
    global severity
    global reqAuth
    global fingerprintNames
    global appPowerLink
    global desc
    global suggest
    global hasExp
    global targets
    global suricata_rules
    global command
    global file_path
    global headers
    global keyword
    global method
    global payload_data
    global attack_payload_data
    global references
    global uri
    global app_main_port
    global appVersion
    global attack_uri
    global upload_directory
    global timeout
    global file_suffix
    global template
    vul_id = env_dist.get('VUL_ID')
    vul_date = env_dist.get('VUL_DATE')
    create_date = env_dist.get('CREATEDATE')
    update_date = env_dist.get('UPDATEDATE')
    app_name = env_dist.get('APP_NAME')
    vul_name = env_dist.get('VUL_NAME')
    vul_num = env_dist.get('VUL_NUM')
    cve_num = env_dist.get('CVE_NUM')
    cnvd_num = env_dist.get('CNVD_NUM')
    vul_type = env_dist.get('VUL_TYPE')
    poc_category = env_dist.get('POC_CATEGORY')
    severity = env_dist.get('SEVERITY')
    reqAuth = env_dist.get('REQAUTH')
    fingerprintNames = env_dist.get('FINGERPRINT_NAMES')
    appPowerLink = env_dist.get('APP_POWER_LINK')
    desc = env_dist.get('DESC')
    suggest = env_dist.get('SUGGEST')
    hasExp = env_dist.get('HASEXP')
    targets = env_dist.get('TARGETS')
    suricata_rules = env_dist.get('SURICATA_RULES')
    command = env_dist.get('COMMAND')
    file_path = env_dist.get('FILE_PATH')
    headers = env_dist.get('HEADERS')
    keyword = env_dist.get('KEYWORD')
    method = env_dist.get('METHOD')
    payload_data = env_dist.get('PAYLOAD_DATA')
    attack_payload_data = env_dist.get('ATTACK_PAYLOAD_DATA')
    references = env_dist.get('REFERENCES')
    uri = env_dist.get('URI')
    app_main_port = env_dist.get('APP_MAIN_PORT')
    appVersion = env_dist.get('APPVERSION')
    attack_uri = env_dist.get('ATTACK_URI')
    upload_directory = env_dist.get('UPLOAD_DIRECTORY')
    timeout = env_dist.get('TIMEOUT')
    file_suffix = env_dist.get('FILE_SUFFIX')
    template = env_dist.get("TEMPLATE")

    for server in serverlist:
        t = json.dumps(server['searchData'])
        t = t.replace("{VULID}", vul_id)
        searchlist = json.loads(t)
        print(f"尝试从{server['name']}中获取数据中")
        try:
            if server['searchMethod'] == "POST":
                searchres = requests.post(url=server["searchURL"], data=searchlist, headers=server['header'],
                                          cookies=server['cookie'])
            elif server['searchMethod'] == "GET":
                searchres = requests.get(url=server["searchURL"], params=searchlist, headers=server['header'],
                                         cookies=server['cookie'])
            else:
                searchres = requests.post(url=server["searchURL"], json=searchlist, headers=server['header'],
                                          cookies=server['cookie'])
            param = eval("searchres.json()" + server['paramPosition'])
            t = json.dumps(server['informationData'])
            t = t.replace("{PARAM}", str(param))
            informationlist = json.loads(t)

            if server['informationMethod'] == "POST":
                vul_detail = requests.post(url=server['informationURL'], cookies=server['cookie'], headers=server['header'],
                                           data=informationlist)
            elif server['informationMethod'] == "GET":
                vul_detail = requests.get(url=server['informationURL'], cookies=server['cookie'], headers=server['header'],
                                          params=informationlist)
            else:
                vul_detail = requests.post(url=server['informationURL'], cookies=server['cookie'], headers=server['header'],
                                           json=informationlist)

            vul_detail = eval("vul_detail.json()" + server['detailPosition'])
            conventer = json.load(open(f"conventer/{server['conventer']}"))
            # 变量覆盖
            for i in conventer:
                globals()[i] = eval("vul_detail" + conventer[i])
            print(f"从{server['name']}中获取数据成功，变量已覆盖")
        except:
            print(f"从{server['name']}中获取数据失败")

    className = app_name.replace(' ', '_') + '_' + vul_num.replace('-', '_')
    filePath = r'pocs/%s.py' % className
    class_file = open(filePath, 'w')
    lines = []

    # 模版文件
    template_file = open(f'templates/{template}', 'r')
    tmpl = Template(template_file.read())
    pat = re.compile('>(.*?)<')
    desc = (''.join(pat.findall(desc)))

    # 模版替换
    # substitute 会报错 没有匹配到的数值；safe_substitute 会将没有匹配到的数据 原封不动展示出来
    lines.append(tmpl.safe_substitute(
        REFERENCES=references,
        CLASSNAME=className,
        VUL_ID=vul_id,
        VUL_DATE=vul_date,
        CREATEDATE=create_date,
        UPDATEDATE=update_date,
        APP_NAME=app_name,
        VUL_NAME=vul_name,
        VUL_NUM=vul_num,
        CVE_NUM=cve_num,
        CNVD_NUM=cnvd_num,
        VUL_TYPE=vul_type,
        POC_CATEGORY=poc_category,
        SEVERITY=severity,
        REQAUTH=reqAuth,
        FINGERPRINT_NAMES=fingerprintNames,
        APP_POWER_LINK=appPowerLink,
        DESC=desc,
        SUGGEST=suggest,
        HASEXP=hasExp,
        TARGETS=targets,
        SURICATA_RULES=suricata_rules,
        COMMAND=command,
        FILE_PATH=file_path,
        HEADERS=headers,
        KEYWORD=keyword,
        METHOD=method,
        PAYLOAD_DATA=payload_data,
        URI=uri,
        ATTACK_PAYLOAD_DATA=attack_payload_data,
        APPVERSION=appVersion,
        ATTACK_URI=attack_uri,
        APP_MAIN_PORT=app_main_port,
        UPLOAD_DIRECTORY=upload_directory,
        FILE_SUFFIX=file_suffix,
        TIMEOUT=timeout,
        EXPIRE_DATE='06JUN14'))
    # 0.将生成的代码写入文件
    class_file.writelines(lines)
    class_file.close()
def generate():
    className = env_dist.get('CLASSNAME')
    vul_id = env_dist.get('VUL_ID')
    vul_date = env_dist.get('VUL_DATE')
    create_date = env_dist.get('CREATEDATE')
    update_date = env_dist.get('UPDATEDATE')
    app_name = env_dist.get('APP_NAME')
    vul_name = env_dist.get('VUL_NAME')
    vul_num = env_dist.get('VUL_NUM')
    cve_num = env_dist.get('CVE_NUM')
    cnvd_num = env_dist.get('CNVD_NUM')
    vul_type = env_dist.get('VUL_TYPE')
    poc_category = env_dist.get('POC_CATEGORY')
    severity = env_dist.get('SEVERITY')
    reqAuth = env_dist.get('REQAUTH')
    fingerprintNames = env_dist.get('FINGERPRINT_NAMES')
    appPowerLink = env_dist.get('APP_POWER_LINK')
    desc = env_dist.get('DESC')
    suggest = env_dist.get('SUGGEST')
    hasExp = env_dist.get('HASEXP')
    targets = env_dist.get('TARGETS')
    suricata_rules = env_dist.get('SURICATA_RULES')
    command = env_dist.get('COMMAND')
    file_path = env_dist.get('FILE_PATH')
    headers = env_dist.get('HEADERS')
    keyword = env_dist.get('KEYWORD')
    method = env_dist.get('METHOD')
    payload_data = env_dist.get('PAYLOAD_DATA')
    attack_payload_data = env_dist.get('ATTACK_PAYLOAD_DATA')
    references = env_dist.get('REFERENCES')
    uri = env_dist.get('URI')
    app_main_port = env_dist.get('APP_MAIN_PORT')
    appVersion = env_dist.get('APPVERSION')
    attack_uri = env_dist.get('ATTACK_URI')
    upload_directory = env_dist.get('UPLOAD_DIRECTORY')
    timeout = env_dist.get('TIMEOUT')
    file_suffix = env_dist.get('FILE_SUFFIX')
    filePath = r'pocs/%s.py' % className
    class_file = open(filePath, 'w')
    lines = []

    # 模版文件
    template_file = open(r'pocsuite3_code_upload_files.template', 'r')
    tmpl = Template(template_file.read())
    # 模版替换
    # substitute 会报错 没有匹配到的数值；safe_substitute 会将没有匹配到的数据 原封不动展示出来
    lines.append(tmpl.safe_substitute(
        REFERENCES=references,
        CLASSNAME=className,
        VUL_ID=vul_id,
        VUL_DATE=vul_date,
        CREATEDATE=create_date,
        UPDATEDATE=update_date,
        APP_NAME=app_name,
        VUL_NAME=vul_name,
        VUL_NUM=vul_num,
        CVE_NUM=cve_num,
        CNVD_NUM=cnvd_num,
        VUL_TYPE=vul_type,
        POC_CATEGORY=poc_category,
        SEVERITY=severity,
        REQAUTH=reqAuth,
        FINGERPRINT_NAMES=fingerprintNames,
        APP_POWER_LINK=appPowerLink,
        DESC=desc,
        SUGGEST=suggest,
        HASEXP=hasExp,
        TARGETS=targets,
        SURICATA_RULES=suricata_rules,
        COMMAND=command,
        FILE_PATH=file_path,
        HEADERS=headers,
        KEYWORD=keyword,
        METHOD=method,
        PAYLOAD_DATA=payload_data,
        URI=uri,
        ATTACK_PAYLOAD_DATA=attack_payload_data,
        APPVERSION=appVersion,
        ATTACK_URI=attack_uri,
        APP_MAIN_PORT=app_main_port,
        UPLOAD_DIRECTORY=upload_directory,
        FILE_SUFFIX=file_suffix,
        TIMEOUT=timeout,
        EXPIRE_DATE='06JUN14'))
    # 0.将生成的代码写入文件
    class_file.writelines(lines)
    class_file.close()


if __name__ == '__main__':
    get_info_from_public_url()
