# -*- coding: utf-8 -*-
#                    _
#     /\            | |
#    /  \   _ __ ___| |__   ___ _ __ _   _
#   / /\ \ | '__/ __| '_ \ / _ \ '__| | | |
#  / ____ \| | | (__| | | |  __/ |  | |_| |
# /_/    \_\_|  \___|_| |_|\___|_|   \__, |
#                                     __/ |
#                                    |___/
# Copyright (C) 2017 Anand Tiwari
#
# Email:   anandtiwarics@gmail.com
# Twitter: @anandtiwarics
#
# This file is part of ArcherySec Project.

import ast
import hashlib
import json
import os
import re
import time
import uuid
from pprint import pprint

import requests
import yaml
from django.db.models import Q
from zapv2 import ZAPv2

from archerysettings.models import ZapSettingsDb

from projects.models import ProjectDb

from utility.email_notify import email_sch_notify

from archerysettings.models import GitlabDb

try:
    from scanners.scanner_parser.web_scanner import zap_xml_parser
except Exception as e:
    print(e)
import subprocess
from datetime import datetime

import defusedxml.ElementTree as ET

from webscanners.models import (WebScanResultsDb, WebScansDb, cookie_db,
                                excluded_db, zap_spider_db)

# ZAP Database import

# Global Variables
setting_file = os.getcwd() + "/apidata.json"
# zap_setting = load_settings.ArcherySettings(setting_file)
zap_api_key = "dwed23wdwedwwefw4rwrfw"
zap_hosts = "0.0.0.0"
zap_ports = "8090"

risk = ""
name = ""
attack = ""
confidence = ""
wascid = ""
description = ""
reference = ""
sourceid = ""
solution = ""
param = ""
method = ""
url = ""
pluginId = ""
other = ""
alert = ""
messageId = ""
evidence = ""
cweid = ""
risk = ""
vul_col = ""
all_vuln = ""

import socket

# Getting a random free tcp port in python using sockets


def get_free_tcp_port():
    tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp.bind(("", 0))
    addr, port = tcp.getsockname()
    tcp.close()
    return port


def zap_local():
    random_port = str(get_free_tcp_port())
    zap_path = "/home/archerysec/app/zap/"
    executable = "zap.sh"
    executable_path = os.path.join(zap_path, executable)

    zap_command = [
        executable_path,
        "-daemon",
        "-config",
        "api.disablekey=false",
        "-config",
        "api.key=" + zap_api_key,
        "-port",
        random_port,
        "-host",
        zap_hosts,
        "-config",
        "api.addrs.addr.name=.*",
        "-config",
        "api.addrs.addr.regex=true",
    ]

    log_path = os.getcwd() + "/" + "zap.log"

    with open(log_path, "w+") as log_file:
        subprocess.Popen(
            zap_command, cwd=zap_path, stdout=log_file, stderr=subprocess.STDOUT
        )

    return random_port


def zap_connect(random_port):
    all_zap = ZapSettingsDb.objects.filter()

    zap_api_key = "none"
    zap_hosts = "none"
    zap_ports = "none"
    zap_enabled = False

    for zap in all_zap:
        zap_enabled = zap.enabled

    if zap_enabled is False:
        zap_api_key = "none"
        zap_hosts = "none"
        zap_ports = random_port

    if zap_enabled is True:
        for zap in all_zap:
            zap_api_key = zap.zap_api
            zap_hosts = zap.zap_url
            zap_ports = zap.zap_port
    zap = ZAPv2(
        apikey=zap_api_key,
        proxies={
            "http": "http://" + zap_hosts + ":" + str(zap_ports),
            "https": "https://" + zap_hosts + ":" + str(zap_ports),
        },
    )
    return zap


def zap_replacer(target_url, random_port):
    zap = zap_connect(random_port=random_port)
    try:
        zap.replacer.remove_rule(description=target_url, apikey=zap_api_key)
    except Exception as e:
        print("ZAP Replacer error")
    return

def zap_spider_thread(count, random_port):
    zap = zap_connect(random_port=random_port)
    zap.spider.set_option_thread_count(count, apikey=zap_api_key)
    return

def zap_scan_thread(count, random_port):
    zap = zap_connect(random_port=random_port)
    zap.ascan.set_option_thread_per_host(count, apikey=zap_api_key)
    return

def zap_spider_setOptionMaxDepth(count, random_port):
    zap = zap_connect(random_port=random_port)
    zap.spider.set_option_max_depth(count, apikey=zap_api_key)
    return

def zap_scan_setOptionHostPerScan(count, random_port):
    zap = zap_connect(random_port=random_port)
    zap.ascan.set_option_host_per_scan(count, apikey=zap_api_key)
    return

class ZAPScanner:
    """
    ZAP Scanner Plugin. Interacting with ZAP Scanner API.
    """
    # Global variable's
    spider_alert = []
    target_url = [] # get from user input
    driver = []
    new_uri = []
    excluded_url = []
    vul_col = []
    note = []
    rtt = []
    tags = []
    timestamp = []
    responseHeader = []
    requestBody = []
    responseBody = []
    requestHeader = []
    cookieParams = []
    res_type = []
    res_id = []
    alert = []
    project_id = None
    scan_ip = None
    burp_status = 0
    serialNumber = []
    types = []
    name = []
    host = []
    path = []
    location = []
    severity = []
    confidence = []
    issueBackground = []
    remediationBackground = []
    references = []
    vulnerabilityClassifications = []
    issueDetail = []
    requestresponse = []
    vuln_id = []
    methods = []
    dec_res = []
    dec_req = []
    decd_req = []
    scanner = []
    all_scan_url = []
    all_url_vuln = []
    false_positive = ""
    context_name=""
    context_id = ""
    context_include_url = "" # from user input
    context_exclude_url = "" # from user input


    """ Connect with ZAP scanner global variable """

    def __init__(self, target_url, project_id, rescan_id, rescan, random_port, request):
        """

        :param target_url: Target URL parameter.
        :param project_id: Project ID parameter.
        """
        self.target_url = target_url
        self.project_id = project_id
        self.rescan_id = rescan_id
        self.rescan = rescan
        self.zap = zap_connect(random_port=random_port)
        self.request = request


    def create_context(self,context_name):
        self.context_name=context_name
        context = self.zap.context
        contextId = context.new_context(contextname=context_name)
        if contextId == "already_exists":
            context_info = self.zap.context.context(context_name)
            self.context_id = context_info.get('id')
        else:
            self.context_id = contextId
        pprint('Use context name: ' + self.context_name)
        # print(self.context_name)
        return self.context_id

        # Include URL in the context
    def include_urls(self,context_name,context_include_url):
        context = self.zap.context
        print('Include URL in context:')
        pprint(context_include_url + ' -> ' +
                   context.include_in_context(contextname=context_name,
                                              regex=context_include_url))
        # Exclude URL in the context
    def exclude_urls(self,context_name,context_exclude_url):
        context = self.zap.context
        print('Exclude URL from context:')
        pprint(url + ' -> ' +
                   context.exclude_from_context(contextname=context_name,
                                                regex=context_exclude_url))

    def zap_spider(self,max_duration):
        """
        Scan trigger in ZAP Scanner and return Scan ID
        :return:
        """
        spider_id = ""
        try:
            print("targets:-----", self.target_url)
            print(self.context_name)
            try:
                self.zap.spider.set_option_max_duration(max_duration)

                spider_scan_id = self.zap.spider.scan(url=self.target_url, maxchildren=None, recurse=False,
                                     contextname=self.context_name, subtreeonly=None)
                print('Scan ID equals ' + spider_scan_id)
                time.sleep(2)
            except Exception as e:
                print("Spider Error")
            time.sleep(5)
            # save_all = zap_spider_db(
            #     spider_url=self.target_url, spider_scanid=spider_scan_id
            # )
            # save_all.save()
        except Exception as e:
            print(e)
        return spider_scan_id

    def zap_spider_thread(self, thread_value):
        """
        The function use for the increasing Spider thread in ZAP scanner.
        :return:
        """
        thread = ""
        try:
            thread = self.zap.spider.set_option_thread_count(
                apikey=zap_api_key, integer=thread_value
            )
            print("zap spider thread is running")
        except Exception as e:
            print("Spider Thread error")
        return thread

    def spider_status(self, spider_id):
        """
        The function return the spider status.
        :param spider_id:
        :return:
        """

        try:
            while int(self.zap.spider.status(spider_id)) < 100:
                print('Spider progress ' + self.zap.spider.status(spider_id) + '%')
                global spider_status
                spider_status = self.zap.spider.status(spider_id)
                time.sleep(2)
        except Exception as e:
            print(e)
        spider_status = "100"
        print('Spider scan completed')
        return spider_status

    def spider_result(self, spider_id):
        """
        The function return spider result.
        :param spider_id:
        :return:
        """
        data_out = ""
        try:
            # maybe it updated to full_result and not results
            spider_res_out = self.zap.spider.results(spider_id)
            data_out = "\n".join(map(str, spider_res_out))
        except Exception as e:
            print(e)
        return data_out

    # Ajax Spider Config :
    def zap_ajax_spider(self,target,max_duration=60,inscope=None,subtreeonly=None):
        ajax = self.zap.ajaxSpider
        ajax.set_option_max_duration(max_duration)
        pprint('Start Ajax Spider -> ' + ajax.scan(url=target,contextname=self.context_name ,inscope=inscope,subtreeonly=subtreeonly))
        # Give the Ajax spider a chance to start
        time.sleep(10)
        while (ajax.status != 'stopped'):
            print('Ajax Spider is ' + ajax.status)
            time.sleep(5)
        print("Ajax spider completed")

    def zap_pscan(self):

        # enable passive scan
        print("Enable passive Scan ->"+ self.zap.pscan.set_enabled("true"))
        # in scope scan :
        print("Enable passive Scan Only in Scope ->" + self.zap.pscan.set_scan_only_in_scope("true") )

        pprint('Enable all passive scanners -> ' +
               self.zap.pscan.enable_all_scanners())
        while (int(self.zap.pscan.records_to_scan) > 0):
            print('Records to passive scan : {}'.format(self.zap.pscan.records_to_scan))
            time.sleep(2)
        print('Passive Scan completed')
    def zap_ascan(self):
        """
        The function Trigger scan in ZAP scanner
        :return:
        """
        ascan_id = ""
        print("inside the active scan function")
        print(self.context_id)
        print("the context is : ",self.context_name)
        try:
            # scan_id = self.zap.ascan.scan(self.target_url,context_id)
            print("the url is : ",self.target_url)
            ascan_id = self.zap.ascan.scan(url=self.target_url,contextid=self.context_id, recurse=True, inscopeonly=True)
            print('Start Active scan. Scan ID equals ' + ascan_id)
        except Exception as e:
            print("ZAP SCAN ERROR")
        return ascan_id

    def zap_scan_status(self, scan_id, un_scanid):
        """
        The function return the ZAP Scan Status.
        :param scan_id:
        :return:
        """

        try:
            while int(self.zap.ascan.status(scan_id)) < 100:
                scan_status = self.zap.ascan.status(scan_id)
                print("ZAP Scan Status:", scan_status)
                time.sleep(10)
                WebScansDb.objects.filter(scan_id=un_scanid).update(
                    scan_status=scan_status
                )
        except Exception as e:
            print(e)

        scan_status = 100
        WebScansDb.objects.filter(scan_id=un_scanid).update(scan_status=scan_status)
        return scan_status

    def check_accessibility(self):

        """
        this function return True if the target is accessible
        """
        print("the target isssss ",self.target_url)
        print("the context name issssssss ",self.context_name)
        accessible_urls = self.zap.context.urls(self.context_name)
        print(accessible_urls)

        if self.target_url in accessible_urls:
            return True
        return False

    def zap_scan_result(self, target_url):
        """
        The function return ZAP Scan Results.
        :return:
        """
        global all_vuln
        zap_enabled = False

        all_zap = ZapSettingsDb.objects.filter()
        for zap in all_zap:
            zap_enabled = zap.enabled

        if zap_enabled is False:
            try:
                all_vuln = self.zap.core.xmlreport()
                print(target_url)
            except Exception as e:
                print("zap scan result error")
        else:
            # all_vuln = self.zap.core.alerts(baseurl=target_url)
            all_vuln = self.zap.alert.alerts(baseurl=target_url,contextname=self.context_name)
        return all_vuln

    def zap_result_save(self, all_vuln, project_id, un_scanid, target_url, request):
        """
        The function save all data in Archery Database
        :param all_vuln:
        :param project_id:
        :param un_scanid:
        :return:
        """
        date_time = datetime.now()
        zap_enabled = False

        all_zap = ZapSettingsDb.objects.filter()
        for zap in all_zap:
            zap_enabled = zap.enabled

        if zap_enabled is False:
            root_xml = ET.fromstring(all_vuln)
            en_root_xml = ET.tostring(root_xml, encoding="utf8").decode(
                "ascii", "ignore"
            )
            root_xml_en = ET.fromstring(en_root_xml)
            try:
                zap_xml_parser.xml_parser(
                    project_id=project_id,
                    scan_id=un_scanid,
                    root=root_xml_en,
                    request=request,
                )
                self.zap.core.delete_all_alerts()
            except Exception as e:
                print(e)
        else:
            global name, attack, wascid, description, reference, reference, sourceid, solution, param, method, url, messageId, alert, pluginId, other, evidence, cweid, risk, vul_col, false_positive
            for data in all_vuln:
                for key, value in data.items():
                    if key == "name":
                        name = value

                    if key == "attack":
                        attack = value

                    if key == "wascid":
                        wascid = value

                    if key == "description":
                        description = value

                    if key == "reference":
                        reference = value

                    if key == "sourceid":
                        sourceid = value

                    if key == "solution":
                        solution = value

                    if key == "param":
                        param = value

                    if key == "method":
                        method = value

                    if key == "url":
                        url = value

                    if key == "pluginId":
                        pluginId = value

                    if key == "other":
                        other = value

                    if key == "alert":
                        alert = value

                    if key == "attack":
                        attack = value

                    if key == "messageId":
                        messageId = value

                    if key == "evidence":
                        evidence = str(value)

                    if key == "cweid":
                        cweid = value

                    if key == "risk":
                        risk = value
                if risk == "Critical":
                    vul_col = "critical"
                    risk = "Critical"
                elif risk == "High":
                    vul_col = "danger"
                    risk = "High"
                elif risk == "Medium":
                    vul_col = "warning"
                    risk = "Medium"
                elif risk == "info":
                    vul_col = "info"
                    risk = "Low"
                else:
                    vul_col = "info"
                    risk = "Low"

                dup_data = name + risk + target_url
                duplicate_hash = hashlib.sha256(dup_data.encode("utf-8")).hexdigest()
                match_dup = (
                    WebScanResultsDb.objects.filter(
                        dup_hash=duplicate_hash, organization=request.user.organization
                    )
                    .values("dup_hash")
                    .distinct()
                )
                lenth_match = len(match_dup)
                vuln_id = uuid.uuid4()
                if lenth_match == 0:
                    duplicate_vuln = "No"
                    dump_data = WebScanResultsDb(
                        vuln_id=vuln_id,
                        severity_color=vul_col,
                        scan_id=un_scanid,
                        project_id=project_id,
                        severity=risk,
                        reference=reference,
                        url=target_url,
                        title=name,
                        solution=solution,
                        instance=evidence,
                        description=description,
                        false_positive="No",
                        jira_ticket="NA",
                        vuln_status="Open",
                        dup_hash=duplicate_hash,
                        vuln_duplicate=duplicate_vuln,
                        scanner="Zap",
                        organization=request.user.organization,
                    )
                    dump_data.save()
                else:
                    duplicate_vuln = "Yes"

                    dump_data = WebScanResultsDb(
                        vuln_id=vuln_id,
                        severity_color=vul_col,
                        scan_id=un_scanid,
                        project_id=project_id,
                        severity=risk,
                        reference=reference,
                        url=target_url,
                        title=name,
                        solution=solution,
                        instance="na",
                        description=description,
                        false_positive="Duplicate",
                        jira_ticket="NA",
                        vuln_status="Duplicate",
                        dup_hash=duplicate_hash,
                        vuln_duplicate=duplicate_vuln,
                        scanner="Zap",
                        organization=request.user.organization,
                    )
                    dump_data.save()

                false_p = WebScanResultsDb.objects.filter(
                    false_positive_hash=duplicate_hash,
                    organization=request.user.organization,
                )
                fp_lenth_match = len(false_p)

                if fp_lenth_match == 1:
                    false_positive = "Yes"
                else:
                    false_positive = "No"

                vul_dat = WebScanResultsDb.objects.filter(
                    vuln_id=vuln_id,
                    scanner="Zap",
                    organization=request.user.organization,
                )
                # full_data = []
                # for data in vul_dat:
                #     print("the evidence is : ",data)
                #     key = "Evidence"
                #     value = data.instance
                #     dd = re.sub(r"<[^>]*>", " ", value)
                #     instance = key + ": " + dd
                #     full_data.append(instance)
                # removed_list_data = ",".join(full_data)

                # WebScanResultsDb.objects.filter(
                #     vuln_id=vuln_id, organization=request.user.organization
                # ).update(instance=full_data)

            zap_all_vul = WebScanResultsDb.objects.filter(
                scan_id=un_scanid,
                false_positive="No",
                scanner="Zap",
                organization=request.user.organization,
            )

            duplicate_count = WebScanResultsDb.objects.filter(
                scan_id=un_scanid,
                vuln_duplicate="Yes",
                organization=request.user.organization,
            )

            total_critical = len(zap_all_vul.filter(severity="Critical"))
            total_high = len(zap_all_vul.filter(severity="High"))
            total_medium = len(zap_all_vul.filter(severity="Medium"))
            total_low = len(zap_all_vul.filter(severity="Low"))
            total_info = len(zap_all_vul.filter(severity="Informational"))
            total_duplicate = len(duplicate_count.filter(vuln_duplicate="Yes"))
            total_vul = total_high + total_medium + total_low + total_info

            WebScansDb.objects.filter(
                scan_id=un_scanid, organization=request.user.organization
            ).update(
                scan_status="100",
                total_vul=total_vul,
                date_time=date_time,
                critical_vul=total_critical,
                high_vul=total_high,
                medium_vul=total_medium,
                low_vul=total_low,
                info_vul=total_info,
                total_dup=total_duplicate,
                scan_url=target_url,
                organization=request.user.organization,
            )
            if total_vul == total_duplicate: ## weird idk why
                WebScansDb.objects.filter(scan_id=un_scanid).update(
                    scan_status="100",
                    total_vul=total_vul,
                    date_time=date_time,
                    project_id=project_id,
                    critical_vul=total_critical,
                    high_vul=total_high,
                    medium_vul=total_medium,
                    low_vul=total_low,
                    total_dup=total_duplicate,
                    organization=request.user.organization,
                )

            # subject = "Archery Tool Scan Status - ZAP Scan Completed"
            # message = (
            #         "ZAP Scanner has completed the scan "
            #         "  %s <br> Total: %s <br>High: %s <br>"
            #         "Medium: %s <br>Low %s"
            #         % (target_url, total_vul, total_high, total_medium, total_low)
            # )
            # print("the email from zap result  message is : ", message)
            # email_sch_notify(subject=subject, message=message)

    def zap_shutdown(self):
        """
        :return:
        """
        self.zap.core.shutdown(apikey=zap_api_key)

    def exclude_url(self):
        """
        Exclude URL from scan. Data are fetching from Archery database.
        :return:
        """
        excluded_url = ""
        try:
            all_excluded = excluded_db.objects.filter(
                Q(exclude_url__icontains=self.target_url)
            )
            for data in all_excluded:
                excluded_url = data.exclude_url
                print("excluded url ", excluded_url)
        except Exception as e:
            print(e)

        try:
            self.zap.spider.exclude_from_scan(
                regex=excluded_url,
            )
        except Exception as e:
            print(e)

        return excluded_url

    def cookies(self):
        """
        Cookies value extracting from Archery database and replacing
         into ZAP scanner.
        :return:
        """
        all_cookies = ""
        try:
            all_cookie = cookie_db.objects.filter(Q(url__icontains=self.target_url))
            for da in all_cookie:
                all_cookies = da.cookie

        except Exception as e:
            print(e)
        print("All cookies", all_cookies)
        print("Target URL---", self.target_url)

        try:
            self.zap.replacer.add_rule(
                apikey=zap_api_key,
                description=self.target_url,
                enabled="true",
                matchtype="REQ_HEADER",
                matchregex="false",
                replacement=all_cookies,
                matchstring="Cookie",
                initiators="",
            )
        except Exception as e:
            print(e)


def run_af_plan(file_path,random_port):
    plan_id = None
    zap = zap_connect(random_port=random_port)
    try:
        plan_id = zap.automation.run_plan(filepath=file_path,apikey=zap_api_key)


        time.sleep(1)
    except Exception as e:
        print("Zap Automation Framework fails to run then given plan because of :")
        print(e)

    return plan_id

def af_plan_progress(plan_id):
    all_zap = ZapSettingsDb.objects.filter()
    for zap in all_zap:
        zap_api_key = zap.zap_api

    url = "http://localhost:8090/JSON/automation/view/planProgress/"
    params = {
        'apikey': zap_api_key ,
        'planId': plan_id
    }
    finished_time=""
    while (finished_time==""):
        time.sleep(4)
        response = requests.get(url, params=params)
        finished_time = response.json()['finished']
    print("plan"+plan_id+" is done ")
    return True


def upload_file(file_name,file):
    uploaded_file_path = None
    zap = zap_connect(random_port=8080)
    try:
        # print(file)
        uploaded_file_path = zap.core.file_upload(filename=file_name, filecontents=file)
    except Exception as e:
        print("Error occurred when uploading a file  :")
        print(e)
    return uploaded_file_path

def upload_plan_gitlab(repository,branch,filename):

    gitlab = GitlabDb.objects.filter()
    if len(gitlab) == 0:
        print("Gitlab is not connected, please check gitlab connectivety")
        return None
    gitlab_username = gitlab[0].gitlab_username
    gitlab_url = gitlab[0].gitlab_url
    private_token = gitlab[0].gitlab_api
    gitlab_repo = gitlab[0].gitlab_repo
    filename = filename
    branch = branch
    encoded_project_path = f"{gitlab_username}/{gitlab_repo}".replace("/", "%2F")
    gitlab_url = f"{gitlab_url}/{encoded_project_path}/repository/files/{filename}/raw?ref={branch}&private_token={private_token}"
    try:
        response = requests.get(gitlab_url)
    except :
        print("failed to send request, check gitlab connectivety params")
        return None
    print(gitlab_url)
    # Check if the request was successful
    if response.status_code == 200:
        yaml_data = yaml.safe_load(response.text)
        print("the plan is : ")
        print(yaml_data)
        return yaml_data
    else:
        print(f"Failed to download YAML file. Status code: {response.status_code}")
        return None
