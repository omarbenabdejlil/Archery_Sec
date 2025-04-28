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
# Copyright (C) 2024 Ahmed Aissa
# Email:   ahmed.aissa.ing@gmail.com
# linkedin: @ahmedaissa

# This file is part of ArcherySec Project.


from __future__ import unicode_literals

import json
import os
import threading
import time
import uuid
from datetime import datetime

import yaml
from archerysettings.models import EmailDb, SettingsDb, ZapSettingsDb
from django.conf import settings
from django.contrib import messages
from django.core.mail import send_mail
from django.http import HttpResponseRedirect, JsonResponse
from django.shortcuts import HttpResponse, render
from django.template.loader import render_to_string
from django.urls import reverse
from notifications.signals import notify
from projects.models import ProjectDb
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from scanners.scanner_plugin.web_scanner import zap_plugin
from scanners.scanner_plugin.web_scanner.zap_plugin import run_af_plan
from scanners.scanner_plugin.web_scanner.zap_plugin import upload_plan_gitlab
from user_management import permissions
from webscanners.models import WebScansDb, AutomationPlan
from webscanners.zapscanner.serializers import (ZapScansSerializer,
                                                ZapSettingsSerializer)

from scanners.scanner_plugin.web_scanner.zap_plugin import upload_file

scans_status = None
to_mail = ""
scan_id = None
scan_name = None


def email_notify(user, subject, message):
    global to_mail
    all_email = EmailDb.objects.all()
    for email in all_email:
        to_mail = email.recipient_list

    print(to_mail)
    email_from = settings.EMAIL_HOST_USER
    recipient_list = [to_mail]
    try:
        send_mail(subject, message, email_from, recipient_list)
    except Exception as e:
        notify.send(user, recipient=user, verb="Email Settings Not Configured")


def email_sch_notify(subject, message):
    global to_mail
    all_email = EmailDb.objects.all()
    for email in all_email:
        to_mail = email.recipient_list

    print(to_mail)
    email_from = settings.EMAIL_HOST_USER
    recipient_list = [to_mail]
    try:
        send_mail(subject, message, email_from, recipient_list)
    except Exception as e:
        print(e)

def launch_zap_scan(
        target_url, project_id, rescan_id, rescan, scan_id, user, request,include_url=None,exclude_url=None,
        active = False,
        passive = False,
        ajax_spider = False,
        spider = False,
        auth = False,
):
    """
    The function Launch ZAP Scans .
    :param target_url: Target URL
    :param project_id: Project ID
    :return:
    """
    zap_enabled = False
    random_port = "8091"

    all_zap = ZapSettingsDb.objects.filter(organization=request.user.organization)
    for zap in all_zap:
        zap_enabled = zap.enabled

    if zap_enabled is False:
        print("started local instance")
        random_port = zap_plugin.zap_local()
        for i in range(0, 100):
            while True:
                try:
                    # Connection Test
                    zap_connect = zap_plugin.zap_connect(random_port)
                    # zap_connect.spider.scan(url=target_url)
                except Exception as e:
                    print("ZAP Connection Not Found, re-try after 5 sec")
                    time.sleep(5)
                    continue
                break

    zap_plugin.zap_scan_thread(count=30, random_port=random_port)
    zap_plugin.zap_scan_setOptionHostPerScan(count=3, random_port=random_port)

    # Load ZAP Plugin
    zap = zap_plugin.ZAPScanner(
        target_url,
        project_id,
        rescan_id,
        rescan,
        random_port=random_port,
        request=request,
    )
    project_dat = ProjectDb.objects.get(id=project_id, organization=request.user.organization)
    context_name = project_dat.project_name
    zap.exclude_url() # exclude global urls
    zap.create_context(context_name)
    if include_url is not None:
        zap.include_urls(context_name,include_url)
    if exclude_url is not None:
        zap.include_urls(context_name, exclude_url)
    zap.cookies()
    date_time = datetime.now()

    try:
        save_all_scan = WebScansDb(
            project_id=project_id,
            scan_url=target_url,
            scan_id=scan_id,
            date_time=date_time,
            rescan_id=rescan_id,
            rescan=rescan,
            scan_status="0",
            scanner="Zap",
            organization=request.user.organization,
        )
        save_all_scan.save()
        notify.send(user, recipient=user, verb="ZAP Scan URL %s Added" % target_url)
    except Exception as e:
        print(e)
    notify.send(user, recipient=user, verb="ZAP Scan Started")
    time.sleep(3)

    if spider:
        max_depth = request.POST.get('spiderMaxDepth',5)
        spider_thread = request.POST.get('spiderThread',20)
        max_duration = request.POST.get('spiderMaxDuration',2)
        zap_plugin.zap_spider_thread(count=spider_thread, random_port=random_port)
        zap_plugin.zap_spider_setOptionMaxDepth(count=max_depth, random_port=random_port)
        spider_id = zap.zap_spider(max_duration)
        zap.spider_status(spider_id=spider_id)
        zap.spider_result(spider_id=spider_id)
        notify.send(user, recipient=user, verb="ZAP Scan Spider Completed")
        time.sleep(5)

    if ajax_spider:
        max_duration = request.POST.get('maxDuration',5)
        in_scope = request.POST.get('inScope',"true") == 'true'
        sub_tree_only = request.POST.get('subTreeOnly',"true") == 'true'
        zap.zap_ajax_spider(target_url,max_duration,in_scope,sub_tree_only)

    accessiblity = zap.check_accessibility()

    if accessiblity:
        print("the given target is accessible from ZAP server . ")
        print("Running zap scan ...")
        if passive:
            zap.zap_pscan()
            time.sleep(3)

        """ ZAP Scan trigger on target_url  """
        if active:
            zap_scan_id = zap.zap_ascan()
            print("the active scan status is : ", zap_scan_id)
            zap.zap_scan_status(scan_id=zap_scan_id, un_scanid=scan_id)
            """ Save Vulnerability in database """
            time.sleep(5)

        all_vuln = zap.zap_scan_result(target_url=target_url)
        zap.zap_result_save(
            all_vuln=all_vuln,
            project_id=project_id,
            un_scanid=scan_id,
            target_url=target_url,
            request=request,
        )
        all_zap_scan = WebScansDb.objects.filter(
            scan_id=scan_id, scanner="Zap", organization=request.user.organization
        )
        print(len(all_zap_scan))

        total_vuln = ""
        total_high = ""
        total_medium = ""
        total_low = ""
        for data in all_zap_scan:
            total_vuln = data.total_vul
            total_high = data.high_vul
            total_medium = data.medium_vul
            total_low = data.low_vul

        if zap_enabled is False:
            zap.zap_shutdown()
        #
        notify.send(user, recipient=user, verb="ZAP Scan URL %s Completed" % target_url)

        subject = "Archery Tool Scan Status - ZAP Scan Completed"
        message = (
                "ZAP Scanner has completed the scan "
                "  %s <br> Total: %s <br>High: %s <br>"
                "Medium: %s <br>Low %s"
                % (target_url, total_vuln, total_high, total_medium, total_low)
        )
        print("the email message is : ", message)
        email_sch_notify(subject=subject, message=message)

    else :
        print("the target is not accessible through ZAP  ")




def launch_schudle_zap_scan(
    target_url, project_id, rescan_id, rescan, scan_id, request
):
    """
    The function Launch ZAP Scans.
    :param target_url: Target URL
    :param project_id: Project ID
    :return:
    """
    random_port = "8090"

    # Connection Test
    zap_connect = zap_plugin.zap_connect(random_port)

    try:
        zap_connect.spider.scan(url=target_url)

    except Exception:
        subject = "ZAP Connection Not Found"
        message = "ZAP Scanner failed due to setting not found "

        email_sch_notify(subject=subject, message=message)
        print("ZAP Connection Not Found")
        return HttpResponseRedirect(reverse("webscanners:index"))

    # Load ZAP Plugin
    zap = zap_plugin.ZAPScanner(
        target_url,
        project_id,
        rescan_id,
        rescan,
        random_port=random_port,
        request=request,
    )
    zap.exclude_url()
    time.sleep(3)
    zap.cookies()
    time.sleep(3)
    date_time = datetime.now()
    try:
        save_all_scan = WebScansDb(
            project_id=project_id,
            scan_url=target_url,
            scan_id=scan_id,
            date_time=date_time,
            rescan_id=rescan_id,
            rescan=rescan,
            scan_status="0",
            scanner="Zap",
            organization=request.user.organization,
        )

        save_all_scan.save()
    except Exception as e:
        print(e)
    zap.zap_spider_thread(thread_value=30)
    spider_id = zap.zap_spider()
    zap.spider_status(spider_id=spider_id)
    zap.spider_result(spider_id=spider_id)
    time.sleep(5)
    """ ZAP Scan trigger on target_url  """
    zap_scan_id = zap.zap_scan()
    zap.zap_scan_status(scan_id=zap_scan_id, un_scanid=scan_id)
    """ Save Vulnerability in database """
    time.sleep(5)
    all_vuln = zap.zap_scan_result(target_url=target_url)
    time.sleep(5)
    zap.zap_result_save(
        all_vuln=all_vuln,
        project_id=project_id,
        un_scanid=scan_id,
        target_url=target_url,
        request=request,
    )
    all_zap_scan = WebScansDb.objects.filter(
        scanner="zap", organization=request.user.organization
    )

    total_vuln = ""
    total_high = ""
    total_medium = ""
    total_low = ""
    for data in all_zap_scan:
        total_vuln = data.total_vul
        total_high = data.high_vul
        total_medium = data.medium_vul
        total_low = data.low_vul

    subject = "Archery Tool Scan Status - ZAP Scan Completed"
    message = (
        "ZAP Scanner has completed the scan "
        "  %s <br> Total: %s <br>High: %s <br>"
        "Medium: %s <br>Low %s"
        % (target_url, total_vuln, total_high, total_medium, total_low)
    )

    email_sch_notify(subject=subject, message=message)


class ZapScan(APIView):
    permission_classes = (IsAuthenticated, permissions.IsAnalyst)

    def post(self, request):
        scans_status = ""
        scan_id = ""
        project_uu_id = None
        target_url = None
        user = request.user

        if request.path[:4] == "/api":
            _url = None
            _project_id = None

            serializer = ZapScansSerializer(data=request.data)
            if serializer.is_valid():
                target_url = request.POST.get(
                    "url",
                )

                project_uu_id = request.POST.get(
                    "project_id",
                )
        else:
            target_url = request.POST.get("url")
            project_uu_id = request.POST.get("project_id")
        project_id = (
            ProjectDb.objects.filter(
                uu_id=project_uu_id, organization=request.user.organization
            )
            .values("id")
            .get()["id"]
        )
        rescan_id = None
        rescan = "No"
        target_item = str(target_url)
        value = target_item.replace(" ", "")
        target__split = value.split(",")
        split_length = target__split.__len__()
        for i in range(0, split_length):
            target = target__split.__getitem__(i)
            scan_id = uuid.uuid4()
            thread = threading.Thread(
                target=launch_zap_scan,
                args=(target, project_id, rescan_id, rescan, scan_id, user, request),
            )
            thread.daemon = True
            thread.start()
            time.sleep(10)
        if scans_status == "100": # weird !!
            scans_status = "0"
        else:
            if request.path[:4] == "/api":
                return Response({"scan_id": scan_id})
            return HttpResponse(status=200)

        if request.path[:4] == "/api":
            return Response({"scan_id": scan_id})
        else:
            return render(request, "webscanners/zapscanner/zap_scan_list.html")


class ZapSetting(APIView):
    permission_classes = (IsAuthenticated, permissions.IsAnalyst)

    def get(self, request):
        zap_api_key = ""
        zap_hosts = None
        zap_ports = None
        zap_enabled = False

        all_zap = ZapSettingsDb.objects.filter()
        for zap in all_zap:
            zap_api_key = zap.zap_api
            zap_hosts = zap.zap_url
            zap_ports = zap.zap_port
            zap_enabled = zap.enabled

        if zap_enabled:
            zap_enabled = "True"
        else:
            zap_enabled = "False"

        if request.path[:4] == "/api":
            return Response(
                {
                    "zap_api_key": zap_api_key,
                    "zap_hosts": zap_hosts,
                    "zap_ports": zap_ports,
                    "zap_enabled": zap_enabled,
                }
            )
        else:
            return render(
                request,
                "webscanners/zapscanner/zap_settings_form.html",
                {
                    "zap_apikey": zap_api_key,
                    "zap_host": zap_hosts,
                    "zap_port": zap_ports,
                    "zap_enabled": zap_enabled,
                },
            )


class ZapSettingUpdate(APIView):
    permission_classes = (IsAuthenticated, permissions.IsAnalyst)

    def get(self, request):
        return render(request, "webscanners/zapscanner/zap_settings_form.html")

    def post(self, request):
        zaphost = "NA"
        port = "NA"
        apikey = "NA"

        all_zap = ZapSettingsDb.objects.filter()
        all_zap.delete()

        all_zap_data = SettingsDb.objects.filter(setting_scanner="Zap")
        all_zap_data.delete()

        if request.POST.get("zap_enabled") == "on":
            zap_enabled = True
        else:
            zap_enabled = False

        if request.path[:4] == "/api":
            serializer = ZapSettingsSerializer(data=request.data)
            if serializer.is_valid():
                apikey = request.data.get(
                    "zap_api_key",
                )
                zaphost = request.data.get(
                    "zap_host",
                )
                port = request.data.get(
                    "zap_port",
                )
                zap_enabled = request.data.get(
                    "zap_enabled",
                )
        else:
            apikey = request.POST.get(
                "apikey",
            )
            zaphost = request.POST.get(
                "zappath",
            )
            port = request.POST.get(
                "port",
            )

        setting_id = uuid.uuid4()

        save_zap_data = SettingsDb(
            setting_id=setting_id,
            setting_scanner="Zap",
        )
        save_zap_data.save()

        save_data = ZapSettingsDb(
            setting_id=setting_id,
            zap_url=zaphost,
            zap_port=port,
            zap_api=apikey,
            enabled=zap_enabled,
        )
        save_data.save()

        if request.path[:4] == "/api":
            if zap_enabled is False:
                return Response({"message": "OWASP ZAP scanner updated!!!"})

        zap_enabled = False
        random_port = "8091"
        target_url = "https://archerysec.com"
        zap_info = ""

        all_zap = ZapSettingsDb.objects.filter()
        for zap in all_zap:
            zap_enabled = zap.enabled

        if zap_enabled is False:
            if request.path[:4] == "/api":
                return Response({"message": "OWASP ZAP Scanner Disabled"})
            zap_info = "Disabled"
            try:
                random_port = zap_plugin.zap_local()
            except:
                return render(
                    request, "setting/settings_page.html", {"zap_info": zap_info}
                )

            for i in range(0, 100):
                while True:
                    try:
                        # Connection Test
                        zap_connect = zap_plugin.zap_connect(random_port)
                        zap_connect.spider.scan(url=target_url)
                    except Exception as e:
                        print("ZAP Connection Not Found, re-try after 5 sec")
                        time.sleep(5)
                        continue
                    break
        else:
            try:
                zap_connect = zap_plugin.zap_connect(
                    random_port,
                )
                zap_connect.spider.scan(url=target_url)
                zap_info = True
                SettingsDb.objects.filter(setting_id=setting_id).update(
                    setting_status=zap_info
                )
                if request.path[:4] == "/api":
                    return Response({"message": "OWASP ZAP scanner updated!!!"})
            except:
                zap_info = False
                SettingsDb.objects.filter(setting_id=setting_id).update(
                    setting_status=zap_info
                )
                if request.path[:4] == "/api":
                    return Response({"message": "Not updated, Something Wrong !!!"})

        return HttpResponseRedirect(reverse("archerysettings:settings"))



# AF views

def fetch_af_plans(request):
    af_plans = AutomationPlan.objects.all().values('title', 'description')
    return JsonResponse({'af_plans': list(af_plans)})

def full_scan_content(request):
    data = {...}
    html_content = render_to_string('webscanners/zapscanner/zap_fullScan.html',{'data': data})
    return HttpResponse(html_content)
def script_section_content(request):
    data = {...}
    html_content = render_to_string('webscanners/zapscanner/zapScript.html', {'data': data})
    return HttpResponse(html_content)

def af_section_content(request):
    projects = ProjectDb.objects.all()
    af_plans = AutomationPlan.objects.all()
    html_content = render_to_string('webscanners/zapscanner/autoFramework.html', {
        'af_plans': af_plans,
        'projects': projects
    },request=request)
    return HttpResponse(html_content)

def save_plan(request):
    if request.method == 'POST':
        title = request.POST.get('planTitle')

        gitlab_repo = request.POST.get('gitlabRepo',None)
        gitlab_branch = request.POST.get('gitlabBranch',None)
        gitlab_file_name = request.POST.get('gitlabFileName',None)

        description = request.POST.get('planDescription')
        targetUrl = request.POST.get('targetUrl')

        project_id =  request.POST.get('project_uuid')
        project = ProjectDb.objects.get(uu_id=project_id)

        if gitlab_repo != "":
            print("the gitlab repo is : ",gitlab_repo)
            uploaded_file = upload_plan_gitlab(gitlab_repo,gitlab_branch,gitlab_file_name)
            print(uploaded_file)
            file_path = os.path.join("zap", gitlab_file_name)
            with open(file_path, 'w', encoding='utf-8') as destination:
                yaml.dump(uploaded_file, destination)
            file_name= gitlab_file_name
        elif 'fileUpload' in request.FILES:
            uploaded_file = request.FILES['fileUpload']
            file_name = uploaded_file.name
            save_directory = 'zap'
            file_path = os.path.join(save_directory, file_name)
            with open(file_path, 'wb+') as destination:
                for chunk in uploaded_file.chunks():
                    destination.write(chunk)

        try:
            destination = project.project_name + "/" + file_name
            zap_path = "/home/zap/.ZAP/transfer/" + destination

            # upload the file to zap file system
            file_path = os.path.join('zap/', file_name)
            with open(file_path, 'r') as file:
                uploaded_file = file.read()

            uploaded_file_yaml = yaml.safe_load(uploaded_file) # dict format
            context_name = uploaded_file_yaml.get("env", {}).get("contexts", [{}])[0].get("name", "")
            path = upload_file(destination, uploaded_file)

            plan = AutomationPlan(title=title,
                                  description=description,
                                  target=targetUrl,
                                  file_name=file_name,
                                  context = context_name,
                                  created_by=request.user,
                                  project_uuid=project_id,
                                  project_name=project.project_name,
                                  zap_path=zap_path
                                  )
            plan.save()
            request.session['redirected'] = True
            return HttpResponseRedirect(reverse('webscanners:dast_scans'))
        except Exception as e:
            print("Error occurred when uploading a file to owasp zap   :")
            print(e)
    return JsonResponse({'error': 'Invalid request method ( need post req ) '}, status=405)

def delete_plan(request):
    if request.method == 'POST':

            plans_id = request.POST.getlist('checked_plans')
            print(plans_id)
            print(len(plans_id))
            try :
                for plan_id in plans_id:

                    # plan_id = request.POST.get("plan_id")
                    # Retrieve the AutomationPlan object
                    plan = AutomationPlan.objects.get(uu_id=plan_id)

                    file_path = os.path.join('zap/', plan.file_name)
                    if os.path.exists(file_path):
                        os.remove(file_path)
                    else:
                        print("The file does not exist:", file_path)
                    plan.delete()
                request.session['redirected'] = True
                return JsonResponse({'redirect': True})

                # return HttpResponseRedirect(reverse('webscanners:dast_scans'))
            except AutomationPlan.DoesNotExist:
                    return JsonResponse({'error': 'The plan does not exist'}, status=404)
            except Exception as e:
                    return JsonResponse({'error': str(e)}, status=400)
    else:
        return JsonResponse({'error': 'Invalid request method'}, status=405)

def af_run(request):
    if request.method == 'POST':
        checked_plans = request.POST.getlist('checked_plans')
        group_id = request.POST.get('group_id')
        project_uu_id = request.POST.get('project_id')
        attack_type = request.POST.get('attack_type')
        project_id = ProjectDb.objects.get(uu_id=project_uu_id, organization=request.user.organization).id
        scan_id = uuid.uuid4()
        if attack_type == "Automation Framework":
            zap_af(request, checked_plans, project_id, scan_id)
            # thread = threading.Thread(
            #     target=zap_af,
            #     args=(request, checked_plans,project_id,scan_id
            #         ),
            # )
            # thread.daemon = True
            # thread.start()
        return HttpResponse(status=200)

class PlanRunFailed(Exception):
    pass


def zap_af(request, plans_id, project_id, scan_id):
    for plan_id in plans_id:
            plan = AutomationPlan.objects.get(uu_id=plan_id)
            file_path = plan.zap_path
            targetUrl = plan.target
            context_name = plan.context
            ## context
            plan_ran_id = run_af_plan(file_path, 10)
            if plan_ran_id is None:
                messages.warning(request, "Can't Run this plan : check zap connection")
                raise PlanRunFailed("Can't Run this plan : check zap connection")
            elif plan_ran_id == "does_not_exist":
                messages.warning(request, "Plan NOT FOUND in ZAP server : Re Upload the plan ")
                raise PlanRunFailed("Plan NOT FOUND in ZAP server  : Re Upload the plan")
            else:
                messages.success(request, "Plan is running ")
            thread = threading.Thread(
                target=running_plan,
                args=(project_id,targetUrl,request,plan_ran_id,context_name,scan_id
                    ),
            )
            thread.daemon = True
            thread.start()




def running_plan(project_id,targetUrl,request,plan_ran_id,context_name,scan_id):
                    try:
                        date_time = datetime.now()
                        save_all_scan = WebScansDb(
                            project_id=project_id,
                            scan_url=targetUrl,
                            scan_id=scan_id,
                            date_time=date_time,
                            rescan_id=None,
                            rescan="No",
                            scan_status="0",
                            scanner="Zap",
                            organization=request.user.organization,
                        )
                        save_all_scan.save()
                        # notify.send(request.user, recipient=user, verb="ZAP Scan URL %s Added" % target_url)
                    except Exception as e:
                        print(e)
                    print("the id of the ran plan is ", plan_ran_id)

                    plan_finished = zap_plugin.af_plan_progress(plan_ran_id)
                    if plan_finished == True:
                        # update the status
                        update_scan = WebScansDb.objects.get(scan_id=scan_id)
                        update_scan.scan_status = "100"
                        update_scan.save()

                        zap = zap_plugin.ZAPScanner(
                            targetUrl,
                            project_id,
                            None,
                            "No",
                            random_port=8090,
                            request=request,
                        )
                        zap.create_context(context_name)
                        all_vuln = zap.zap_scan_result(targetUrl)
                        zap.zap_result_save(all_vuln, project_id, scan_id, targetUrl, request)
                        print("Plan with ID "+plan_ran_id, "is Done")
