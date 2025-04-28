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

# Copyright (C) 2024 Ahmed Aissa
# Email:   ahmed.aissa.ing@gmail.com
# linkedin: @ahmedaissa

# This file is part of ArcherySec Project.

import time
import uuid

import requests
from django.core import signing
from django.http import HttpResponseRedirect
from django.shortcuts import HttpResponse, render
from django.urls import reverse
from jira import JIRA
from notifications.models import Notification
from rest_framework.permissions import IsAuthenticated
from rest_framework.renderers import TemplateHTMLRenderer
from rest_framework.views import APIView

from archerysettings.models import ( EmailDb,
                                    SettingsDb,
                                    ZapSettingsDb)
from jiraticketing.models import jirasetting
from scanners.scanner_plugin.web_scanner import zap_plugin
from user_management import permissions
from utility.email_notify import email_sch_notify

from archerysettings.models import GitlabDb


class GitlabSetting(APIView):
    renderer_classes = [TemplateHTMLRenderer]
    template_name = "setting/gitlab_setting_form.html"
    permission_classes = (IsAuthenticated, permissions.IsAdmin)

    def get(self, request):
        gitlab = GitlabDb.objects.filter(organization=request.user.organization)
        if len(gitlab)>0:
            gitlab = gitlab[0]
            return render(
                request, "setting/gitlab_setting_form.html", {"gitlab": gitlab}
            )
        else:
            return render(
                request, "setting/gitlab_setting_form.html", {"gitlab": ""}
            )



    def post(self,request):
        gitlab = GitlabDb.objects.filter(organization=request.user.organization)

        gitlab_setting_data = SettingsDb.objects.filter(
            setting_scanner="Gitlab", organization=request.user.organization
        )

        gitlab_username = request.POST.get("gitlab_username")
        gitlab_url = request.POST.get("gitlab_url")
        gitlab_api = request.POST.get("gitlab_api")
        gitlab_repo = request.POST.get("gitlab_repo")

        gitlab.delete()
        gitlab_setting_data.delete()
        setting_id = uuid.uuid4()

        save_gitlab = GitlabDb(
            gitlab_username=gitlab_username,
            gitlab_url=gitlab_url,
            gitlab_api=gitlab_api,
            setting_id=setting_id,
            gitlab_repo = gitlab_repo,
            organization=request.user.organization,
        )
        save_gitlab.save()

        if gitlab_test(gitlab_username,gitlab_url,gitlab_api,gitlab_repo):
            setting_status = True
        else :
            setting_status = False
        # if test oki :
        setting_id = uuid.uuid4()
        gitlab_setting = SettingsDb(
            setting_id=setting_id,
            setting_scanner="Gitlab",
            setting_status=setting_status,
            organization=request.user.organization,
        )
        gitlab_setting.save()
        return HttpResponseRedirect(reverse("archerysettings:settings"))



class EmailSetting(APIView):
    renderer_classes = [TemplateHTMLRenderer]
    template_name = "setting/email_setting_form.html"

    permission_classes = (IsAuthenticated, permissions.IsAdmin)

    def get(self, request):
        all_email = EmailDb.objects.filter(organization=request.user.organization)
        return render(
            request, "setting/email_setting_form.html", {"all_email": all_email}
        )

    def post(self, request):
        all_email = EmailDb.objects.filter(organization=request.user.organization)

        email_setting_data = SettingsDb.objects.filter(
            setting_scanner="Email", organization=request.user.organization
        )

        subject = request.POST.get("email_subject")
        from_message = request.POST.get("email_message")
        email_to = request.POST.get("to_email")

        all_email.delete()
        email_setting_data.delete()

        setting_id = uuid.uuid4()

        save_email = EmailDb(
            subject=subject,
            message=from_message,
            recipient_list=email_to,
            setting_id=setting_id,
            organization=request.user.organization,
        )
        save_email.save()

        subject_test = "test"
        message = "test"

        email = email_sch_notify(subject=subject_test, message=message)

        if email is False:
            setting_status = False
        else:
            setting_status = True

        save_setting_info = SettingsDb(
            setting_id=setting_id,
            setting_scanner="Email",
            setting_status=setting_status,
            organization=request.user.organization,
        )
        save_setting_info.save()
        return HttpResponseRedirect(reverse("archerysettings:settings"))


class DeleteSettings(APIView):
    renderer_classes = [TemplateHTMLRenderer]

    permission_classes = (IsAuthenticated, permissions.IsAdmin)

    def post(self, request):
        setting_id = request.POST.get("setting_id")
        tool = request.POST.get("tool")

        if tool =="Gitlab":
            delete_dat = GitlabDb.objects.filter(
                organization=request.user.organization
            )
            delete_dat.delete()
        delete_dat = SettingsDb.objects.filter(
            setting_id=setting_id, organization=request.user.organization
        )
        delete_dat.delete()
        return HttpResponseRedirect(reverse("archerysettings:settings"))


class Settings(APIView):
    renderer_classes = [TemplateHTMLRenderer]
    template_name = "setting/settings_page.html"

    permission_classes = (IsAuthenticated, permissions.IsAdmin)

    def get(self, request):
        all_notify = Notification.objects.unread()

        all_settings_data = SettingsDb.objects.filter(
            organization=request.user.organization
        )

        return render(
            request,
            "setting/settings_page.html",
            {"all_settings_data": all_settings_data, "all_notify": all_notify},
        )

    def post(self, request):
        all_notify = Notification.objects.unread()

        jira_url = None
        j_username = None
        password = None
        # Loading settings

        all_settings_data = SettingsDb.objects.filter(
            organization=request.user.organization
        )


        all_zap = ZapSettingsDb.objects.filter(organization=request.user.organization)
        jira_setting = jirasetting.objects.filter(
            organization=request.user.organization
        )

        for jira in jira_setting:
            jira_url = jira.jira_server
            j_username = jira.jira_username
            password = jira.jira_password
        jira_server = jira_url
        if j_username is None:
            jira_username = None
        else:
            jira_username = signing.loads(j_username)

        if password is None:
            jira_password = None
        else:
            jira_password = signing.loads(password)

        zap_enabled = False
        random_port = "8091"
        target_url = "https://archerysec.com"

        setting_of = request.POST.get("setting_of")
        setting_id = request.POST.get("setting_id")
        if setting_of == "zap":
            all_zap = ZapSettingsDb.objects.filter(
                organization=request.user.organization
            )
            for zap in all_zap:
                zap_enabled = zap.enabled

            if zap_enabled is False:
                zap_info = "Disabled"
                try:
                    random_port = zap_plugin.zap_local()
                except Exception:
                    return render(
                        request, "setting/settings_page.html", {"zap_info": zap_info}
                    )

                for i in range(0, 100):
                    while True:
                        try:
                            # Connection Test
                            zap_connect = zap_plugin.zap_connect(random_port)
                            zap_connect.spider.scan(url=target_url)
                        except Exception:
                            print("ZAP Connection Not Found, re-try after 5 sec")
                            time.sleep(5)
                            continue
                        break
            else:
                try:
                    zap_connect = zap_plugin.zap_connect(random_port)
                    zap_connect.spider.scan(url=target_url)
                    zap_info = True
                    SettingsDb.objects.filter(
                        setting_id=setting_id, organization=request.user.organization
                    ).update(setting_status=zap_info)
                except Exception:
                    zap_info = False
                    SettingsDb.objects.filter(
                        setting_id=setting_id, organization=request.user.organization
                    ).update(setting_status=zap_info)

        if setting_of == "jira":
            global jira_projects, jira_ser
            jira_setting = jirasetting.objects.filter(
                organization=request.user.organization
            )

            for jira in jira_setting:
                jira_url = jira.jira_server
                username = jira.jira_username
                password = jira.jira_password

                if jira_url is None:
                    print("No jira url found")

            try:
                jira_server = jira_url
                jira_username = signing.loads(username)
                jira_password = signing.loads(password)
            except Exception:
                jira_info = False

            options = {"server": jira_server}
            try:
                if jira_username is not None and jira_username != "":
                    jira_ser = JIRA(
                        options, basic_auth=(jira_username, jira_password), timeout=5
                    )
                else:
                    jira_ser = JIRA(options, token_auth=jira_password, timeout=5)

                jira_projects = jira_ser.projects()
                print(len(jira_projects))
                jira_info = True
                SettingsDb.objects.filter(
                    setting_id=setting_id, organization=request.user.organization
                ).update(setting_status=jira_info)
            except Exception as e:
                print(e)
                jira_info = False
                SettingsDb.objects.filter(
                    setting_id=setting_id, organization=request.user.organization
                ).update(setting_status=jira_info)

        if setting_of == "gitlab":

            gitlab_setting = GitlabDb.objects.filter(
                organization=request.user.organization
            )

            for gitlab in gitlab_setting:
                gitlab_url = gitlab.gitlab_url
                gitlab_username = gitlab.gitlab_username
                gitlab_api = gitlab.gitlab_api
                gitlab_repo = gitlab.gitlab_repo

            SettingsDb.objects.filter(
                setting_id=setting_id, organization=request.user.organization
            ).update(setting_status=gitlab_test(gitlab_username,gitlab_url,gitlab_api,gitlab_repo))

        return render(
            request,
            "setting/settings_page.html",
            {"all_settings_data": all_settings_data, "all_notify": all_notify},
        )


def gitlab_test(gitlab_username,gitlab_url,private_token,gitlab_repo):
        gitlab_url = "https://gitlab.com/api/v4/projects"
        encoded_project_path = f"{gitlab_username}/{gitlab_repo}".replace("/", "%2F")

        project_url = f"https://gitlab.com/api/v4/projects/{encoded_project_path}?private_token={private_token}"

        response = requests.get(project_url)

        if response.status_code == 200:
            return True
        else:
            print(f"Failed to connect to Gitlab Repo with status code {response.status_code}")
            return False