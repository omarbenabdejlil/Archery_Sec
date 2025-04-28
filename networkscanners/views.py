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
""" Author: Anand Tiwari """

from __future__ import unicode_literals

import hashlib
import os

from django.conf import settings
from django.core import signing
from django.core.mail import send_mail
from django.http import HttpResponseRedirect
from django.shortcuts import HttpResponse, render
from django.urls import reverse
from jira import JIRA
from notifications.models import Notification
from notifications.signals import notify
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.renderers import TemplateHTMLRenderer
from rest_framework.response import Response
from rest_framework.views import APIView

from archerysettings.models import EmailDb, SettingsDb
from jiraticketing.models import jirasetting
from networkscanners.models import (NetworkScanDb, NetworkScanResultsDb,
                                    TaskScheduleDb)
from networkscanners.serializers import (NetworkScanDbSerializer,
                                         NetworkScanResultsDbSerializer,
                                         )
from projects.models import ProjectDb

from user_management import permissions

api_data = os.getcwd() + "/" + "apidata.json"

# status = ""
name = ""
creation_time = ""
modification_time = ""
host = ""
port = ""
threat = ""
severity = ""
description = ""
page = ""
family = ""
cvss_base = ""
cve = ""
bid = ""
xref = ""
tags = ""
banner = ""


def email_notify(user, subject, message):
    to_mail = ""
    all_email = EmailDb.objects.all()
    for email in all_email:
        to_mail = email.recipient_list

    email_from = settings.EMAIL_HOST_USER
    recipient_list = [to_mail]
    try:
        send_mail(subject, message, email_from, recipient_list)
    except Exception:
        notify.send(user, recipient=user, verb="Email Settings Not Configured")
        pass


class NetworkScanList(APIView):
    permission_classes = [IsAuthenticated | permissions.VerifyAPIKey]

    def get(self, request):
        scan_list = NetworkScanDb.objects.filter(organization=request.user.organization)
        all_notify = Notification.objects.unread()
        if request.path[:4] == "/api":
            serialized_data = NetworkScanDbSerializer(scan_list, many=True)
            return Response(serialized_data.data)
        else:
            return render(
                request,
                "networkscanners/scans/list_scans.html",
                {"all_scans": scan_list, "message": all_notify},
            )


class NetworkScanVulnInfo(APIView):
    permission_classes = [IsAuthenticated | permissions.VerifyAPIKey]

    def get(self, request, uu_id=None):
        jira_url = None
        jira = jirasetting.objects.filter(organization=request.user.organization)
        for d in jira:
            jira_url = d.jira_server
        if uu_id is None:
            scan_id = request.GET["scan_id"]
            ip = request.GET["ip"]
            vuln_data = NetworkScanResultsDb.objects.filter(
                scan_id=scan_id, ip=ip, organization=request.user.organization
            )
        else:
            try:
                vuln_data = NetworkScanResultsDb.objects.filter(
                    scan_id=uu_id, organization=request.user.organization
                )
            except Exception:
                return Response(
                    {"message": "Scan Id Doesn't Exist"},
                    status=status.HTTP_404_NOT_FOUND,
                )
        if request.path[:4] == "/api":
            serialized_data = NetworkScanResultsDbSerializer(vuln_data, many=True)
            return Response(serialized_data.data)
        else:
            return render(
                request,
                "networkscanners/scans/list_vuln_info.html",
                {"vuln_data": vuln_data, "jira_url": jira_url},
            )


class NetworkScanVulnMark(APIView):
    renderer_classes = [TemplateHTMLRenderer]
    template_name = "networkscanners/scans/list_vuln_info.html"

    permission_classes = (IsAuthenticated, permissions.IsAnalyst)

    def post(self, request):
        false_positive = request.POST.get("false")
        status = request.POST.get("status")
        vuln_id = request.POST.get("vuln_id")
        scan_id = request.POST.get("scan_id")
        scanner = request.POST.get("scanner")
        ip = request.POST.get("ip")
        notes = request.POST.get("note")
        NetworkScanResultsDb.objects.filter(
            vuln_id=vuln_id,
            scan_id=scan_id,
            scanner=scanner,
            organization=request.user.organization,
        ).update(false_positive=false_positive, vuln_status=status, note=notes)

        if false_positive == "Yes":
            vuln_info = NetworkScanResultsDb.objects.filter(
                scan_id=scan_id,
                vuln_id=vuln_id,
                scanner=scanner,
                organization=request.user.organization,
            )
            for vi in vuln_info:
                name = vi.title
                url = vi.ip
                severity = vi.severity
                dup_data = name + url + severity
                false_positive_hash = hashlib.sha256(
                    dup_data.encode("utf-8")
                ).hexdigest()
                NetworkScanResultsDb.objects.filter(
                    vuln_id=vuln_id,
                    scan_id=scan_id,
                    scanner=scanner,
                    organization=request.user.organization,
                ).update(
                    false_positive=false_positive,
                    vuln_status="Closed",
                    false_positive_hash=false_positive_hash,
                    note=notes,
                )

        all_vuln = NetworkScanResultsDb.objects.filter(
            scan_id=scan_id,
            false_positive="No",
            vuln_status="Open",
            scanner=scanner,
            organization=request.user.organization,
        )

        total_critical= len(all_vuln.filter(severity="Critical"))
        total_high = len(all_vuln.filter(severity="High"))
        total_medium = len(all_vuln.filter(severity="Medium"))
        total_low = len(all_vuln.filter(severity="Low"))
        total_info = len(all_vuln.filter(severity="Informational"))
        total_dup = len(all_vuln.filter(vuln_duplicate="Yes"))
        total_vul = total_high + total_medium + total_low + total_info + total_critical

        NetworkScanDb.objects.filter(
            scan_id=scan_id, scanner=scanner, organization=request.user.organization
        ).update(
            total_vul=total_vul,
            critical_vul=total_critical,
            high_vul=total_high,
            medium_vul=total_medium,
            low_vul=total_low,
            info_vul=total_info,
            total_dup=total_dup,
        )
        return HttpResponseRedirect(
            reverse("networkscanners:list_vuln_info")
            + "?scan_id=%s&ip=%s&scanner=%s" % (scan_id, ip, scanner)
        )


class NetworkScanDetails(APIView):
    enderer_classes = [TemplateHTMLRenderer]
    template_name = "networkscanners/scans/vuln_details.html"

    permission_classes = (IsAuthenticated,)

    def get(self, request):
        jira_server = None
        jira_username = None
        jira_password = None
        jira_projects = None
        vuln_id = request.GET["vuln_id"]
        scanner = request.GET["scanner"]
        jira_setting = jirasetting.objects.filter(
            organization=request.user.organization
        )
        # user = request.user

        for jira in jira_setting:
            jira_server = jira.jira_server
            jira_username = jira.jira_username
            jira_password = jira.jira_password

        if jira_username is not None:
            jira_username = signing.loads(jira_username)

        if jira_password is not None:
            jira_password = signing.loads(jira_password)

        options = {"server": jira_server}
        try:
            if jira_username is not None and jira_username != "":
                jira_ser = JIRA(
                    options,
                    basic_auth=(jira_username, jira_password),
                    max_retries=0,
                    timeout=30,
                )
            else:
                jira_ser = JIRA(
                    options, token_auth=jira_password, max_retries=0, timeout=30
                )
            jira_projects = jira_ser.projects()
        except Exception as e:
            print(e)
            jira_projects = None
            # notify.send(user, recipient=user, verb="Jira settings not found")

        vul_dat = NetworkScanResultsDb.objects.filter(
            vuln_id=vuln_id, scanner=scanner, organization=request.user.organization
        ).order_by("vuln_id")

        return render(
            request,
            "networkscanners/scans/vuln_details.html",
            {"vul_dat": vul_dat, "jira_projects": jira_projects},
        )


class NetworkScanDelete(APIView):
    renderer_classes = [TemplateHTMLRenderer]
    template_name = "networkscanners/scans/list_scans.html"

    permission_classes = (
        IsAuthenticated,
        permissions.IsAnalyst,
    )

    def post(self, request):
        scan_id = request.POST.get("scan_id")

        scan_item = str(scan_id)
        value = scan_item.replace(" ", "")
        value_split = value.split(",")
        split_length = value_split.__len__()
        # print "split_length", split_length
        for i in range(0, split_length):
            scan_id = value_split.__getitem__(i)

            item = NetworkScanDb.objects.filter(
                scan_id=scan_id, organization=request.user.organization
            )
            item.delete()
            item_results = NetworkScanResultsDb.objects.filter(
                scan_id=scan_id, organization=request.user.organization
            )
            item_results.delete()
        return HttpResponseRedirect(reverse("networkscanners:list_scans"))


class NetworkScanVulnDelete(APIView):
    renderer_classes = [TemplateHTMLRenderer]
    template_name = "networkscanners/scans/list_vuln_info.html"

    permission_classes = (IsAuthenticated, permissions.IsAnalyst)

    def post(self, request):
        vuln_id = request.POST.get("vuln_id")
        scan_id = request.POST.get("scan_id")
        scan_item = str(vuln_id)
        value = scan_item.replace(" ", "")
        value_split = value.split(",")
        split_length = value_split.__len__()
        # print "split_length", split_length
        for i in range(0, split_length):
            vuln_id = value_split.__getitem__(i)
            delete_vuln = NetworkScanResultsDb.objects.filter(
                vuln_id=vuln_id, organization=request.user.organization
            )
            delete_vuln.delete()
        all_vuln = (
            NetworkScanResultsDb.objects.filter(
                scan_id=scan_id, organization=request.user.organization
            )
            .exclude(severity="Information")
            .exclude(severity="Log")
        )

        total_vul = len(all_vuln)
        total_critical = len(all_vuln.filter(severity="Critical"))
        total_high = len(all_vuln.filter(severity="High"))
        total_medium = len(all_vuln.filter(severity="Medium"))
        total_low = len(all_vuln.filter(severity="Low"))
        # total_info = len(all_vuln.filter(severity="Information"))

        NetworkScanDb.objects.filter(scan_id=scan_id).update(
            total_vul=total_vul,
            critical_vul=total_critical,
            high_vul=total_high,
            medium_vul=total_medium,
            low_vul=total_low,
            organization=request.user.organization
            # info_vul=total_info,
        )
        return HttpResponseRedirect(reverse("networkscanners:list_scans"))
