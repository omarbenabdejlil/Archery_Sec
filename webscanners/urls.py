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

from django.urls import include, path

from webscanners import views, web_views

app_name = "webscanners"

urlpatterns = [
    path("", web_views.Dast_scans.as_view(), name="index"),
    path("dast/", web_views.Dast_scans.as_view(), name="dast_scans"),
    path("schedule-fullscan/", web_views.launch_schedule_zapfullscan_data, name="launch_schedule_zapfullscan"),
    path("del-schedule-scan/", web_views.delete_schedule, name="del_schedule_scan"),

    path("dast-config/", web_views.dast, name="dast"),

    path("del_notify/", web_views.DeleteNotify.as_view(), name="del_notify"),
    path("del_all_notify/", web_views.DeleteAllNotify.as_view(), name="del_all_notify"),
    # Dynamic scans
    path("list_vuln/", views.WebScanVulnList.as_view(), name="list_vuln"),
    path("list_scans/", views.WebScanList.as_view(), name="list_scans"),
    path("list_vuln_info/", views.WebScanVulnInfo.as_view(), name="list_vuln_info"),
    path("scan_details/", views.WebScanDetails.as_view(), name="scan_details"),
    path("scan_delete/", views.WebScanDelete.as_view(), name="scan_delete"),
    path("vuln_delete/", views.WebScanVulnDelete.as_view(), name="vuln_delete"),
    path("vuln_mark/", views.WebScanVulnMark.as_view(), name="vuln_mark"),
]
