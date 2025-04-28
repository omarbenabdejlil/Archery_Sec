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

from webscanners.zapscanner import views

app_name = "zapscanner"

urlpatterns = [
    path('zap-script-get/', views.script_section_content, name='script_section_content'),

    path('zap-plan-delete/', views.delete_plan, name='delete_plan'),
    path('run-plan/', views.af_run, name='run_plan'),
    path('save-plan/', views.save_plan, name='save_plan'),
    path('fetch-af-plans/', views.fetch_af_plans, name='fetch_af_plans'),
    path('zap-af-get/', views.af_section_content, name='af_section_content'),





    path('fullscan/', views.full_scan_content, name='full_scan_content'),


    path("zap_scan/", views.ZapScan.as_view(), name="zap_scan"),
    path("zap_settings/", views.ZapSetting.as_view(), name="zap_settings"),
    path(
        "zap_setting_update/",
        views.ZapSettingUpdate.as_view(),
        name="zap_setting_update",
    ),
]
