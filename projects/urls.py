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

from projects import views

app_name = "projects"

urlpatterns = [
    path("", views.get_projects, name="project_list"),
    path("project_scans/", views.project_scans, name="project_scans"),
    path("redirect_to_dast/", views.redirect_to_dast, name="redirect_to_dast"),

    # path("project_scans/dast-scan", views.dast_scan, name="dast_scan"),

    path("overview/", views.project_overview, name='project_overview'),

    # note router
    path("add-note/", views.add_note, name='add_note'),
    path("delete-note/", views.delete_note, name='delete_note'),

    # project members
    path("add-member/", views.add_member, name='add_member'),
    path("delete-member/", views.delete_member, name='delete_member'),

    path("project_metrics/", views.project_metrics, name='project_metrics'),
    path("project_vuln/", views.project_vuln, name='project_vuln'),

    path("project_create/", views.ProjectCreate.as_view(), name="project_create"),
    path("project_delete/", views.ProjectDelete.as_view(), name="project_delete"),
    path("project_edit/", views.project_edit, name="project_settings"),

]
