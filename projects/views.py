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

import datetime
from itertools import chain

from cloudscanners.models import CloudScansDb, CloudScansResultsDb
from compliance.models import InspecScanDb, DockleScanDb
from dashboard.scans_data import scans_query
from django.contrib import messages
from django.shortcuts import HttpResponseRedirect, render, redirect
from django.urls import reverse
from groups.models import GroupDb
from networkscanners.models import NetworkScanDb, NetworkScanResultsDb
from notifications.models import Notification
from pentest.models import PentestScanDb, PentestScanResultsDb
from projects.models import MonthDb, ProjectDb
from projects.serializers import (ProjectCreateSerializers,
                                  ProjectDataSerializers)
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.renderers import TemplateHTMLRenderer
from rest_framework.response import Response
from rest_framework.views import APIView
from staticscanners.models import StaticScansDb, StaticScanResultsDb
from user_management import permissions
from user_management.models import Organization
from webscanners.models import WebScansDb, WebScanResultsDb

from projects.models import Note

from networkscanners.models import TaskScheduleDb

from projects.models import Member

project_dat = None


def project_edit(request):
    """
    :param request:
    :return:
    """
    global project_dat
    if request.method == "GET":
        project_uu_id = request.GET["uu_id"]

        project_dat = ProjectDb.objects.get(
            uu_id=project_uu_id,
            organization=request.user.organization,
        )
        groups = GroupDb.objects.all()
        priorities = ["high","medium","low"]
        return render(request,
                      'projects/settings.html',
                      {
                          "project_dat": project_dat,
                          "groups": groups,
                          "priorities": priorities
                      })
    if request.method == "POST":
        project_uuid = request.POST.get("project_uuid")
        project_name = request.POST.get("project_name")
        project_disc = request.POST.get("project_disc")
        project_group_uuid = request.POST.get("group")
        project_priority = request.POST.get("priority")
        member_name= request.POST.get("member_name","")
        if member_name != "":
            member_role = request.POST.get("member_role")
            member_team = request.POST.get("member_team")



        ProjectDb.objects.filter(uu_id=project_uuid).update(
            project_name=project_name,
            project_disc=project_disc,
            group=GroupDb.objects.get(uu_id=project_group_uuid),
            priority=project_priority,
        )
        messages.success(request, "Project updated")

        return redirect(reverse("projects:project_overview") + f"?uu_id={project_uuid}")




def get_projects(request):
    global all_projects
    all_project = ProjectDb.objects.filter(organization=request.user.organization)
    all_notify = Notification.objects.unread()
    return render(
        request,
        "projects/project_list.html",
        {"all_project": all_project, "message": all_notify},
    )


# def project_data(request):
#     """
#     this function is for displaying details about a project
#     """
#     if request.GET["uu_id"]:
#         uu_id = request.GET["uu_id"]
#     else:
#         # create error page to be rendred when no uuid found in request parameters
#         uu_id = ""
#     project_dat = ProjectDb.objects.get(
#         uu_id=uu_id, organization=request.user.organization
#     )
#
#     return  render(request,"projects/project_data.html",{'project_dat':project_dat})


def project_overview(request):
    if request.GET["uu_id"]:
        uu_id = request.GET["uu_id"]
    else:
        uu_id = ""
    project_dat = ProjectDb.objects.get(
        uu_id=uu_id, organization=request.user.organization
    )
    notes = Note.objects.filter(project_uuid=uu_id)
    members = Member.objects.filter(project_uuid=uu_id)
    all_critical = scans_query.all_vuln(project_id=uu_id, query="critical")
    all_high = scans_query.all_vuln(project_id=uu_id, query="high")
    all_medium = scans_query.all_vuln(project_id=uu_id, query="medium")
    all_low = scans_query.all_vuln(project_id=uu_id, query="low")
    all_closed_vuln = scans_query.all_vuln_count_data(uu_id, query="Closed")
    total = all_critical, all_high, all_medium, all_low
    total_vuln = sum(total)
    scanners=scans_query.all_scanners(project_id=uu_id)
    last_scan_date=scans_query.last_scan_date(project_id=uu_id)
    return render(
        request,
        "projects/project_overview.html",
        {
            'project_dat': project_dat,
            'all_critical': all_critical,
            'all_high': all_high,
            'all_medium': all_medium,
            'all_low': all_low,
            'all_closed_vuln': all_closed_vuln,
            'total_vuln': total_vuln,
            'scanners': scanners,
            'notes': notes,
            'members': members,
            'last_scan_date':last_scan_date
        })


def project_scans(request):
    if request.method == "GET":
        uu_id = request.GET["uu_id"]
    else:
        uu_id = ""

    project_dat = ProjectDb.objects.get(
        uu_id=uu_id, organization=request.user.organization
    )
    all_scheduled_scans = TaskScheduleDb.objects.filter(project_id=uu_id)
    web_scan_dat = WebScansDb.objects.filter(
        project__uu_id=uu_id, organization=request.user.organization
    )
    static_scan = StaticScansDb.objects.filter(
        project__uu_id=uu_id, organization=request.user.organization
    )
    cloud_scan = CloudScansDb.objects.filter(
        project__uu_id=uu_id, organization=request.user.organization
    )
    network_dat = NetworkScanDb.objects.filter(
        project__uu_id=uu_id, organization=request.user.organization
    )
    inspec_dat = InspecScanDb.objects.filter(
        project__uu_id=uu_id, organization=request.user.organization
    )
    dockle_dat = DockleScanDb.objects.filter(
        project__uu_id=uu_id, organization=request.user.organization
    )
    compliance_dat = chain(inspec_dat, dockle_dat)
    all_comp_inspec = InspecScanDb.objects.filter(
        project__uu_id=uu_id, organization=request.user.organization
    )

    all_comp_dockle = InspecScanDb.objects.filter(
        project__uu_id=uu_id, organization=request.user.organization
    )

    all_compliance_seg = chain(all_comp_inspec, all_comp_dockle)

    pentest = PentestScanDb.objects.filter(
        project__uu_id=uu_id, organization=request.user.organization
    )
    all_notify = Notification.objects.unread()

    return render(
        request,
        "projects/project_scans.html", {
            'project_dat': project_dat,
            "web_scan_dat": web_scan_dat,
            "static_scan": static_scan,
            "cloud_scan": cloud_scan,
            "pentest": pentest,
            "network_dat": network_dat,
            "all_compliance": all_compliance_seg,
            "compliance_dat": compliance_dat,
            "inspec_dat": inspec_dat,
            "dockle_dat": dockle_dat,
            "all_scheduled_scans":all_scheduled_scans,
            "message": all_notify,
        },
    )


def redirect_to_dast(request):
    if request.POST['project_uuid'] and request.POST['group_uuid']:
        request.session['redirected_to_dast_scan'] = True
        request.session['project_uuid'] = request.POST['project_uuid']
        request.session['group_uuid'] = request.POST['group_uuid']
    return HttpResponseRedirect(reverse('webscanners:dast_scans'))


def project_metrics(request):
    if request.GET["uu_id"]:
        uu_id = request.GET["uu_id"]
    else:
        # create error page to be rendred when no uuid found in request parameters
        uu_id = ""
    project_dat = ProjectDb.objects.get(
        uu_id=uu_id, organization=request.user.organization
    )

    web_scan_dat = WebScansDb.objects.filter(
        project__uu_id=uu_id, organization=request.user.organization
    )
    static_scan = StaticScansDb.objects.filter(
        project__uu_id=uu_id, organization=request.user.organization
    )
    cloud_scan = CloudScansDb.objects.filter(
        project__uu_id=uu_id, organization=request.user.organization
    )
    network_dat = NetworkScanDb.objects.filter(
        project__uu_id=uu_id, organization=request.user.organization
    )
    inspec_dat = InspecScanDb.objects.filter(
        project__uu_id=uu_id, organization=request.user.organization
    )
    dockle_dat = DockleScanDb.objects.filter(
        project__uu_id=uu_id, organization=request.user.organization
    )
    compliance_dat = chain(inspec_dat, dockle_dat)
    all_comp_inspec = InspecScanDb.objects.filter(
        project__uu_id=uu_id, organization=request.user.organization
    )

    all_comp_dockle = InspecScanDb.objects.filter(
        project__uu_id=uu_id, organization=request.user.organization
    )

    all_compliance_seg = chain(all_comp_inspec, all_comp_dockle)

    pentest = PentestScanDb.objects.filter(
        project__uu_id=uu_id, organization=request.user.organization
    )

    all_notify = Notification.objects.unread()

    all_critical = scans_query.all_vuln(project_id=uu_id, query="critical")
    all_high = scans_query.all_vuln(project_id=uu_id, query="high")
    all_medium = scans_query.all_vuln(project_id=uu_id, query="medium")
    all_low = scans_query.all_vuln(project_id=uu_id, query="low")

    total = all_critical, all_high, all_medium, all_low

    total_vuln = sum(total)

    return render(
        request, 'projects/project_metric.html',
        {
            'project_dat': project_dat,
            "project_id": uu_id,
            "total_vuln": total_vuln,
            "all_vuln": scans_query.all_vuln(project_id=uu_id, query="total"),
            "total_web": scans_query.all_web(project_id=uu_id, query="total"),
            "total_static": scans_query.all_static(project_id=uu_id, query="total"),
            "total_cloud": scans_query.all_cloud(project_id=uu_id, query="total"),
            "total_network": scans_query.all_net(project_id=uu_id, query="total"),
            "all_critical": all_critical,
            "all_high": all_high,
            "all_medium": all_medium,
            "all_low": all_low,
            "all_web_critical": scans_query.all_web(project_id=uu_id, query="critical"),
            "all_web_high": scans_query.all_web(project_id=uu_id, query="high"),
            "all_web_medium": scans_query.all_web(project_id=uu_id, query="medium"),
            "all_network_medium": scans_query.all_net(project_id=uu_id, query="medium"),
            "all_network_critical": scans_query.all_net(
                project_id=uu_id, query="critical"
            ),
            "all_network_high": scans_query.all_net(project_id=uu_id, query="high"),
            "all_web_low": scans_query.all_web(project_id=uu_id, query="low"),
            "all_network_low": scans_query.all_net(project_id=uu_id, query="low"),
            "all_static_critical": scans_query.all_static(
                project_id=uu_id, query="critical"
            ),
            "all_static_high": scans_query.all_static(project_id=uu_id, query="high"),
            "all_static_medium": scans_query.all_static(
                project_id=uu_id, query="medium"
            ),
            "all_static_low": scans_query.all_static(project_id=uu_id, query="low"),
            "all_cloud_critical": scans_query.all_cloud(
                project_id=uu_id, query="critical"
            ),
            "all_cloud_high": scans_query.all_cloud(project_id=uu_id, query="high"),
            "all_cloud_medium": scans_query.all_cloud(project_id=uu_id, query="medium"),
            "all_cloud_low": scans_query.all_cloud(project_id=uu_id, query="low"),
            "all_compliance_failed": scans_query.all_compliance(
                project_id=uu_id, query="failed"
            ),
            "all_compliance_passed": scans_query.all_compliance(
                project_id=uu_id, query="passed"
            ),
            "all_compliance_skipped": scans_query.all_compliance(
                project_id=uu_id, query="skipped"
            ),
            "total_compliance": scans_query.all_compliance(
                project_id=uu_id, query="total"
            ),
            "all_closed_vuln": scans_query.all_vuln_count_data(uu_id, query="Closed"),
            "all_false_positive": scans_query.all_vuln_count_data(uu_id, query="false"),
            "message": all_notify,
        },
    )




def project_vuln(request):
    if request.GET["uu_id"]:
        uu_id = request.GET["uu_id"]
    else:
        # create error page to be rendred when no uuid found in request parameters
        uu_id = ""
    project_dat = ProjectDb.objects.get(
        uu_id=uu_id, organization=request.user.organization
    )
    web_all_high = ""
    sast_all_high = ""
    cloud_all_high = ""
    net_all_high = ""
    pentest_all_high = ""

    all_notify = Notification.objects.unread()
    if request.GET["uu_id"]:
        project_uu_id = request.GET["uu_id"]
        severity = request.GET["severity"]
        if project_uu_id == "none":
            project_id = ""
        else:
            project_id = (
                ProjectDb.objects.filter(
                    uu_id=project_uu_id, organization=request.user.organization
                )
                .values("id")
                .get()["id"]
            )
    else:
        project_id = ""
        severity = ""

    if severity == "All_Closed":
        web_all_high = WebScanResultsDb.objects.filter(
            vuln_status="Closed" ,project_id=project_id, organization=request.user.organization
        )
        sast_all_high = StaticScanResultsDb.objects.filter(
            vuln_status="Closed", organization=request.user.organization , project_id=project_id

        )
        cloud_all_high = CloudScansResultsDb.objects.filter(
            vuln_status="Closed", organization=request.user.organization , project_id=project_id
        )
        net_all_high = NetworkScanResultsDb.objects.filter(
            vuln_status="Closed", organization=request.user.organization , project_id=project_id
        )
        pentest_all_high = PentestScanResultsDb.objects.filter(
            organization=request.user.organization , project_id=project_id
        )

    # add your scanner name here <scannername>
    elif severity == "All_False_Positive":
        web_all_high = WebScanResultsDb.objects.filter(
            false_positive="Yes", organization=request.user.organization, project_id=project_id
        )
        sast_all_high = StaticScanResultsDb.objects.filter(
            false_positive="Yes", organization=request.user.organization, project_id=project_id
        )
        cloud_all_high = CloudScansResultsDb.objects.filter(
            false_positive="Yes", organization=request.user.organization, project_id=project_id
        )
        net_all_high = NetworkScanResultsDb.objects.filter(
            false_positive="Yes", organization=request.user.organization, project_id=project_id
        )
        pentest_all_high = PentestScanResultsDb.objects.filter(
            organization=request.user.organization , project_id=project_id
        )

    elif severity == "Network":
        net_all_high = NetworkScanResultsDb.objects.filter(
            false_positive="No", organization=request.user.organization , project_id=project_id
        )

    elif severity == "Web":
        web_all_high = WebScanResultsDb.objects.filter(
            false_positive="No", organization=request.user.organization, project_id=project_id
        )
        pentest_all_high = PentestScanResultsDb.objects.filter(
            pentest_type="web", organization=request.user.organization, project_id=project_id
        )

    # add your scanner name here <scannername>
    elif severity == "Static":
        sast_all_high = StaticScanResultsDb.objects.filter(
            false_positive="No", organization=request.user.organization, project_id=project_id
        )
        pentest_all_high = PentestScanResultsDb.objects.filter(
            pentest_type="static", organization=request.user.organization, project_id=project_id
        )

    elif severity == "Cloud":
        cloud_all_high = CloudScansResultsDb.objects.filter(
            false_positive="No", organization=request.user.organization, project_id=project_id
        )
        pentest_all_high = PentestScanResultsDb.objects.filter(
            pentest_type="cloud", organization=request.user.organization, project_id=project_id
        )

    elif severity == "Critical":
        # add your scanner name here <scannername>

        web_all_high = WebScanResultsDb.objects.filter(
            project_id=project_id,
            severity="Critical",
            false_positive="No",
            organization=request.user.organization,
        )
        sast_all_high = StaticScanResultsDb.objects.filter(
            project_id=project_id,
            severity="Critical",
            false_positive="No",
            organization=request.user.organization,
        )
        cloud_all_high = CloudScansResultsDb.objects.filter(
            project_id=project_id,
            severity="Critical",
            false_positive="No",
            organization=request.user.organization,
        )
        net_all_high = NetworkScanResultsDb.objects.filter(
            project_id=project_id,
            severity="Critical",
            false_positive="No",
            organization=request.user.organization,
        )

        pentest_all_high = PentestScanResultsDb.objects.filter(
            severity="Critical",
            project_id=project_id,
            organization=request.user.organization,
        )

    elif severity == "High":
        # add your scanner name here <scannername>

        web_all_high = WebScanResultsDb.objects.filter(
            project_id=project_id,
            severity="High",
            false_positive="No",
            organization=request.user.organization,
        )
        sast_all_high = StaticScanResultsDb.objects.filter(
            project_id=project_id,
            severity="High",
            false_positive="No",
            organization=request.user.organization,
        )
        cloud_all_high = CloudScansResultsDb.objects.filter(
            project_id=project_id,
            severity="High",
            false_positive="No",
            organization=request.user.organization,
        )
        net_all_high = NetworkScanResultsDb.objects.filter(
            project_id=project_id,
            severity="High",
            false_positive="No",
            organization=request.user.organization,
        )

        pentest_all_high = PentestScanResultsDb.objects.filter(
            severity="High",
            project_id=project_id,
            organization=request.user.organization,
        )

    elif severity == "Medium":
        # All Medium

        # add your scanner name here <scannername>

        web_all_high = WebScanResultsDb.objects.filter(
            project_id=project_id,
            severity="Medium",
            organization=request.user.organization,
        )
        sast_all_high = StaticScanResultsDb.objects.filter(
            project_id=project_id,
            severity="Medium",
            organization=request.user.organization,
        )
        cloud_all_high = CloudScansResultsDb.objects.filter(
            project_id=project_id,
            severity="Medium",
            organization=request.user.organization,
        )
        net_all_high = NetworkScanResultsDb.objects.filter(
            project_id=project_id,
            severity="Medium",
            organization=request.user.organization,
        )

        pentest_all_high = PentestScanResultsDb.objects.filter(
            severity="Medium",
            project_id=project_id,
            organization=request.user.organization,
        )

    # All Low
    elif severity == "Low":
        # add your scanner name here <scannername>

        web_all_high = WebScanResultsDb.objects.filter(
            project_id=project_id,
            severity="Low",
            organization=request.user.organization,
        )
        sast_all_high = StaticScanResultsDb.objects.filter(
            project_id=project_id,
            severity="Low",
            organization=request.user.organization,
        )
        cloud_all_high = CloudScansResultsDb.objects.filter(
            project_id=project_id,
            severity="Low",
            organization=request.user.organization,
        )
        net_all_high = NetworkScanResultsDb.objects.filter(
            project_id=project_id,
            severity="Low",
            organization=request.user.organization,
        )

        pentest_all_high = PentestScanResultsDb.objects.filter(
            severity="Low",
            project_id=project_id,
            organization=request.user.organization,
        )

    elif severity == "Total":
        # add your scanner name here <scannername>
        web_all_high = WebScanResultsDb.objects.filter(
            project_id=project_id, organization=request.user.organization
        )
        sast_all_high = StaticScanResultsDb.objects.filter(
            project_id=project_id, organization=request.user.organization
        )
        cloud_all_high = CloudScansResultsDb.objects.filter(
            project_id=project_id, organization=request.user.organization
        )
        net_all_high = NetworkScanResultsDb.objects.filter(
            project_id=project_id, organization=request.user.organization
        )

        pentest_all_high = PentestScanResultsDb.objects.filter(
            project_id=project_id, organization=request.user.organization
        )

    elif severity == "False":
        # add your scanner name here <scannername>
        web_all_high = WebScanResultsDb.objects.filter(
            project_id=project_id,
            false_positive="Yes",
            organization=request.user.organization,
        )
        sast_all_high = StaticScanResultsDb.objects.filter(
            project_id=project_id,
            false_positive="Yes",
            organization=request.user.organization,
        )
        cloud_all_high = CloudScansResultsDb.objects.filter(
            project_id=project_id,
            false_positive="Yes",
            organization=request.user.organization,
        )
        net_all_high = NetworkScanResultsDb.objects.filter(
            project_id=project_id,
            false_positive="Yes",
            organization=request.user.organization,
        )

        pentest_all_high = ""

    elif severity == "Close":
        # add your scanner name here <scannername>
        web_all_high = WebScanResultsDb.objects.filter(
            project_id=project_id,
            vuln_status="Closed",
            organization=request.user.organization,
        )
        sast_all_high = StaticScanResultsDb.objects.filter(
            project_id=project_id,
            vuln_status="Closed",
            organization=request.user.organization,
        )
        cloud_all_high = CloudScansResultsDb.objects.filter(
            project_id=project_id,
            vuln_status="Closed",
            organization=request.user.organization,
        )
        net_all_high = NetworkScanResultsDb.objects.filter(
            project_id=project_id,
            vuln_status="Closed",
            organization=request.user.organization,
        )

        pentest_all_high = PentestScanResultsDb.objects.filter(
            project_id=project_id,
            vuln_status="Closed",
            organization=request.user.organization,
        )

    else:
        return HttpResponseRedirect(
            reverse("projects")  # + "?project_id=%s" % project_id)
        )

    return render(
        request,
        "projects/project_vuln.html",
        {
            "project_dat": project_dat,
            "web_all_high": web_all_high,
            "sast_all_high": sast_all_high,
            "cloud_all_high": cloud_all_high,
            "net_all_high": net_all_high,
            "pentest_all_high": pentest_all_high,
            "project_id": project_id,
            "severity": severity,
            "message": all_notify,
        },
    )
    # return render (request,'projects/project_vuln.html',{'project_dat':project_dat})


class ProjectList(APIView):
    permission_classes = [IsAuthenticated | permissions.VerifyAPIKey]

    def get(self, request, uu_id=None):
        if uu_id == None:
            projects = ProjectDb.objects.filter(organization=request.user.organization)
            serialized_data = ProjectDataSerializers(projects, many=True)
        else:
            try:
                projects = ProjectDb.objects.filter(
                    uu_id=uu_id, organization=request.user.organization
                )
                serialized_data = ProjectDataSerializers(projects, many=True)
            except ProjectDb.DoesNotExist:
                return Response(
                    {"message": "User Doesn't Exist"}, status=status.HTTP_404_NOT_FOUND
                )

        if request.path[:4] == "/api":
            return Response(serialized_data.data)
        else:
            return Response({"serializer": serialized_data, "projects": projects})


class ProjectDelete(APIView):
    renderer_classes = [TemplateHTMLRenderer]
    template_name = "dashboard/project.html"
    permission_classes = (IsAuthenticated, permissions.IsAdmin)

    def post(self, request):
        try:
            project_id = request.data.get("project_id")
            projects = ProjectDb.objects.filter(
                uu_id=project_id, organization=request.user.organization
            ).first()
            projects.delete()

            notes = Note.objects.filter(project_uuid=project_id)
            for note in notes:
                note.delete()

            members = Member.objects.filter(project_uuid=project_id)
            for member in members:
                member.delete()

            return HttpResponseRedirect("/projects/")
        except ProjectDb.DoesNotExist:
            return Response(
                {"message": "User Doesn't Exist"}, status=status.HTTP_404_NOT_FOUND
            )


class ProjectCreate(APIView):
    renderer_classes = [TemplateHTMLRenderer]
    template_name = "projects/project_create.html"

    permission_classes = (IsAuthenticated, permissions.IsAdmin)

    def get(self, request):
        org = Organization.objects.all()
        group_name = request.GET.get("name", "")
        if group_name == "":
            groups = GroupDb.objects.all()
        else:
            groups = GroupDb.objects.filter(group_name=group_name, organization=request.user.organization)

        projects = ProjectDb.objects.filter(organization=request.user.organization)
        serialized_data = ProjectDataSerializers(projects, many=True)

        return Response(
            {"serializer": serialized_data, "projects": projects, "org": org, "groups": groups}
        )
        # groups = {"BNA","Post","Bankerise"}
        # return Response({"groups": groups})

    def post(self, request):

        serializer = ProjectCreateSerializers(data=request.data)
        serializer.is_valid(raise_exception=True)

        name = request.data.get("project_name")
        description = request.data.get("project_disc","")
        priority = request.data.get("priority")
        group_id = request.data.get("group")

        if group_id == "":
            group = GroupDb.objects.filter(group_name="Standalone", organization=request.user.organization).get()
        else:
            group = GroupDb.objects.filter(uu_id=group_id, organization=request.user.organization).get()

        project = ProjectDb(
            project_name=name,
            project_disc=description,
            created_by=request.user,
            organization=request.user.organization,
            priority=priority,
            group=group,
            total_vuln=0,
            total_critical=0,
            total_high=0,
            total_medium=0,
            total_low=0,
            total_open=0,
            total_false=0,
            total_close=0,
            total_net=0,
            total_web=0,
            total_static=0,
            critical_net=0,
            critical_web=0,
            critical_static=0,
            high_net=0,
            high_web=0,
            high_static=0,
            medium_net=0,
            medium_web=0,
            medium_static=0,
            low_net=0,
            low_web=0,
            low_static=0,
        )
        project.save()
        all_month_data_display = MonthDb.objects.filter(
            organization=request.user.organization
        )

        if len(all_month_data_display) == 0:
            save_months_data = MonthDb(
                project_id=project.id,
                month=datetime.datetime.now().month,
                critical=0,
                high=0,
                medium=0,
                low=0,
            )
            save_months_data.save()
        messages.success(request, "Project Created")
        return HttpResponseRedirect("/projects/")


# Note views
def add_note(request):
    if request.method == "POST":
        added_by=request.user.name
        added_note=request.POST.get('new-note',"")
        project_uuid = request.POST.get('project_uuid',"")
        note=Note(project_uuid=project_uuid,note=added_note,added_by=added_by)
        note.save()
    return redirect(reverse("projects:project_overview") + f"?uu_id={project_uuid}")

def delete_note(request):
    if request.method == "POST":
        project_uuid = request.POST.get('project_id', "")
        note_id = request.POST.get('note_id', "")
        note = Note.objects.filter(
            uu_id=note_id
        ).first()
        note.delete()

    return redirect(reverse("projects:project_overview") + f"?uu_id={project_uuid}")

def add_member(request):
    if request.method == "POST":
        name = request.POST.get('name', "")
        role = request.POST.get('role', "")
        team = request.POST.get('team', "")
        project_uuid = request.POST.get('project_uuid', "")
        member = Member(name=name,
                        role=role,
                        team=team,
                        project_uuid=project_uuid
                        )
        member.save()
    return redirect(reverse("projects:project_overview") + f"?uu_id={project_uuid}")

def delete_member(request):
    if request.method == "POST":
        project_uuid = request.POST.get('project_uuid', "")
        member_id = request.POST.get('member_id', "")
        member = Member.objects.filter(
            uu_id=member_id
        ).first()
        member.delete()
    return redirect(reverse("projects:project_overview") + f"?uu_id={project_uuid}")