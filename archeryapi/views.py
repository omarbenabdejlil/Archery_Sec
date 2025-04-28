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
#
# This file is part of ArcherySec Project.
import csv
import datetime
import io
import json
import os
import secrets
import threading
import uuid
from time import sleep

import defusedxml.ElementTree as ET
from django.core.files.uploadedfile import UploadedFile
from django.shortcuts import HttpResponseRedirect, render
from django.utils.html import escape
from lxml import etree
from rest_framework import status
from rest_framework.parsers import FormParser, MultiPartParser
from rest_framework.permissions import (AllowAny, BasePermission,
                                        IsAuthenticated)
from rest_framework.renderers import TemplateHTMLRenderer
from rest_framework.response import Response
from rest_framework.views import APIView

from archeryapi.models import OrgAPIKey
from archeryapi.serializers import (GenericScanResultsDbSerializer,
                                    JiraLinkSerializer, OrgAPIKeySerializer)
from cloudscanners.models import CloudScansDb, CloudScansResultsDb
from compliance.models import DockleScanDb, InspecScanDb
from networkscanners.models import NetworkScanDb, NetworkScanResultsDb
from projects.models import MonthDb, ProjectDb
from projects.serializers import (ProjectCreateSerializers,
                                  ProjectDataSerializers)
from scanners.scanner_parser import scanner_parser
from staticscanners.models import StaticScanResultsDb, StaticScansDb
from user_management import permissions
from user_management.models import Organization, UserProfile
from webscanners.models import WebScanResultsDb, WebScansDb

from groups.models import GroupDb

from groups.serializers import GroupDataSerializers

from webscanners.zapscanner.serializers import ZapScansSerializer


from webscanners.zapscanner.views import launch_zap_scan

from scanners.scanner_parser.network_scanner import OpenVas_Parser


class CreateProject(APIView):
    permission_classes = (BasePermission, permissions.VerifyAPIKey)

    def post(self, request):
        """
        Current user's identity endpoint.
        """
        _project_name = None
        _project_id = None

        try:
            request.user = UserProfile.objects.get(name="cli")
        except :
            print("cli user doesnt exist")
            return Response({"error": "No cli user "})
        group_name = request.data.get(
            "group_name",
        )
        serializer = ProjectDataSerializers(data=request.data)
        print("the coming data is : ",request.data)
        if serializer.is_valid():
            print("m here inside seri condition ")
            project_name = request.data.get(
                "project_name",
            )

            project_disc = request.data.get(
                "project_disc",
            )


            print(" the project name is : ",project_name)
            print("the group name is : ",group_name)
            # priority = request.data.get(
            #     "priority",
            # )

            all_project = ProjectDb.objects.filter(project_name=project_name)

            for project in all_project:
                _project_name = project.project_name
                _project_id = project.uu_id

            if _project_name == project_name:
                return Response(
                    {"message": "Project already existed", "project_id": _project_id}
                )

            else:
                if group_name == "":
                    group = GroupDb.objects.filter(group_name="Standalone",).get()
                else:
                    group = GroupDb.objects.filter(group_name=group_name,).get()

                priority = "low"
                print("the group name is :",group_name)
                project = ProjectDb(
                    project_name=project_name,
                    project_disc=project_disc,
                    group=group,
                    priority=priority,
                    created_by=request.user,
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

                all_month_data_display = MonthDb.objects.filter()

                if len(all_month_data_display) == 0:
                    save_months_data = MonthDb(
                        project_id=project.id,
                        month=datetime.datetime.now().month,
                        high=0,
                        medium=0,
                        low=0,
                    )
                    save_months_data.save()

                if not project_name:
                    return Response({"error": "No name passed"})
                return Response(
                    # {"message": "Project Created", "project_id": project.uu_id}
                    {"message":"Project Created", "project_id": project.uu_id}
                )
        print(serializer.errors)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class CreateGroup(APIView):
    permission_classes = (BasePermission, permissions.VerifyAPIKey)

    def post(self,request):

        request.user= UserProfile.objects.get(name="cli")
        print(request.user.name)
        _group_name = None
        serializer = GroupDataSerializers(data=request.data)
        print("the coming group data is : ",request.data)

        if serializer.is_valid():

            group_name= request.data.get(
                "group_name",
            )

            group_description = request.data.get(
                "group_description",
            )

            print("the group name is :",group_name)
            print("the group disc is :",group_description)

            all_groups = GroupDb.objects.filter(group_name=group_name)
            for group in all_groups:
                _group_name = group.group_name

            if _group_name == group_name:
                return Response(
                    {"message": "Group already existed", "group name": _group_name}
                )
            else:
                group = GroupDb(
                    group_name=group_name,
                    group_description=group_description,
                    total_projects=0,
                    organization=request.user.organization,
                    created_by=request.user,
                )
                GroupDb.save(group)
                if not group_name:
                    return Response({"error": "No group name passed"})
                return Response(
                    # {"message": "Project Created", "project_id": project.uu_id}
                    {"message": "Group Created", "group_id": group.uu_id}
                )
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)




class UploadScanResult(APIView):
    parser_classes = (MultiPartParser,)
    permission_classes = (BasePermission, permissions.VerifyAPIKey)

    def check_file_ext(self, file):
        split_tup = os.path.splitext(file)
        file_extension = split_tup[1]
        return file_extension

    def web_result_data(self, scan_id, project_uu_id, scanner):
        all_web_data = WebScanResultsDb.objects.filter(scan_id=scan_id)
        total_vul = len(all_web_data)
        total_critical = len(all_web_data.filter(severity="Critical"))
        total_high = len(all_web_data.filter(severity="High"))
        total_medium = len(all_web_data.filter(severity="Medium"))
        total_low = len(all_web_data.filter(severity="Low"))
        return Response(
            {
                "message": "Scan Data Uploaded",
                "project_id": escape(project_uu_id),
                "scan_id": escape(scan_id),
                "scanner": escape(scanner),
                "result": {
                    "total_vul": escape(total_vul),
                    "total_critical": escape(total_critical),
                    "total_high": escape(total_high),
                    "total_medium": escape(total_medium),
                    "total_low": escape(total_low),
                },
            }
        )

    def sast_result_data(self, scan_id, project_uu_id, scanner):
        all_sast_data = StaticScanResultsDb.objects.filter(scan_id=scan_id)
        total_vul = len(
            all_sast_data.filter(severity__in=["Critical", "High", "Medium", "Low"])
        )
        total_critical = len(all_sast_data.filter(severity="Critical"))
        total_high = len(all_sast_data.filter(severity="High"))
        total_medium = len(all_sast_data.filter(severity="Medium"))
        total_low = len(all_sast_data.filter(severity="Low"))
        return Response(
            {
                "message": "Scan Data Uploaded",
                "project_id": escape(project_uu_id),
                "scan_id": escape(scan_id),
                "scanner": escape(scanner),
                "result": {
                    "total_vul": escape(total_vul),
                    "total_critical": escape(total_critical),
                    "total_high": escape(total_high),
                    "total_medium": escape(total_medium),
                    "total_low": escape(total_low),
                },
            }
        )

    def cloud_result_data(self, scan_id, project_uu_id, scanner):
        all_cloud_data = CloudScansResultsDb.objects.filter(scan_id=scan_id)
        total_vul = len(all_cloud_data)
        total_critical = len(all_cloud_data.filter(severity="Critical"))
        total_high = len(all_cloud_data.filter(severity="High"))
        total_medium = len(all_cloud_data.filter(severity="Medium"))
        total_low = len(all_cloud_data.filter(severity="Low"))
        return Response(
            {
                "message": "Scan Data Uploaded",
                "project_id": escape(project_uu_id),
                "scan_id": escape(scan_id),
                "scanner": escape(scanner),
                "result": {
                    "total_vul": escape(total_vul),
                    "total_high": escape(total_high),
                    "total_medium": escape(total_medium),
                    "total_low": escape(total_low),
                    "total_critical": escape(total_critical),
                },
            }
        )

    def network_result_data(self, scan_id, project_uu_id, scanner):
        all_net_data = NetworkScanResultsDb.objects.filter(scan_id=scan_id)
        total_vul = len(all_net_data)
        total_critical = len(all_net_data.filter(severity="Critical"))
        total_high = len(all_net_data.filter(severity="High"))
        total_medium = len(all_net_data.filter(severity="Medium"))
        total_low = len(all_net_data.filter(severity="Low"))
        return Response(
            {
                "message": "Scan Data Uploaded",
                "project_id": escape(project_uu_id),
                "scan_id": escape(scan_id),
                "scanner": escape(scanner),
                "result": {
                    "total_vul": escape(total_vul),
                    "total_critical": escape(total_critical),
                    "total_high": escape(total_high),
                    "total_medium": escape(total_medium),
                    "total_low": escape(total_low),
                },
            }
        )

    def post(self, request, format=None):

        date_time = datetime.datetime.now()
        project_name = request.data.get("project_name",None)
        print("the project name is : ",project_name)
        # project_uu_id = request.data.get("project_id",None)

        if project_name is not None :
            project_uu_id = (
                ProjectDb.objects.filter(project_name=project_name).values("uu_id").get()["uu_id"]
            )

        if project_uu_id is not None :
            project_id = (
                    ProjectDb.objects.filter(uu_id=project_uu_id).values("id").get()["id"]
            )

        scanner = request.data.get("scanner")

        if isinstance(request.data.get("filename"), UploadedFile):
            file = request.data.get("filename").read().decode("utf-8")
        else:
            file = request.data.get("filename")

        scan_url = request.data.get("scan_url")

        scan_id = uuid.uuid4()
        scan_status = "100"

        parser_dict = scanner_parser.parser_function_dict.get(
            scanner, "Not implemented"
        )
        if parser_dict == "Not implemented":
            return Response(
                {
                    "error": "Scanner is not implemented",
                },
                status=status.HTTP_400_BAD_REQUEST,
            )
        filetype = parser_dict.get("type", "Unknown")
        if filetype == "Unknown":
            return Response(
                {
                    "error": "Unknown file type",
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        # Put the data in memory
        if filetype == "XML" or filetype == "Nessus":
            root_xml = ET.fromstring(file)
            en_root_xml = ET.tostring(root_xml, encoding="utf8").decode(
                "ascii", "ignore"
            )
            data = ET.fromstring(en_root_xml)
        elif filetype == "LXML":
            xml_dat = bytes(bytearray(file, encoding="utf-8"))
            data = etree.XML(xml_dat)
        elif filetype == "JSON":
            data = json.loads(file)
        elif filetype == "CSV":
            reader = csv.DictReader(io.StringIO(file))
            data = [line for line in reader]
        # Custom data loader
        elif filetype == "JS":
            file_data = file.replace("scoutsuite_results =", "").lstrip()
            json_payload = "".join(file_data)
            data = json.loads(json_payload)
        # Unsupported file type case
        else:
            return Response(
                {
                    "error": "Unsupported file type",
                },
                status=status.HTTP_400_BAD_REQUEST,
            )

        db_type = parser_dict.get("dbtype", "Unsupported")
        if db_type == "Unsupported":
            return Response(
                {
                    "error": "Unsupported DB type",
                },
                status=status.HTTP_400_BAD_REQUEST,
            )
        need_to_store = True
        custom_return = False
        # Store to database - regular types
        if "dbname" in parser_dict:
            db_name = parser_dict.get("dbname", "Unknown")
            if db_type == "WebScans":
                return_func = self.web_result_data
                scan_dump = WebScansDb(
                    scan_url=scan_url,
                    scan_id=scan_id,
                    project_id=project_id,
                    scan_status=scan_status,
                    scanner=db_name,
                )
            elif db_type == "StaticScans":
                return_func = self.sast_result_data
                scan_dump = StaticScansDb(
                    target=scan_url,
                    scan_id=scan_id,
                    project_id=project_id,
                    scan_status=scan_status,
                    scanner=db_name,
                )
            elif db_type == "NetworkScan":
                return_func = self.network_result_data
                # OpenVAS special case
                if scanner == "openvas":
                    need_to_store = False
                    hosts = OpenVas_Parser.get_hosts(root_xml)
                    for host in hosts:
                        scan_dump = NetworkScanDb(
                            ip=host,
                            scan_id=scan_id,
                            project_id=project_id,
                            scan_status=scan_status,
                            scanner=db_name,
                        )
                        scan_dump.save()
                # Regular network scan case
                else:
                    host = parser_dict["getHostFunction"](data)
                    scan_dump = NetworkScanDb(
                        ip=host,
                        scan_id=scan_id,
                        project_id=project_id,
                        scan_status=scan_status,
                        scanner=db_name,
                    )
            elif db_type == "CloudScans":
                return_func = self.cloud_result_data
                scan_dump = CloudScansDb(
                    scan_id=scan_id,
                    date_time=date_time,
                    project_id=project_id,
                    scan_status=scan_status,
                    rescan="No",
                    scanner=db_name,
                )

        elif db_type == "InspecScan":
            custom_return = True
            scan_dump = InspecScanDb(
                project_name=scan_url,
                scan_id=scan_id,
                project_id=project_id,
                scan_status=scan_status,
            )
        elif db_type == "DockleScan":
            custom_return = True
            scan_dump = DockleScanDb(
                scan_id=scan_id,
                date_time=date_time,
                project_id=project_id,
                scan_status=scan_status,
            )
        elif db_type == "Nessus":
            return_func = self.network_result_data
            need_to_store = False
            # Nessus does not store before the parser
        # Store the dump (except for no need to store cases)
        if need_to_store is True:
            scan_dump.save()

        # Call the parser
        parser_func = parser_dict["parserFunction"]
        parser_func(data, project_id, scan_id, request)

        # Success !
        if custom_return is True:

            result = {
                    "message": "Scan Data Uploaded",
                    "project_id": escape(project_uu_id),
                    "scan_id": escape(scan_id),
                    "scanner": escape(scanner),
                }
            print("report is uploaded from the CLI ", result)
            return Response(result)
        else:
            return return_func(scan_id, project_id, scanner)


class APIKey(APIView):
    renderer_classes = [TemplateHTMLRenderer]
    template_name = "access-key/access-key-list.html"
    permission_classes = (
        IsAuthenticated,
        permissions.IsAdmin,
    )

    def get(self, request):
        all_active_keys = OrgAPIKey.objects.filter(
            is_active=True, organization=request.user.organization
        )

        serialized_data = OrgAPIKeySerializer(all_active_keys, many=True)
        return render(
            request,
            "access-key/access-key-list.html",
            {"all_active_keys": all_active_keys, "serialized_data": serialized_data},
        )

    def post(self, request):
        user = request.user

        api_key = self.generate_api_key(user)
        name = request.POST.get("name")

        # new_api_key =
        OrgAPIKey.objects.create(api_key=api_key, created_by=user, name=name)

        # content = {"APIKey": api_key, "id": new_api_key.uu_id}
        return HttpResponseRedirect("/api/access-key/")

    def generate_api_key(self, user: UserProfile) -> str:
        """
        return string api key
        """
        api_key = secrets.token_urlsafe(48)

        return api_key


class DisableAPIKey(APIView):
    permission_classes = (
        IsAuthenticated,
        permissions.IsAdmin,
    )

    def put(self, request, api_key_uuid):
        user = request.user
        current_org = user.organization

        key_object = OrgAPIKey.objects.filter(
            org_subscription=current_org,
            is_active=True,
            uu_id=api_key_uuid,
            organization=request.user.organization,
        ).update(is_active=False)

        if key_object > 0:
            content = {"message": "API Key Deactivate"}
            http_status = status.HTTP_200_OK
        else:
            content = {"message": "API Key Not Found"}
            http_status = status.HTTP_404_NOT_FOUND

        return Response(content, http_status)




class DeleteAPIKey(APIView):
    permission_classes = (
        IsAuthenticated,
        permissions.IsAdmin,
    )

    def post(self, request):
        uu_id = request.POST.get("uu_id")

        scan_item = str(uu_id)
        value = scan_item.replace(" ", "")
        value_split = value.split(",")
        split_length = value_split.__len__()
        for i in range(0, split_length):
            uu_id = value_split.__getitem__(i)

            item = OrgAPIKey.objects.filter(
                uu_id=uu_id, organization=request.user.organization
            )
            item.delete()
        return HttpResponseRedirect("/api/access-key/")



class OWASP_ZAP(APIView):
    permission_classes = (BasePermission, permissions.VerifyAPIKey)

    def post(self,request):

        request.user= UserProfile.objects.get(name="cli")
        print(request.data)

        try:
            print("running owasp zap scan triggered from CLI")
            # request.data.update(serializer.data)

            project_name = request.data.get('project_name',None)

            project_uu_id = (
                ProjectDb.objects.filter(project_name=project_name).values("uu_id").get()["uu_id"]
            )

            project_id = (
                ProjectDb.objects.filter(
                    uu_id=project_uu_id, organization=request.user.organization
                )
                .values("id")
                .get()["id"]
            )

            user = request.user
            rescan_id = None
            rescan = "No"
            scan_id = uuid.uuid4()
            data= request.data
            print(data)
            target = data.get('target_urls').strip().rstrip('/')
            print(target)
            includeRegex = target+".*"
            print(includeRegex)
            excludeRegex = data.get('exclude_regex')
            active = data.get('active')
            passive = data.get('passive')
            ajax_spider = data.get('ajax_spider')
            spider = data.get('spider')
            auth = data.get('auth')

            print("active is : ",active )
            print("passive is : ",passive )
            print("ajax_spider is : ",ajax_spider )
            print("spider is : ",spider )
            print("auth is : ",auth )


            thread = threading.Thread(
                target=launch_zap_scan,
                args=(
                    target, project_id, rescan_id, rescan, scan_id, user, request,
                    includeRegex,
                    excludeRegex,
                    active,
                    passive,
                    ajax_spider,
                    spider,
                    auth,
                ),
            )

            thread.daemon = True
            thread.start()

            sleep(2)


            if thread.is_alive():
                all_zap_scan = WebScansDb.objects.get(
                    scan_id=scan_id, scanner="Zap", organization=request.user.organization
                )

                while all_zap_scan.scan_status != "100":
                    sleep(5)
                    all_zap_scan = WebScansDb.objects.get(
                        scan_id=scan_id, scanner="Zap", organization=request.user.organization
                    )
                total_vuln = all_zap_scan.total_vul
                total_high = all_zap_scan.high_vul
                total_medium = all_zap_scan.medium_vul
                total_low = all_zap_scan.low_vul

                message = (
                        "ZAP Scanner has completed the scan against "
                        "  %s \n Total: %s \nHigh: %s \n"
                        "Medium: %s \nLow %s"
                        % (target, total_vuln, total_high, total_medium, total_low)
                )
                return Response({"message": message})
            else :
                print("Can't run zap scan triggered from CLI ")
                message = " Can't Run zap Scan , check zap connectivety "
                return Response({"message": message})
        except :
            return Response({"message": "fails to run zap scan "})