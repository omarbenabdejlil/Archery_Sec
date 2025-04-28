# Copyright (C) 2024 Ahmed Aissa
# Email:   ahmed.aissa.ing@gmail.com
# linkedin: @ahmedaissa

from django.shortcuts import render



import datetime
from itertools import chain
from django.contrib import messages
from django.http import HttpResponseRedirect
from django.shortcuts import HttpResponseRedirect, get_object_or_404, render
from django.urls import reverse
from notifications.models import Notification
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.renderers import TemplateHTMLRenderer
from rest_framework.response import Response
from rest_framework.views import APIView

from projects.models import MonthDb, ProjectDb
from user_management import permissions
from user_management.models import Organization

from groups.models import GroupDb

group_dat = None

class GroupList(APIView):
    permission_classes = [IsAuthenticated | permissions.VerifyAPIKey]
    # renderer_classes = [TemplateHTMLRenderer]
    # template_name = "groups/groups_list.html"
    def get(self, request):
        group_name = request.GET.get("name", "")

        if group_name == "":
            groups = GroupDb.objects.filter(organization=request.user.organization)
            for group in groups :
                projects = ProjectDb.objects.filter(organization=request.user.organization,group=group)
                project_number = len(projects)
                group.total_projects= project_number

            ### TBD: When I'll work on CLI part of the project
            # serialized_data = GroupDataSerializers(groups, many=
            # return Response({ "groups": groups})
            return render(request, 'groups/groups_list.html',{"groups":groups})
        else:
            try:
                group = GroupDb.objects.filter(
                    group_name=group_name, organization=request.user.organization
                ).get()
                projects = ProjectDb.objects.filter(organization=request.user.organization,group=group)
                group.total_projects=len(projects)
                # Calculate sums
                all_critical = 0
                all_high = 0
                all_medium = 0
                all_low=0
                for project in projects:
                    all_critical += project.total_critical
                    all_high += project.total_high
                    all_medium += project.total_medium
                    all_low += project.total_low
                return render(
                    request,
                    'groups/group_projects.html',
                    {"group":group,
                     "projects":projects,
                     "all_critical":all_critical,
                     "all_low":all_low,
                     "all_medium":all_medium,
                     "all_high":all_high,
                     })
            except GroupDb.DoesNotExist:
                return Response(
                    {"message": "group Doesn't Exist"}, status=status.HTTP_404_NOT_FOUND
                )

        # if request.path[:4] == "/api":
        #     return Response(serialized_data.data)
        # else:
        #     return Response({"serializer": serialized_data, "projects": projects})


class GroupCreate(APIView):
    permission_classes = [IsAuthenticated | permissions.VerifyAPIKey]
    renderer_classes = [TemplateHTMLRenderer]
    template_name = "groups/group_create.html"

    def get(self, request, uu_id=None):
        return Response({})

    def post(self, request):
        name = request.data.get("group_name")
        desc = request.data.get("group_description")

        group_created = GroupDb(
            group_name=name,
            total_projects = 0,
            group_description=desc,
            organization=request.user.organization,
            created_by=request.user,
        )
        GroupDb.save(group_created)
        messages.success(request, "Group Created")
        return HttpResponseRedirect("/groups/")

class GroupDelete(APIView):

    permission_classes = (IsAuthenticated, permissions.IsAdmin)

    def post(self, request):
        try:
            group_id = request.data.get("group_uuid")
            groups = GroupDb.objects.filter(
                uu_id=group_id, organization=request.user.organization
            )
            projects = ProjectDb.objects.filter(organization=request.user.organization,group=groups[0])
            for project in projects:
                project.group = GroupDb.objects.filter(group_name="Standalone", organization=request.user.organization).get()
                project.save()
            groups.delete()
            return HttpResponseRedirect("/groups/")
        except ProjectDb.DoesNotExist:
            return Response(
                {"message": "Group Doesn't Exist"}, status=status.HTTP_404_NOT_FOUND
            )


def update_group(request):
    if request.method == "POST":
        group_uuid=request.POST.get('group_id')
        group_name = request.POST.get('group_name')
        group_description = request.POST.get('group_description')
        print("updating view is called ",group_name)

        GroupDb.objects.filter(uu_id=group_uuid, organization=request.user.organization).update(
            group_name=group_name,
            group_description=group_description
        )
        return HttpResponseRedirect(reverse('groups:groups_list'))