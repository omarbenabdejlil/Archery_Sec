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
from django.shortcuts import HttpResponseRedirect, render, redirect

from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.events import EVENT_JOB_EXECUTED , EVENT_JOB_ERROR


import threading
import uuid
from datetime import datetime, timezone, timedelta

from django.http import HttpResponseRedirect
from django.shortcuts import HttpResponse, render
from django.urls import reverse
from notifications.models import Notification
from rest_framework.permissions import IsAuthenticated
from rest_framework.renderers import TemplateHTMLRenderer
from rest_framework.views import APIView

from projects.models import ProjectDb
from user_management import permissions
from webscanners.models import (WebScansDb, cookie_db, excluded_db,
                                task_schedule_db)

from groups.models import GroupDb
from django.contrib import messages

from webscanners.zapscanner.views import launch_zap_scan

from networkscanners.models import TaskScheduleDb

from webscanners.zapscanner.views import zap_af

from webscanners.zapscanner.views import PlanRunFailed


def error_404_view(request):
    return render(request, "error/404.html")


class DeleteNotify(APIView):
    renderer_classes = [TemplateHTMLRenderer]

    permission_classes = (IsAuthenticated,)

    def get(self, request):
        notify_id = request.GET["notify_id"]

        notify_del = Notification.objects.filter(
            id=notify_id, organization=request.user.organization
        )
        notify_del.delete()

        return HttpResponseRedirect(reverse("dashboard:dashboard"))


class DeleteAllNotify(APIView):
    renderer_classes = [TemplateHTMLRenderer]

    permission_classes = (IsAuthenticated,)

    def get(self, request):
        notify_del = Notification.objects.filter()
        notify_del.delete()

        return HttpResponseRedirect(reverse("dashboard:dashboard"))

class Dast_scans(APIView):
    renderer_classes = [TemplateHTMLRenderer]
    template_name = "webscanners/dast_scans.html"

    permission_classes = (IsAuthenticated, permissions.IsAnalyst)

    def get(self, request):
        redirected_from_project_scans = False
        redirected_zap = False
        project_uuid = False
        group_uuid = False
        redirected = request.session.get('redirected', False) # if its called from zap AF to upload plan
        redirected_from_project_scans = request.session.get('redirected_to_dast_scan', False) # redirected from project scans
        if redirected:
            redirected_zap = True
            del request.session['redirected']
        if redirected_from_project_scans:
            project_uuid= request.session.get('project_uuid', False)
            group_uuid = request.session.get('group_uuid', False)
            del request.session['project_uuid']
            del request.session['group_uuid']
            del request.session['redirected_to_dast_scan']

        all_scans = WebScansDb.objects.filter(organization=request.user.organization)
        all_excluded_url = excluded_db.objects.filter()
        all_cookies = cookie_db.objects.filter()
        projects = ProjectDb.objects.filter(organization=request.user.organization)
        groups = GroupDb.objects.filter(organization=request.user.organization)
        all_notify = Notification.objects.unread()
        return render(
            request,
            "webscanners/dast_scans.html",
            {
                "all_scans": all_scans,
                "all_excluded_url": all_excluded_url,
                "all_cookies": all_cookies,
                "projects": projects,
                "groups": groups,
                "redirected_from_project_scans": redirected_from_project_scans,
                "project_uuid": project_uuid,
                "group_uuid": group_uuid,
                "message": all_notify,
                "redirected_zap": redirected_zap
            },
        )

def dast(request):
    if request.method == 'POST':
            group_id = request.POST.get('group_id')
            project_uu_id = request.POST.get('project_id')
            scan = request.POST.get('scan_type')

            if scan == 'ZAP':
                scans_status = ""
                scan_id = ""
                target_url = None
                user = request.user
                rescan_id = None
                rescan = "No"
                attack_type = request.POST.get('attack_type') # for owasp zap scan
                project_id = (
                    ProjectDb.objects.filter(
                        uu_id=project_uu_id, organization=request.user.organization
                    )
                    .values("id")
                    .get()["id"]
                )
                if attack_type == "Full Scan":
                    active = request.POST.get('active') == 'true'
                    passive = request.POST.get('passive') == 'true'
                    ajax_spider = request.POST.get('ajaxSpider') == 'true'
                    spider = request.POST.get('spider') == 'true'
                    auth = request.POST.get('auth') == 'true'
                    targetUrls = request.POST.get('target_urls')
                    includeRegex = request.POST.get('include_regex')
                    excludeRegex = request.POST.get('exclude_regex')
                    includeRegex=str(includeRegex)
                    target_item = str(targetUrls)
                    value = target_item.replace(" ", "")
                    target__split = value.split(",")
                    split_length = target__split.__len__()
                    for i in range(0, split_length):
                        target = target__split.__getitem__(i)
                        scan_id = uuid.uuid4()
                        thread = threading.Thread(
                            target=launch_zap_scan,
                            args=(
                                target, project_id, rescan_id, rescan, scan_id, user, request,
                                includeRegex,
                                excludeRegex,
                                active ,
                                passive ,
                                ajax_spider ,
                                spider ,
                                auth ,
                            ),
                        )
                        thread.daemon = True
                        thread.start()
            # print("the scan ends here ")
            # request.session['project_uuid']=project_uu_id
            # return HttpResponseRedirect(reverse("projects:project_scans"))
    # return render(request, "webscanners/zapscanner/zap_scan_list.html")
            messages.success(request, "Scan is Running ")
            return HttpResponse(status=200)
    return HttpResponse(status=200)



def launch_schedule_zapfullscan_data(request):

    if request.method == 'POST':
        group_id = request.POST.get('group_id')
        project_uu_id = request.POST.get('project_id')
        scan_type = request.POST.get('scan_type')
        attack_type = request.POST.get('attack_type')
        print(attack_type)
        year = "*"
        month = "*"
        day_of_week = "*"
        day = "*"
        week = "*"
        hour = "*"
        minute = "0"
        second = "0"
        periodic = request.POST.get('periodic', "")
        if periodic == 'None':
            date = request.POST.get('date_time', "")
            date = datetime.strptime(date, "%Y-%m-%dT%H:%M")
            year = date.year
            month = date.month
            day = date.day
            hour = date.hour
            minute = date.minute
            second = date.second

        elif periodic == 'HOURLY':
            hour = int(request.POST.get('hours', "*"))
            hour = '*/{}'.format(hour)

        elif periodic == 'DAILY':
            time = request.POST.get('time', "")  # oki
            time = datetime.strptime(time, "%H:%M")
            hour = time.hour
            minute = time.minute

        elif periodic == 'WEEKLY':  # oki
            day_of_week = request.POST.get('day', "")
            time = request.POST.get('time', "")
            time = datetime.strptime(time, "%H:%M")
            hour = time.hour
            minute = time.minute

        if attack_type == "Full Scan":
            active = request.POST.get('active') == 'true'
            passive = request.POST.get('passive') == 'true'
            ajax_spider = request.POST.get('ajaxSpider') == 'true'
            spider = request.POST.get('spider') == 'true'
            auth = request.POST.get('auth') == 'true'
            targetUrls = request.POST.get('target_urls')
            includeRegex = request.POST.get('include_regex')
            excludeRegex = request.POST.get('exclude_regex')


            # Schedule zap full scan
            schedule_zap_full_scan(
                group_id, project_uu_id, scan_type, attack_type, active, passive, ajax_spider, spider, auth,
                targetUrls, includeRegex, excludeRegex, request,
                periodic, year, month,day_of_week, day,hour, minute, second, week
            )
        elif attack_type == "Automation Framework":
            plans_id = request.POST.getlist('checked_plans')
            print("the plan id is : ",plans_id)

            schedule_zap_af(group_id, project_uu_id, scan_type, attack_type, request, plans_id,
                            periodic, year, month, day_of_week, day, hour, minute, second, week
                            )
        messages.success(request, "Scan Scheduled ")
        return HttpResponse(status=200)

def launch_schedule_zapfullscan(
        group_id, project_id, scan_type, attack_type, active, passive, ajax_spider, spider, auth,
        targetUrls, includeRegex, excludeRegex, request , scan_id
    ):
    if scan_type == 'ZAP' and attack_type == "Full Scan":
        launch_zap_scan(
            targetUrls.strip(), project_id, None, "No", scan_id, request.user,request, includeRegex,
            excludeRegex, active, passive, ajax_spider, spider, auth ,
        )

def launch_schedule_zapaf(request,plans_id,project_id,scan_id):
    try:
        zap_af(request, plans_id,project_id,scan_id)
        return HttpResponse(status=200)
    except PlanRunFailed as e:
        raise e



## when deleting scheduling scan , delete it from the job ( apschedule db )
def schedule_zap_af(group_id, project_uu_id, scan_type, attack_type, request,plans_id,
             periodic, year, month, day_of_week, day, hour, minute, second, week

):
    global scheduler
    project = ProjectDb.objects.get(uu_id=project_uu_id, organization=request.user.organization)
    project_id = project.id
    project_name = project.project_name
    scan_id = uuid.uuid4()
    target=""

    scheduler = BackgroundScheduler(timezone=timezone(timedelta(hours=1)))

    scheduler.add_job(
        launch_schedule_zapaf,
        trigger='cron',
        args=[ request,plans_id,project_id,scan_id],
        year=year,
        month=month,
        day_of_week=day_of_week,
        day=day,
        hour=hour,
        minute=minute,
        second=second,
        week=week,
        id=str(scan_id),
        replace_existing=True,
        name=" run scheduled zap AF against " + project_name + " project. "
    )

    # on success
    scheduler.add_listener(update_schedule, EVENT_JOB_EXECUTED)
    # on fail
    scheduler.add_listener(error_handler, EVENT_JOB_ERROR)

    scheduler.start()
    next_run_time = scheduler.get_job(str(scan_id)).next_run_time
    schedule_time = next_run_time.strftime("%Y-%m-%d %H:%M:%S")

    save_schedule_scan = TaskScheduleDb(
        task_id=scan_id,
        target="run from AF",
        schedule_time=schedule_time,
        status="Waiting",
        project_id=project_uu_id,
        scanner=scan_type,
        periodic_task=periodic,
        created_by=request.user
    )
    save_schedule_scan.save()


def schedule_zap_full_scan(group_id, project_uu_id, scan_type, attack_type, active, passive, ajax_spider, spider, auth,
            targetUrls, includeRegex, excludeRegex, request,
             periodic, year, month, day_of_week, day, hour, minute, second, week

):
    global scheduler
    """
    this function schedule a full scan on demand :
        - hoursly
        - weekly scan
        - run once at x date
        - daily run
    """

    project = ProjectDb.objects.get(uu_id=project_uu_id, organization=request.user.organization)
    project_id = project.id
    project_name=project.project_name
    scan_id = uuid.uuid4()

    scheduler = BackgroundScheduler(timezone=timezone(timedelta(hours=1)))

    scheduler.add_job(
        launch_schedule_zapfullscan,
        trigger='cron',
        args=[group_id, project_id, scan_type, attack_type, active, passive, ajax_spider, spider, auth,
            targetUrls, includeRegex, excludeRegex, request , scan_id ],
        year= year,
        month= month,
        day_of_week= day_of_week,
        day= day,
        hour= hour,
        minute= minute,
        second= second,
        week= week,
        id=str(scan_id),
        replace_existing=True,
        name=" run scheduled zap scan against "+project_name+"project. "
    )

    # on success
    scheduler.add_listener(update_schedule, EVENT_JOB_EXECUTED)
    # on fail
    scheduler.add_listener(error_handler, EVENT_JOB_ERROR)

    scheduler.start()
    next_run_time = scheduler.get_job(str(scan_id)).next_run_time
    schedule_time = next_run_time.strftime("%Y-%m-%d %H:%M:%S")

    save_schedule_scan = TaskScheduleDb(
        task_id=scan_id,
        target=targetUrls,
        schedule_time=schedule_time,
        status="Waiting",
        project_id=project_uu_id,
        scanner=scan_type,
        periodic_task=periodic,
        created_by=request.user
    )
    save_schedule_scan.save()



def update_schedule(event):
    global scheduler
    """
    this function runs after each schedule event to update the next schedule
    in the TaskScheduleDb database
    """
    scan_id = event.job_id
    scheduled_task = TaskScheduleDb.objects.get(task_id=scan_id)
    periodic = scheduled_task.periodic_task
    schedule_time=scheduled_task.schedule_time

    if periodic == "None":
        scheduled_task.schedule_time = "Done At " + schedule_time
        scheduled_task.status = "Done"
    else:
        next_run_time = scheduler.get_job(scan_id).next_run_time
        schedule_time = next_run_time.strftime("%Y-%m-%d %H:%M:%S")
        scheduled_task.schedule_time = schedule_time
        scheduled_task.status = "Done"

    scheduled_task.save()


def error_handler(event):
    scan_id = event.job_id
    error = event.exception
    print(" Schedule Job with id : "+scan_id+" failed to Run with error : ",error)
    scheduled_task = TaskScheduleDb.objects.get(task_id=scan_id)
    scheduled_task.status = "Failed"
    periodic = scheduled_task.periodic_task
    if periodic == "None":
        schedule_time = scheduled_task.schedule_time
        scheduled_task.schedule_time = "Failed At " + schedule_time

    scheduled_task.save()


def delete_schedule(request):
    global scheduler  # Access the global variable

    if request.method == "POST":

        task_ids = request.POST.get("task_id")
        scan_item = str(task_ids)
        value = scan_item.replace(" ", "")
        value_split = value.split(",")
        split_length = value_split.__len__()
        # print "split_length", split_length
        for i in range(0, split_length):
            scan_id = value_split.__getitem__(i)
            scheduled_task = TaskScheduleDb.objects.get(task_id=scan_id)
            periodic = scheduled_task.periodic_task
            project_id = scheduled_task.project_id
            status = scheduled_task.status
            if periodic == 'None' and status == 'Done':
                scheduled_task.delete()
            else:
                scheduler.remove_job(str(scan_id))
                scheduled_task.delete()
        return redirect(reverse("projects:project_scans") + f"?uu_id={project_id}")