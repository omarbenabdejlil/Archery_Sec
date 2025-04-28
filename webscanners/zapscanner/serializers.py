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

from rest_framework import serializers


class ZapScansSerializer(serializers.Serializer):
    project_id = serializers.UUIDField(required=True, help_text="Provide ScanId")
    group_id = serializers.CharField(required=False, help_text="the groupd id ")
    scan_type = serializers.CharField(required=False, help_text="scan type ")
    attack_type = serializers.CharField(required=False, help_text="attack type")
    active = serializers.BooleanField(required=False, help_text="")
    spider = serializers.BooleanField(required=False, help_text="")
    passive = serializers.BooleanField(required=False, help_text="")
    target_urls = serializers.CharField(required=True, help_text="")
    ajaxSpider  = serializers.CharField(required=False, help_text="")
    auth = serializers.BooleanField(required=False)
    include_regex = serializers.CharField(required=False)
    exclude_regex = serializers.CharField(required=False)

class ZapSettingsSerializer(serializers.Serializer):
    zap_api_key = serializers.CharField()
    zap_host = serializers.CharField()
    zap_port = serializers.IntegerField()
    zap_enabled = serializers.BooleanField()
