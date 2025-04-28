# -*- coding: utf-8 -*-
#                    _
#     /\            | |
#    /  \   _ __ ___| |__   ___ _ __ _   _
#   / /\ \ | '__/ __| '_ \ / _ \ '__| | | |
#  / ____ \| | | (__| | | |  __/ |  | |_| |
# /_/    \_\_|  \___|_| |_|\___|_|   \__, |
#                                     __/ |
#                                    |___/
# Copyright (C) 2024 Ahmed Aissa
# Email:   ahmed.aissa.ing@gmail.com
# linkedin: @ahmedaissa

from rest_framework import serializers

class GroupDataSerializers(serializers.Serializer):

    uu_id = serializers.UUIDField(read_only=True)
    organization = (serializers.CharField(read_only=True),)
    group_name = serializers.CharField(required=True, help_text="Group Name")
    group_description = serializers.CharField(allow_blank=True, help_text="Group Description")
    date_time = serializers.DateTimeField(read_only=True)
    total_projects = serializers.IntegerField(default=0)


class GroupCreateSerializers(serializers.Serializer):
    group_name = serializers.CharField(required=True, help_text="Group Name")
    group_description = serializers.CharField(required=False,allow_blank=True, help_text="Group Description")
