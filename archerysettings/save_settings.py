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

"""Author: Anand Tiwari """

import json
import uuid

from django.core import signing

from archerysettings.models import (EmailDb,
                                    NmapVulnersSettingDb,
                                    ZapSettingsDb)


class SaveSettings:
    def __init__(self, setting_file):
        self.setting_file = setting_file

    def nmap_vulners(self, enabled, version, online, timing):
        """
        Save NAMP Vulners Settings into setting file.
        :param enabled:
        :param version:
        :param online:
        :param timing:
        :return:
        """
        all_nv = NmapVulnersSettingDb.objects.filter()
        all_nv.delete()
        if timing > 5:
            timing = 5
        elif timing < 0:
            timing = 0

        save_nv_settings = NmapVulnersSettingDb(
            enabled=enabled, version=version, online=online, timing=timing
        )
        save_nv_settings.save()

    def save_zap_settings(self, apikey, zaphost, zaport, setting_id):
        """
        Save ZAP Settings into setting file.
        :param apikey:
        :param zaphost:
        :param zaport:
        :return:
        """
        all_zap = ZapSettingsDb.objects.filter()
        all_zap.delete()

        save_zapsettings = ZapSettingsDb(
            zap_url=zaphost,
            zap_api=apikey,
            zap_port=zaport,
            setting_id=setting_id,
        )
        save_zapsettings.save()

    def save_email_settings(self, email_subject, email_from, email_to):
        """

        :param email_subject:
        :param email_from:
        :param email_to:
        :return:
        """

        try:
            with open(self.setting_file, "r+") as f:
                data = json.load(f)
                data["email_subject"] = email_subject
                data["from_email"] = email_from
                data["to_email"] = email_to
                f.seek(0)
                json.dump(data, f, indent=4)
                f.truncate()
        except Exception as e:
            return e
        return f.close()

    def email_settings(self, subject, message, recipient_list, setting_id):
        """

        :param arachnihost:
        :param arachniport:
        :return:
        """
        all_email = EmailDb.objects.filter()
        all_email.delete()

        save_emailsettings = EmailDb(
            subject=subject,
            message=message,
            setting_id=setting_id,
            recipient_list=recipient_list,
        )
        save_emailsettings.save()
