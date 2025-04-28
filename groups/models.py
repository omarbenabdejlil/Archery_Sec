# this app is created by @Ahmed Aissa


import uuid
from django.db import models
from django.utils import timezone
from user_management.models import Organization, UserProfile

class GroupDb(models.Model):
    """Class for  model"""
    class Meta:
        db_table = "group"
        verbose_name_plural = "Groups"

    uu_id = models.UUIDField(unique=True, default=uuid.uuid4, editable=False)
    group_name = models.CharField(max_length=255)
    group_description = models.TextField(blank=True)
    total_projects = models.IntegerField(blank=True, null=True)
    created_time = models.DateTimeField(
        auto_now=True,
        blank=True,
    )
    created_by = models.ForeignKey(
        UserProfile,
        related_name="group_db_creator",
        on_delete=models.SET_NULL,
        null=True,
    )
    updated_time = models.DateTimeField(auto_now=True, blank=True, null=True)
    updated_by = models.ForeignKey(
        UserProfile,
        related_name="group_db_updated",
        on_delete=models.SET_NULL,
        null=True,
    )
    organization = models.ForeignKey(Organization, on_delete=models.CASCADE, default=1)

    def __str__(self):
        return self.group_name

    ###  Usefull for metrics ans statistique
    ### TBD: queries projects databases on demand or save data on Group_Db
    # total_vuln = models.IntegerField(blank=True, null=True)
    # total_critical = models.IntegerField(blank=True, null=True)
    # total_high = models.IntegerField(blank=True, null=True)
    # total_medium = models.IntegerField(blank=True, null=True)
    # total_low = models.IntegerField(blank=True, null=True)
    # total_open = models.IntegerField(blank=True, null=True)
    # total_false = models.IntegerField(blank=True, null=True)
    # total_close = models.IntegerField(blank=True, null=True)
    # total_net = models.IntegerField(blank=True, null=True)
    # total_web = models.IntegerField(blank=True, null=True)
    # total_static = models.IntegerField(blank=True, null=True)
    # total_cloud = models.IntegerField(blank=True, null=True)
    # critical_net = models.IntegerField(blank=True, null=True)
    # critical_web = models.IntegerField(blank=True, null=True)
    # critical_static = models.IntegerField(blank=True, null=True)
    # critical_cloud = models.IntegerField(blank=True, null=True)
    # high_net = models.IntegerField(blank=True, null=True)
    # high_web = models.IntegerField(blank=True, null=True)
    # high_static = models.IntegerField(blank=True, null=True)
    # high_cloud = models.IntegerField(blank=True, null=True)
    # medium_net = models.IntegerField(blank=True, null=True)
    # medium_web = models.IntegerField(blank=True, null=True)
    # medium_static = models.IntegerField(blank=True, null=True)
    # medium_cloud = models.IntegerField(blank=True, null=True)
    # low_net = models.IntegerField(blank=True, null=True)
    # low_web = models.IntegerField(blank=True, null=True)
    # low_static = models.IntegerField(blank=True, null=True)
    # low_cloud = models.IntegerField(blank=True, null=True)
    #

