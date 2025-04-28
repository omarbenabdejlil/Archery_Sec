from django.urls import include, path
from rest_framework import routers
from rest_framework.documentation import include_docs_urls
from rest_framework.urlpatterns import format_suffix_patterns

from archeryapi import views

from networkscanners.views import (NetworkScanList, NetworkScanVulnInfo,
                                   )
from projects.views import ProjectList
from staticscanners.views import SastScanList, SastScanVulnInfo

from webscanners.views import WebScanList, WebScanVulnInfo
API_TITLE = "Archery API"
API_DESCRIPTION = (
    "Archery is an opensource vulnerability"
    " assessment and management tool which helps developers and "
    "pentesters to perform scans and manage vulnerabilities. Archery "
    "uses popular opensource tools to "
    "perform comprehensive scaning for web "
    "application and network. It also performs web application "
    "dynamic authenticated scanning and covers the whole applications "
    "by using selenium. The developers "
    "can also utilize the tool for implementation of their DevOps CI/CD environment. "
)

router = routers.DefaultRouter()

app_name = "archeryapi"

urlpatterns = [
    # path("api-auth/", include("rest_framework.urls", namespace="rest_framework")),
    path(
        "v1/docs/",
        include_docs_urls(
            title=API_TITLE,
            description=API_DESCRIPTION,
            public=True,
        ),
    ),
    path("v1/uploadscan/", views.UploadScanResult.as_view()),
    path("access-key/", views.APIKey.as_view(), name="access-key"),
    path("access-key-delete/", views.DeleteAPIKey.as_view(), name="access-key-delete"),
    # Project API
    path("v1/project-list/", ProjectList.as_view()),
    path("v1/project-list/<str:uu_id>/", ProjectList.as_view()),

    path("v1/project-create/", views.CreateProject.as_view()),
    path("v1/group-create/", views.CreateGroup.as_view()),

    # ZAP API endpoints
    path("v1/zap-scan/", views.OWASP_ZAP.as_view()),
    # Web scans API endpoints
    path("v1/web-scans/", WebScanList.as_view()),
    path("v1/web-scans/<str:uu_id>/", WebScanVulnInfo.as_view()),
    # Network scan API endpoints
    path("v1/network-scans/", NetworkScanList.as_view()),
    path("v1/network-scans/<str:uu_id>/", NetworkScanVulnInfo.as_view()),
    # Static scan API endpoints
    path("v1/sast-scans/", SastScanList.as_view()),
    path("v1/sast-scans/<str:uu_id>/", SastScanVulnInfo.as_view()),

]

urlpatterns = format_suffix_patterns(urlpatterns)
