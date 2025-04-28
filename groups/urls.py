from django.urls import path

from groups import views

app_name = "groups"

urlpatterns = [
    path("", views.GroupList.as_view(), name="groups_list"),
    path("group_create/", views.GroupCreate.as_view(), name="group_create"),
    path("group_delete/", views.GroupDelete.as_view(), name="group_delete"),
    path("group_update/", views.update_group, name="group_update"),

    # path("", views.GroupProjects.as_view(), name="group_projects"),

]