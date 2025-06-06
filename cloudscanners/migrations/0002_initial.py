# Generated by Django 3.2.15 on 2024-05-22 15:53

from django.conf import settings
from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    initial = True

    dependencies = [
        migrations.swappable_dependency(settings.AUTH_USER_MODEL),
        ('projects', '0001_initial'),
        ('user_management', '0001_initial'),
        ('cloudscanners', '0001_initial'),
    ]

    operations = [
        migrations.AddField(
            model_name='cloudscansresultsdb',
            name='created_by',
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='cloud_scan_result_db_created', to=settings.AUTH_USER_MODEL),
        ),
        migrations.AddField(
            model_name='cloudscansresultsdb',
            name='organization',
            field=models.ForeignKey(default=1, on_delete=django.db.models.deletion.CASCADE, to='user_management.organization'),
        ),
        migrations.AddField(
            model_name='cloudscansresultsdb',
            name='project',
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, to='projects.projectdb'),
        ),
        migrations.AddField(
            model_name='cloudscansresultsdb',
            name='updated_by',
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='cloud_scan_result_db_updated', to=settings.AUTH_USER_MODEL),
        ),
        migrations.AddField(
            model_name='cloudscansdb',
            name='created_by',
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='cloud_scan_db_created', to=settings.AUTH_USER_MODEL),
        ),
        migrations.AddField(
            model_name='cloudscansdb',
            name='organization',
            field=models.ForeignKey(default=1, on_delete=django.db.models.deletion.CASCADE, to='user_management.organization'),
        ),
        migrations.AddField(
            model_name='cloudscansdb',
            name='project',
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.CASCADE, to='projects.projectdb'),
        ),
        migrations.AddField(
            model_name='cloudscansdb',
            name='updated_by',
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='cloud_scan_db_updated', to=settings.AUTH_USER_MODEL),
        ),
    ]
