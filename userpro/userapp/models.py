from django.db import models
from django.contrib.auth import models as auth_models
from django.core.validators import MinLengthValidator
from django.dispatch import receiver
from django.urls import reverse
from django_rest_passwordreset.signals import reset_password_token_created
from django.core.mail import send_mail

class RsmRoleMaster(models.Model):
    role_id = models.CharField( primary_key=True, max_length=11)
    role_description = models.CharField( max_length=45, blank=True,null=True)
    role_type = models.CharField( max_length=45, blank=True,null=True)
    permissions = models.CharField(max_length=500)
    class Meta:
        managed = False
        db_table = 'RSM_ROLE_MASTER'

class RsmUserMaster(models.Model):
    user_id = models.CharField(primary_key=True, max_length=45)
    user_name = models.CharField(max_length=45, blank=True, null=True)
    password = models.CharField(max_length=128,blank=False, null=False,validators=[MinLengthValidator(8)])
    email_id = models.CharField(max_length=100, blank=True, null=True)
    mobile = models.CharField(max_length=15, unique=True, blank=False, null=False,validators=[MinLengthValidator(10)])
    role = models.CharField(max_length=45, blank=True, null=True)
    status = models.CharField(max_length=45,default="0", blank=True, null=True)
    type = models.CharField(max_length=45, blank=True, null=True)
    updated_timestamp = models.DateTimeField(auto_now_add=True,blank=True, null=True)

    class Meta:
        managed = False
        db_table = 'RSM_USER_MASTER'