from django.db.models import Max
from rest_framework import serializers
from .models import RsmRoleMaster ,RsmUserMaster
from model_utils import Choices
from django.contrib.auth.hashers import make_password,check_password

class RsmUserMasterSeri(serializers.ModelSerializer):
    #password = serializers.CharField(read_only=True)
    class Meta:
        model = RsmUserMaster
        fields = ('user_id', 'user_name', 'password', 'email_id', 'mobile',
                  'role', 'status', 'type', 'updated_timestamp')
    def validate(self, args):
        userid = args.get('user_id', None)
        username = args.get('user_name', None)
        password = args.get('password', None)
        email = args.get('email_id', None)
        mobile = args.get('mobile', None)
        role = args.get('role', None)
        role_choice = Choices('SuperAdmin','superadmin', 'User', 'user','employee','Employee','Admin', 'admin','Manager','manager')
#changes made for testing purpose
        if RsmUserMaster.objects.filter(email_id=email).exists() or\
                RsmUserMaster.objects.filter(mobile=mobile).exists():
            raise serializers.ValidationError({'account':'account is already exists'})

        if not len(mobile) == 10 or not len(password) >= 8:
            raise serializers.ValidationError({
                'Message': [{'Contact': 'minimum 10 digit','Password': 'minimun 8 digit' }]
            })

        if role not in role_choice :
            raise serializers.ValidationError({
                'Message': [{'role': ' Mension Your Valid Role'}]
            })

        #userid = 1001 if RsmUserMaster.objects.count() == 0 else RsmUserMaster.objects.aggregate(max=Max('user_id'))["max"] + 1
        return super().validate(args)

    def create(self,validated_data):
        validated_data['password']=make_password(validated_data['password'])
        return super(RsmUserMasterSeri,self).create(validated_data)

class RsmRoleMasterSeri(serializers.ModelSerializer):
    role_id = serializers.CharField()
    role_description = serializers.CharField()
    role_type = serializers.CharField()

    class Meta:
        model = RsmRoleMaster
        fields = ('role_id', 'role_description', 'role_type','permissions','access')

class UserSeri(serializers.ModelSerializer):
    status = serializers.CharField(read_only=True)
    class Meta:
        model = RsmUserMaster
        fields = ('password', 'email_id')
    def check(self,validated_data):
        validated_data['password']=check_password(validated_data['password'])
        return super(UserSeri,self).check(validated_data)

class RsmUserUpdateSeri(serializers.ModelSerializer):
    password = serializers.CharField(read_only=True)
    class Meta:
        model = RsmUserMaster
        fields = ('user_id','user_name', 'password', 'email_id', 'mobile',
                  'role', 'status', 'type', 'updated_timestamp')

    '''def validate(self, args):
        password = args.get('password', None)
        make = make_password(password)

        if not RsmUserMaster.objects.filter(password=make).exists():
            raise serializers.ValidationError({
            'Message': [{'password': 'update required valid password'}]
            })'''

class ForgotPassSeri(serializers.ModelSerializer):
    user_name = serializers.CharField(read_only=True)
    pass
    class Meta:
        model = RsmUserMaster
        fields = 'user_name','password'

    def validate(self, args):
        verify = args.get('email_id', None)
        if RsmUserMaster.objects.filter(email_id=verify).exists():
            pass

class ResetPassSeri(serializers.ModelSerializer):
    class Meta:
        model = RsmUserMaster
        fields = ['password']
    '''def validate(self, args):
        password = args.get('password', None)

        validated = make_password(['password'])
        RsmUserMaster.objects.filter(user_name=username).update(password=validated['password'])
        return super(ResetPassSeri, self)'''

class ChangePassSeri(serializers.ModelSerializer):
    password = serializers.CharField(read_only=True)
    pass
    class Meta:
        model = RsmUserMaster
        fields = ('user_name', 'email_id', 'password')

    old_password = None