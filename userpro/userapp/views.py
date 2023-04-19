from datetime import datetime
from django.contrib.auth.hashers import check_password
import uuid
from django.core.exceptions import ObjectDoesNotExist
from django.core.mail import send_mail

from rest_framework import viewsets, status, views, exceptions, response
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from .models import RsmUserMaster
from .serializers import RsmUserMasterSeri, RsmUserUpdateSeri, ResetPassSeri
from .import serializers as user_serializer
from .import services

class RsmUser(viewsets.ModelViewSet):
    queryset = RsmUserMaster.objects.raw('select user_id, user_name,password,email_id,mobile,role,status,type,updated_timestamp from hes_exp.RSM_USER_MASTER')
    serializer_class = RsmUserMasterSeri

class Usergetall(views.APIView):

    def get(self, request, format=None):
        queryset = RsmUserMaster.objects.all()
        serializer = RsmUserMasterSeri(queryset, many=True)
        return Response(serializer.data,status=status.HTTP_302_FOUND)

class UserRegister(views.APIView):
    query = RsmUserMaster

    def post(self, request, *args, **kwargs):
        serializer = user_serializer.RsmUserMasterSeri(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data
        serializer.instance = serializer.create(data)
        return Response({'status': 'success','status_code': status.HTTP_201_CREATED,
                         'message': 'Registered Successfully.','data': [serializer.data]})

class UserLogin(views.APIView):
    def post(self, request):
        username = request.data["user_name"]
        password = request.data["password"]
        check_email = services.user_email_selector(username)
        user = RsmUserMaster.objects.filter(user_name=username).first()
        if user is None:
            raise exceptions.AuthenticationFailed({'status': 'failure','password':user,
                                                   'status_code': status.HTTP_400_BAD_REQUEST,"Message": "Invalid UserName."})

        pass_check = check_password(password, check_email.password)

        if pass_check is True:
            RsmUserMaster.objects.filter(user_name=username).update(updated_timestamp=datetime.now())
            RsmUserMaster.objects.filter(user_name=username).update(status="1")
            token = services.create_token(user_name=check_email.user_name)
            resp = response. Response({
                'status': 'success','status_code': status.HTTP_200_OK,'password':pass_check,
                'message': 'Login Successfully.','access_token': token})
            resp.set_cookie(key="jwt", value=token, httponly=True)  # secure=True secure the token(hidden form)
            return resp
        return Response({'status': 'failure','password':pass_check,
                         'status_code': status.HTTP_400_BAD_REQUEST,'message': 'Enter Valid Password.'})

class UserGet(views.APIView):

    def get(self, request, pk, format=None):
        try:
            queryset = RsmUserMaster.objects.filter(user_name=pk).latest('updated_timestamp')
            serializer = RsmUserUpdateSeri(queryset, many=False)
            if serializer is not None:
                return Response({'status': 'success', 'status_code': status.HTTP_302_FOUND, 'Data': serializer.data})

        except ObjectDoesNotExist:
            user = RsmUserMaster.objects.filter(user_name=pk).first()
            if user is None:
                raise exceptions.AuthenticationFailed({'status': 'Failure', 'status_code': status.HTTP_400_BAD_REQUEST,
                             'Message': 'Data Not Found'})

class UserUpdate(views.APIView):

    def get_object(self, pk):
        try:
            return RsmUserMaster.objects.get(user_id=pk)
        except ObjectDoesNotExist:
            return Response({'status': 'Failure', 'status_code': status.HTTP_400_BAD_REQUEST,
                             'Message': 'Data Not Found'})

    def get(self, request, pk, format=None): #without getting also working
        queryset = RsmUserMaster.objects.get(user_id=pk)
        serializer = RsmUserUpdateSeri(queryset, many=False)
        return Response({'status': 'success','status_code': status.HTTP_302_FOUND,'Data': serializer.data})

    def patch(self, request, pk, format=None):
        snippet = self.get_object(pk)
        serializer = RsmUserUpdateSeri(snippet, data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({'status': 'success', 'code': status.HTTP_302_FOUND, 'Data': serializer.data,
                             'Message': 'Updated Successfully'})
        if not serializer.is_valid():
            return Response({'status': 'Failure', 'code': status.HTTP_400_BAD_REQUEST, 'Message': 'No changes made for Updation'})

class UserDelete(views.APIView):
    serializer = RsmUserMasterSeri

    def get_object(self, pk):
        try:
            return RsmUserMaster.objects.get(user_id=pk)
        except ObjectDoesNotExist:
            return Response({'status': 'Failure', 'status_code': status.HTTP_400_BAD_REQUEST,
                             'Message': 'Data Not Found'})

    def get(self, request, pk, format=None): #without getting also working
        queryset = RsmUserMaster.objects.get(user_id=pk)
        serializer = RsmUserUpdateSeri(queryset, many=False)
        return Response({'status': 'success','status_code': status.HTTP_302_FOUND,'Data': serializer.data})

    def delete(self, request, pk, format=None):
        snippet = self.get_object(pk)
        snippet.delete()
        return Response({'status': 'success','status_code': status.HTTP_302_FOUND,'Message': 'Deleted Successfully'})

class ForgotPass(views.APIView):
    def post(self, request):
        email = request.data["email_id"]
        if RsmUserMaster.objects.filter(email_id=email).first():
            fptoken_cookie = str(uuid.uuid4())
            services.send_forget_password(email, fptoken_cookie)
            fpresponse = response. Response({'status': 'success', 'Message':
                'Check your mail,forgot password TOKEN have sent to your mailID',
                             'email_id':email,'status_code':status.HTTP_200_OK})
            fpresponse.set_cookie(key="jwt", value=fptoken_cookie, httponly=True,secure=True)  # secure=True secure the token(hidden form)
            return fpresponse

        if not RsmUserMaster.objects.filter(email_id=email).first():
            return Response({'status': 'fail','Message':'MailID Not Matched or Not Exist.',
                             'status_code':status.HTTP_400_BAD_REQUEST})

class ResetPassword(views.APIView):
    def post(self, request,id):
        user = RsmUserMaster.objects.get(id=user_id)
        password = request.data.get('password')
        user.set_password(password)
        user.save()
        return Response({'status': 'success', 'Message': 'Password reset successfully.',
                         'status_code': status.HTTP_200_OK})

class ResetPass(views.APIView):
    def post(self, request,fptoken_cookie):
        fptoken_cookie = request.COOKIES.get('jwt')
        if not fptoken_cookie:
            return Response({'status': 'fail', 'Message': 'Invalid or expired token.', 'status_code': status.HTTP_400_BAD_REQUEST})
        try:
            payload = jwt.decode(fptoken_cookie, settings.SECRET_KEY, algorithms=['HS256'])
        except jwt.ExpiredSignatureError:
            return Response({'status': 'fail', 'Message': 'Token expired.', 'status_code': status.HTTP_400_BAD_REQUEST})
        except jwt.InvalidTokenError:
            return Response({'status': 'fail', 'Message': 'Invalid token.', 'status_code': status.HTTP_400_BAD_REQUEST})
        user_id = payload['user_id']
        user = RsmUserMaster.objects.get(id=user_id)
        password = request.data['password']
        confirm_password = request.data['password']
        if password != confirm_password:
            return Response({'status': 'fail', 'Message': 'Passwords do not match.', 'status_code': status.HTTP_400_BAD_REQUEST})
        user.set_password(password)
        user.save()
        response.delete_cookie('jwt')
        return Response({'status': 'success', 'Message': 'Password reset successfully.', 'status_code': status.HTTP_200_OK})

class Changepass(views.APIView):
# if 'token' in request.session and request.POST.get('token') == request.session['token']:
    def patch(self, request):
        token = kwargs.get('token')
        session_id = self.request.session.session_key
        if token == session_id:
            serializer = ResetPassSeri(data=request.data)
            serializer.is_valid(raise_exception=True)
            serializer.save()
            return Response({'status': 'success', 'status_code': status.HTTP_302_FOUND, 'Data': serializer.data,
                             'Message': 'Updated Successfully'})
        else:
            return Response({'status': 'Failure', 'status_code': status.HTTP_400_BAD_REQUEST,
                             'Message': 'Try with another mailid.'})

class UserLogout(views.APIView):
    def post(self,request):
        email = request.data["email_id"]
        user = RsmUserMaster.objects.all()
        resp = response.Response()
        resp.delete_cookie("jwt")
        RsmUserMaster.objects.filter(email_id=email).update(updated_timestamp=datetime.now())
        resp.data = {'status': 'success','code': status.HTTP_302_FOUND,'Message': 'Logout Successfully'}
        return resp
