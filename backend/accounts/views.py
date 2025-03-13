from django.shortcuts import render
from django.core.mail import send_mail
from django.conf import settings
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.utils import timezone
from .models import (
    CustomUser, COUNTRY, STATE, CITY, 
    CURRENCY, LANGUAGE, DESIGNATION, CATEGORY,
    UNIVERSITY, INSTITUTE, DEPARTMENT, PROGRAM, BRANCH, DASHBOARD_MASTER,
    YEAR, SEMESTER, SEMESTER_DURATION,CASTE_MASTER,QUOTA_MASTER,ADMISSION_QUOTA_MASTER
)
from rest_framework.decorators import api_view
from django.contrib.auth import authenticate
from rest_framework_simplejwt.tokens import RefreshToken
from .serializers import (
    CountrySerializer, StateSerializer, CitySerializer,
    CurrencySerializer, LanguageSerializer, DesignationSerializer,
    CategorySerializer, UniversitySerializer, InstituteSerializer, 
    DepartmentSerializer, ProgramSerializer, BranchSerializer, 
    DashboardMasterSerializer, YearSerializer, SemesterSerializer, SemesterDurationSerializer,CasteSerializer,QuotaSerializer,AdmissionQuotaSerializer
)

from rest_framework import viewsets
from rest_framework.permissions import IsAuthenticated
from django.views.decorators.csrf import ensure_csrf_cookie
from django.utils.decorators import method_decorator
from rest_framework_simplejwt.settings import api_settings
from rest_framework.permissions import AllowAny
from .models import STATE
from .serializers import StateSerializer
from .models import CITY, CURRENCY, LANGUAGE, DESIGNATION, CATEGORY, UNIVERSITY, INSTITUTE, ACADEMIC_YEAR
from .serializers import (CitySerializer, CurrencySerializer, 
                        LanguageSerializer, DesignationSerializer, CategorySerializer, UniversitySerializer, InstituteSerializer, AcademicYearSerializer)
from django.http import JsonResponse
from django.db import connection
import logging  # Add this at the top with other imports
from establishments.models import EMPLOYEE_MASTER  # Add this import

logger = logging.getLogger(__name__)  # Add this after imports


class LoginView(APIView):
    permission_classes = [AllowAny]  # Allow unauthenticated access
    
    def post(self, request):
        print("==== Login Request ====")
        print(f"Request Data: {request.data}")
        print(f"Request Headers: {request.headers}")
        print(f"Request Method: {request.method}")
        print(f"Request Path: {request.path}")
        
        user_id = request.data.get('user_id')
        password = request.data.get('password')

        if not user_id or not password:
            print(f"Missing credentials - user_id: {bool(user_id)}, password: {bool(password)}")
            return Response({
                'status': 'error',
                'message': 'Please provide both USER_ID and PASSWORD'
            }, status=status.HTTP_400_BAD_REQUEST)

        try:
            print(f"Looking for user with ID: {user_id.upper()}")
            user = CustomUser.objects.get(USER_ID=user_id.upper())
            
            print(f"Login attempt for user: {user.USER_ID}")
            print(f"Failed attempts: {user.FAILED_LOGIN_ATTEMPTS}")
            print(f"Last failed login: {user.LAST_FAILED_LOGIN}")
            print(f"Permanent lock: {user.PERMANENT_LOCK}")

            if not user.IS_ACTIVE:
                return Response({
                    'status': 'error',
                    'message': 'Account is not active'
                }, status=status.HTTP_403_FORBIDDEN)

            # Check account lock status
            is_locked, lock_message = user.is_account_locked()
            if is_locked:
                return Response({
                    'status': 'error',
                    'message': lock_message
                }, status=status.HTTP_403_FORBIDDEN)

            # Verify password
            if not user.check_password(password):
                user.increment_failed_attempts()
                
                remaining_attempts = 0
                if user.FAILED_LOGIN_ATTEMPTS < 3:
                    remaining_attempts = 3 - user.FAILED_LOGIN_ATTEMPTS
                elif user.FAILED_LOGIN_ATTEMPTS < 5:
                    remaining_attempts = 5 - user.FAILED_LOGIN_ATTEMPTS
                elif user.FAILED_LOGIN_ATTEMPTS < 8:
                    remaining_attempts = 8 - user.FAILED_LOGIN_ATTEMPTS
                
                message = "Invalid credentials. "
                if remaining_attempts > 0:
                    message += f"{remaining_attempts} attempts remaining before next level of account lock."
                else:
                    message += "Account will be locked due to too many failed attempts."
                
                return Response({
                    'status': 'error',
                    'message': message
                }, status=status.HTTP_401_UNAUTHORIZED)

            # Reset failed attempts on successful login
            user.reset_failed_attempts()

            # Generate and send OTP
            otp = user.generate_otp()
            
            try:
                send_mail(
                    subject='Login Verification OTP - College ERP',
                    message=(
                        f'Dear {user.FIRST_NAME},\n\n'
                        f'Your verification OTP is: {otp}\n'
                        f'This OTP will expire in 3 minutes.\n\n'
                        f'If you did not attempt to login, please secure your account.\n\n'
                        f'Best regards,\n'
                        f'College ERP Team'
                    ),
                    from_email=settings.DEFAULT_FROM_EMAIL,
                    recipient_list=[user.EMAIL],
                    fail_silently=False,
                )
                
                return Response({
                    'status': 'success',
                    'message': 'Login successful. Please verify OTP sent to your email.',
                    'user_id': user.USER_ID,
                    'email': user.EMAIL[:3] + '*' * (len(user.EMAIL.split('@')[0]) - 3) + '@' + user.EMAIL.split('@')[1]
                }, status=status.HTTP_200_OK)
                
            except Exception as e:
                user.OTP_SECRET = None
                user.save()
                return Response({
                    'status': 'error',
                    'message': 'Failed to send verification OTP. Please try again.'
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
                
        except CustomUser.DoesNotExist:
            return Response({
                'status': 'error',
                'message': 'Invalid USER_ID'
            }, status=status.HTTP_404_NOT_FOUND)

@method_decorator(ensure_csrf_cookie, name='dispatch')
class SendOTPView(APIView):
    permission_classes = [AllowAny]  # Allow unauthenticated access
    
    def post(self, request):
        user_id = request.data.get('user_id')
        if not user_id:
            return Response({
                'status': 'error',
                'message': 'Please provide USER_ID'
            }, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            user = CustomUser.objects.get(USER_ID=user_id)
            
            if not user.IS_ACTIVE:
                return Response({
                    'status': 'error',
                    'message': 'Account is not active'
                }, status=status.HTTP_403_FORBIDDEN)
 
            # Check account lock status and get detailed message
            is_locked, lock_message = user.is_account_locked()
            if is_locked:
                return Response({
                    'status': 'error',
                    'message': lock_message,
                    'locked': True,
                    'lockTime': user.LOCK_EXPIRY.isoformat() if user.LOCK_EXPIRY else None
                }, status=status.HTTP_403_FORBIDDEN)

            otp = user.generate_otp()
            
            try:
                send_mail(
                    subject='Login OTP - College ERP',
                    message=(
                        f'Dear {user.FIRST_NAME},\n\n'
                        f'Your OTP for login is: {otp}\n'
                        f'This OTP will expire in 3 minutes.\n\n'
                        f'If you did not request this OTP, please ignore this email.\n\n'
                        f'Best regards,\n'
                        f'College ERP Team'
                    ),
                    from_email=settings.DEFAULT_FROM_EMAIL,
                    recipient_list=[user.EMAIL],
                    fail_silently=False,
                )
                
                return Response({
                    'status': 'success',
                    'message': f'OTP sent successfully to {user.EMAIL}',
                    'user_id': user.USER_ID,
                    'email': user.EMAIL[:3] + '*' * (len(user.EMAIL.split('@')[0]) - 3) + '@' + user.EMAIL.split('@')[1]
                }, status=status.HTTP_200_OK)
                
            except Exception as e:
                user.OTP_SECRET = None
                user.save()
                return Response({
                    'status': 'error',
                    'message': 'Failed to send OTP email. Please try again.'
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        
        except CustomUser.DoesNotExist:
            return Response({
                'status': 'error',
                'message': 'Invalid USER_ID'
            }, status=status.HTTP_404_NOT_FOUND)

class VerifyOTPView(APIView):
    permission_classes = [AllowAny]  # Allow unauthenticated access
    
    def post(self, request):
        user_id = request.data.get('user_id')
        otp = request.data.get('otp')
        
        if not user_id or not otp:
            return Response({
                'status': 'error',
                'message': 'Both user_id and OTP are required'
            }, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = CustomUser.objects.get(USER_ID=user_id)
            is_valid, message = user.verify_otp(otp)
            
            if is_valid:
                # Update login info
                user.update_login_info(request.META.get('REMOTE_ADDR'))
                
                # Get employee details if they exist
                try:
                    employee = EMPLOYEE_MASTER.objects.get(EMPLOYEE_ID=user.USER_ID)
                    department_id = employee.DEPARTMENT.DEPARTMENT_ID if employee.DEPARTMENT else None
                    institute_id = employee.INSTITUTE.INSTITUTE_ID if employee.INSTITUTE else None
                    institute_code = employee.INSTITUTE.CODE if employee.INSTITUTE else None
                    emp_name = employee.EMP_NAME  # Get EMP_NAME
                except EMPLOYEE_MASTER.DoesNotExist:
                    department_id = None
                    institute_id = None
                    institute_code = None
                    emp_name = user.FIRST_NAME  # Set default to user's FIRST_NAME
                    
                # Store session data with emp_name
                session_data = {
                    'user_id': user.USER_ID,
                    'name': emp_name,  # Now emp_name will always be defined
                    'email': user.EMAIL,
                    'is_superuser': user.IS_SUPERUSER,
                    'designation': {
                        'code': user.DESIGNATION.CODE,
                        'name': user.DESIGNATION.NAME,
                    },
                    'permissions': user.DESIGNATION.PERMISSIONS,
                    'last_activity': timezone.now().isoformat(),
                    'department_id': department_id,
                    'institute_id': institute_id,
                    'institute_code': institute_code
                }
                
                # Store all session data
                for key, value in session_data.items():
                    request.session[key] = value
                
                # Generate tokens
                refresh = RefreshToken()
                refresh[api_settings.USER_ID_CLAIM] = user.USER_ID
                refresh['user_id'] = user.USER_ID
                refresh['username'] = user.USERNAME
                refresh['is_superuser'] = user.IS_SUPERUSER
                
                return Response({
                    'status': 'success',
                    'message': message,
                    'token': str(refresh.access_token),
                    'refresh': str(refresh),
                    'user': session_data
                }, status=status.HTTP_200_OK)
            
            return Response({
                'status': 'error',
                'message': message
            }, status=status.HTTP_400_BAD_REQUEST)
            
        except CustomUser.DoesNotExist:
            return Response({
                'status': 'error',
                'message': 'Invalid user'
            }, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            logger.error(f"Error in VerifyOTPView: {str(e)}")
            return Response({
                'status': 'error',
                'message': 'An error occurred during authentication'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class RequestPasswordResetView(APIView):
    def post(self, request):
        user_id = request.data.get('user_id')
        
        if not user_id:
            return Response({
                'status': 'error',
                'message': 'Please provide USER_ID'
            }, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = CustomUser.objects.get(USER_ID=user_id.upper())
            
            if not user.IS_ACTIVE:
                return Response({
                    'status': 'error',
                    'message': 'Account is not active'
                }, status=status.HTTP_403_FORBIDDEN)

            # Generate and send OTP
            otp = user.generate_otp()
            
            try:
                send_mail(
                    subject='Password Reset OTP - College ERP',
                    message=(
                        f'Dear {user.FIRST_NAME},\n\n'
                        f'Your password reset OTP is: {otp}\n'
                        f'This OTP will expire in 3 minutes.\n\n'
                        f'If you did not request a password reset, please ignore this email.\n\n'
                        f'Best regards,\n'
                        f'College ERP Team'
                    ),
                    from_email=settings.DEFAULT_FROM_EMAIL,
                    recipient_list=[user.EMAIL],
                    fail_silently=False,
                )
                
                return Response({
                    'status': 'success',
                    'message': 'Password reset OTP sent successfully',
                    'email': user.EMAIL[:3] + '*' * (len(user.EMAIL.split('@')[0]) - 3) + '@' + user.EMAIL.split('@')[1]
                }, status=status.HTTP_200_OK)
                
            except Exception as e:
                user.OTP_SECRET = None
                user.save()
                return Response({
                    'status': 'error',
                    'message': 'Failed to send OTP email'
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
                
        except CustomUser.DoesNotExist:
            return Response({
                'status': 'error',
                'message': 'User not found'
            }, status=status.HTTP_404_NOT_FOUND)

class VerifyResetOTPView(APIView):
    def post(self, request):
        user_id = request.data.get('user_id')
        otp = request.data.get('otp')
        
        if not user_id or not otp:
            return Response({
                'status': 'error',
                'message': 'Please provide both USER_ID and OTP'
            }, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = CustomUser.objects.get(USER_ID=user_id.upper())
            is_valid, message = user.verify_otp(otp)
            
            return Response({
                'status': 'success' if is_valid else 'error',
                'message': message,
                'verified': is_valid
            }, status=status.HTTP_200_OK if is_valid else status.HTTP_4REQUEST)
            
        except CustomUser.DoesNotExist:
            return Response({
                'status': 'error',
                'message': 'User not found'
            }, status=status.HTTP_404_NOT_FOUND)

class ResetPasswordView(APIView):
    def post(self, request):
        user_id = request.data.get('user_id')
        otp = request.data.get('otp')
        new_password = request.data.get('new_password')
        
        if not all([user_id, otp, new_password]):
            return Response({
                'status': 'error',
                'message': 'Please provide USER_ID, OTP and new password'
            }, status=status.HTTP_400_BAD_REQUEST)

        try:
            user = CustomUser.objects.get(USER_ID=user_id.upper())
            is_valid, message = user.verify_otp(otp)
            
            if not is_valid:
                return Response({
                    'status': 'error',
                    'message': message
                }, status=status.HTTP_400_BAD_REQUEST)
            
            # Set new password
            user.set_password(new_password)
            user.OTP_SECRET = None  # Clear OTP after successful password reset
            user.save()
            
            return Response({
                'status': 'success',
                'message': 'Password reset successful'
            }, status=status.HTTP_200_OK)
            
        except CustomUser.DoesNotExist:
            return Response({
                'status': 'error',
                'message': 'User not found'
            }, status=status.HTTP_404_NOT_FOUND)

class MasterTableListView(APIView):
    def get(self, request):
        master_tables = [
            {"name": "country", "display_name": "Country", "endpoint": "http://localhost:8000/api/master/countries/"},
            {"name": "state", "display_name": "State", "endpoint": "http://localhost:8000/api/master/states/"},
            {"name": "city", "display_name": "City", "endpoint": "http://localhost:8000/api/master/cities/"},
            {"name": "currency", "display_name": "Currency", "endpoint": "http://localhost:8000/api/master/currencies/"},
            {"name": "language", "display_name": "Language", "endpoint": "http://localhost:8000/api/master/languages/"},
            {"name": "designation", "display_name": "Designation", "endpoint": "http://localhost:8000/api/master/designations/"},
            {"name": "department", "display_name": "Department", "endpoint": "http://localhost:8000/api/master/departments/"},
            {"name": "category", "display_name": "Category", "endpoint": "http://localhost:8000/api/master/categories/"}
        ]
        return Response(master_tables)

class BaseModelViewSet(viewsets.ModelViewSet):
    permission_classes = [IsAuthenticated]

    def perform_create(self, serializer):
        print(f"=== Debug Create by {self.request.user.USERNAME} ===")
        # Pass values directly to serializer save
        instance = serializer.save()
        instance.CREATED_BY = str(self.request.user.USERNAME)
        instance.UPDATED_BY = str(self.request.user.USERNAME)
        instance.save()

    def perform_update(self, serializer):
        print(f"=== Debug Update by {self.request.user.USERNAME} ===")
        # Update existing instance
        instance = serializer.save()
        instance.UPDATED_BY = str(self.request.user.USERNAME)
        instance.save()

# Update all ViewSets to inherit from BaseModelViewSet
class CountryViewSet(BaseModelViewSet):
    queryset = COUNTRY.objects.all()
    serializer_class = CountrySerializer

    def list(self, request, *args, **kwargs):
        countries = self.queryset.filter(IS_ACTIVE=True)
        serializer = self.get_serializer(countries, many=True)
        return Response(serializer.data)

class StateViewSet(BaseModelViewSet):
    queryset = STATE.objects.all()
    serializer_class = StateSerializer

    def list(self, request, *args, **kwargs):
        states = self.queryset.filter(IS_ACTIVE=True)
        serializer = self.get_serializer(states, many=True)
        return Response(serializer.data)

class CityViewSet(BaseModelViewSet):
    queryset = CITY.objects.all()
    serializer_class = CitySerializer

    def list(self, request, *args, **kwargs):
        cities = self.queryset.filter(IS_ACTIVE=True)
        serializer = self.get_serializer(cities, many=True)
        return Response(serializer.data)

class CurrencyViewSet(BaseModelViewSet):
    queryset = CURRENCY.objects.all()
    serializer_class = CurrencySerializer

    def list(self, request, *args, **kwargs):
        currencies = self.queryset.filter(IS_ACTIVE=True)
        serializer = self.get_serializer(currencies, many=True)
        return Response(serializer.data)

class LanguageViewSet(BaseModelViewSet):
    queryset = LANGUAGE.objects.all()
    serializer_class = LanguageSerializer

    def list(self, request, *args, **kwargs):
        languages = self.queryset.filter(IS_ACTIVE=True)
        serializer = self.get_serializer(languages, many=True)
        return Response(serializer.data)

class DesignationViewSet(BaseModelViewSet):
    queryset = DESIGNATION.objects.all()
    serializer_class = DesignationSerializer

    def list(self, request, *args, **kwargs):
        designations = self.queryset.filter(IS_ACTIVE=True)
        serializer = self.get_serializer(designations, many=True)
        return Response(serializer.data)

class CategoryViewSet(BaseModelViewSet):
    queryset = CATEGORY.objects.all()
    serializer_class = CategorySerializer

    def create(self, request, *args, **kwargs):
        try:
            # Validate required fields
            required_fields = {
                'NAME': 'Category name',
                'CODE': 'Category code',
                'RESERVATION_PERCENTAGE': 'Reservation percentage'
            }
            
            missing_fields = [
                field_name for field, field_name in required_fields.items() 
                if field not in request.data
            ]
            
            if missing_fields:
                return Response({
                    'error': 'Missing required fields',
                    'message': f"Please provide: {', '.join(missing_fields)}",
                    'fields': missing_fields
                }, status=status.HTTP_400_BAD_REQUEST)

            # Create category with proper error handling
            serializer = self.get_serializer(data=request.data)
            
            try:
                serializer.is_valid(raise_exception=True)
            except serializers.ValidationError as e:
                # Get the first validation error
                error_detail = e.detail
                if isinstance(error_detail, dict) and 'error' in error_detail:
                    # If it's our custom formatted error, return as is
                    return Response(error_detail, status=status.HTTP_400_BAD_REQUEST)
                else:
                    # Format other validation errors
                    field = list(error_detail.keys())[0]
                    return Response({
                        'error': 'Validation error',
                        'message': str(error_detail[field][0]),
                        'field': field
                    }, status=status.HTTP_400_BAD_REQUEST)

            self.perform_create(serializer)
            
            return Response({
                'status': 'success',
                'message': 'Category created successfully',
                'data': serializer.data
            }, status=status.HTTP_201_CREATED)
            
        except Exception as e:
            return Response({
                'error': 'Server error',
                'message': 'An unexpected error occurred while creating the category',
                'detail': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def list(self, request, *args, **kwargs):
        categories = self.queryset.filter(IS_ACTIVE=True)
        serializer = self.get_serializer(categories, many=True)
        return Response(serializer.data)
    

class UniversityViewSet(BaseModelViewSet):
    queryset = UNIVERSITY.objects.all()
    serializer_class = UniversitySerializer

    def list(self, request, *args, **kwargs):
        universities = self.queryset.filter(IS_ACTIVE=True)
        serializer = self.get_serializer(universities, many=True)
        return Response(serializer.data)

class InstituteViewSet(BaseModelViewSet):
    queryset = INSTITUTE.objects.all()
    serializer_class = InstituteSerializer
    
    def list(self, request, *args, **kwargs):
        institutes = self.queryset.filter(IS_ACTIVE=True)
        serializer = self.get_serializer(institutes, many=True)
        return Response(serializer.data)

    def list(self, request, *args, **kwargs):
        university_id = request.query_params.get('university_id', None)
        
        # Filter institutes by IS_ACTIVE and optionally by university_id
        if university_id:
            institutes = self.queryset.filter(IS_ACTIVE=True, UNIVERSITY_id=university_id)
        else:
            institutes = self.queryset.filter(IS_ACTIVE=True)
        
        serializer = self.get_serializer(institutes, many=True)
        return Response(serializer.data)

    def list(self, request, *args, **kwargs):
        university_id = request.query_params.get('university_id', None)
        
        # Filter institutes by IS_ACTIVE and optionally by university_id
        if university_id:
            institutes = self.queryset.filter(IS_ACTIVE=True, UNIVERSITY_id=university_id)
        else:
            institutes = self.queryset.filter(IS_ACTIVE=True)
        
        serializer = self.get_serializer(institutes, many=True)
        return Response(serializer.data)
            
class AcademicYearViewSet(BaseModelViewSet):
    queryset = ACADEMIC_YEAR.objects.all()
    serializer_class = AcademicYearSerializer

    def create(self, request, *args, **kwargs):
        data = request.data
        serializer = self.get_serializer(data=data)

        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
        # institutes = self.queryset.filter(IS_ACTIVE=True)
        # serializer = self.get_serializer(institutes, many=True)
        # return Response(serializer.data)
   
class DepartmentViewSet(BaseModelViewSet):
    queryset = DEPARTMENT.objects.all()
    serializer_class = DepartmentSerializer

    def list(self, request, *args, **kwargs):
        departments = self.queryset.filter(IS_ACTIVE=True)
        serializer = self.get_serializer(departments, many=True)
        return Response(serializer.data)
    
class ProgramListCreateView(BaseModelViewSet):
    queryset = PROGRAM.objects.all()
    serializer_class = ProgramSerializer
    permission_classes = [AllowAny]

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(
                {"message": "Program created successfully!", "data": serializer.data},
                status=status.HTTP_201_CREATED,
            )
        
        print("Serializer Errors:", serializer.errors)  # 🔥 Print errors to console
        return Response(
            {"error": serializer.errors}, 
            status=status.HTTP_400_BAD_REQUEST
        )
    def list(self, request, *args, **kwargs):
        institute_id = request.GET.get("institute_id")  # Get institute_id from query params
        programs = self.queryset.filter(IS_ACTIVE=True)  # Base queryset (filtered by IS_ACTIVE=True)

        if institute_id:
            institute_id = int(institute_id)
            programs = programs.filter(INSTITUTE=institute_id)

        serializer = self.get_serializer(programs, many=True)
        return Response(serializer.data)
    
    def update(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response(
                {"message": "Program updated successfully!", "data": serializer.data},
                status=status.HTTP_200_OK,
            )

        print("Update Errors:", serializer.errors)
        return Response(
            {"error": serializer.errors},
            status=status.HTTP_400_BAD_REQUEST,
        )

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        instance.delete()
        return Response(
            {"message": "Program deleted successfully!"},
            status=status.HTTP_204_NO_CONTENT,
        )        
        
from django.http import JsonResponse
from django.views import View

from django.http import JsonResponse
from django.views import View

class ProgramTableListView(View):
    def get(self, request):
        program_master = [  # ✅ Fixed variable name (no hyphen)
            {"name": "program", "display_name": "Program", "api_url": "http://localhost:8000/api/master/program/"},
            {"name": "BRANCH_MASTER", "display_name": "Branch"},
            {"name": "YEAR_MASTER", "display_name": "Year"},
            {"name": "SEMESTER_MASTER", "display_name": "Semester"},
            {"name": "COURSE_MASTER", "display_name": "Course"},
        ]
        return JsonResponse(program_master, safe=False)  # ✅ Fixed variable reference



class BranchListCreateView(BaseModelViewSet):
    queryset = BRANCH.objects.all().select_related("PROGRAM") 
    serializer_class = BranchSerializer

    def post(self, request):
        try:
            # Clear user session
            request.session.flush()
            
            # Blacklist the JWT token if you're using JWT
            try:
                refresh_token = request.data.get('refresh_token')
                if refresh_token:
                    token = RefreshToken(refresh_token)
                    token.blacklist()
            except Exception as e:
                logger.warning(f"Error blacklisting token: {str(e)}")
            
            return Response({
                'status': 'success',
                'message': 'Successfully logged out'
            })
        except Exception as e:
            logger.error(f"Error in logout: {str(e)}")
            return Response({
                'status': 'error',
                'message': 'Error during logout'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response(
                {"message": "Branch created successfully!", "data": serializer.data},
                status=status.HTTP_201_CREATED,
            )

        print("Serializer Errors:", serializer.errors)  # Debugging
        return Response(
            {"error": serializer.errors},
            status=status.HTTP_400_BAD_REQUEST,
        )
    def list(self, request, *args, **kwargs):
        program_id = request.GET.get("program_id")  # Get program_id from query params
        branches = self.queryset.filter(IS_ACTIVE=True)  # Base queryset with active branches

        if program_id:
            # try:
                program_id = int(program_id)
                branches = branches.filter(PROGRAM=program_id)
        #     except ValueError:
        #         return Response({"error": "Invalid Program ID"}, status=status.HTTP_400_BAD_REQUEST)

        serializer = self.get_serializer(branches, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
    
    # def list(self, request, *args, **kwargs):
    #     branch_id = request.GET.get("branch_id")  # Get branch_id from query params
    #     years = self.queryset  # Get base queryset of active years

    #     if branch_id:
    #         try:
    #             branch_id = int(branch_id)
    #             years = years.filter(BRANCH=branch_id)  # Filter years by branch
    #         except ValueError:
    #             return Response({"error": "Invalid Branch ID"}, status=status.HTTP_400_BAD_REQUEST)

    #     serializer = self.get_serializer(years, many=True)
    #     return Response(serializer.data, status=status.HTTP_200_OK)
    
    

class LogoutView(APIView):
    permission_classes = [IsAuthenticated]
    
    def post(self, request):
        try:
            # Clear user session
            request.session.flush()
            
            # Blacklist the JWT token if you're using JWT
            try:
                refresh_token = request.data.get('refresh_token')
                if refresh_token:
                    token = RefreshToken(refresh_token)
                    token.blacklist()
            except Exception as e:
                logger.warning(f"Error blacklisting token: {str(e)}")
            
            return Response({
                'status': 'success',
                'message': 'Successfully logged out'
            })
        except Exception as e:
            logger.error(f"Error in logout: {str(e)}")
            return Response({
                'status': 'error',
                'message': 'Error during logout'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            
class YearListCreateView(BaseModelViewSet):
    queryset = YEAR.objects.all().select_related("BRANCH")  # ✅ Optimize DB query
    serializer_class = YearSerializer
    
    
    
    def perform_create(self, serializer):
        branch = serializer.validated_data.get('BRANCH')
        if branch is None:
            raise serializer.ValidationError({"BRANCH": "This field is required."})
        serializer.save()

    def perform_update(self, serializer):
        branch = serializer.validated_data.get('BRANCH')
        if branch is None:
            raise serializer.ValidationError({"BRANCH": "This field is required."})
        serializer.save()

    def get_queryset(self):
        queryset = super().get_queryset()  # ✅ Correct indentation
        branch_id = self.request.query_params.get("branch")  
        if branch_id:
            queryset = queryset.filter(BRANCH_id=branch_id)  # ✅ Ensure field name matches model
        return queryset
    
    def list(self, request, *args, **kwargs):
        branch_id = request.GET.get("branch_id")  # Get branch_id from query params
        years = self.queryset  # Get base queryset of active years

        if branch_id:
            try:
                branch_id = int(branch_id)
                years = years.filter(BRANCH=branch_id)  # Filter years by branch
            except ValueError:
                return Response({"error": "Invalid Branch ID"}, status=status.HTTP_400_BAD_REQUEST)

        serializer = self.get_serializer(years, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)

class SemesterListCreateView(viewsets.ModelViewSet):
    """
    API endpoint for listing and creating Semester records.
    """
    queryset = SEMESTER.objects.all().select_related("YEAR")    # Sorting by year and semester
    serializer_class = SemesterSerializer
   
   
    def create(self, request, *args, **kwargs):
        """
        Custom create method to handle extra validation or data processing.
        """
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            serializer.save(CREATED_BY=request.user, UPDATED_BY=request.user)
            return Response({"message": "Semester created successfully!", "data": serializer.data}, status=status.HTTP_201_CREATED)
        return Response({"error": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)
    
    def get_queryset(self):
        """
        Override to filter semesters by year_id.
        """
        queryset = super().get_queryset()
        year_id = self.request.query_params.get("year_id")

        if year_id:
            try:
                queryset = queryset.filter(YEAR_id=int(year_id))
            except ValueError:
                return SEMESTER.objects.none()  # Return an empty queryset if invalid input

        return queryset
    
    def list(self, request, *args, **kwargs):
        year_id = request.GET.get("year_id")  # Get year_id from query params
        semesters = self.get_queryset()  # Apply filtering

        if year_id:
            try:
                year_id = int(year_id)
                semesters = semesters.filter(YEAR_id=year_id)  # Ensure filtering works
            except ValueError:
                return Response({"error": "Invalid Year ID"}, status=status.HTTP_400_BAD_REQUEST)

        serializer = self.get_serializer(semesters, many=True)
        return Response(serializer.data, status=status.HTTP_200_OK)
    
    # def get_semesters(request):
    #     query = "SELECT SEMESTER_ID, SEMESTER, YEAR_ID FROM SEMESTERS"
    #     with connection.cursor() as cursor:
    #         cursor.execute(query)
    #         columns = [col[0] for col in cursor.description]
    #         data = [dict(zip(columns, row)) for row in cursor.fetchall()]
    #         return JsonResponse(data, safe=False)

class SemesterDurationViewSet(BaseModelViewSet):
    queryset = SEMESTER_DURATION.objects.all()
    serializer_class = SemesterDurationSerializer

    def create(self, request, *args, **kwargs):
        data = request.data
        serializer = self.get_serializer(data=data)

        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def list(self, request, *args, **kwargs):
        active_semesters = self.queryset.filter(IS_ACTIVE=True)
        serializer = self.get_serializer(active_semesters, many=True)
        return Response(serializer.data)

class DashboardMasterViewSet(BaseModelViewSet):
    queryset = DASHBOARD_MASTER.objects.all()
    serializer_class = DashboardMasterSerializer

    def list(self, request, *args, **kwargs):
        university_id = request.GET.get("university_id")
        institute_id = request.GET.get("institute_id")
        queryset = self.queryset

        if university_id:
            queryset = queryset.filter(institute__UNIVERSITY_id=university_id)

        if institute_id:
            queryset = queryset.filter(institute__INSTITUTE_ID=institute_id)

        serializer = self.get_serializer(queryset, many=True)
        return Response(serializer.data)

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        self.perform_create(serializer)
        return Response(serializer.data)

    def retrieve(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(instance)
        return Response(serializer.data)

    def update(self, request, *args, **kwargs):
        partial = kwargs.pop('partial', False)
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)
        return Response(serializer.data)

    def destroy(self, request, *args, **kwargs):
        instance = self.get_object()
        self.perform_destroy(instance)
        return Response(status=204)

class CasteListCreateView(BaseModelViewSet):
    queryset =CASTE_MASTER.objects.all()   
    serializer_class = CasteSerializer
    
    
    def create(self, request, *args, **kwargs):
        data = request.data
        serializer = self.get_serializer(data=data)
        
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
    

class QuotaListCreateView(BaseModelViewSet):
    queryset = QUOTA_MASTER.objects.all()
    serializer_class = QuotaSerializer

    def create(self, request, *args, **kwargs):
        data = request.data
        serializer = self.get_serializer(data=data)
        
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
      
      
class AdmissionListCreateView(BaseModelViewSet):
      queryset =ADMISSION_QUOTA_MASTER.objects.all()   
      serializer_class = AdmissionQuotaSerializer
      
      def create(self, request, *args, **kwargs):
        data = request.data
        serializer = self.get_serializer(data=data)
        
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
      
      
      

    
