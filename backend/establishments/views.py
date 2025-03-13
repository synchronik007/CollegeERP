from rest_framework import viewsets, status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.authentication import TokenAuthentication
from django.core.mail import send_mail
from django.conf import settings
from utils.id_generators import generate_employee_id, generate_password
from accounts.models import CustomUser, DESIGNATION
from .models import TYPE_MASTER, STATUS_MASTER, SHIFT_MASTER, EMPLOYEE_MASTER  # Add this import
from .serializers import TypeMasterSerializer, StatusMasterSerializer, ShiftMasterSerializer, EmployeeMasterSerializer
import logging
from django.utils import timezone
from django.db.models import Q
from rest_framework.decorators import action
from django.shortcuts import get_object_or_404
import os

logger = logging.getLogger(__name__)

class EmployeeMasterTableView(APIView):
    permission_classes = [AllowAny]

    def get(self, request):
        master_tables = [
            {
                "name": "type", 
                "display_name": "Employee Type Master", 
                "endpoint": "/api/establishment/type/"  # Updated endpoint
            },
            {
                "name": "status", 
                "display_name": "Employee Status Master", 
                "endpoint": "/api/establishment/status/"  # Updated endpoint
            },
            {
                "name": "shift", 
                "display_name": "Employee Shift Master", 
                "endpoint": "/api/establishment/shift/"  # Updated endpoint
            }
        ]
        logger.debug(f"Returning employee master tables: {master_tables}")
        return Response(master_tables)

class BaseMasterViewSet(viewsets.ModelViewSet):
    permission_classes = [AllowAny]  # Temporarily allow all access

    def get_username_from_request(self):
        auth_header = self.request.headers.get('Authorization', '')
        if (auth_header.startswith('Username ')):
            return auth_header.split(' ')[1]
        return 'SYSTEM'

    def perform_create(self, serializer):
        try:
            username = self.get_username_from_request()
            logger.debug(f"Using username: {username}")
            serializer.save(CREATED_BY=username)
        except Exception as e:
            logger.error(f"Error in perform_create: {str(e)}")
            raise

    def perform_update(self, serializer):
        try:
            username = self.get_username_from_request()
            serializer.save(UPDATED_BY=username)
        except Exception as e:
            logger.error(f"Error in perform_update: {str(e)}")
            raise

    def perform_destroy(self, instance):
        try:
            username = self.get_username_from_request()
            instance.IS_DELETED = True
            instance.DELETED_AT = timezone.now()
            instance.DELETED_BY = username
            instance.save()
        except Exception as e:
            logger.error(f"Error in perform_destroy: {str(e)}")
            raise

class TypeMasterViewSet(BaseMasterViewSet):
    queryset = TYPE_MASTER.objects.all()
    serializer_class = TypeMasterSerializer

    def get_queryset(self):
        return self.queryset.filter(IS_DELETED=False)

    def update(self, request, *args, **kwargs):
        logger.debug(f"Update request data: {request.data}")
        instance = self.get_object()
        logger.debug(f"Updating instance: {instance.ID}")
        
        serializer = self.get_serializer(instance, data=request.data, partial=True)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)
        
        logger.debug(f"Updated data: {serializer.data}")
        return Response(serializer.data)

class StatusMasterViewSet(BaseMasterViewSet):
    queryset = STATUS_MASTER.objects.all()
    serializer_class = StatusMasterSerializer

    def get_queryset(self):
        return self.queryset.filter(IS_DELETED=False)

class ShiftMasterViewSet(BaseMasterViewSet):
    queryset = SHIFT_MASTER.objects.all()
    serializer_class = ShiftMasterSerializer

    def get_queryset(self):
        return self.queryset.filter(IS_DELETED=False)

class EmployeeViewSet(viewsets.ModelViewSet):
    permission_classes = [AllowAny]
    serializer_class = EmployeeMasterSerializer
    queryset = EMPLOYEE_MASTER.objects.filter(IS_DELETED=False)
    lookup_field = 'EMPLOYEE_ID'
    lookup_url_kwarg = 'pk'  # Add this line to map 'pk' from URL to 'EMPLOYEE_ID'

    def create(self, request, *args, **kwargs):
        try:
            logger.info("=== Starting Employee Creation Process ===")
            
            # 1. Generate IDs first
            designation_id = request.data.get('DESIGNATION')
            designation_obj = DESIGNATION.objects.get(DESIGNATION_ID=designation_id)
            employee_id = generate_employee_id(designation_obj.NAME)
            password = generate_password(8)
            
            # 2. Create a new dict for employee data instead of copying request.data
            employee_data = {}
            
            # 3. Add all form fields except files
            for key in request.data.keys():
                if key != 'PROFILE_IMAGE':  # Skip file field
                    employee_data[key] = request.data.get(key)

            # 4. Add generated ID and active status
            employee_data['EMPLOYEE_ID'] = employee_id
            employee_data['IS_ACTIVE'] = 'YES'

            # 5. Add file separately if it exists
            if 'PROFILE_IMAGE' in request.FILES:
                employee_data['PROFILE_IMAGE'] = request.FILES['PROFILE_IMAGE']

            # 6. Create and validate
            serializer = self.get_serializer(data=employee_data)
            if not serializer.is_valid():
                logger.error("Validation errors:")
                logger.error(serializer.errors)
                return Response({
                    'error': 'Validation failed',
                    'details': serializer.errors
                }, status=status.HTTP_400_BAD_REQUEST)

            employee = serializer.save()

            # 4. Create user with proper password hashing
            try:
                username = request.data.get('EMAIL').split('@')[0]
                user = CustomUser.objects.create(
                    USER_ID=employee_id,
                    USERNAME=username,
                    EMAIL=request.data.get('EMAIL'),
                    IS_ACTIVE=True,
                    IS_STAFF=False,
                    IS_SUPERUSER=False,
                    DESIGNATION=designation_obj,
                    FIRST_NAME=request.data.get('EMP_NAME')
                )
                user.set_password(password)
                user.save()
                
                logger.info(f"User created with ID: {user.USER_ID}")

                # 5. Send welcome email
                email_subject = "Your College ERP Account Credentials"
                email_message = f"""
                Dear {request.data.get('EMP_NAME')},

                Your College ERP account has been created. Here are your login credentials:

                Employee ID: {employee_id}
                Username: {username}
                Password: {password}

                Please change your password after first login.

                Best regards,
                College ERP Team
                """

                send_mail(
                    email_subject,
                    email_message,
                    settings.EMAIL_HOST_USER,
                    [user.EMAIL],
                    fail_silently=False,
                )

                return Response({
                    'message': 'Employee and user account created successfully',
                    'employee_id': employee_id,
                    'username': username
                }, status=status.HTTP_201_CREATED)

            except Exception as user_error:
                employee.delete()  # Rollback employee creation if user creation fails
                logger.error(f"User creation failed: {str(user_error)}")
                raise

        except Exception as e:
            logger.error(f"Error in create process: {str(e)}", exc_info=True)
            return Response({
                'error': str(e)
            }, status=status.HTTP_400_BAD_REQUEST)

    @action(detail=False, methods=['get'])
    def search(self, request):
        query = request.query_params.get('query', '')
        if not query:
            return Response({'error': 'Search query is required'}, 
                          status=status.HTTP_400_BAD_REQUEST)

        # Fix the Q objects syntax
        employees = EMPLOYEE_MASTER.objects.filter(
            Q(EMPLOYEE_ID__icontains=query) |
            Q(EMP_NAME__icontains=query) |
            Q(DEPARTMENT__NAME__icontains=query) |
            Q(DESIGNATION__NAME__icontains=query),
            IS_DELETED=False
        ).select_related('DEPARTMENT', 'DESIGNATION')[:10]

        data = [{
            'EMPLOYEE_ID': emp.EMPLOYEE_ID,
            'EMP_NAME': emp.EMP_NAME,
            'DEPARTMENT_NAME': emp.DEPARTMENT.NAME,
            'DESIGNATION_NAME': emp.DESIGNATION.NAME,
        } for emp in employees]

        return Response(data)

    def retrieve(self, request, pk=None):
        try:
            employee = get_object_or_404(EMPLOYEE_MASTER, EMPLOYEE_ID=pk, IS_DELETED=False)
            serializer = self.get_serializer(employee)
            
            # Transform dates to string format if needed
            data = serializer.data
            if data.get('DATE_OF_BIRTH'):
                data['DATE_OF_BIRTH'] = employee.DATE_OF_BIRTH.strftime('%Y-%m-%d')
            if data.get('DATE_OF_JOIN'):
                data['DATE_OF_JOIN'] = employee.DATE_OF_JOIN.strftime('%Y-%m-%d')

            return Response(data)
        except Exception as e:
            return Response(
                {'error': f'Error retrieving employee: {str(e)}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    def get_object(self):
        queryset = self.filter_queryset(self.get_queryset())
        try:
            obj = queryset.get(EMPLOYEE_ID=self.kwargs['pk'])
            self.check_object_permissions(self.request, obj)
            return obj
        except EMPLOYEE_MASTER.DoesNotExist:
            raise Http404("Employee not found")

    def update(self, request, *args, **kwargs):
        try:
            instance = self.get_object()
            logger.info(f"Updating employee: {instance.EMPLOYEE_ID}")

            # Create a new dict for update data instead of copying request.data
            update_data = {}
            
            # Add all form fields except files and EMPLOYEE_ID
            for key in request.data.keys():
                if key not in ['PROFILE_IMAGE', 'EMPLOYEE_ID']:
                    update_data[key] = request.data.get(key)

            # Handle profile image update if provided
            if 'PROFILE_IMAGE' in request.FILES:
                # Delete old profile image if exists
                if instance.PROFILE_IMAGE:
                    instance.PROFILE_IMAGE.delete(save=False)
                
                # Get new file and extension
                new_image = request.FILES['PROFILE_IMAGE']
                ext = os.path.splitext(new_image.name)[1]
                
                # Set filename to EMPLOYEE_ID + extension
                new_image.name = f"{instance.EMPLOYEE_ID}{ext}"
                update_data['PROFILE_IMAGE'] = new_image

            # Update employee data
            serializer = self.get_serializer(
                instance,
                data=update_data,
                partial=True
            )
            
            if not serializer.is_valid():
                logger.error("Update validation errors:")
                logger.error(serializer.errors)
                return Response({
                    'error': 'Validation failed',
                    'details': serializer.errors
                }, status=status.HTTP_400_BAD_REQUEST)

            updated_employee = serializer.save()

            return Response({
                'message': 'Employee updated successfully',
                'data': serializer.data
            })

        except Http404:
            return Response({
                'error': 'Employee not found'
            }, status=status.HTTP_404_NOT_FOUND)
        except Exception as e:
            logger.error(f"Error updating employee: {str(e)}", exc_info=True)
            return Response({
                'error': str(e)
            }, status=status.HTTP_400_BAD_REQUEST)
