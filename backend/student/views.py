from django.shortcuts import render
from rest_framework import viewsets, status
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework.permissions import AllowAny, IsAuthenticated
from rest_framework.authentication import TokenAuthentication
from django.core.mail import send_mail
from .models import STUDENT_MASTER, BRANCH, STUDENT_DETAILS, STUDENT_ACADEMIC_RECORD
from .serializers import StudentMasterSerializer
from .models import STUDENT_MASTER, BRANCH ,STUDENT_ROLL_NUMBER_DETAILS
from .models import STUDENT_MASTER, BRANCH, STUDENT_DETAILS, CHECK_LIST_DOCUMENTS, STUDENT_DOCUMENTS
from .serializers import StudentMasterSerializer, CheckListDoumentsSerializer, StudentDocumentsSerializer, StudentRollNumberDetailsSerializer
from django.conf import settings
import logging
from django.http import Http404
from django.utils import timezone
from django.db.models import Q
from rest_framework.decorators import action
from django.shortcuts import get_object_or_404
from utils.id_generators import generate_student_id
from django.contrib.auth import get_user_model
from utils.id_generators import generate_password
from accounts.models import DESIGNATION
from accounts.models import CustomUser, YEAR
from accounts.views import BaseModelViewSet
from django.db import ProgrammingError


logger = logging.getLogger(__name__)

class StudentMasterViewSet(viewsets.ModelViewSet):
    queryset = STUDENT_MASTER.objects.filter(IS_DELETED=False)
    serializer_class = StudentMasterSerializer
    lookup_field = 'STUDENT_ID'  # Very important
    
    def get_or_default(value, default=None, data_type=int):
        """Returns integer value if valid, otherwise returns default"""
        try:
            if value in [None, '']:
                return default
            return data_type(value)
        except (ValueError, TypeError):
            return default

    @action(detail=True, methods=['post'])
    def generate_embedding(self, request, STUDENT_ID=None):
        """
        Endpoint to receive a cropped face image from Flutter, generate the 128-d
        face embedding using the python face_recognition library, and save it.
        """
        import face_recognition
        import json
        
        student = self.get_object()
        
        if 'image' not in request.FILES:
            return Response({'status': 'error', 'message': 'No face image uploaded. Expected key: "image".'}, status=status.HTTP_400_BAD_REQUEST)
        
        image_file = request.FILES['image']
        
        try:
            # Load the image file for face_recognition
            img_array = face_recognition.load_image_file(image_file)
            
            # Since the image should already be cropped to the face by ML Kit,
            # face_recognition should easily find it (or we can fallback to the whole image)
            encodings = face_recognition.face_encodings(img_array)
            
            if not encodings:
                return Response({'status': 'error', 'message': 'No face could be extracted from the uploaded image.'}, status=status.HTTP_400_BAD_REQUEST)
            
            # Convert numpy array to list, then serialize to JSON
            embedding_list = encodings[0].tolist()
            student.FACE_EMBEDDING = json.dumps(embedding_list)
            student.save(update_fields=['FACE_EMBEDDING'])
            
            return Response({
                'status': 'success',
                'message': 'Face embedding generated and saved successfully'
            }, status=status.HTTP_200_OK)
            
        except Exception as e:
            return Response({
                'status': 'error',
                'message': f'Failed to generate embedding: {str(e)}'
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def get_queryset(self):
     queryset = STUDENT_MASTER.objects.filter(IS_DELETED=False)

     branch_id = self.request.query_params.get('branch_id')
     academic_year = self.request.query_params.get('academic_year')  # Assuming it's stored as 'ACADEMIC_YEAR' in DB

     if branch_id:
        queryset = queryset.filter(BRANCH_ID=branch_id)
     if academic_year:
        queryset = queryset.filter(ACADEMIC_YEAR=academic_year)

     return queryset


    def create(self, request, *args, **kwargs):
        try:
            print("=== Student Creation Debug ===")
            print("Request data:", request.data)
            
            # Convert request data to mutable dictionary
            data = request.data.copy()
            
            # Check for required fields
            required_fields = [
                'INSTITUTE', 'ACADEMIC_YEAR', 'BATCH', 'ADMISSION_CATEGORY',
                'ADMN_QUOTA_ID', 'YEAR_ID',  # Added this field
                'FORM_NO', 'NAME', 'SURNAME', 'FATHER_NAME', 'GENDER',
                'DOB', 'MOB_NO', 'EMAIL_ID', 'PER_ADDRESS', 'BRANCH_ID'
            ]
            
            missing_fields = [field for field in required_fields if field not in request.data]
            if missing_fields:
                return Response({
                    'status': 'error',
                    'message': f'Missing required fields: {", ".join(missing_fields)}'
                }, status=status.HTTP_400_BAD_REQUEST)

            # Validate branch
            branch_id = request.data.get('BRANCH_ID')
            try:
                branch = BRANCH.objects.select_related('PROGRAM').get(BRANCH_ID=branch_id)
            except BRANCH.DoesNotExist:
                return Response({
                    'status': 'error',
                    'message': 'Invalid Branch ID'
                }, status=status.HTTP_400_BAD_REQUEST)

            # Add quota validation if needed
            admission_quota = request.data.get('ADMN_QUOTA_ID')
            if not admission_quota:
                return Response({
                    'status': 'error',
                    'message': 'ADMN_QUOTA_ID is required'
                }, status=status.HTTP_400_BAD_REQUEST)
                
            # Validate that YEAR_ID is provided and exists
            year_id = data.get('YEAR_ID')
            try:
                year_instance = YEAR.objects.get(pk=year_id)
                data['YEAR_SEM_ID'] = year_id  # Store selected year_id
            except YEAR.DoesNotExist:
                return Response({'status': 'error', 'message': 'Invalid YEAR_ID'}, status=status.HTTP_400_BAD_REQUEST)

             

            serializer = self.get_serializer(data=data)
            student = None
            if serializer.is_valid():
                student = serializer.save()
                
                # Save student details record linking to the created student
                STUDENT_DETAILS.objects.create(STUDENT=student)
                
                # Also save entry in STUDENT_ACADEMIC_RECORD table if available
                try:
                    STUDENT_ACADEMIC_RECORD.objects.create(
                        STUDENT_ID=student.STUDENT_ID,
                        INSTITUTE_ID=student.INSTITUTE,
                        CATEGORY=int(student.ADMISSION_CATEGORY),
                        BATCH=student.BATCH,
                        ACADEMIC_YEAR=student.ACADEMIC_YEAR,
                        CLASS_YEAR=student.YEAR_SEM_ID,
                        ADMISSION_DATE=student.ADMISSION_DATE,
                        FORM_NO=student.FORM_NO,
                        QUOTA_ID=student.ADMN_QUOTA_ID,
                        STATUS=student.STATUS,
                        FEE_CATEGORY_ID=int(student.ADMISSION_CATEGORY),
                    )
                except Exception as acad_err:
                    logger.exception("Failed to create STUDENT_ACADEMIC_RECORD; continuing without it: %s", acad_err)
                
                # Create user account with password same as student_id
            else:
                return Response({'status': 'error', 'errors': serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

            try:
                if student is None:
                    raise Exception("Student record was not created; aborting user creation")

                username = request.data.get('EMAIL_ID').split('@')[0]
                password = student.STUDENT_ID  # Use student_id as password

                user = CustomUser.objects.create(
                    USER_ID=student.STUDENT_ID,
                    USERNAME=username,
                    EMAIL=request.data.get('EMAIL_ID'),
                    IS_ACTIVE=True,
                    IS_STAFF=False,
                    IS_SUPERUSER=False,
                    DESIGNATION=None,  # Students typically don't have a designation
                    FIRST_NAME=request.data.get('NAME')
                )
                user.set_password(password)
                user.save()

                print(f"User created with ID: {user.USER_ID}")

                # Send welcome email (optional)
                email_subject = "Your Student Account Credentials"
                email_message = f"""
                Dear {request.data.get('NAME')},

                Your student account has been created. Here are your login credentials:

                Student ID: {student.STUDENT_ID}
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

            except Exception as user_error:
                # Rollback student creation if user creation fails (only if student exists)
                if student is not None:
                    try:
                        student.delete()
                    except Exception:
                        logger.exception("Failed to delete student during rollback")
                print(f"User creation failed: {str(user_error)}")
                raise

            return Response({
                'status': 'success',
                'message': 'Student created successfully',
                'data': serializer.data
            }, status=status.HTTP_201_CREATED)
            
            
        except Exception as e:
            logger.error(f"Error creating student: {str(e)}", exc_info=True)
            return Response({
            'status': 'error',
            'message': str(e)
        }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    def list(self, request, *args, **kwargs):
        try:
            branch_id = request.query_params.get('branch_id')
            academic_year = request.query_params.get('academic_year')
            logger.info("Listing students for branch=%s academic_year=%s", branch_id, academic_year)

            students = self.get_queryset()
            # safe count for debugging
            try:
                qs_count = students.count()
            except Exception:
                qs_count = 'count-failed'
            logger.info("Student queryset size: %s", qs_count)

            serializer = self.get_serializer(students, many=True)
            response_payload = {
                'status': 'success',
                'data': serializer.data
            }
            # Include debug_count in response when running in DEBUG mode
            try:
                from django.conf import settings as _settings
                if getattr(_settings, 'DEBUG', False):
                    response_payload['debug_count'] = qs_count
                    # include a small sample of the returned data for quick client debug
                    response_payload['debug_sample'] = serializer.data[:1] if isinstance(serializer.data, list) else serializer.data
            except Exception:
                pass

            return Response(response_payload)
        except Exception as e:
            logger.error(f"Error listing students: {str(e)}", exc_info=True)
            return Response({
                'status': 'error',
                'message': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

    @action(detail=False, methods=['get'])
    def search(self, request):
        try:
            query = request.query_params.get('query', '')
            if not query:
                return Response({
                    'status': 'error',
                    'message': 'Search query is required'
                }, status=status.HTTP_400_BAD_REQUEST)

            students = self.queryset.filter(
                Q(STUDENT_ID__icontains=query) |
                Q(NAME__icontains=query) |
                Q(SURNAME__icontains=query) |
                Q(MOB_NO__icontains=query) |
                Q(EMAIL_ID__icontains=query)
            )[:10]

            serializer = self.get_serializer(students, many=True)
            return Response({
                'status': 'success',
                'data': serializer.data
            })

        except Exception as e:
            logger.error(f"Error searching students: {str(e)}")
            return Response({
                'status': 'error',
                'message': str(e)
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class StudentRollNumberDetailsViewSet(viewsets.ModelViewSet):
    queryset = STUDENT_ROLL_NUMBER_DETAILS.objects.all()
    serializer_class = StudentRollNumberDetailsSerializer

    def list(self, request, *args, **kwargs):
        try:
            return super().list(request, *args, **kwargs)
        except ProgrammingError as pe:
            logger.exception("Roll numbers table missing or DB error: %s", pe)
            return Response({"status": "success", "data": []}, status=status.HTTP_200_OK)

    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data, many=True)
        if serializer.is_valid():
            serializer.save()
            return Response({"status": "success", "data": serializer.data}, status=status.HTTP_201_CREATED)
        return Response({"status": "error", "errors": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

    def update(self, request, *args, **kwargs):
        instance = self.get_object()
        serializer = self.get_serializer(instance, data=request.data, partial=True)
        if serializer.is_valid():
            serializer.save()
            return Response({"status": "success", "data": serializer.data}, status=status.HTTP_200_OK)
        return Response({"status": "error", "errors": serializer.errors}, status=status.HTTP_400_BAD_REQUEST)

#     @action(detail=False, methods=['get'])
#     def get_students_with_roll_numbers(self, request):
#         branch_id = request.query_params.get('branch_id')
#         academic_year = request.query_params.get('academic_year_id')
#         if not branch_id or not academic_year:
#             return Response({"status": "error", "message": "Branch ID and Academic Year are required."}, status=status.HTTP_400_BAD_REQUEST)
        
#         students = STUDENT_ROLL_NUMBER_DETAILS.objects.filter(BRANCH=branch_id, ACADEMIC_YEAR__ACADEMIC_YEAR=academic_year)
#         serializer = self.get_serializer(students, many=True)
#         return Response({"status": "success", "data": serializer.data}, status=status.HTTP_200_OK)
    
    
# from rest_framework.decorators import api_view
# @api_view(['POST'])
# def save_roll_numbers(request):
#     if request.method == 'POST':
#         # Extract the list of roll numbers from the request data
#         roll_numbers_data = request.data
        
#         # Prepare a list to store the created records
#         created_records = []
        
#         # Process each roll number entry and save to the database
#         for roll_data in roll_numbers_data:
#             student_id = roll_data.get('STUDENT')
#             roll_no = roll_data.get('ROLL_NO')
#             institute_id = roll_data.get('INSTITUTE')
#             branch_id = roll_data.get('BRANCH')
#             year_id = roll_data.get('YEAR')
#             academic_year_id = roll_data.get('ACADEMIC_YEAR')
#             semester_id = roll_data.get('SEMESTER')

#             if student_id and roll_no:
#                 # Create a new record for each student
#                 new_roll_number = STUDENT_ROLL_NUMBER_DETAILS.objects.create(
#                     INSTITUTE_id=institute_id,
#                     BRANCH_id=branch_id,
#                     YEAR_id=year_id,
#                     STUDENT_id=student_id,
#                     ACADEMIC_YEAR_id=academic_year_id,
#                     ROLL_NO=roll_no,
#                     SEMESTER_id=semester_id
#                 )
#                 created_records.append(new_roll_number)
        
#         # Serialize the created records and return a success response
#         serializer = StudentRollNumberDetailsSerializer(created_records, many=True)
#         return Response(serializer.data, status=status.HTTP_201_CREATED)
#     return Response({"detail": "Invalid request"}, status=status.HTTP_400_BAD_REQUEST)

class CheckListDocumentsViewSet(BaseModelViewSet):
     queryset = CHECK_LIST_DOCUMENTS.objects.all()   
     serializer_class = CheckListDoumentsSerializer

from rest_framework import status
from rest_framework.response import Response
from rest_framework.viewsets import ModelViewSet
from .models import STUDENT_DOCUMENTS
from .serializers import StudentDocumentsSerializer

class StudentDocumentsViewSet(ModelViewSet):  # or BaseModelViewSet if customized
    queryset = STUDENT_DOCUMENTS.objects.all()
    serializer_class = StudentDocumentsSerializer

    def create(self, request, *args, **kwargs):
        data = request.data
        student_id = data.get('STUDENT_ID')
        document_id = data.get('DOCUMENT_ID')

        # Check if the same document has already been submitted by this student
        if STUDENT_DOCUMENTS.objects.filter(STUDENT_ID=student_id, DOCUMENT_ID=document_id).exists():
            return Response(
                {"detail": "This document has already been submitted by the student."},
                status=status.HTTP_400_BAD_REQUEST
            )

        serializer = self.get_serializer(data=data)
        if serializer.is_valid():
            serializer.save()
            return Response(serializer.data, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

    def update(self, request, *args, **kwargs):
        kwargs['partial'] = True  # ALLOWS partial updates via PATCH
        return super().update(request, *args, **kwargs)

# ---------------------------------------------------- # 
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status
from .models import STUDENT_DOCUMENTS

@api_view(['PUT'])
def return_documents(request):
    student_id = request.data.get('student_id')
    document_ids = request.data.get('document_ids', [])

    if not student_id or not document_ids:
        return Response({'error': 'Invalid data'}, status=status.HTTP_400_BAD_REQUEST)

    STUDENT_DOCUMENTS.objects.filter(
        STUDENT_ID=student_id,
        DOCUMENT_ID__in=document_ids
    ).update(RETURN='Y')

    return Response({'message': 'Documents marked as returned'})
