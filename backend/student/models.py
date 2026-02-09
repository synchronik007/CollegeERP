import os
from django.db import models
from core.models import AuditModel
from django.utils import timezone
from accounts.models import BRANCH, PROGRAM, INSTITUTE, SEMESTER, YEAR
from academic.models import ACADEMIC_YEAR, EXAMINATION, CURRICULUM

class STUDENT(AuditModel):
    STUDENT_ID = models.AutoField(primary_key=True, db_column='STUDENT_ID')
    ENROLLMENT_NO = models.CharField(max_length=20, unique=True, db_column='ENROLLMENT_NO')
    FIRST_NAME = models.CharField(max_length=50, db_column='FIRST_NAME')
    MIDDLE_NAME = models.CharField(max_length=50, null=True, blank=True, db_column='MIDDLE_NAME')
    LAST_NAME = models.CharField(max_length=50, db_column='LAST_NAME')
    DATE_OF_BIRTH = models.DateField(db_column='DATE_OF_BIRTH')
    GENDER = models.CharField(
        max_length=1,
        choices=[('M', 'Male'), ('F', 'Female'), ('O', 'Other')],
        db_column='GENDER'
    )
    EMAIL = models.EmailField(unique=True, db_column='EMAIL')
    PHONE = models.CharField(max_length=15, db_column='PHONE')
    ADDRESS = models.TextField(db_column='ADDRESS')
    CITY = models.CharField(max_length=50, db_column='CITY')
    STATE = models.CharField(max_length=50, db_column='STATE')
    PINCODE = models.CharField(max_length=6, db_column='PINCODE')
    BLOOD_GROUP = models.CharField(max_length=5, db_column='BLOOD_GROUP')
    PHOTO = models.ImageField(upload_to='student_photos/', null=True, blank=True, db_column='PHOTO')
    
    # Academic Details
    BRANCH = models.ForeignKey(BRANCH, on_delete=models.PROTECT, db_column='BRANCH_ID')
    PROGRAM = models.ForeignKey(PROGRAM, on_delete=models.PROTECT, db_column='PROGRAM_ID')
    ACADEMIC_YEAR = models.ForeignKey(ACADEMIC_YEAR, on_delete=models.PROTECT, db_column='ACADEMIC_YEAR_ID')
    CURRENT_SEMESTER = models.IntegerField(db_column='CURRENT_SEMESTER')
    ADMISSION_DATE = models.DateField(db_column='ADMISSION_DATE')
    
    # Status
    IS_ACTIVE = models.BooleanField(default=True, db_column='IS_ACTIVE')

    class Meta:
        db_table = '"STUDENT"."STUDENTS"'
        verbose_name = 'Student'
        verbose_name_plural = 'Students'

    def __str__(self):
        return f"{self.ENROLLMENT_NO} - {self.FIRST_NAME} {self.LAST_NAME}"

class STUDENT_PARENT(AuditModel):
    PARENT_ID = models.AutoField(primary_key=True, db_column='PARENT_ID')
    STUDENT = models.ForeignKey(STUDENT, on_delete=models.CASCADE, db_column='STUDENT_ID')
    RELATION = models.CharField(
        max_length=10,
        choices=[('FATHER', 'Father'), ('MOTHER', 'Mother'), ('GUARDIAN', 'Guardian')],
        db_column='RELATION'
    )
    FIRST_NAME = models.CharField(max_length=50, db_column='FIRST_NAME')
    MIDDLE_NAME = models.CharField(max_length=50, null=True, blank=True, db_column='MIDDLE_NAME')
    LAST_NAME = models.CharField(max_length=50, db_column='LAST_NAME')
    OCCUPATION = models.CharField(max_length=100, db_column='OCCUPATION')
    EMAIL = models.EmailField(db_column='EMAIL')
    PHONE = models.CharField(max_length=15, db_column='PHONE')
    ANNUAL_INCOME = models.DecimalField(max_digits=12, decimal_places=2, db_column='ANNUAL_INCOME')
    IS_ACTIVE = models.BooleanField(default=True, db_column='IS_ACTIVE')

    class Meta:
        db_table = '"STUDENT"."STUDENT_PARENTS"'
        verbose_name = 'Student Parent'
        verbose_name_plural = 'Student Parents'
        unique_together = ['STUDENT', 'RELATION']

    def __str__(self):
        return f"{self.STUDENT.ENROLLMENT_NO} - {self.RELATION} - {self.FIRST_NAME}"

class STUDENT_ACADEMIC(AuditModel):
    ACADEMIC_ID = models.AutoField(primary_key=True, db_column='ACADEMIC_ID')
    STUDENT = models.ForeignKey(STUDENT, on_delete=models.CASCADE, db_column='STUDENT_ID')
    QUALIFICATION = models.CharField(max_length=50, db_column='QUALIFICATION')  # e.g., "10th", "12th", "BTech"
    BOARD_UNIVERSITY = models.CharField(max_length=100, db_column='BOARD_UNIVERSITY')
    INSTITUTION = models.CharField(max_length=200, db_column='INSTITUTION')
    YEAR_OF_PASSING = models.IntegerField(db_column='YEAR_OF_PASSING')
    PERCENTAGE = models.DecimalField(max_digits=5, decimal_places=2, db_column='PERCENTAGE')
    DIVISION = models.CharField(max_length=20, db_column='DIVISION')  # First, Second, Third
    SUBJECTS = models.JSONField(db_column='SUBJECTS')  # Store subjects as JSON
    DOCUMENTS = models.JSONField(db_column='DOCUMENTS', null=True, blank=True)  # Store document URLs
    IS_VERIFIED = models.BooleanField(default=False, db_column='IS_VERIFIED')

    class Meta:
        db_table = '"STUDENT"."STUDENT_ACADEMICS"'
        verbose_name = 'Student Academic'
        verbose_name_plural = 'Student Academics'
        unique_together = ['STUDENT', 'QUALIFICATION']

    def __str__(self):
        return f"{self.STUDENT.ENROLLMENT_NO} - {self.QUALIFICATION}"

class STUDENT_RESULT(AuditModel):
    RESULT_ID = models.AutoField(primary_key=True, db_column='RESULT_ID')
    STUDENT = models.ForeignKey(STUDENT, on_delete=models.CASCADE, db_column='STUDENT_ID')
    CURRICULUM = models.ForeignKey(CURRICULUM, on_delete=models.PROTECT, db_column='CURRICULUM_ID')
    EXAMINATION = models.ForeignKey(EXAMINATION, on_delete=models.PROTECT, db_column='EXAMINATION_ID')
    MARKS_OBTAINED = models.DecimalField(max_digits=5, decimal_places=2, db_column='MARKS_OBTAINED')
    IS_PASS = models.BooleanField(db_column='IS_PASS')
    GRADE = models.CharField(max_length=2, db_column='GRADE')
    GRADE_POINTS = models.DecimalField(max_digits=10, decimal_places=1, db_column='GRADE_POINTS')
    ATTEMPT_NUMBER = models.IntegerField(default=1, db_column='ATTEMPT_NUMBER')
    REMARKS = models.CharField(max_length=255, null=True, blank=True, db_column='REMARKS')
    IS_VERIFIED = models.BooleanField(default=False, db_column='IS_VERIFIED')

    class Meta:
        db_table = '"STUDENT"."STUDENT_RESULTS"'
        verbose_name = 'Student Result'
        verbose_name_plural = 'Student Results'
        unique_together = ['STUDENT', 'CURRICULUM', 'EXAMINATION', 'ATTEMPT_NUMBER']

    def __str__(self):
        return f"{self.STUDENT.ENROLLMENT_NO} - {self.CURRICULUM.COURSE.CODE} - {self.EXAMINATION.NAME}"

class STUDENT_MASTER(AuditModel):
    RECORD_ID = models.AutoField(primary_key=True, db_column='RECORD_ID')
    STUDENT_ID = models.CharField(max_length=20, unique=True, db_column='STUDENT_ID')
    INSTITUTE = models.CharField(max_length=20, db_column='INSTITUTE_CODE')
    ACADEMIC_YEAR = models.CharField(max_length=10, db_column='ACADEMIC_YEAR')
    BATCH = models.CharField(
        max_length=4,
        db_column='BATCH',
        help_text='Expected graduation/passout year (e.g., 2025)'
    )
    ADMISSION_CATEGORY = models.CharField(max_length=20, db_column='ADMISSION_CATEGORY')
    FORM_NO = models.IntegerField(db_column='FORM_NO')
    VALIDITY = models.DateField(db_column='VALIDITY', default=timezone.now)
    NAME_ON_CERTIFICATE = models.CharField(max_length=100, db_column='NAME_ON_CERTIFICATE', blank=True, default='')
    NAME = models.CharField(max_length=100, db_column='NAME')
    SURNAME = models.CharField(max_length=100, db_column='SURNAME')
    PARENT_NAME = models.CharField(max_length=100, db_column='PARENT_NAME', default='')
    MOTHER_NAME = models.CharField(max_length=100, db_column='MOTHER_NAME', blank=True, default='')
    FATHER_NAME = models.CharField(max_length=100, db_column='FATHER_NAME', default='')
    GENDER = models.CharField(max_length=10, db_column='GENDER', choices=[
        ('male', 'Male'),
        ('female', 'Female'),
        ('other', 'Other')
    ])
    DOB = models.DateField(db_column='DOB')
    DOP = models.DateField(db_column='DOP', null=True, blank=True)
    PER_ADDRESS = models.TextField(db_column='PER_ADDRESS', blank=True, default='')
    LOC_ADDRESS = models.TextField(db_column='LOC_ADDRESS', blank=True, default='')
    PER_STATE_ID = models.IntegerField(db_column='PER_STATE_ID', default=1)
    LOC_STATE_ID = models.IntegerField(db_column='LOC_STATE_ID', default=1)
    PER_PHONE_NO = models.CharField(max_length=15, db_column='PER_PHONE_NO', blank=True, default='')
    LOC_PHONE_NO = models.CharField(max_length=15, db_column='LOC_PHONE_NO', blank=True, default='')
    MOB_NO = models.CharField(max_length=15, db_column='MOB_NO')
    EMAIL_ID = models.EmailField(db_column='EMAIL_ID')
    PER_CITY = models.CharField(max_length=50, db_column='PER_CITY', blank=True, default='')
    LOC_CITY = models.CharField(max_length=50, db_column='LOC_CITY', blank=True, default='')
    NATIONALITY = models.CharField(max_length=50, db_column='NATIONALITY', default='INDIAN')
    BLOOD_GR = models.CharField(max_length=5, db_column='BLOOD_GR', default='O+')
    CASTE = models.CharField(max_length=50, db_column='CASTE', default='GENERAL')
    BRANCH_ID = models.ForeignKey(
        'accounts.BRANCH',
        to_field='BRANCH_ID',
        on_delete=models.PROTECT,
        db_column='BRANCH_ID'
    )
    ENROLMENT_NO = models.CharField(max_length=20, db_column='ENROLMENT_NO', blank=True, default='')
    IS_ACTIVE = models.CharField(max_length=8, db_column='IS_ACTIVE', default='YES')
    HANDICAPPED = models.CharField(max_length=10, db_column='HANDICAPPED', default='NO')
    MARK_ID = models.CharField(max_length=20, db_column='MARK_ID', blank=True, default='0')
    ADMISSION_DATE = models.DateField(db_column='ADMISSION_DATE', default=timezone.now)
    QUOTA_ID = models.IntegerField(db_column='QUOTA_ID', default=1)
    
    PER_PIN = models.CharField(max_length=6, db_column='PER_PIN', blank=True, default='')
    LOC_PIN = models.CharField(max_length=6, db_column='LOC_PIN', blank=True, default='')
    YEAR_SEM_ID = models.IntegerField(db_column='YEAR_SEM_ID', default=1)
    DATE_LEAVING = models.DateField(db_column='DATE_LEAVING', null=True, blank=True)
    RELIGION = models.CharField(max_length=50, db_column='RELIGION', blank=True, default='')
    DOB_WORD = models.CharField(max_length=100, db_column='DOB_WORD', blank=True, default='')
    ADMN_ROUND = models.CharField(max_length=10, db_column='ADMN_ROUND', default='1')
    BANK_NAME = models.CharField(max_length=100, db_column='BANK_NAME', blank=True, default='')
    BANK_ACC_NO = models.CharField(max_length=20, db_column='BANK_ACC_NO', blank=True, default='')
    EMERGENCY_NO = models.CharField(max_length=15, db_column='EMERGENCY_NO', blank=True, default='')
    PER_TALUKA = models.CharField(max_length=50, db_column='PER_TALUKA', blank=True, default='')
    PER_DIST = models.CharField(max_length=50, db_column='PER_DIST', blank=True, default='')
    LOC_TALUKA = models.CharField(max_length=50, db_column='LOC_TALUKA', blank=True, default='')
    LOC_DIST = models.CharField(max_length=50, db_column='LOC_DIST', blank=True, default='')
    EDITPERSON = models.CharField(max_length=100, db_column='EDITPERSON', default='SYSTEM')
    ADMN_QUOTA_ID = models.IntegerField(db_column='ADMN_QUOTA_ID', default=0)
    STATUS = models.CharField(max_length=20, db_column='STATUS', default='ACTIVE')
    JOINING_STATUS = models.CharField(max_length=20, db_column='JOINING_STATUS', default='JOINED')
    REGISTRATION_DATE = models.DateField(db_column='REGISTRATION_DATE', default=timezone.now)
    LATERAL_STATUS = models.CharField(max_length=20, db_column='LATERAL_STATUS', default='NO')
    JOINING_STATUS_DATE = models.DateField(db_column='JOINING_STATUS_DATE', default=timezone.now)
    RETENTION_STATUS_DATE = models.DateField(db_column='RETENTION_STATUS_DATE', default=timezone.now)

    def save(self, *args, **kwargs):
        if not self.STUDENT_ID:
            latest_entry = STUDENT_MASTER.objects.filter(
                BATCH=self.BATCH, 
                BRANCH_ID=self.BRANCH_ID
            ).count() + 1
            program_name = self.BRANCH_ID.PROGRAM.NAME
            self.STUDENT_ID = f"{program_name}{self.BATCH[-2:]}{latest_entry:03d}"
        super().save(*args, **kwargs)

    class Meta:
        db_table = '"STUDENT"."STUDENT_MASTER"'
        verbose_name = 'Student Master'
        verbose_name_plural = 'Student Masters'
        indexes = [
            models.Index(fields=['STUDENT_ID']),
            models.Index(fields=['EMAIL_ID']),
            models.Index(fields=['MOB_NO'])
        ]

    def __str__(self):
        return f"{self.STUDENT_ID} - {self.NAME} {self.SURNAME}"

      
class STUDENT_ROLL_NUMBER_DETAILS(AuditModel):
    RECORD_ID = models.AutoField(primary_key=True, db_column='RECORD_ID')
    INSTITUTE = models.ForeignKey(INSTITUTE, on_delete=models.PROTECT, db_column='INSTITUTE_ID')
    BRANCH = models.ForeignKey(BRANCH, on_delete=models.PROTECT, db_column='BRANCH_ID')
    YEAR = models.ForeignKey(YEAR, on_delete=models.PROTECT, db_column='YEAR_ID')
    STUDENT = models.ForeignKey(
        'STUDENT_MASTER',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        related_name='roll_number_details'
    )
    ACADEMIC_YEAR = models.CharField(ACADEMIC_YEAR, max_length=10, db_column='ACADEMIC_YEAR')
    ROLL_NO = models.CharField(max_length=20, db_column='ROLLNO')
    SEMESTER = models.ForeignKey(SEMESTER, on_delete=models.PROTECT, db_column='SEMESTER_ID')
    BATCH = models.IntegerField(db_column='BATCH', null=True, blank=True)
    GUARDIAN = models.CharField(max_length=100, db_column='GUARDIAN', null=True, blank=True)

    class Meta:
        db_table = '"STUDENT"."STUDENT_ROLL_NUMBER_DETAILS"'
        verbose_name = 'Student Roll Number Details'
        verbose_name_plural = 'Student Roll Number Details'

    def __str__(self):
        return f"{self.STUDENT.RECORD_ID if self.STUDENT else None} - {self.ROLL_NO}"

class STUDENT_DETAILS(AuditModel):
    RECORD_ID = models.AutoField(primary_key=True, db_column='RECORD_ID')

    STUDENT = models.ForeignKey(
        'STUDENT_MASTER',
        on_delete=models.CASCADE,
        null=True,
        blank=True
    )

    PLACE_OF_BIRTH = models.CharField(max_length=100, db_column='PLACE_OF_BIRTH', null=True, blank=True, default='')
    LAST_CLG_ATTEND = models.CharField(max_length=255, db_column='LAST_CLG_ATTEND', null=True, blank=True, default='')
    LAST_CLG_ADD = models.CharField(db_column='LAST_CLG_ADD', null=True, blank=True, default='')
    LAST_CLG_CITY = models.CharField(max_length=100, db_column='LAST_CLG_CITY', null=True, blank=True, default='')
    LAST_CLG_UNIV = models.CharField(max_length=255, db_column='LAST_CLG_UNIV', null=True, blank=True, default='')
    LAST_CLG_ROLL = models.CharField(max_length=50, db_column='LAST_CLG_ROLL', null=True, blank=True, default='')

    PCM_MARKS = models.DecimalField(max_digits=6, decimal_places=2, db_column='PCM_MARKS', null=True, blank=True, default=None)
    PCM_OUTOF = models.DecimalField(max_digits=6, decimal_places=2, db_column='PCM_OUTOF', null=True, blank=True, default=None)
    TOT_MARKS_OBTAIN = models.DecimalField(max_digits=6, decimal_places=2, db_column='TOT_MARKS_OBTAIN', null=True, blank=True, default=None)
    TOT_MAX_MARKS = models.DecimalField(max_digits=6, decimal_places=2, db_column='TOT_MAX_MARKS', null=True, blank=True, default=None)
    SCORE = models.DecimalField(max_digits=6, decimal_places=2, db_column='SCORE', null=True, blank=True, default=None)
    MERIT = models.DecimalField(max_digits=6, decimal_places=2, db_column='MERIT', null=True, blank=True, default=None)

    NATIONALITY = models.CharField(max_length=50, db_column='NATIONALITY', null=True, blank=True, default='INDIAN')
    

    ADMISSION_QUOTA = models.IntegerField(db_column='ADMISSION_QUOTA', null=True, blank=True, default=None)
    QUALIFYING_EXAM = models.CharField(max_length=100, db_column='QUALIFYING_EXAM', null=True, blank=True, default='')
    MONTH_OF_PASSING = models.CharField(max_length=20, db_column='MONTH_OF_PASSING', null=True, blank=True, default='')
    YEAR_OF_PASSING = models.IntegerField(db_column='YEAR_OF_PASSING', null=True, blank=True, default=None)

    MEDIUM = models.CharField(max_length=50, db_column='MEDIUM', null=True, blank=True, default='')
    DRV_LICENSE = models.CharField(max_length=20, db_column='DRV_LICENSE', null=True, blank=True, default='')
    AADHAR_NO = models.CharField(max_length=12, db_column='AADHAR_NO', null=True, blank=True, default='')

    BANK_NAME = models.CharField(max_length=100, db_column='BANK_NAME', null=True, blank=True, default='')
    BRANCH_NAME = models.CharField(max_length=100, db_column='BRANCH_NAME', null=True, blank=True, default='')
    BANK_ACCOUNT_NO = models.CharField(max_length=20, db_column='BANK_ACCOUNT_NO', null=True, blank=True, default='')
    BANK_CITY = models.CharField(max_length=100, db_column='BANK_CITY', null=True, blank=True, default='')

    MINORITY = models.CharField(max_length=3, db_column='MINORITY', choices=[('YES', 'Yes'), ('NO', 'No')], default='NO')
    HOSTELER = models.CharField(max_length=3, db_column='HOSTELER', choices=[('YES', 'Yes'), ('NO', 'No')], default='NO')

    MOTHER_MOB = models.CharField(max_length=15, db_column='MOTHER_MOB', null=True, blank=True, default='')
    PARENT_MAIL = models.EmailField(db_column='PARENT_MAIL', null=True, blank=True, default='')
    FATHER_MOB = models.CharField(max_length=15, db_column='FATHER_MOB', null=True, blank=True, default='')

    INCOME = models.DecimalField(max_digits=10, decimal_places=2, db_column='INCOME', null=True, blank=True, default=None)
    PAN_NO = models.CharField(max_length=10, db_column='PAN_NO', null=True, blank=True, default='')
    
    COLLEGE_PREFERENCE = models.TextField(db_column='COLLEGE_PREFERENCE', null=True, blank=True, default='')

    

    class Meta:
        db_table = '"STUDENT"."STUDENT_DETAILS"'
        verbose_name = 'Student Details'
        verbose_name_plural = 'Student Details'
        indexes = [
            models.Index(fields=['AADHAR_NO']),
            models.Index(fields=['PAN_NO']),
        ]

    def __str__(self):
        return f"Details of {self.STUDENT.RECORD_ID if self.STUDENT else None}"    
    
class STUDENT_ACADEMIC_RECORD(AuditModel):
    RECORD_ID = models.AutoField(primary_key=True, db_column='RECORD_ID')
    STUDENT_ID = models.CharField(max_length=20, db_column='STUDENT_ID')
    INSTITUTE_ID = models.CharField(max_length=20, db_column='INSTITUTE_ID')
    CATEGORY = models.IntegerField(db_column='CATEGORY')
    BATCH = models.CharField(max_length=4, db_column='BATCH')
    ACADEMIC_YEAR = models.CharField(max_length=10, db_column='ACADEMIC_YEAR')
    CLASS_YEAR = models.IntegerField(db_column='CLASS_YEAR')
    ADMISSION_DATE = models.DateField(db_column='ADMISSION_DATE')
    FORM_NO = models.IntegerField(db_column='FORM_NO')
    QUOTA_ID = models.IntegerField(db_column='QUOTA_ID')
    STATUS = models.CharField(max_length=20, db_column='STATUS', default='ACTIVE')  # A for Active, you can customize
    FEE_CATEGORY_ID = models.IntegerField(db_column='FEE_CATEGORY_ID')

    class Meta:
        db_table = '"STUDENT"."STUDENT_ACADEMIC_RECORD"'
        verbose_name = 'Student Academic Record'
        verbose_name_plural = 'Student Academic Records'

    def __str__(self):
        return f"{self.STUDENT_ID} - {self.ACADEMIC_YEAR}"
        return f"Details of {self.STUDENT_ID}"

class CHECK_LIST_DOCUMENTS(AuditModel):
    RECORD_ID = models.AutoField(primary_key=True, db_column='RECORD_ID')  
    NAME = models.CharField(max_length=1000, db_column='NAME', unique=True, null=True)  
    IS_MANDATORY = models.BooleanField(default=False, db_column='IS_MANDATORY')
    class Meta:
        db_table = '"STUDENT"."CHECK_LIST_DOCUMNETS"'
        verbose_name = 'Check List Documents'
        verbose_name_plural = 'Check List Documents'

    def _str_(self):
        return f"{self.NAME} - {self.RECORD_ID}"

from django.db import models

def student_document_upload_path(instance, filename):
        ext = filename.split('.')[-1]
        student_id = instance.STUDENT.RECORD_ID if instance.STUDENT else 'UNKNOWN'
        doc_id = instance.DOCUMENT_ID.RECORD_ID if instance.DOCUMENT_ID else '0'
        new_filename = f"{student_id}_{doc_id}.{ext}"
        return os.path.join('student_documents', new_filename)

class STUDENT_DOCUMENTS(AuditModel):
    RECORDID = models.AutoField(primary_key=True)

    STUDENT = models.ForeignKey(
        'STUDENT_MASTER',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        db_column='RECORD_ID',
        related_name='DOCUMENTS_BY_STUDENT'
    )

    ACADEMIC_YEAR = models.CharField(max_length=10, db_column='ACADEMIC_YEAR', null=True)

    DOC_NAME = models.ForeignKey(
        'CHECK_LIST_DOCUMENTS',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        to_field='NAME',
        db_column='DOC_NAME',
        related_name='DOCUMENTS_BY_NAME'
    )

    DOCUMENT_ID = models.ForeignKey(
        'CHECK_LIST_DOCUMENTS',
        on_delete=models.SET_NULL,
        null=True,
        blank=True,
        to_field='RECORD_ID',
        db_column='DOCUMENT_ID',
        related_name='DOCUMENTS_BY_ID'
    )

    TEMPRETURN = models.CharField(max_length=1, blank=True, null=True, db_column='TEMPRETURN')
    RETURN = models.CharField(max_length=1, default='N', blank=True, null=True, db_column='RETURN')

    # Updated to handle actual file uploads
    DOC_IMAGES = models.FileField(
        upload_to=student_document_upload_path,
        blank=True,
        null=True,
        db_column='DOC_IMAGES'
    )

    VERIFIED = models.CharField(max_length=1, default='V', blank=True, null=True, db_column='VERIFIED')
    ORIGINAL = models.CharField(max_length=1, blank=True, null=True, db_column='ORIGINAL')
    PHOTOCOPY = models.CharField(max_length=1, blank=True, null=True, db_column='PHOTOCOPY')
    REMARKS = models.CharField(max_length=500, blank=True, null=True, db_column='REMARKS')
    DEFICIENCY = models.CharField(max_length=1, blank=True, null=True, db_column='DEFICIENCY')

    class Meta:
        db_table = '"STUDENT"."STUDENT_DOCUMENTS"'
        verbose_name = 'Student Documents'
        verbose_name_plural = 'Student Documents'
        unique_together = ('STUDENT', 'DOCUMENT_ID')

    def __str__(self):
        return f"Student Document Record {self.RECORDID}"

