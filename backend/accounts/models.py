from django.db import models
from django.contrib.auth.hashers import make_password, check_password
from django.utils import timezone
import random
import string
from core.models import AuditModel
from django.contrib.auth.models import AbstractUser, BaseUserManager
import secrets
from datetime import datetime, timedelta

class CustomUserManager(BaseUserManager):
    def get_by_natural_key(self, username):
        """
        Enable authentication via USERNAME field
        """
        return self.get(USERNAME=username)

    def normalize_email(self, email):
        """
        Normalize the email address by lowercasing it.
        """
        return email.lower() if email else None

    def create_user(self, USER_ID, USERNAME, EMAIL, password=None, **extra_fields):
        if not USER_ID:
            raise ValueError('USER_ID is required')
        if not USERNAME:
            raise ValueError('USERNAME is required')
        if not EMAIL:
            raise ValueError('EMAIL is required')

        user = self.model(
            USER_ID=USER_ID,
            USERNAME=USERNAME,
            EMAIL=self.normalize_email(EMAIL),
            **extra_fields
        )
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, USER_ID, USERNAME, EMAIL, password=None, **extra_fields):
        if not EMAIL:
            raise ValueError('EMAIL is required')
        if not USERNAME:
            raise ValueValueError('USERNAME is required')
        if not USER_ID:
            raise ValueError('USER_ID is required')
            
        extra_fields.setdefault('IS_STAFF', True)
        extra_fields.setdefault('IS_SUPERUSER', True)
        extra_fields.setdefault('IS_ACTIVE', True)
        
        user = self.model(
            USER_ID=USER_ID,
            USERNAME=USERNAME,
            EMAIL=self.normalize_email(EMAIL),
            **extra_fields
        )
        user.set_password(password)
        user.save(using=self._db)
        return user

    def make_random_password(self, length=10, 
                           allowed_chars='abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789'):
        """
        Generate a random password with the given length and allowed characters.
        """
        return ''.join(random.choice(allowed_chars) for i in range(length))

class DESIGNATION(AuditModel):
    DESIGNATION_ID = models.AutoField(primary_key=True, db_column='DESIGNATION_ID')
    NAME = models.CharField(max_length=50, unique=True, db_column='NAME')
    CODE = models.CharField(max_length=20, unique=True, db_column='CODE')
    DESCRIPTION = models.TextField(null=True, blank=True, db_column='DESCRIPTION')
    PERMISSIONS = models.JSONField(
        default=dict, 
        db_column='PERMISSIONS',
        help_text='Define permissions like {"module_name": {"action": bool}}'
    )
    IS_ACTIVE = models.BooleanField(default=True, db_column='IS_ACTIVE')
    CREATED_AT = models.DateTimeField(auto_now_add=True, db_column='CREATED_AT')
    UPDATED_AT = models.DateTimeField(auto_now=True, db_column='UPDATED_AT')
    CREATED_BY = models.CharField(max_length=50, db_column='CREATED_BY', default='system')
    UPDATED_BY = models.CharField(max_length=50, db_column='UPDATED_BY', default='system')

    class Meta:
        db_table = 'DESIGNATIONS'
        verbose_name = 'Designation'
        verbose_name_plural = 'Designations'

    def __str__(self):
        return f"{self.DESIGNATION_ID} - {self.NAME}"

class PASSWORD_HISTORY(models.Model):
    PASSWORD_HISTORY_ID = models.AutoField(primary_key=True, db_column='PASSWORD_HISTORY_ID')
    USER = models.ForeignKey(
        'CustomUser', 
        on_delete=models.CASCADE, 
        related_name='password_history',
        db_column='USER_ID'
    )
    PASSWORD = models.CharField(max_length=128, db_column='PASSWORD')
    CREATED_AT = models.DateTimeField(auto_now_add=True, db_column='CREATED_AT')

    class Meta:
        db_table = 'PASSWORD_HISTORY'
        ordering = ['-CREATED_AT']

class CustomUser(AbstractUser):
    # Disable default fields completely
    last_login = None  
    date_joined = None
    
    # Use our uppercase versions
    LAST_LOGIN = models.DateTimeField(null=True, blank=True, db_column='LAST_LOGIN')
    DATE_JOINED = models.DateTimeField(default=timezone.now, db_column='DATE_JOINED')
    
    # Required fields for Django auth
    USERNAME_FIELD = 'USERNAME'
    EMAIL_FIELD = 'EMAIL'
    REQUIRED_FIELDS = ['EMAIL', 'USER_ID']  # Add as class variable, not instance variable
    
    # Primary Key
    USER_ID = models.CharField(
        primary_key=True,
        max_length=20,
        db_column='USER_ID'
    )

    # Authentication fields
    USERNAME = models.CharField(
        max_length=150,
        unique=True,
        db_column='USERNAME'
    )
    PASSWORD = models.CharField(
        max_length=128,
        db_column='PASSWORD'
    )
    EMAIL = models.EmailField(
        unique=True,
        db_column='EMAIL'
    )

    # Personal Information
    FIRST_NAME = models.CharField(max_length=150, db_column='FIRST_NAME')
    LAST_NAME = models.CharField(max_length=150, db_column='LAST_NAME')
    DESIGNATION = models.ForeignKey(
        DESIGNATION, 
        null=True,  # Add this
        blank=True,  # Add this
        on_delete=models.PROTECT, 
        db_column='DESIGNATION_ID',
        related_name='users'
    )
    PHONE_NUMBER = models.CharField(max_length=15, null=True, blank=True, db_column='PHONE_NUMBER')
    PROFILE_PICTURE = models.ImageField(upload_to='profile_pics/', null=True, blank=True, db_column='PROFILE_PICTURE')

    # Status fields
    IS_ACTIVE = models.BooleanField(default=True, db_column='IS_ACTIVE')
    IS_STAFF = models.BooleanField(default=False, db_column='IS_STAFF')
    IS_SUPERUSER = models.BooleanField(default=False, db_column='IS_SUPERUSER')
    IS_EMAIL_VERIFIED = models.BooleanField(default=False, db_column='IS_EMAIL_VERIFIED')
    
    # Timestamps
    CREATED_AT = models.DateTimeField(
        auto_now_add=True, 
        db_column='CREATED_AT'
    )
    UPDATED_AT = models.DateTimeField(
        auto_now=True, 
        db_column='UPDATED_AT'
    )
    LAST_LOGIN = models.DateTimeField(null=True, blank=True, db_column='LAST_LOGIN')
    DATE_JOINED = models.DateTimeField(
        default=timezone.now,  # Change from auto_now_add to default
        db_column='DATE_JOINED'
    )

    # Security and Login tracking fields
    LAST_LOGIN_IP = models.GenericIPAddressField(null=True, blank=True, db_column='LAST_LOGIN_IP')
    LAST_LOGIN_ATTEMPT = models.DateTimeField(null=True, blank=True, db_column='LAST_LOGIN_ATTEMPT')
    LAST_FAILED_LOGIN = models.DateTimeField(null=True, blank=True, db_column='LAST_FAILED_LOGIN')  # Add this field
    FAILED_LOGIN_ATTEMPTS = models.IntegerField(default=0, db_column='FAILED_LOGIN_ATTEMPTS')
    IS_LOCKED = models.BooleanField(default=False, db_column='IS_LOCKED')
    LOCKED_UNTIL = models.DateTimeField(null=True, blank=True, db_column='LOCKED_UNTIL')
    PASSWORD_CHANGED_AT = models.DateTimeField(null=True, blank=True, db_column='PASSWORD_CHANGED_AT')
    PERMANENT_LOCK = models.BooleanField(default=False, db_column='PERMANENT_LOCK')
    LOCK_REASON = models.CharField(max_length=255, null=True, blank=True, db_column='LOCK_REASON')
    
    # OTP related fields
    OTP_SECRET = models.CharField(max_length=16, null=True, blank=True, db_column='OTP_SECRET')
    OTP_CREATED_AT = models.DateTimeField(null=True, blank=True, db_column='OTP_CREATED_AT')
    OTP_ATTEMPTS = models.IntegerField(default=0, db_column='OTP_ATTEMPTS')
    OTP_VERIFIED = models.BooleanField(default=False, db_column='OTP_VERIFIED')
    MAX_OTP_TRY = models.IntegerField(default=3, db_column='MAX_OTP_TRY')
    OTP_BLOCKED_UNTIL = models.DateTimeField(null=True, blank=True, db_column='OTP_BLOCKED_UNTIL')
    OTP_EXPIRY = models.DateTimeField(null=True, blank=True)  # Add this field

    objects = CustomUserManager()

    class Meta:
        db_table = '"ADMIN"."USERS"'  # Not just 'USERS'
        verbose_name = 'User'
        verbose_name_plural = 'Users'
        ordering = ['USER_ID']

    @property
    def is_anonymous(self):
        return False

    @property
    def is_authenticated(self):
        return True

    @property
    def is_active(self):
        return self.IS_ACTIVE

    @is_active.setter
    def is_active(self, value):
        self.IS_ACTIVE = value

    @property
    def is_staff(self):
        return self.IS_STAFF

    @property
    def is_superuser(self):
        return self.IS_SUPERUSER

    @property
    def is_email_verified(self):
        return self.IS_EMAIL_VERIFIED

    @property
    def username(self):
        return self.USERNAME

    @property
    def email(self):
        return self.EMAIL

    @property
    def first_name(self):
        return self.FIRST_NAME

    @property
    def last_name(self):
        return self.LAST_NAME

    @property
    def password(self):
        return self.PASSWORD

    @password.setter
    def password(self, value):
        self.PASSWORD = value

    def get_username(self):
        return self.USERNAME

    def check_password_history(self, raw_password):
        """Check if password exists in user's password history"""
        for history in self.password_history.all()[:5]:
            if check_password(raw_password, history.PASSWORD):
                return False
        return True

    def set_password(self, raw_password):
        """Override set_password to include password history"""
        if not raw_password:
            return

        # Only check password history if user already exists
        if self.pk and not self.check_password_history(raw_password):
            raise ValueError("Cannot reuse any of your last 5 passwords")

        self.PASSWORD = make_password(raw_password)
        self.PASSWORD_CHANGED_AT = timezone.now()
        
        # Don't save or create password history during initial user creation
        if not self._state.adding:  # Only if this is an update, not a new user
            self.save()
            
            PASSWORD_HISTORY.objects.create(
                USER=self,
                PASSWORD=self.PASSWORD
            )
            
            # Keep only last 5 passwords
            old_passwords = self.password_history.all()[5:]
            for old_password in old_passwords:
                old_password.delete()

    def check_password(self, raw_password):
        return check_password(raw_password, self.PASSWORD)

    def get_session_auth_hash(self):
        """
        Override to use our PASSWORD field instead of password
        """
        return self.PASSWORD

    def has_perm(self, perm, obj=None):
        return self.IS_SUPERUSER

    def has_module_perms(self, app_label):
        return self.IS_SUPERUSER

    def increment_failed_attempts(self):
        self.FAILED_LOGIN_ATTEMPTS = (self.FAILED_LOGIN_ATTEMPTS or 0) + 1
        self.LAST_FAILED_LOGIN = timezone.now()
        
        # Update lock status based on attempts
        if self.FAILED_LOGIN_ATTEMPTS >= 8:
            self.PERMANENT_LOCK = True
            self.LOCK_REASON = "Too many failed login attempts (8+). Administrative unlock required."
        elif self.FAILED_LOGIN_ATTEMPTS >= 5:
            self.LOCKED_UNTIL = timezone.now() + timezone.timedelta(hours=6)
        elif self.FAILED_LOGIN_ATTEMPTS >= 3:
            self.LOCKED_UNTIL = timezone.now() + timezone.timedelta(hours=1)
            
        self.save(update_fields=[
            'FAILED_LOGIN_ATTEMPTS', 
            'LAST_FAILED_LOGIN',
            'PERMANENT_LOCK',
            'LOCK_REASON',
            'LOCKED_UNTIL'
        ])

    def reset_failed_attempts(self):
        if self.PERMANENT_LOCK:
            return False  # Can't reset if permanently locked
            
        self.FAILED_LOGIN_ATTEMPTS = 0
        self.LAST_FAILED_LOGIN = None
        self.LOCKED_UNTIL = None
        self.save(update_fields=[
            'FAILED_LOGIN_ATTEMPTS',
            'LAST_FAILED_LOGIN',
            'LOCKED_UNTIL'
        ])
        return True

    def is_account_locked(self):
        """
        Check account lock status with different conditions:
        - 3 failed attempts: 1 hour lock
        - 5 failed attempts: 6 hours lock
        - 8 or more attempts: permanent lock (admin unlock required)
        """
        if self.PERMANENT_LOCK:
            return True, "Account is permanently locked. Please contact administrator."

        if not self.FAILED_LOGIN_ATTEMPTS or not self.LAST_FAILED_LOGIN:
            return False, "Account is not locked."

        current_time = timezone.now()

        # Check for permanent lock (8+ attempts)
        if self.FAILED_LOGIN_ATTEMPTS >= 8:
            self.PERMANENT_LOCK = True
            self.LOCK_REASON = "Too many failed login attempts (8+). Administrative unlock required."
            self.save(update_fields=['PERMANENT_LOCK', 'LOCK_REASON'])
            return True, "Account has been permanently locked due to too many failed attempts. Please contact administrator."

        # Check for 6-hour lock (5-7 attempts)
        if self.FAILED_LOGIN_ATTEMPTS >= 5:
            lock_duration = timezone.timedelta(hours=6)
            lock_end_time = self.LAST_FAILED_LOGIN + lock_duration
            if current_time < lock_end_time:
                remaining_time = lock_end_time - current_time
                hours = int(remaining_time.total_seconds() // 3600)
                minutes = int((remaining_time.total_seconds() % 3600) // 60)
                return True, f"Account is locked for {hours}h {minutes}m due to multiple failed attempts."

        # Check for 1-hour lock (3-4 attempts)
        if self.FAILED_LOGIN_ATTEMPTS >= 3:
            lock_duration = timezone.timedelta(hours=1)
            lock_end_time = self.LAST_FAILED_LOGIN + lock_duration
            if current_time < lock_end_time:
                remaining_time = lock_end_time - current_time
                minutes = int(remaining_time.total_seconds() // 60)
                return True, f"Account is locked for {minutes} minutes due to failed attempts."

        # Reset failed attempts if lock period has expired
        self.reset_failed_attempts()
        return False, "Account is not locked."

    def update_login_info(self, ip_address):
        """Update login audit information"""
        current_time = timezone.now()
        update_fields = [
            'LAST_LOGIN_IP',
            'LAST_LOGIN',
            'LAST_LOGIN_ATTEMPT',
            'FAILED_LOGIN_ATTEMPTS',
            'IS_LOCKED',
            'LOCKED_UNTIL'
        ]
        
        self.LAST_LOGIN_IP = ip_address
        self.LAST_LOGIN = current_time
        self.LAST_LOGIN_ATTEMPT = current_time
        self.FAILED_LOGIN_ATTEMPTS = 0
        self.IS_LOCKED = False
        self.LOCKED_UNTIL = None
        
        self.save(update_fields=update_fields)

    def generate_otp(self):
        try:
            otp = ''.join(secrets.choice(string.digits) for _ in range(6))
            current_time = timezone.now()
            expiry = current_time + timezone.timedelta(minutes=3)
            
            update_fields = {
                'OTP_SECRET': otp,
                'OTP_EXPIRY': expiry,
                'OTP_CREATED_AT': current_time,
                'OTP_ATTEMPTS': 0,
                'OTP_VERIFIED': False,
                'OTP_BLOCKED_UNTIL': None  # Reset blocking when new OTP generated
            }
            
            # Update all fields atomically
            CustomUser.objects.filter(pk=self.pk).update(**update_fields)
            
            # Update instance attributes
            for field, value in update_fields.items():
                setattr(self, field, value)
            
            return otp
        except Exception as e:
            print(f"OTP Generation error: {str(e)}")
            return None

    def verify_otp(self, otp, clear_on_success=False):
        try:
            current_time = timezone.now()

            # Check if OTP is blocked
            if self.OTP_BLOCKED_UNTIL and current_time < self.OTP_BLOCKED_UNTIL:
                block_remaining = self.OTP_BLOCKED_UNTIL - current_time
                minutes = int(block_remaining.total_seconds() // 60)
                return False, f"OTP verification blocked for {minutes} minutes"

            if not self.OTP_SECRET or not self.OTP_EXPIRY:
                return False, "No valid OTP found"

            if current_time > self.OTP_EXPIRY:
                self.OTP_SECRET = None
                self.OTP_EXPIRY = None
                self.save(update_fields=['OTP_SECRET', 'OTP_EXPIRY'])
                return False, "OTP has expired"

            if self.OTP_ATTEMPTS >= self.MAX_OTP_TRY:
                # Block OTP verification for 15 minutes
                self.OTP_BLOCKED_UNTIL = current_time + timezone.timedelta(minutes=15)
                self.save(update_fields=['OTP_BLOCKED_UNTIL'])
                return False, "Too many attempts. Try again after 15 minutes"

            if otp != self.OTP_SECRET:
                self.OTP_ATTEMPTS += 1
                self.save(update_fields=['OTP_ATTEMPTS'])
                remaining = self.MAX_OTP_TRY - self.OTP_ATTEMPTS
                return False, f"Invalid OTP. {remaining} attempts remaining"

            # Success case
            update_fields = {
                'OTP_VERIFIED': True,
                'OTP_ATTEMPTS': 0
            }
            
            if clear_on_success:
                update_fields.update({
                    'OTP_SECRET': None,
                    'OTP_EXPIRY': None
                })

            # Update all fields
            for field, value in update_fields.items():
                setattr(self, field, value)
            self.save(update_fields=list(update_fields.keys()))
            
            return True, "OTP verified successfully"
            
        except Exception as e:
            print(f"OTP verification error: {str(e)}")
            return False, "Error during OTP verification"

    def has_module_permission(self, module_name):
        """Check if user has permission for a module based on designation"""
        if self.IS_SUPERUSER:
            return True
        return self.DESIGNATION.PERMISSIONS.get(module_name, {}).get('access', False)

    def has_action_permission(self, module_name, action):
        """Check if user has permission for specific action in a module"""
        if self.IS_SUPERUSER:
            return True
        return self.DESIGNATION.PERMISSIONS.get(module_name, {}).get(action, False)

    @classmethod
    def get_email_field_name(cls):
        return cls.EMAIL_FIELD

    def save(self, *args, **kwargs):
        if self.pk:  # If this is an update
            try:
                old_instance = self.__class__.objects.filter(pk=self.pk).first()
                if old_instance:
                    # Store all audit fields
                    audit_fields = [
                        'LAST_LOGIN_ATTEMPT',
                        'LAST_FAILED_LOGIN',
                        'LAST_LOGIN_IP',
                        'FAILED_LOGIN_ATTEMPTS',
                        'IS_LOCKED',
                        'LOCKED_UNTIL',
                        'PERMANENT_LOCK',
                        'LOCK_REASON',
                        'OTP_BLOCKED_UNTIL'
                    ]
                    # Preserve existing audit field values
                    for field in audit_fields:
                        current_value = getattr(self, field, None)
                        if current_value is None:
                            setattr(self, field, getattr(old_instance, field, None))
            except self.__class__.DoesNotExist:
                pass
        super().save(*args, **kwargs)

    def delete(self, *args, **kwargs):
        super().delete(*args, **kwargs)

class UNIVERSITY(AuditModel):
    UNIVERSITY_ID = models.AutoField(primary_key=True, db_column='UNIVERSITY_ID')
    NAME = models.CharField(max_length=255, db_column='NAME')
    CODE = models.CharField(max_length=50, unique=True, db_column='CODE')
    ADDRESS = models.TextField(db_column='ADDRESS')
    CONTACT_NUMBER = models.CharField(max_length=15, db_column='CONTACT_NUMBER')
    EMAIL = models.EmailField(unique=True, db_column='EMAIL')
    WEBSITE = models.URLField(null=True, blank=True, db_column='WEBSITE')
    ESTD_YEAR = models.IntegerField(db_column='ESTD_YEAR')
    IS_ACTIVE = models.BooleanField(default=True, db_column='IS_ACTIVE')
    CREATED_BY = models.CharField(max_length=50, db_column='CREATED_BY', default='system')
    UPDATED_BY = models.CharField(max_length=50, db_column='UPDATED_BY', default='system')

    class Meta:
        db_table = 'UNIVERSITIES'
        verbose_name = 'University'
        verbose_name_plural = 'Universities'

    def __str__(self):
        return f"{self.CODE} - {self.NAME}"

class INSTITUTE(AuditModel):
    INSTITUTE_ID = models.AutoField(primary_key=True, db_column='INSTITUTE_ID')
    UNIVERSITY = models.ForeignKey(
        UNIVERSITY,
        on_delete=models.PROTECT,
        db_column='UNIVERSITY_ID',
        related_name='institutes'
    )
    NAME = models.CharField(max_length=255, db_column='NAME')
    CODE = models.CharField(max_length=50, unique=True, db_column='CODE')
    ADDRESS = models.TextField(db_column='ADDRESS')
    CONTACT_NUMBER = models.CharField(max_length=15, db_column='CONTACT_NUMBER')
    EMAIL = models.EmailField(unique=True, db_column='EMAIL')
    WEBSITE = models.URLField(null=True, blank=True, db_column='WEBSITE')
    ESTD_YEAR = models.IntegerField(db_column='ESTD_YEAR')
    IS_ACTIVE = models.BooleanField(default=True, db_column='IS_ACTIVE')
    CREATED_BY = models.CharField(max_length=50, db_column='CREATED_BY', default='system')
    UPDATED_BY = models.CharField(max_length=50, db_column='UPDATED_BY', default='system')

    class Meta:
        db_table = 'INSTITUTES'
        verbose_name = 'Institute'
        verbose_name_plural = 'Institutes'

    def __str__(self):
        return f"{self.CODE} - {self.NAME}"

class PROGRAM(AuditModel):
    PROGRAM_ID = models.AutoField(primary_key=True, db_column='PROGRAM_ID')
    INSTITUTE = models.ForeignKey(
        INSTITUTE,
        on_delete=models.PROTECT,
        db_column='INSTITUTE_ID',
        related_name='programs'
    )
    NAME = models.CharField(max_length=255, db_column='NAME')
    CODE = models.CharField(max_length=20, unique=True, db_column='CODE')
    DURATION_YEARS = models.IntegerField(db_column='DURATION_YEARS')
    LEVEL = models.CharField(
        max_length=10,
        choices=[
            ('UG', 'Undergraduate'),
            ('PG', 'Postgraduate'),
            ('DIP', 'Diploma')
        ],
        db_column='LEVEL'
    )
    TYPE = models.CharField(
        max_length=2,
        choices=[
            ('FT', 'Full Time'),
            ('PT', 'Part Time')
        ],
        db_column='TYPE'
    )
    DESCRIPTION = models.TextField(
        db_column='DESCRIPTION',
        null=True,
        blank=True,
        default=""
    )
    IS_ACTIVE = models.BooleanField(default=True, db_column='IS_ACTIVE')
    CREATED_BY = models.CharField(max_length=50, db_column='CREATED_BY', default='system')
    UPDATED_BY = models.CharField(max_length=50, db_column='UPDATED_BY', default='system')
   

    class Meta:
        db_table = 'PROGRAMS'
        verbose_name = 'Program'
        verbose_name_plural = 'Programs'

    def __str__(self):
        return f"{self.CODE} - {self.NAME}"
    
class DEPARTMENT(AuditModel):
    DEPARTMENT_ID = models.AutoField(primary_key=True, db_column='DEPARTMENT_ID')
    INSTITUTE_CODE = models.CharField(
        max_length=50,
        db_column='INSTITUTE_CODE',
        default='DEFAULT', 
    )
    NAME = models.CharField(max_length=255, db_column='NAME')
    CODE = models.CharField(max_length=20, unique=True, db_column='CODE')
    IS_ACTIVE = models.BooleanField(default=True, db_column='IS_ACTIVE')
    
    class Meta:
        db_table = 'DEPARTMENTS'
        verbose_name = 'Department'
        verbose_name_plural = 'Departments'

    def __str__(self):
        return f"{self.CODE} - {self.NAME}"

class BRANCH(AuditModel):
    BRANCH_ID = models.AutoField(primary_key=True, db_column='BRANCH_ID' )
    PROGRAM = models.ForeignKey(
        PROGRAM,
        on_delete=models.PROTECT,
        db_column='PROGRAM_ID',
        related_name='branches'
    )
    NAME = models.CharField(max_length=255, db_column='NAME')
    CODE = models.CharField(max_length=20, unique=True, db_column='CODE')
    DESCRIPTION = models.TextField(
        db_column='DESCRIPTION',
        null=True,
        blank=True,
        default=""
    )
    IS_ACTIVE = models.BooleanField(default=True, db_column='IS_ACTIVE')
    CREATED_BY = models.CharField(max_length=50, db_column='CREATED_BY', default='system')
    UPDATED_BY = models.CharField(max_length=50, db_column='UPDATED_BY', default='system')

    class Meta:
        db_table = 'BRANCHES'
        verbose_name = 'Branch'
        verbose_name_plural = 'Branches'

    def __str__(self):
        return f"{self.CODE} - {self.NAME}"
    
class YEAR(AuditModel):
    YEAR_ID = models.AutoField(primary_key=True, db_column='YEAR_ID')
    YEAR = models.CharField(max_length=255, db_column='YEAR')
    BRANCH = models.ForeignKey(
        BRANCH,
        on_delete=models.PROTECT,
        db_column='BRANCH_ID',
        related_name='years'
    )

    class Meta:
        db_table = 'YEARS'
        verbose_name = 'Year'
        verbose_name_plural = 'Years'

    def _str_(self):
        return f"{self.YEAR_ID} - {self.YEAR}"

class SEMESTER(AuditModel):
    SEMESTER_ID = models.AutoField(primary_key=True, db_column='SEMESTER_ID')
    SEMESTER = models.CharField(max_length=255, db_column='SEMESTER')
    YEAR = models.ForeignKey(
        YEAR, 
        on_delete=models.PROTECT,
        db_column='YEAR_ID',
        related_name='semesters'
    )
    class Meta:
        db_table = 'SEMESTERS'
        verbose_name = 'Semester'
        verbose_name_plural = 'Semesters'

    def _str_(self):
        return f"{self.SEMESTER_ID} - {self.SEMESTER}"

class COUNTRY(AuditModel):
    COUNTRY_ID = models.AutoField(primary_key=True, db_column='COUNTRY_ID')
    NAME = models.CharField(max_length=100, db_column='NAME')
    CODE = models.CharField(max_length=3, unique=True, db_column='CODE')
    PHONE_CODE = models.CharField(max_length=5, db_column='PHONE_CODE')
    IS_ACTIVE = models.BooleanField(default=True, db_column='IS_ACTIVE')
    CREATED_BY = models.CharField(max_length=50, db_column='CREATED_BY', null=True)  # Changed
    UPDATED_BY = models.CharField(max_length=50, db_column='UPDATED_BY', null=True)  # Changed

    class Meta:
        db_table = 'COUNTRIES'
        verbose_name = 'Country'
        verbose_name_plural = 'Countries'

    def __str__(self):
        return f"{self.CODE} - {self.NAME}"

class STATE(AuditModel):
    STATE_ID = models.AutoField(primary_key=True, db_column='STATE_ID')
    COUNTRY = models.ForeignKey(
        COUNTRY,
        on_delete=models.PROTECT,
        db_column='COUNTRY_ID',
        related_name='states'
    )
    NAME = models.CharField(max_length=100, db_column='NAME')
    CODE = models.CharField(max_length=3, db_column='CODE')
    IS_ACTIVE = models.BooleanField(default=True, db_column='IS_ACTIVE')
    CREATED_BY = models.CharField(max_length=50, db_column='CREATED_BY', null=True)  # Changed
    UPDATED_BY = models.CharField(max_length=50, db_column='UPDATED_BY', null=True)  # Changed
    CREATED_AT = models.DateTimeField(auto_now_add=True, db_column='CREATED_AT')
    UPDATED_AT = models.DateTimeField(auto_now=True, db_column='UPDATED_AT')

    class Meta:
        db_table = 'STATES'
        verbose_name = 'State'
        verbose_name_plural = 'States'
        unique_together = ('COUNTRY', 'CODE')

    def __str__(self):
        return f"{self.CODE} - {self.NAME}"

class CITY(AuditModel):
    CITY_ID = models.AutoField(primary_key=True, db_column='CITY_ID')
    STATE = models.ForeignKey(
        STATE,
        on_delete=models.PROTECT,
        db_column='STATE_ID',
        related_name='cities'
    )
    NAME = models.CharField(max_length=100, db_column='NAME')
    CODE = models.CharField(max_length=5, db_column='CODE')
    IS_ACTIVE = models.BooleanField(default=True, db_column='IS_ACTIVE')
    CREATED_BY = models.CharField(max_length=50, db_column='CREATED_BY', default='system')
    UPDATED_BY = models.CharField(max_length=50, db_column='UPDATED_BY', default='system')

    class Meta:
        db_table = 'CITIES'
        verbose_name = 'City'
        verbose_name_plural = 'Cities'
        unique_together = ('STATE', 'CODE')

    def __str__(self):
        return f"{self.CODE} - {self.NAME}"

class CURRENCY(AuditModel):
    CURRENCY_ID = models.AutoField(primary_key=True, db_column='CURRENCY_ID')
    NAME = models.CharField(max_length=50, db_column='NAME')
    CODE = models.CharField(max_length=3, unique=True, db_column='CODE')
    SYMBOL = models.CharField(max_length=5, db_column='SYMBOL')
    IS_ACTIVE = models.BooleanField(default=True, db_column='IS_ACTIVE')
    CREATED_BY = models.CharField(max_length=50, db_column='CREATED_BY', default='system')
    UPDATED_BY = models.CharField(max_length=50, db_column='UPDATED_BY', default='system')

    class Meta:
        db_table = 'CURRENCIES'
        verbose_name = 'Currency'
        verbose_name_plural = 'Currencies'

    def __str__(self):
        return f"{self.CODE} ({self.SYMBOL})"

class LANGUAGE(AuditModel):
    LANGUAGE_ID = models.AutoField(primary_key=True, db_column='LANGUAGE_ID')
    NAME = models.CharField(max_length=50, db_column='NAME')
    CODE = models.CharField(max_length=5, unique=True, db_column='CODE')
    IS_ACTIVE = models.BooleanField(default=True, db_column='IS_ACTIVE')
    CREATED_BY = models.CharField(max_length=50, db_column='CREATED_BY', default='system')
    UPDATED_BY = models.CharField(max_length=50, db_column='UPDATED_BY', default='system')

    class Meta:
        db_table = 'LANGUAGES'
        verbose_name = 'Language'
        verbose_name_plural = 'Languages'

    def __str__(self):
        return f"{self.CODE} - {self.NAME}"

class CATEGORY(AuditModel):
    CATEGORY_ID = models.AutoField(primary_key=True, db_column='CATEGORY_ID')
    NAME = models.CharField(max_length=50, db_column='NAME')
    CODE = models.CharField(max_length=10, unique=True, db_column='CODE')
    DESCRIPTION = models.TextField(null=True, blank=True, db_column='DESCRIPTION')
    RESERVATION_PERCENTAGE = models.DecimalField(
        max_digits=5,
        decimal_places=2,
        default=0.00,
        db_column='RESERVATION_PERCENTAGE'
    )
    IS_ACTIVE = models.BooleanField(default=True, db_column='IS_ACTIVE')
    CREATED_BY = models.CharField(max_length=50, db_column='CREATED_BY', default='system')
    UPDATED_BY = models.CharField(max_length=50, db_column='UPDATED_BY', default='system')

    class Meta:
        db_table = 'CATEGORIES'
        verbose_name = 'Category'
        verbose_name_plural = 'Categories'
    def __str__(self):
        return f"{self.CODE} - {self.NAME}"

class ACADEMIC_YEAR(AuditModel):
    ACADEMIC_YEAR_ID = models.AutoField(primary_key=True, db_column='ACADEMIC_YEAR_ID')  # Primary key
    ACADEMIC_YEAR = models.CharField(max_length=50, db_column='ACADEMIC_YEAR',null=True)  # Academic year (e.g., "2023-2024")
    START_DATE = models.DateField(db_column='START_DATE')  # Start date of the academic year
    END_DATE = models.DateField(db_column='END_DATE')  # End date of the academic year
    INSTITUTE = models.CharField(max_length=50, db_column='INSTITUTE', null=True) 


    IS_ACTIVE = models.BooleanField(default=True, db_column='IS_ACTIVE')
    CREATED_BY = models.CharField(max_length=50, db_column='CREATED_BY', default='system')
    UPDATED_BY = models.CharField(max_length=50, db_column='UPDATED_BY', default='system')

    class Meta:
        db_table = 'ACADEMIC_YEARS'
        verbose_name = 'Academic Year'
        verbose_name_plural = 'Academic Years'

class DASHBOARD_MASTER(AuditModel):
    DBM_ID = models.AutoField(primary_key=True, db_column='DBM_ID')
    EMP_ID = models.CharField(max_length=50, db_column='EMP_ID')  # Removed unique=True
    DASHBOARD_NAME = models.CharField(max_length=50, db_column='DASHBOARD_NAME')
    INSTITUTE = models.CharField(max_length=50, db_column='INSTITUTE_ID')

    class Meta:
        db_table = 'DASHBOARD_MASTER'
        verbose_name = 'Dashboard Master'
        verbose_name_plural = 'Dashboard Masters'

    def __str__(self):
        return f"{self.DASHBOARD_NAME} - {self.EMP_ID}"


class SEMESTER_DURATION(AuditModel):
    SEMESTER_DURATION_ID = models.AutoField(primary_key=True, db_column='SEMESTER_DURATION_ID')
    SEMESTER = models.CharField(max_length=50, db_column='SEMESTER', null=True)
    START_DATE = models.DateField(db_column='START_DATE')
    END_DATE = models.DateField(db_column='END_DATE')

    IS_ACTIVE = models.BooleanField(default=True, db_column='IS_ACTIVE')
    CREATED_BY = models.CharField(max_length=50, db_column='CREATED_BY', default='system')
    UPDATED_BY = models.CharField(max_length=50, db_column='UPDATED_BY', default='system')

    class Meta:
        db_table = 'SEMESTER_DURATION'
        verbose_name = 'Semester Duration'
        verbose_name_plural = 'Semester Durations'

    def __str__(self):
        return f"{self.SEMESTER} ({self.START_DATE} - {self.END_DATE})"
    
class CASTE_MASTER(AuditModel):
    CASTE_ID = models.AutoField(primary_key=True, db_column='CASTE_ID')  
    NAME = models.CharField(max_length=50, db_column='NAME', null=True)  

    class Meta:
        db_table = 'CASTE_MASTER'
        verbose_name = 'Caste Master'
        verbose_name_plural = 'Caste Masters'

    def __str__(self):
        return f"{self.NAME} - {self.CASTE_ID}"

class QUOTA_MASTER(AuditModel):
    QUOTA_ID = models.AutoField(primary_key=True, db_column='CASTE_ID')  
    NAME = models.CharField(max_length=50, db_column='NAME', null=True)  

    class Meta:
        db_table = 'QUOTA_MASTER'
        verbose_name = 'Quota Master'
        verbose_name_plural = 'Quota Masters'

    def __str__(self):
        return f"{self.NAME} - {self.QUOTA_ID}"

class ADMISSION_QUOTA_MASTER(AuditModel):
    ADMN_QUOTA_ID = models.AutoField(primary_key=True, db_column='CASTE_ID')  
    NAME = models.CharField(max_length=50, db_column='NAME', null=True)  

    class Meta:
        db_table = 'ADMISSION_QUOTA_MASTER'
        verbose_name = 'Admission Quota Master'
        verbose_name_plural = 'Admission Quota Masters'

    def __str__(self):
        return f"{self.NAME} - {self.ADMN_QUOTA_ID}"