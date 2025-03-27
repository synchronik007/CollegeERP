from rest_framework import serializers
from .models import COUNTRY, STATE, CITY, CURRENCY, LANGUAGE, DESIGNATION, CATEGORY, UNIVERSITY, INSTITUTE, DEPARTMENT, PROGRAM, BRANCH, YEAR, SEMESTER, ACADEMIC_YEAR, SEMESTER_DURATION, DASHBOARD_MASTER,CASTE_MASTER,QUOTA_MASTER,ADMISSION_QUOTA_MASTER

class CountrySerializer(serializers.ModelSerializer):
    class Meta:
        model = COUNTRY
        fields = ['COUNTRY_ID', 'NAME', 'CODE', 'PHONE_CODE', 'IS_ACTIVE', 'CREATED_BY', 'UPDATED_BY']

class StateSerializer(serializers.ModelSerializer):
    class Meta:
        model = STATE
        fields = ['STATE_ID', 'COUNTRY', 'NAME', 'CODE', 'IS_ACTIVE', 'CREATED_BY', 'UPDATED_BY']

class CitySerializer(serializers.ModelSerializer):
    class Meta:
        model = CITY
        fields = ['CITY_ID', 'STATE', 'NAME', 'CODE', 'IS_ACTIVE', 'CREATED_BY', 'UPDATED_BY']

class CurrencySerializer(serializers.ModelSerializer):
    class Meta:
        model = CURRENCY
        fields = ['CURRENCY_ID', 'NAME', 'CODE', 'SYMBOL', 'IS_ACTIVE', 'CREATED_BY', 'UPDATED_BY']

class LanguageSerializer(serializers.ModelSerializer):
    class Meta:
        model = LANGUAGE
        fields = ['LANGUAGE_ID', 'NAME', 'CODE', 'IS_ACTIVE', 'CREATED_BY', 'UPDATED_BY']

class DesignationSerializer(serializers.ModelSerializer):
    class Meta:
        model = DESIGNATION
        fields = ['DESIGNATION_ID', 'NAME', 'CODE', 'DESCRIPTION', 'PERMISSIONS', 'IS_ACTIVE', 'CREATED_BY', 'UPDATED_BY']

class CategorySerializer(serializers.ModelSerializer):
    class Meta:
        model = CATEGORY
        fields = ['CATEGORY_ID', 'NAME', 'CODE', 'DESCRIPTION', 'RESERVATION_PERCENTAGE', 'IS_ACTIVE', 'CREATED_BY', 'UPDATED_BY']

    def validate(self, data):
        if 'CODE' in data:
            data['CODE'] = data['CODE'].upper()
            if not data['CODE'].isalnum():
                raise serializers.ValidationError({
                    "error": "Invalid format",
                    "message": "Category code must contain only letters and numbers",
                    "field": "CODE"
                })
            if self.instance is None and CATEGORY.objects.filter(CODE=data['CODE']).exists():
                raise serializers.ValidationError({
                    "error": "Duplicate entry",
                    "message": f"Category with code '{data['CODE']}' already exists",
                    "field": "CODE"
                })
        if 'RESERVATION_PERCENTAGE' in data:
            try:
                percentage = float(data['RESERVATION_PERCENTAGE'])
                if not (0 <= percentage <= 100):
                    raise serializers.ValidationError({
                        "error": "Invalid value",
                        "message": "Reservation percentage must be between 0 and 100",
                        "field": "RESERVATION_PERCENTAGE"
                    })
            except (TypeError, ValueError):
                raise serializers.ValidationError({
                    "error": "Invalid format",
                    "message": "Reservation percentage must be a valid number",
                    "field": "RESERVATION_PERCENTAGE"
                })
        return data

class UniversitySerializer(serializers.ModelSerializer):
    class Meta:
        model = UNIVERSITY
        fields = [
            'UNIVERSITY_ID', 'NAME', 'CODE', 'ADDRESS', 
            'CONTACT_NUMBER', 'EMAIL', 'WEBSITE', 'ESTD_YEAR', 
            'IS_ACTIVE', 'CREATED_BY', 'UPDATED_BY'
        ]

class InstituteSerializer(serializers.ModelSerializer):
    class Meta:
        model = INSTITUTE
        fields = [
            'INSTITUTE_ID', 'UNIVERSITY', 'NAME', 'CODE',
            'ADDRESS', 'CONTACT_NUMBER', 'EMAIL', 'WEBSITE',
            'ESTD_YEAR', 'IS_ACTIVE', 'CREATED_BY', 'UPDATED_BY'
        ]

class AcademicYearSerializer(serializers.ModelSerializer):
    class Meta:
        model = ACADEMIC_YEAR
        fields = [
            'ACADEMIC_YEAR', 'START_DATE', 'END_DATE',
            'INSTITUTE', 'IS_ACTIVE', 'CREATED_BY', 'UPDATED_BY'
        ]

class DepartmentSerializer(serializers.ModelSerializer):
    class Meta:
        model = DEPARTMENT
        fields = ['DEPARTMENT_ID', 'INSTITUTE_CODE', 'NAME', 'CODE', 'IS_ACTIVE', 'CREATED_BY', 'UPDATED_BY']

class ProgramSerializer(serializers.ModelSerializer):
    class Meta:
        model = PROGRAM
        fields = [
            'PROGRAM_ID', 'INSTITUTE', 'NAME', 'CODE', 
            'DURATION_YEARS', 'LEVEL', 'TYPE', 'DESCRIPTION',
            'IS_ACTIVE', 'CREATED_BY', 'UPDATED_BY'
        ]

class BranchSerializer(serializers.ModelSerializer):
    PROGRAM_CODE = serializers.CharField(source='PROGRAM.CODE', read_only=True)
    INSTITUTE_CODE = serializers.CharField(source='PROGRAM.INSTITUTE.CODE', read_only=True)

    class Meta:
        model = BRANCH
        fields = [
            'BRANCH_ID', 'PROGRAM', 'NAME', 'CODE',
            'DESCRIPTION', 'IS_ACTIVE', 'CREATED_BY',
            'UPDATED_BY', 'PROGRAM_CODE', 'INSTITUTE_CODE'
        ]

class DashboardMasterSerializer(serializers.ModelSerializer):
    class Meta:
        model = DASHBOARD_MASTER
        fields = ['DBM_ID', 'EMP_ID', 'DASHBOARD_NAME', 'INSTITUTE']
        read_only_fields = ['DBM_ID']

class YearSerializer(serializers.ModelSerializer):
    BRANCH_CODE = serializers.CharField(source='BRANCH.CODE', read_only=True)
    BRANCH_NAME = serializers.CharField(source='BRANCH.NAME', read_only=True)

    class Meta:
        model = YEAR
        fields = ['YEAR_ID', 'YEAR', 'BRANCH', 'BRANCH_CODE', 'BRANCH_NAME']

    def validate_BRANCH_ID(self, value):
        if not value:
            raise serializers.ValidationError("Branch ID is required.")
        return value

class SemesterSerializer(serializers.ModelSerializer):
    BRANCH_NAME = serializers.CharField(source='YEAR.BRANCH.NAME', read_only=True)
    YEAR_YEAR = serializers.CharField(source='YEAR.YEAR', read_only=True)

    class Meta:
        model = SEMESTER
        fields = ['SEMESTER_ID', 'SEMESTER', 'YEAR', 'YEAR_YEAR', 'BRANCH_NAME']

class SemesterDurationSerializer(serializers.ModelSerializer):
    class Meta:
        model = SEMESTER_DURATION
        fields = ['SEMESTER', 'START_DATE', 'END_DATE', 'IS_ACTIVE', 'CREATED_BY', 'UPDATED_BY']
        

class CasteSerializer(serializers.ModelSerializer):
    class Meta:
        model = CASTE_MASTER
        fields = ['CASTE_ID','NAME']
        
class QuotaSerializer(serializers.ModelSerializer):
    
    class Meta:
        model = QUOTA_MASTER
        fields =['QUOTA_ID','NAME']
        
class AdmissionQuotaSerializer(serializers.ModelSerializer):
    class Meta:
        model =ADMISSION_QUOTA_MASTER
        fields =['ADMN_QUOTA_ID','NAME']
      

