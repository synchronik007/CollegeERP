from django.urls import path, include
from rest_framework.routers import DefaultRouter
from . import views
from .views import LogoutView

router = DefaultRouter()
router.register(r'master/countries', views.CountryViewSet, basename='country')
router.register(r'master/states', views.StateViewSet, basename='state')
router.register(r'master/cities', views.CityViewSet, basename='city')
router.register(r'master/currencies', views.CurrencyViewSet, basename='currency')
router.register(r'master/languages', views.LanguageViewSet, basename='language')
router.register(r'master/designations', views.DesignationViewSet, basename='designation')
router.register(r'master/departments', views.DepartmentViewSet, basename='department')
router.register(r'master/categories', views.CategoryViewSet, basename='category')
router.register(r'master/universities', views.UniversityViewSet, basename='university')
router.register(r'master/institutes', views.InstituteViewSet, basename='institute')
router.register(r'master/academic-years', views.AcademicYearViewSet, basename='academic-year')
router.register(r'master/program', views.ProgramListCreateView, basename='program')
router.register(r'master/semester-duration', views.SemesterDurationViewSet, basename='semester-duration')
router.register(r'master/branch', views.BranchListCreateView, basename='branch')
router.register(r'master/dashboard-master', views.DashboardMasterViewSet, basename='dashboard-master')
router.register(r'master/year', views.YearListCreateView, basename='year')
router.register(r'master/semester', views.SemesterListCreateView, basename='semester')
router.register(r'master/caste', views.SemesterListCreateView, basename='caste')

app_name = 'accounts'

urlpatterns = [
    path('', include(router.urls)),
    path('auth/login/', views.LoginView.as_view(), name='login'),
    path('auth/send-otp/', views.SendOTPView.as_view(), name='send-otp'),
    path('auth/verify-otp/', views.VerifyOTPView.as_view(), name='verify-otp'),
    path('auth/request-password-reset/', views.RequestPasswordResetView.as_view(), name='request-password-reset'),
    path('auth/verify-reset-otp/', views.VerifyResetOTPView.as_view(), name='verify-reset-otp'),
    path('auth/reset-password/', views.ResetPasswordView.as_view(), name='reset-password'),
    path('auth/logout/', LogoutView.as_view(), name='logout'),
    path('master/tables/', views.MasterTableListView.as_view(), name='master-tables'),
    path('api/master/academic-years', include(router.urls)),
    path('api/master/semester-duration', include(router.urls)),
    path('api/program-master/', views.ProgramTableListView.as_view(), name='program-master'),
]
