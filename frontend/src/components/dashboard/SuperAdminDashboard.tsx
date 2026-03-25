import React, { useState } from "react";
import { Routes, Route, Navigate, useNavigate } from "react-router-dom";
import { Box, Grid, Card, CardContent, Typography, useTheme } from "@mui/material";
import { DashboardNavbar } from "../layout/Navbar";
import Footer from "../layout/Footer";
import Sidebar from "../layout/Sidebar";
import MasterEntryPage from "../master/MasterEntryPage";
import UniversityMaster from "../master/UniversityMaster";
import InstituteMasterEntry from "../master/InstituteMasterEntry";
import AcademicYearMaster from "../master/AcademicYearMaster";
import InstituteMaster from "../master/InstituteMaster";
import SettingsPanel from "../adminfeatures/Settings/SettingsPanel";
import EmployeeTypeEntry from "../Employee/employeeTypeEntry";
import CreateEmployee from "../MasterEmployee/CreateEmployee";
import ProgramEntryForm from "../CourseMaster/ProgramEntryForm";
import DashboardMaster from "../DashboardMaster/DashboardMaster";
import SemesterDuration from "../master/SemesterDuration";
import StudentInfoForm from "../StudentMaster/StudentInfoForm";
import EmployeeDetail from "../employeeDetails/employeedetail";
import AcademicQualification from "../employeeDetails/academicQualification";
import AdmissionTable from "../Admission/AdmissionTable";
import StudentRollNo from "../StudentMaster/StudentRollNo";
import StudentDocument from "../studentTransaction/StudentDocument";
import CollegeExamTypeTableView from "../Exam/CollegeExamTypeTableView";
import StudentReturnForm from "../StudentMaster/DocumentReturn";
import CommitteeMasterForm from "../Committee/CommitteeMasterForm";
import EventType from "../Event/EventType";
import EventMaster from "../Event/EventMaster";
import PermissionManagement from "../adminfeatures/PermissionManagement";
import AttendanceManagement from "../attendance/AttendanceManagement";

const DashboardHome = ({ user }: any) => (
  <Box sx={{ p: 3 }}>
    <Typography variant="h4" gutterBottom>
      Welcome to {user?.is_superuser || user?.IS_SUPERUSER ? "Super Admin" : "Admin"} Dashboard
    </Typography>
    <Grid container spacing={3} sx={{ mt: 2 }}>
      <Grid item xs={12} sm={6} md={3}>
        <Card sx={{ bgcolor: "primary.main", color: "primary.contrastText" }}>
          <CardContent>
            <Typography variant="h6" gutterBottom>
              Total Users
            </Typography>
            <Typography variant="h3">
              1,234
            </Typography>
          </CardContent>
        </Card>
      </Grid>
      {/* Add more dashboard cards/widgets as needed */}
    </Grid>
  </Box>
);

const SuperAdminDashboard = ({ user }: any) => {
  const [isSidebarOpen, setIsSidebarOpen] = useState(true);
  const navigate = useNavigate();
  const theme = useTheme();

  const handleLogout = () => {
    sessionStorage.clear();
    localStorage.clear();
    navigate("/", { replace: true });
  };

  return (
    <Box sx={{ display: "flex", flexDirection: "column", height: "100vh", overflow: "hidden" }}>
      <DashboardNavbar
        user={user}
        title="Synchronik"
        onLogout={handleLogout}
        onSidebarToggle={() => setIsSidebarOpen(!isSidebarOpen)}
      />

      <Box sx={{ display: "flex", flexGrow: 1, overflow: "hidden" }}>
        <Sidebar
          isOpen={isSidebarOpen}
          setIsOpen={setIsSidebarOpen}
          user={user}
          title={user?.is_superuser || user?.IS_SUPERUSER ? "Super Admin Portal" : "Admin Portal"}
        />

        <Box
          component="main"
          sx={{
            flexGrow: 1,
            overflow: "hidden",
            bgcolor: "#f4f6f8",
            display: "flex",
            flexDirection: "column"
          }}
        >
          <Box
            sx={{
              flexGrow: 1,
              overflow: "auto",
              p: 3
            }}
          >
            <Routes>
              <Route
                path="/"
                element={<Navigate to="/dashboard/home" replace />}
              />
              <Route path="/home" element={<DashboardHome user={user} />} />
              <Route path="/master" element={<MasterEntryPage />} />
              <Route path="/master/:tableName" element={<MasterEntryPage />} />
              <Route path="/master/university" element={<UniversityMaster />} />
              <Route path="/master/institute" element={<InstituteMasterEntry />} />
              <Route path="/master/academic" element={<AcademicYearMaster />} />
              <Route path="/master/semesterduration" element={<SemesterDuration />} />
              <Route path="/master/institute" element={<InstituteMaster />} />
              <Route path="/dashboardmaster" element={<DashboardMaster />} />
              <Route path="/settings" element={<SettingsPanel />} />
              <Route path="/employee" element={<EmployeeTypeEntry />} />
              <Route
                path="/master-employee/create"
                element={<CreateEmployee />}
              />
              <Route
                path="/student-master/studentrollno"
                element={<StudentRollNo />}
              />
              <Route
                path="/student-master/student"
                element={<StudentInfoForm />}
              />
              <Route
                path="/student-master/documents-return"
                element={<StudentReturnForm />}
              />
              <Route path="/courseMaster" element={<ProgramEntryForm />} />
              <Route path="/establishment/master" element={<MasterEntryPage />} />
              <Route path="/establishment/master/:tableName" element={<MasterEntryPage />} />
              <Route
                path="/establishment/employeedetails"
                element={<EmployeeDetail />}
              />
              <Route
                path="/establishment/academic-qualification"
                element={<AcademicQualification />}
              />
              <Route path="/student-section" element={<AdmissionTable />} />
              <Route path="/student-section/document" element={<StudentDocument />} />
              <Route path="/exam/college-exam-type" element={<CollegeExamTypeTableView />} />
              <Route path="/commiittee/Committee Master" element={<CommitteeMasterForm />} />
              <Route path="/Event/Event Master" element={<EventMaster />} />
              <Route path="/Event/Event TYpe" element={<EventType />} />
              <Route path="/administration/permissions" element={<PermissionManagement />} />
              <Route path="/attendance/management" element={<AttendanceManagement />} />
            </Routes>
          </Box>
          <Footer />
        </Box>
      </Box>
    </Box>
  );
};

export default SuperAdminDashboard;
