import React, { useState } from "react";
import { Routes, Route, Navigate, useNavigate } from "react-router-dom";
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
import NameEntryForm from "../CourseMaster/ProgramEntryForm";
import SemesterDurationForm from "../master/SemesterDuration";
import CreateEmployee from "../MasterEmployee/CreateEmployee";
import ProgramTable from "../CourseMaster/Programtable";
import ProgramList from "../CourseMaster/ProgramList";
import DashboardMaster from "../DashboardMaster/DashboardMaster";
import SemesterDurationTableView from "../master/SemesterDurationTableView";
import AdmissionTable from "../Admission/AdmissionTable";


const DashboardHome = () => (
  <div className="container-fluid p-4">
    <h2>Welcome to Admin Dashboard</h2>
    <div className="row mt-4">
      <div className="col-md-3 mb-4">
        <div className="card bg-primary text-white">
          <div className="card-body">
            <h5 className="card-title">Total Users</h5>
            <h3 className="mb-0">1,234</h3>
          </div>
        </div>
      </div>
      {/* Add more dashboard cards/widgets as needed */}
    </div>
  </div>
);

const SuperAdminDashboard = ({ user }: any) => {
  const [isSidebarOpen, setIsSidebarOpen] = useState(true);
  const navigate = useNavigate();

  const handleLogout = () => {
    // Clear session storage
    sessionStorage.clear();
    // Clear local storage if you're using it
    localStorage.clear();
    // Navigate to home/login page
    navigate("/", { replace: true });
  };

  return (
    <div className="vh-100 d-flex flex-column overflow-hidden">
      <div style={{ height: "64px" }}>
        {" "}
        {/* Updated height to match navbar */}
        <DashboardNavbar
          user={user}
          title="Super Admin Portal"
          onLogout={handleLogout}
        />
      </div>

      <div className="flex-grow-1 d-flex overflow-hidden">
        <Sidebar isOpen={isSidebarOpen} setIsOpen={setIsSidebarOpen} />

        <div className="flex-grow-1 overflow-auto">
          <Routes>
            <Route
              path="/"
              element={<Navigate to="/dashboard/home" replace />}
            />
            <Route path="/home" element={<DashboardHome />} />
            <Route path="/master" element={<MasterEntryPage />} />
            <Route path="/master/:tableName" element={<MasterEntryPage />} />
            <Route path="/master/university" element={<UniversityMaster />} />
            <Route path="/master/institute" element={<InstituteMasterEntry />} />
            <Route path="/master/academic" element={<AcademicYearMaster />} />
            <Route path="/master/semesterduration" element={<SemesterDurationTableView />} />
            <Route path="/master/institute" element={<InstituteMaster />} />
            <Route path="/dashboardmaster" element={<DashboardMaster />} />
            <Route path="/settings" element={<SettingsPanel />} />
            <Route path="/employee" element={<EmployeeTypeEntry />} />
            <Route
              path="/master-employee/create"
              element={<CreateEmployee />}
            />
            <Route path="/courseMaster" element={<ProgramTable />} />
            <Route path="/admissionMaster" element={<AdmissionTable />} />
          </Routes>
        </div>
      </div>
      <Footer />
    </div>
  );
};

export default SuperAdminDashboard;
