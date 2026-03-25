import React, { useState, useEffect } from "react";
import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom";
import Home from "./components/Home";
import AdminDashboard from "./components/dashboard/AdminDashboard";
import TeacherDashboard from "./components/dashboard/TeacherDashboard";
import StudentDashboard from "./components/dashboard/StudentDashboard";
import { ROLES, getDashboardRoute } from "./utils/roles";
import CoeDashboard from "./components/dashboard/CoeDashboard";
import HodDashboard from "./components/dashboard/HodDashboard";
import FacultyDashboard from "./components/dashboard/FacultyDashboard";
import FinanceDashboard from "./components/dashboard/FinanceDashboard";
import LibraryDashboard from "./components/dashboard/LibraryDashboard";
import HostelDashboard from "./components/dashboard/HostelDashboard";
import PlacementDashboard from "./components/dashboard/PlacementDashboard";
import SuperAdminDashboard from "./components/dashboard/SuperAdminDashboard";
import { SettingsProvider } from "./context/SettingsContext";
import { ThemeProvider } from "./context/ThemeContext";
import CssBaseline from "@mui/material/CssBaseline";
import "./styles/globals.css";
import StudentRollForm from "./components/StudentMaster/StudentRollNo";
import Sidebar from "./components/layout/Sidebar";
interface User {
  user_id: string;
  username: string;
  email: string;
  designation: string;
  permissions: any;
}

const App = () => {
  const [user, setUser] = useState<any>(null);
  const [loading, setLoading] = useState(true);

  const handleLoginSuccess = (userData: any) => {
    console.log("=== Setting User Data ===");
    console.log("User Data:", userData);

    // Ensure designation data is properly structured
    const processedUserData = {
      ...userData,
      designation: {
        ...userData.designation,
        code: userData.designation?.code?.toUpperCase(),
      },
    };

    console.log("Processed User Data:", processedUserData);

    // Store in localStorage and state
    localStorage.setItem("user", JSON.stringify(processedUserData));
    setUser(processedUserData);
  };

  useEffect(() => {
    const initializeAuth = () => {
      try {
        const savedUser = localStorage.getItem("user");
        if (savedUser) {
          const parsedUser = JSON.parse(savedUser);
          console.log("Restored session for:", parsedUser.username);
          setUser(parsedUser);
        }
      } catch (error) {
        console.error("Session restoration failed:", error);
        localStorage.removeItem("user");
      } finally {
        setLoading(false);
      }
    };

    initializeAuth();
  }, []);

  const isAuthorized = (requiredRole: string) => {
    console.log("Checking authorization for:", requiredRole);

    if (!user?.designation?.code) {
      console.log("No user session found");
      return false;
    }

    const userRole = user.designation.code.toUpperCase();
    const isSuperAdmin = userRole === "SUPERADMIN";
    const isAuthorized =
      isSuperAdmin || userRole === requiredRole.toUpperCase();

    console.log(`User ${user.username} authorization:`, isAuthorized);
    return isAuthorized;
  };

  if (loading) {
    return <div>Loading...</div>; // Or your loading component
  }

  return (
    <ThemeProvider>
      <CssBaseline />
      <SettingsProvider>
        <BrowserRouter>
          <Routes>
            <Route
              path="/"
              element={
                user ? (
                  <Navigate to={getDashboardRoute(user.designation?.code)} />
                ) : (
                  <Home onLoginSuccess={handleLoginSuccess} />
                )
              }
            />

            {/* Unified Dashboard Shell Route */}
            <Route
              path="/dashboard/*"
              element={
                user && (isAuthorized(ROLES.SUPERADMIN) || isAuthorized(ROLES.ADMIN)) ? (
                  <SuperAdminDashboard user={user} />
                ) : (
                  <Navigate to="/" />
                )
              }
            />

            <Route
              path="/superadmin-dashboard"
              element={
                user && (isAuthorized(ROLES.SUPERADMIN) || isAuthorized(ROLES.ADMIN)) ? (
                  <SuperAdminDashboard user={user} />
                ) : (
                  <Navigate to="/" />
                )
              }
            />

            {/* Academic Routes */}
            <Route
              path="/coe-dashboard"
              element={
                isAuthorized(ROLES.COE) ? (
                  <CoeDashboard user={user} />
                ) : (
                  <Navigate to="/" />
                )
              }
            />
            <Route
              path="/hod-dashboard"
              element={
                isAuthorized(ROLES.HOD) ? (
                  <HodDashboard user={user} />
                ) : (
                  <Navigate to="/" />
                )
              }
            />
            <Route
              path="/faculty-dashboard"
              element={
                isAuthorized(ROLES.FACULTY) ? (
                  <FacultyDashboard user={user} />
                ) : (
                  <Navigate to="/" />
                )
              }
            />

            {/* Student Route */}
            <Route
              path="/student-dashboard"
              element={
                isAuthorized(ROLES.STUDENT) ? (
                  <StudentDashboard user={user} />
                ) : (
                  <Navigate to="/" />
                )
              }
            />
            <Route path="/student-roll-form" element={<StudentRollForm />} />

            {/* Teacher Route */}
            <Route
              path="/teacher-dashboard"
              element={
                isAuthorized(ROLES.TEACHER) ? (
                  <TeacherDashboard user={user} />
                ) : (
                  <Navigate to="/" />
                )
              }
            />






            {/* Administrative Routes */}
            <Route
              path="/finance-dashboard"
              element={
                isAuthorized(ROLES.FINANCE) ? (
                  <FinanceDashboard user={user} />
                ) : (
                  <Navigate to="/" />
                )
              }
            />
            <Route
              path="/library-dashboard"
              element={
                isAuthorized(ROLES.LIBRARY) ? (
                  <LibraryDashboard user={user} />
                ) : (
                  <Navigate to="/" />
                )
              }
            />
            <Route
              path="/hostel-dashboard"
              element={
                isAuthorized(ROLES.WARDEN) ? (
                  <HostelDashboard user={user} />
                ) : (
                  <Navigate to="/" />
                )
              }
            />
            <Route
              path="/placement-dashboard"
              element={
                isAuthorized(ROLES.PLACEMENT) ? (
                  <PlacementDashboard user={user} />
                ) : (
                  <Navigate to="/" />
                )
              }
            />


            <Route path="*" element={<Navigate to="/" />} />
          </Routes>
        </BrowserRouter>
      </SettingsProvider>
    </ThemeProvider>
  );
};

export default App;
