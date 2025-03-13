import React, { useState } from "react";
import { Link, useLocation } from "react-router-dom";
import MasterTableList from "../master/MasterTableList";
import { useTheme as useMUITheme } from "@mui/material/styles";

interface SidebarProps {
  isOpen: boolean;
  setIsOpen: (isOpen: boolean) => void;
}

const Sidebar: React.FC<SidebarProps> = ({ isOpen, setIsOpen }) => {
  const location = useLocation();
  const theme = useMUITheme();
  const [expandedMenus, setExpandedMenus] = useState<string[]>([]);

  const menuItems = [
    { icon: "bi-speedometer2", text: "Dashboard", path: "/dashboard/home" },
    {
      icon: "bi-gear-fill",
      text: "Administration",
      children: [
        {
          icon: "bi-people-fill",
          text: "Master Employee",
          children: [
            {
              icon: "bi-person-plus-fill",
              text: "Create Employee",
              path: "/dashboard/master-employee/create",
              exact: true,
            },
          ],
        },
        {
          icon: "bi-database-fill",
          text: "Master",
          children: [
            {
              icon: "bi-database-fill",
              text: "Master Entry",
              path: "/dashboard/master",
              exact: true,
            },
            {
              icon: "bi-people-fill",
              text: "Employee Type",
              path: "/dashboard/employee",
              exact: true,
            },
            {
              icon: "bi-people-fill",
              text: "Course Master",
              path: "/dashboard/coursemaster",
              exact: true,
            },
            {
              icon: "bi-people-fill",
              text: "Admission Master",
              path: "/dashboard/admissionmaster",
              exact: true,
            },
          ],
        },
      ],
    },
    {
      icon: "bi-building",
      text: "University",
      path: "/dashboard/master/university",
      exact: true,
    },
    {
      icon: "bi-mortarboard",
      text: "Institute",
      path: "/dashboard/master/institute",
      exact: true,
    },
    {
      icon: "bi-gear-fill",
      text: "System Settings",
      path: "/dashboard/settings",
    },
    // {
    //   icon: "bi-building",
    //   text: "Master University",
    //   path: "/dashboard/master/university",
    // },
    // {
    //   icon: "bi-building",
    //   text: "Master Institute",
    //   path: "/dashboard/master/institute",
    // },
    {
      icon: "bi-calendar",
      text: "Academic Year Master",
      path: "/dashboard/master/academic",
    },
    {
      icon: "bi bi-hourglass",
      text: "Semester Duration",
      path: "/dashboard/master/semesterduration",
    },
    {
      icon: "bi-speedometer2",
      text: "Dashboard Master",
      path: "/dashboard/dashboardmaster",
    },
    { icon: "bi-shield-lock", text: "Roles & Permissions", path: "/roles" },
    { icon: "bi-sliders", text: "Configuration", path: "/config" },
    { icon: "bi-person-lines-fill", text: "User Management", path: "/users" },
    { icon: "bi-clock-history", text: "Audit Logs", path: "/audit" },
  ];

  const toggleSubmenu = (text: string) => {
    setExpandedMenus((prev) =>
      prev.includes(text)
        ? prev.filter((item) => item !== text)
        : [...prev, text]
    );
  };

  const renderMenuItem = (item: any, level = 0) => {
    const hasChildren = item.children && item.children.length > 0;
    const isExpanded = expandedMenus.includes(item.text);

    return (
      <div key={item.text} style={{ marginLeft: level * 15 }}>
        {item.path ? (
          <Link
            to={item.path}
            className={`
              d-flex align-items-center text-decoration-none p-2 mb-1 rounded
              ${isActive(item.path, item.exact) ? "bg-primary text-white" : ""}
              hover-effect
            `}
            style={{
              color: isActive(item.path, item.exact)
                ? theme.palette.primary.contrastText
                : theme.palette.text.secondary,
              backgroundColor: isActive(item.path, item.exact)
                ? theme.palette.primary.main
                : "transparent",
              transition: "all 0.3s",
            }}
            title={!isOpen ? item.text : ""}
          >
            <i className={`${item.icon} ${isOpen ? "me-2" : ""}`}></i>
            {isOpen && <span className="small">{item.text}</span>}
          </Link>
        ) : (
          <div
            className="d-flex align-items-center p-2 mb-1 rounded cursor-pointer hover-effect"
            onClick={() => toggleSubmenu(item.text)}
            style={{
              color: theme.palette.text.secondary,
              transition: "all 0.3s",
              cursor: "pointer",
            }}
          >
            <i className={`${item.icon} ${isOpen ? "me-2" : ""}`}></i>
            {isOpen && (
              <>
                <span className="small">{item.text}</span>
                <i
                  className={`bi bi-chevron-${
                    isExpanded ? "down" : "right"
                  } ms-auto`}
                ></i>
              </>
            )}
          </div>
        )}
        {hasChildren && isExpanded && isOpen && (
          <div className="submenu-container">
            {item.children.map((child: any) =>
              renderMenuItem(child, level + 1)
            )}
          </div>
        )}
      </div>
    );
  };

  // Update isActive to check for exact matches
  const isActive = (path: string, exact?: boolean) => {
    if (exact) {
      return location.pathname === path;
    }
    return location.pathname.startsWith(path);
  };

  return (
    <div
      className={`border-end transition-width`}
      style={{
        width: isOpen ? "250px" : "50px",
        backgroundColor: theme.palette.background.paper,
        borderColor: theme.palette.divider,
      }}
    >
      {/* Sidebar Header */}
      <div
        className="p-3 border-bottom d-flex align-items-center"
        style={{
          backgroundColor: theme.palette.background.paper,
          borderColor: theme.palette.divider,
        }}
      >
        <button
          className="btn btn-link p-0 me-2 text-primary"
          onClick={() => setIsOpen(!isOpen)}
        >
          <i
            className={`bi ${isOpen ? "bi-chevron-left" : "bi-chevron-right"}`}
          ></i>
        </button>
        {isOpen && (
          <h5 className="mb-0 text-primary d-flex align-items-center">
            <i className="bi bi-grid-fill me-2"></i>
            Admin Portal
          </h5>
        )}
      </div>

      {/* Sidebar Menu */}
      <div className="p-2">{menuItems.map((item) => renderMenuItem(item))}</div>
    </div>
  );
};

export default Sidebar;
