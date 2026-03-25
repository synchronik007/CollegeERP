import React, { useState, useEffect } from "react";
import { Link, useLocation } from "react-router-dom";
import {
  Box,
  Drawer,
  List,
  ListItemButton,
  ListItemIcon,
  ListItemText,
  Collapse,
  IconButton,
  Typography,
  useTheme,
  useMediaQuery,
  Tooltip,
  Divider,
  alpha,
} from "@mui/material";
import {
  ChevronLeft,
  ChevronRight,
  ExpandLess,
  ExpandMore,
  Dashboard as DashboardIcon,
  Settings as SettingsIcon,
  Person as PersonIcon,
  School as SchoolIcon,
  Business as BusinessIcon,
  Event as EventIcon,
  Group as GroupIcon,
  Assignment as AssignmentIcon,
  Description as DescriptionIcon,
  TableChart as TableChartIcon,
  AdminPanelSettings as AdminPanelSettingsIcon,
  CalendarMonth as CalendarMonthIcon,
  Security as SecurityIcon,
  FactCheck as FactCheckIcon,
} from "@mui/icons-material";
import axiosInstance from "../../api/axios";

const drawerWidth = 280; // Slightly wider for better readability

export interface SidebarMenuItem {
  icon: React.ReactNode;
  text: string;
  path?: string;
  exact?: boolean;
  onClick?: () => void;
  children?: SidebarMenuItem[];
  subItems?: SidebarMenuItem[];
}

interface SidebarProps {
  isOpen: boolean;
  setIsOpen: (isOpen: boolean) => void;
  menuItems?: SidebarMenuItem[];
  title?: string;
  user?: any;
}

const Sidebar: React.FC<SidebarProps> = ({ isOpen, setIsOpen, menuItems: customMenuItems, title = "Menu", user }) => {
  // ... (rest of code)

  // Inside render:
  const location = useLocation();
  const theme = useTheme();
  const isMobile = useMediaQuery(theme.breakpoints.down("md"));
  const [expandedMenus, setExpandedMenus] = useState<string[]>([]);
  const [permissions, setPermissions] = useState<string[]>([]);

  useEffect(() => {
    if (user && !user.is_superuser && !user.IS_SUPERUSER) {
      fetchPermissions();
    }
  }, [user]);

  const fetchPermissions = async () => {
    try {
      const response = await axiosInstance.get("/api/permissions/my_permissions/");
      if (response.data.status === "success") {
        const paths = response.data.data.map((p: any) => p.menu_path);
        setPermissions(paths);
      }
    } catch (error) {
      console.error("Failed to fetch permissions", error);
    }
  };

  // Default menu items (SuperAdmin) - keeping the same structure
  const defaultMenuItems: SidebarMenuItem[] = [
    { icon: <DashboardIcon />, text: "Dashboard", path: "/dashboard/home" },
    {
      icon: <AdminPanelSettingsIcon />,
      text: "Administration",
      children: [
        {
          icon: <GroupIcon />,
          text: "Master Employee",
          children: [
            { icon: <PersonIcon />, text: "Create Employee", path: "/dashboard/master-employee/create", exact: true },
          ],
        },
        {
          icon: <SecurityIcon />,
          text: "Permissions",
          path: "/dashboard/administration/permissions",
          exact: true
        },
        {
          icon: <SettingsIcon />,
          text: "Master",
          children: [
            { icon: <TableChartIcon />, text: "Master Entry", path: "/dashboard/master", exact: true },
            { icon: <PersonIcon />, text: "Employee Type", path: "/dashboard/employee", exact: true },
            { icon: <SchoolIcon />, text: "Course Master", path: "/dashboard/coursemaster", exact: true },
          ],
        },
      ],
    },
    {
      icon: <BusinessIcon />,
      text: "Establishment",
      children: [
        {
          icon: <SettingsIcon />,
          text: "Master",
          children: [
            { icon: <TableChartIcon />, text: "Master Entry", path: "/dashboard/establishment/master", exact: true }
          ],
        },
        {
          icon: <PersonIcon />,
          text: "Employee Master",
          children: [
            { icon: <DescriptionIcon />, text: "Employee Details", path: "/dashboard/establishment/employeedetails", exact: true },
          ],
        },
      ],
    },
    {
      icon: <SchoolIcon />,
      text: "Student Section",
      children: [
        {
          icon: <SettingsIcon />,
          text: "Master Entry",
          children: [
            { icon: <TableChartIcon />, text: "Master Entry", path: "/dashboard/student-section/", exact: true }
          ],
        },
        {
          icon: <DescriptionIcon />,
          text: "Transaction",
          children: [
            { icon: <TableChartIcon />, text: "Document Collection", path: "/dashboard/student-section/document", exact: true },
            { icon: <AssignmentIcon />, text: "Documents Return", path: "/dashboard/student-master/documents-return", exact: true },
          ],
        },
        {
          icon: <PersonIcon />,
          text: "Student Master",
          children: [
            { icon: <PersonIcon />, text: "Basic Student Info", path: "/dashboard/student-master/student", exact: true },
            { icon: <AssignmentIcon />, text: "Student Roll No", path: "/dashboard/student-master/studentrollno", exact: true },
          ],
        },
      ],
    },
    {
      icon: <FactCheckIcon />,
      text: "Attendance",
      children: [
        {
          icon: <TableChartIcon />,
          text: "Attendance Management",
          path: "/dashboard/attendance/management",
          exact: true,
        },
      ],
    },
    {
      icon: <AssignmentIcon />,
      text: "Exam Section",
      children: [
        {
          icon: <SettingsIcon />,
          text: "Master",
          children: [
            { icon: <TableChartIcon />, text: "College Exam Type", path: "/dashboard/exam/college-exam-type", exact: true }
          ],
        },
      ],
    },
    {
      icon: <GroupIcon />,
      text: "Committee",
      children: [
        {
          icon: <SettingsIcon />,
          text: "Main Entry",
          children: [
            { icon: <TableChartIcon />, text: "Committee Master", path: "/dashboard/commiittee/Committee Master", exact: true }
          ],
        },
      ],
    },
    {
      icon: <EventIcon />,
      text: "Events",
      children: [
        {
          icon: <SettingsIcon />,
          text: "Master Entry",
          children: [
            { icon: <TableChartIcon />, text: "Event Type", path: "/dashboard/Event/Event Type", exact: true },
            { icon: <EventIcon />, text: "Event Master", path: "/dashboard/Event/Event Master", exact: true },
          ],
        },
      ],
    },
    { icon: <SchoolIcon />, text: "University", path: "/dashboard/master/university", exact: true },
    { icon: <BusinessIcon />, text: "Institute", path: "/dashboard/master/institute", exact: true },
    { icon: <SettingsIcon />, text: "System Settings", path: "/dashboard/settings" },
    { icon: <CalendarMonthIcon />, text: "Academic Year Master", path: "/dashboard/master/academic" },
    { icon: <AssignmentIcon />, text: "Semester Duration", path: "/dashboard/master/semesterduration" },
    { icon: <DashboardIcon />, text: "Dashboard Master", path: "/dashboard/dashboardmaster" },
  ];

  const isAllowed = (item: SidebarMenuItem): boolean => {
    if (!user || user.is_superuser || user.IS_SUPERUSER) return true;

    // If it has a real path, check permissions
    if (item.path && item.path !== "#") {
      return permissions.includes(item.path);
    }

    // If it has children, check if any child is allowed
    const children = item.children || item.subItems;
    if (children && children.length > 0) {
      return children.some(isAllowed);
    }

    // Items with path "#" or no path/children are usually dashboard actions, allow them
    return true;
  };

  const filterMenuItems = (items: SidebarMenuItem[]): SidebarMenuItem[] => {
    return items
      .filter(isAllowed)
      .map(item => ({
        ...item,
        children: item.children ? filterMenuItems(item.children) : undefined,
        subItems: item.subItems ? filterMenuItems(item.subItems) : undefined
      }))
      .filter(item => {
        // If it was originally a folder (had children), only keep it if it still has children
        const hadChildren = items.find(i => i.text === item.text)?.children?.length || 0;
        if (hadChildren > 0) {
          return item.children && item.children.length > 0;
        }
        return true;
      });
  };

  // Merge logic: If custom items are provided, also include the "Administration" block if allowed
  let finalMenuItems: SidebarMenuItem[] = [];
  if (customMenuItems) {
    const filteredCustom = filterMenuItems(customMenuItems);
    const adminMenu = defaultMenuItems.find(item => item.text === "Administration");

    if (adminMenu && isAllowed(adminMenu)) {
      const filteredAdmin = filterMenuItems([adminMenu])[0];
      finalMenuItems = [...filteredCustom, filteredAdmin];
    } else {
      finalMenuItems = filteredCustom;
    }
  } else {
    finalMenuItems = filterMenuItems(defaultMenuItems);
  }

  const menuItems = finalMenuItems;

  const handleDrawerToggle = () => {
    setIsOpen(!isOpen);
  };

  const toggleSubmenu = (text: string) => {
    setExpandedMenus((prev) =>
      prev.includes(text) ? prev.filter((item) => item !== text) : [...prev, text]
    );
  };

  const isActive = (path: string, exact?: boolean) => {
    if (exact) {
      return location.pathname === path;
    }
    return location.pathname.startsWith(path);
  };

  const renderMenuItem = (item: SidebarMenuItem, level = 0) => {
    const children = item.children || item.subItems;
    const hasChildren = children && children.length > 0;
    const isExpanded = expandedMenus.includes(item.text);
    const active = item.path ? isActive(item.path, item.exact) : false;

    // Improved indentation logic
    const paddingLeft = 12 + level * 16;

    // Visual indicator for hierarchy (vertical line for children)
    const isChild = level > 0;

    return (
      <React.Fragment key={item.text}>
        <ListItemButton
          onClick={() => {
            if (hasChildren) {
              toggleSubmenu(item.text);
              if (!isOpen && !isMobile) setIsOpen(true);
            } else {
              if (item.onClick) item.onClick();
              if (isMobile && (item.path || item.onClick)) setIsOpen(false);
            }
          }}
          component={item.path ? Link : "div"}
          to={item.path || "#"}
          selected={active}
          sx={{
            minHeight: 44, // More compact
            mx: 1.5, // Side margins for pill look
            my: 0.5,
            borderRadius: 2, // Rounded corners
            pl: `${paddingLeft}px`,
            justifyContent: isOpen ? "initial" : "center",
            position: 'relative',
            transition: "all 0.2s ease-in-out",
            // Active State
            "&.Mui-selected": {
              backgroundColor: theme.palette.primary.main,
              color: theme.palette.primary.contrastText,
              boxShadow: `0 4px 12px ${alpha(theme.palette.primary.main, 0.3)}`,
              "&:hover": {
                backgroundColor: theme.palette.primary.dark,
              },
              "& .MuiListItemIcon-root": {
                color: theme.palette.primary.contrastText,
              },
            },
            // Hover State (Inactive)
            "&:not(.Mui-selected):hover": {
              backgroundColor: alpha(theme.palette.primary.main, 0.08),
              transform: "translateX(4px)",
            },
          }}
        >
          {/* Hierarchy Guide Line for nested items */}
          {isChild && (
            <Box
              sx={{
                position: 'absolute',
                left: level * 12 + 6,
                top: 0,
                bottom: 0,
                width: '2px',
                bgcolor: alpha(theme.palette.divider, 0.5),
                display: isOpen ? 'block' : 'none'
              }}
            />
          )}

          <Tooltip title={!isOpen && !isMobile ? item.text : ""} placement="right">
            <ListItemIcon
              sx={{
                minWidth: 0,
                mr: isOpen ? 2 : "auto",
                justifyContent: "center",
                color: active ? "inherit" : theme.palette.text.secondary,
                transition: "color 0.2s",
              }}
            >
              {item.icon}
            </ListItemIcon>
          </Tooltip>

          <ListItemText
            primary={item.text}
            primaryTypographyProps={{
              fontSize: "0.875rem",
              fontWeight: active || hasChildren ? 600 : 400,
              noWrap: true,
            }}
            sx={{ opacity: isOpen ? 1 : 0, transition: "opacity 0.2s" }}
          />

          {hasChildren && isOpen && (
            <Box sx={{ color: active ? 'inherit' : 'text.secondary', display: 'flex' }}>
              {isExpanded ? <ExpandLess sx={{ fontSize: 18 }} /> : <ExpandMore sx={{ fontSize: 18 }} />}
            </Box>
          )}
        </ListItemButton>

        {hasChildren && (
          <Collapse in={isExpanded && isOpen} timeout="auto" unmountOnExit>
            <List component="div" disablePadding sx={{ position: 'relative' }}>
              {/* Vertical line connecting children */}
              {isOpen && (
                <Box
                  sx={{
                    position: 'absolute',
                    left: 20 + level * 16,
                    top: 0,
                    bottom: 0,
                    width: '1px',
                    bgcolor: theme.palette.divider,
                    zIndex: 0
                  }}
                />
              )}
              {children!.map((child: SidebarMenuItem) => renderMenuItem(child, level + 1))}
            </List>
          </Collapse>
        )}
      </React.Fragment>
    );
  };

  const drawerContent = (
    <Box sx={{ display: "flex", flexDirection: "column", height: "100%", overflow: 'hidden' }}>
      {/* Header */}
      <Box
        sx={{
          display: "flex",
          alignItems: "center",
          justifyContent: isOpen ? "space-between" : "center",
          p: 2,
          minHeight: 64,
        }}
      >
        {isOpen && (
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
            <Box component="img" src="/logo.svg" sx={{ height: 28 }} alt="Logo" />
            <Typography variant="h6" color="primary" sx={{ fontWeight: 800, fontSize: '1.1rem' }}>
              {title}
            </Typography>
          </Box>
        )}
        {!isMobile && (
          <IconButton onClick={handleDrawerToggle} size="small" sx={{ bgcolor: alpha(theme.palette.background.default, 0.5) }}>
            {theme.direction === "rtl" || !isOpen ? <ChevronRight fontSize="small" /> : <ChevronLeft fontSize="small" />}
          </IconButton>
        )}
        {isMobile && isOpen && (
          <IconButton onClick={handleDrawerToggle}>
            <ChevronLeft />
          </IconButton>
        )}
      </Box>
      <Divider sx={{ mb: 1, mx: 2 }} />

      {/* Menu List - Scrollable Area */}
      <Box
        sx={{
          flexGrow: 1,
          overflowY: "auto",
          overflowX: "hidden",
          "&::-webkit-scrollbar": { width: "4px" },
          "&::-webkit-scrollbar-track": { background: "transparent" },
          "&::-webkit-scrollbar-thumb": { background: theme.palette.divider, borderRadius: "4px" },
          "&::-webkit-scrollbar-thumb:hover": { background: theme.palette.text.disabled },
          pb: 2
        }}
      >
        <List component="nav" sx={{ px: 0 }}>
          {menuItems.map((item) => renderMenuItem(item))}
        </List>
      </Box>

      {/* User Profile / Footer (Optional - placed at bottom) */}
      {isOpen && (
        <Box sx={{ p: 2, mt: 'auto', borderTop: `1px solid ${theme.palette.divider}` }}>
          <Typography variant="caption" color="text.secondary" display="block" align="center">
            v1.0.0
          </Typography>
        </Box>
      )}
    </Box>
  );

  return (
    <Box
      component="nav"
      sx={{
        width: { md: isOpen ? drawerWidth : 70 },
        flexShrink: { md: 0 },
        height: '100%', // Critical for scrolling
        transition: theme.transitions.create('width', {
          easing: theme.transitions.easing.sharp,
          duration: theme.transitions.duration.enteringScreen,
        }),
      }}
    >
      {/* Mobile Drawer */}
      <Drawer
        variant="temporary"
        open={isOpen && isMobile}
        onClose={handleDrawerToggle}
        ModalProps={{ keepMounted: true }}
        sx={{
          display: { xs: "block", md: "none" },
          "& .MuiDrawer-paper": {
            boxSizing: "border-box",
            width: drawerWidth,
            borderRight: "none",
            boxShadow: theme.shadows[4]
          },
        }}
      >
        {drawerContent}
      </Drawer>

      {/* Desktop Layout - Using Box to avoid Drawer position fixed issues */}
      <Box
        sx={{
          display: { xs: "none", md: "block" },
          width: isOpen ? drawerWidth : 70,
          height: '100%',
          borderRight: 'none', // Border handled by inner or wrapper if needed
          bgcolor: 'background.paper',
          boxShadow: `4px 0 24px ${alpha(theme.palette.common.black, 0.02)}`,
          overflow: 'hidden', // Ensure no partial overflow
          transition: theme.transitions.create('width', {
            easing: theme.transitions.easing.sharp,
            duration: theme.transitions.duration.enteringScreen,
          }),
        }}
      >
        {drawerContent}
      </Box>
    </Box>
  );
};

export default Sidebar;
