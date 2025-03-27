import React, { useState, useEffect } from "react";
import {
  TextField,
  Grid,
  Paper,
  Button,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  Typography,
  Box,
  Divider,
  FormControlLabel,
  Checkbox,
  Avatar,
  Stack,
  Alert,
  Snackbar,
} from "@mui/material";
import { AdapterDateFns } from "@mui/x-date-pickers/AdapterDateFns";
import { LocalizationProvider, DatePicker } from "@mui/x-date-pickers";
import type { Dayjs } from "dayjs";
import { EmployeeFormData } from "./types";
import axios from "axios";
import {
  fetchTypeEntries,
  fetchShiftEntries,
  fetchStatusEntries,
} from "../../api/establishmentService";
import { SelectChangeEvent } from "@mui/material/Select";
import { masterService } from "../../api/masterService";
import { instituteService } from "../../api/instituteService";
import { employeeService } from "../../api/MasterEmployeeService";
import SearchEmployeeDialog from "./SearchEmployeeDialog";
import SearchIcon from "@mui/icons-material/Search";

const CreateEmployee = () => {
  const initialFormState: EmployeeFormData = {
    institute: "",
    department: "", // Change back to empty string
    shortCode: "",
    empType: "",
    empName: "",
    fatherName: "",
    motherName: "",
    dateOfBirth: null,
    designation: "",
    permanentAddress: "",
    email: "",
    localAddress: "",
    panNo: "",
    permanentCity: "",
    permanentPinNo: "",
    drivingLicNo: "",
    sex: "",
    status: "",
    maritalStatus: "",
    dateOfJoin: null,
    localCity: "",
    localPinNo: "",
    position: "",
    shift: "",
    bloodGroup: "",
    active: "yes",
    phoneNo: "",
    mobileNo: "",
    category: "", // Change back to empty string
    bankAccountNo: "",
    unaNo: "",
    profileImage: null,
  };

  const [formData, setFormData] = useState<EmployeeFormData>(initialFormState);

  const [institutes, setInstitutes] = useState([
    { id: "1", name: "Institute 1" },
    { id: "2", name: "Institute 2" },
  ]);

  const [sameAsPermAddress, setSameAsPermAddress] = useState(false);
  const [photoPreview, setPhotoPreview] = useState<string | null>(null);
  const [employeeTypes, setEmployeeTypes] = useState<any[]>([]);
  const [shifts, setShifts] = useState<any[]>([]);
  const [statuses, setStatuses] = useState<any[]>([]);
  const [departments, setDepartments] = useState<any[]>([]);
  const [designations, setDesignations] = useState<any[]>([]);
  const [categories, setCategories] = useState<any[]>([]);

  const [notification, setNotification] = useState({
    open: false,
    message: "",
    severity: "success" as "success" | "error",
  });

  const [openSearch, setOpenSearch] = useState(false);
  const [searchResults, setSearchResults] = useState<any[]>([]);
  const [searchLoading, setSearchLoading] = useState(false);

  const [isEditing, setIsEditing] = useState(false);
  const [currentEmployeeId, setCurrentEmployeeId] = useState<string | null>(
    null
  );

  useEffect(() => {
    const fetchInstitutes = async () => {
      try {
        const response = await instituteService.getInstitutes();
        console.log("Institutes:", response.data);
        setInstitutes(response.data);
      } catch (error) {
        console.error("Error fetching institutes:", error);
      }
    };
    fetchInstitutes();
  }, []);

  useEffect(() => {
    const fetchDropdownData = async () => {
      try {
        const [typeRes, shiftRes, statusRes] = await Promise.all([
          fetchTypeEntries(),
          fetchShiftEntries(),
          fetchStatusEntries(),
        ]);

        // Log the raw responses to see their structure
        console.log("Raw Type Data:", typeRes.data);
        console.log("Raw Shift Data:", shiftRes.data);
        console.log("Raw Status Data:", statusRes.data);

        // Set the state without filtering
        setEmployeeTypes(typeRes.data || []);
        setShifts(shiftRes.data || []);
        setStatuses(statusRes.data || []);
      } catch (error) {
        console.error("Error fetching dropdown data:", error);
      }
    };
    fetchDropdownData();
  }, []);

  useEffect(() => {
    const fetchMasterData = async () => {
      try {
        const [deptRes, desigRes] = await Promise.all([
          masterService.getDepartments(),
          masterService.getDesignations(),
        ]);
        console.log("Departments:", deptRes.data);
        console.log("Designations:", desigRes.data);
        setDepartments(deptRes.data);
        setDesignations(desigRes.data);
      } catch (error) {
        console.error("Error fetching master data:", error);
      }
    };
    fetchMasterData();
  }, []);

  useEffect(() => {
    const fetchCategories = async () => {
      try {
        const response = await masterService.getCategories();
        console.log("Categories:", response.data);
        setCategories(response.data);
      } catch (error) {
        console.error("Error fetching categories:", error);
      }
    };
    fetchCategories();
  }, []);

  // Debug helper
  useEffect(() => {
    console.log("Employee Types:", employeeTypes);
    console.log("Shifts:", shifts);
    console.log("Statuses:", statuses);
  }, [employeeTypes, shifts, statuses]);

  const handleInputChange = (
    e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>
  ) => {
    const { name, value } = e.target;
    console.log(`Input changed - name: ${name}, value: ${value}`); // Debug log
    setFormData((prev) => ({
      ...prev,
      [name]: value,
    }));
  };

  // Add new handler for Select components
  const handleSelectChange = (e: SelectChangeEvent) => {
    console.log("Select Change:", e.target.name, e.target.value);
    setFormData((prev) => {
      const newState = {
        ...prev,
        [e.target.name]: e.target.value,
      };
      console.log("New Form Data:", newState);
      return newState;
    });
  };

  const handleFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files[0]) {
      const file = e.target.files[0];
      setFormData({
        ...formData,
        profileImage: file,
      });
      // Create preview URL
      const previewUrl = URL.createObjectURL(file);
      setPhotoPreview(previewUrl);
    }
  };

  // Cleanup preview URL on component unmount
  React.useEffect(() => {
    return () => {
      if (photoPreview) {
        URL.revokeObjectURL(photoPreview);
      }
    };
  }, [photoPreview]);

  const handleDateChange =
    (field: "dateOfBirth" | "dateOfJoin") => (date: Date | null) => {
      setFormData({
        ...formData,
        [field]: date,
      });
    };

  const handleAddressChange = (
    e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>
  ) => {
    const { name, value } = e.target;
    setFormData((prev) => {
      if (sameAsPermAddress && name.startsWith("permanent")) {
        const localField = name.replace("permanent", "local");
        return {
          ...prev,
          [name]: value,
          [localField]: value,
        };
      }
      return {
        ...prev,
        [name]: value,
      };
    });
  };

  const handleSameAddressChange = (
    event: React.ChangeEvent<HTMLInputElement>
  ) => {
    const isChecked = event.target.checked;
    setSameAsPermAddress(isChecked);

    if (isChecked) {
      // When checkbox is checked, copy all permanent address fields to local
      setFormData((prev) => ({
        ...prev,
        localAddress: prev.permanentAddress,
        localCity: prev.permanentCity,
        localPinNo: prev.permanentPinNo,
      }));
    }
  };

  const resetForm = () => {
    // Reset all form fields to initial state
    setFormData(initialFormState);
    setPhotoPreview(null);
    setIsEditing(false);
    setCurrentEmployeeId(null);
    setSameAsPermAddress(false); // Reset address checkbox

    // Reset any touched/modified form fields
    const formElements = document.querySelector("form");
    if (formElements) {
      formElements.reset();
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      const formDataObj = new FormData();

      // Convert string IDs to numbers before sending
      const requiredFields = {
        EMP_NAME: formData.empName,
        EMAIL: formData.email,
        DESIGNATION: formData.designation,
        DEPARTMENT: Number(formData.department), // Convert to number
        INSTITUTE: formData.institute,
        DATE_OF_JOIN: formData.dateOfJoin
          ? new Date(formData.dateOfJoin).toISOString().split("T")[0]
          : "",
        MOBILE_NO: formData.mobileNo,
        SEX: formData.sex,
        CATEGORY: Number(formData.category), // Convert to number
        EMP_TYPE: Number(formData.empType), // Add this line
        SHORT_CODE: formData.shortCode,     // Add this
        POSITION: formData.position,        // Add this
      };

      // Log what we're sending
      console.log("Form Data Values:", {
        department: formData.department, // This will now be the CODE
        category: formData.category, // This will now be the CODE
        position: formData.position,
      });

      // Validate required fields
      const missingFields = Object.entries(requiredFields)
        .filter(([_, value]) => !value)
        .map(([key]) => key);

      if (missingFields.length > 0) {
        setNotification({
          open: true,
          message: `Please fill in required fields: ${missingFields.join(
            ", "
          )}`,
          severity: "error",
        });
        return;
      }

      // Add required fields
      Object.entries(requiredFields).forEach(([key, value]) => {
        formDataObj.append(key, String(value));
      });

      // Add optional fields (only if they have values)
      const optionalFields = {
        SHORT_CODE: formData.shortCode || "",
        FATHER_NAME: formData.fatherName || "",
        MOTHER_NAME: formData.motherName || "",
        DATE_OF_BIRTH: formData.dateOfBirth
          ? new Date(formData.dateOfBirth).toISOString().split("T")[0]
          : "",
        PERMANENT_ADDRESS: formData.permanentAddress || "",
        LOCAL_ADDRESS: formData.localAddress || "",
        PAN_NO: formData.panNo || "",
        PERMANENT_CITY: formData.permanentCity || "",
        PERMANENT_PIN: formData.permanentPinNo || "",
        DRIVING_LICENSE_NO: formData.drivingLicNo || "",
        STATUS: formData.status || "",
        MARITAL_STATUS: formData.maritalStatus || "",
        LOCAL_CITY: formData.localCity || "",
        LOCAL_PIN: formData.localPinNo || "",
        SHIFT: formData.shift || "",
        BLOOD_GROUP: formData.bloodGroup || "",
        IS_ACTIVE: formData.active || "yes",
        PHONE_NO: formData.phoneNo || "",
        BANK_ACCOUNT_NO: formData.bankAccountNo || "",
        UAN_NO: formData.unaNo || "",
      };

      // Add optional fields
      Object.entries(optionalFields).forEach(([key, value]) => {
        formDataObj.append(key, value || ''); // Send empty string instead of skipping
      });

      // Add profile image if exists
      if (formData.profileImage) {
        formDataObj.append("PROFILE_IMAGE", formData.profileImage);
      }

      // Log data being sent
      console.log("Sending data:", Object.fromEntries(formDataObj));

      let response;
      if (isEditing && currentEmployeeId) {
        // Only include fields that have changed
        const currentEmployee = await employeeService.getEmployee(
          currentEmployeeId
        );
        const changedFields = {};

        // Add only changed fields to formData
        Object.entries(formData).forEach(([key, value]) => {
          const apiKey = key.toUpperCase();
          if (value !== currentEmployee.data[apiKey]) {
            formDataObj.append(apiKey, value);
          }
        });

        // Always include profile image if selected
        if (formData.profileImage) {
          formDataObj.append("PROFILE_IMAGE", formData.profileImage);
        }

        response = await employeeService.updateEmployee(
          currentEmployeeId,
          formDataObj
        );
      } else {
        response = await employeeService.createEmployee(formDataObj);
      }

      setNotification({
        open: true,
        message: isEditing
          ? "Employee updated successfully!"
          : `Employee created successfully! Employee ID: ${response.data.employee_id}`,
        severity: "success",
      });

      // Call resetForm after successful submission
      resetForm();
    } catch (error: any) {
      console.error("Submit Error:", error);
      const errorMessage =
        error.response?.data?.error || "Failed to create employee";
      setNotification({
        open: true,
        message: errorMessage,
        severity: "error",
      });
    }
  };

  const handleCloseNotification = () => {
    setNotification((prev) => ({ ...prev, open: false }));
  };

  // Add this helper function at the top of the component
  const RequiredLabel = ({ label }: { label: string }) => (
    <span>
      {label} <span style={{ color: "#d32f2f" }}>*</span>
    </span>
  );

  // Add a new helper function for single star labels
  const SingleStarLabel = ({ label }: { label: string }) => (
    <span>
      {label} <span style={{ color: "#d32f2f" }}>*</span>
    </span>
  );

  const handleSearch = async (query: string) => {
    setSearchLoading(true);
    try {
      const response = await employeeService.searchEmployees(query);
      setSearchResults(response.data);
    } catch (error) {
      console.error("Error searching employees:", error);
      setNotification({
        open: true,
        message: "Error searching employees",
        severity: "error",
      });
    } finally {
      setSearchLoading(false);
    }
  };

  const handleSelectEmployee = async (employeeId: string) => {
    try {
      const response = await employeeService.getEmployee(employeeId);
      const employeeData = response.data;

      // Map API response fields to form data fields
      const mappedFormData = {
        institute: employeeData.INSTITUTE,
        department: employeeData.DEPARTMENT,
        shortCode: employeeData.SHORT_CODE || "",
        empType: employeeData.EMP_TYPE || "",
        empName: employeeData.EMP_NAME,
        fatherName: employeeData.FATHER_NAME || "",
        motherName: employeeData.MOTHER_NAME || "",
        dateOfBirth: employeeData.DATE_OF_BIRTH
          ? new Date(employeeData.DATE_OF_BIRTH)
          : null,
        designation: employeeData.DESIGNATION,
        permanentAddress: employeeData.PERMANENT_ADDRESS || "",
        email: employeeData.EMAIL,
        localAddress: employeeData.LOCAL_ADDRESS || "",
        panNo: employeeData.PAN_NO || "",
        permanentCity: employeeData.PERMANENT_CITY || "",
        permanentPinNo: employeeData.PERMANENT_PIN || "",
        drivingLicNo: employeeData.DRIVING_LICENSE_NO || "",
        sex: employeeData.SEX || "",
        status: employeeData.STATUS || "",
        maritalStatus: employeeData.MARITAL_STATUS || "",
        dateOfJoin: employeeData.DATE_OF_JOIN
          ? new Date(employeeData.DATE_OF_JOIN)
          : null,
        localCity: employeeData.LOCAL_CITY || "",
        localPinNo: employeeData.LOCAL_PIN || "",
        position: employeeData.POSITION || "",
        shift: employeeData.SHIFT || "",
        bloodGroup: employeeData.BLOOD_GROUP || "",
        active: employeeData.IS_ACTIVE || "yes",
        phoneNo: employeeData.PHONE_NO || "",
        mobileNo: employeeData.MOBILE_NO || "",
        category: employeeData.CATEGORY,
        bankAccountNo: employeeData.BANK_ACCOUNT_NO || "",
        unaNo: employeeData.UAN_NO || "",
        profileImage: null, // Reset profile image since we'll load it separately
      };

      setFormData(mappedFormData);

      // Handle profile image if exists
      if (employeeData.PROFILE_IMAGE) {
        setPhotoPreview(employeeData.PROFILE_IMAGE);
      }

      setOpenSearch(false);
      setIsEditing(true);
      setCurrentEmployeeId(employeeId);

      // Show notification
      setNotification({
        open: true,
        message: "Employee data loaded for editing",
        severity: "success",
      });
    } catch (error) {
      console.error("Error fetching employee details:", error);
      setNotification({
        open: true,
        message: "Error fetching employee details",
        severity: "error",
      });
    }
  };

  // Add this helper to determine button text
  const getSubmitButtonText = () => {
    if (isEditing) {
      return "Update Employee Details";
    }
    return "Save Employee Details";
  };

  return (
    <Paper elevation={3} sx={{ p: 0.5, m: 0.25, maxHeight: "98vh" }}>
      <Snackbar
        open={notification.open}
        autoHideDuration={6000}
        onClose={handleCloseNotification}
        anchorOrigin={{ vertical: "top", horizontal: "center" }}
      >
        <Alert
          onClose={handleCloseNotification}
          severity={notification.severity}
          variant="filled"
        >
          {notification.message}
        </Alert>
      </Snackbar>
      <form onSubmit={handleSubmit}>
        <Grid container spacing={0.5}>
          {/* Header with Photo */}
          <Grid item xs={12} sx={{ mb: 0.5 }}>
            <Stack
              direction="row"
              justifyContent="space-between"
              alignItems="center"
            >
              <Stack direction="row" spacing={2} alignItems="center">
                <Typography variant="h6" sx={{ fontWeight: "bold" }}>
                  {isEditing
                    ? `Edit Employee: ${currentEmployeeId}`
                    : "Create Employee"}
                </Typography>
                <Button
                  variant="outlined"
                  startIcon={<SearchIcon />}
                  size="small"
                  onClick={() => setOpenSearch(true)}
                >
                  Search Employee
                </Button>
                {isEditing && (
                  <Button
                    variant="outlined"
                    color="info"
                    size="small"
                    onClick={resetForm}
                  >
                    Create New Employee
                  </Button>
                )}
              </Stack>
              <Stack direction="row" spacing={1.5} alignItems="center">
                <Avatar
                  src={photoPreview || undefined}
                  sx={{
                    width: 100,
                    height: 100,
                    border: "2px solid #e0e0e0",
                    boxShadow: 1,
                    borderRadius: "8px", // Making it slightly square
                  }}
                />
                <Button variant="outlined" component="label" size="small">
                  Upload Photo
                  <input
                    type="file"
                    hidden
                    accept="image/*"
                    onChange={handleFileUpload}
                  />
                </Button>
              </Stack>
            </Stack>
          </Grid>

          {/* Row 1 - Basic Info */}
          <Grid item xs={2}>
            <FormControl fullWidth size="small">
              <InputLabel>{<SingleStarLabel label="Institute" />}</InputLabel>
              <Select
                value={formData.institute}
                name="institute"
                onChange={handleSelectChange}
                error={!formData.institute}
                label={<SingleStarLabel label="Institute" />}
              >
                {institutes.map((inst: any) => (
                  <MenuItem key={inst.INSTITUTE_ID} value={inst.CODE}>
                    {inst.NAME}
                  </MenuItem>
                ))}
              </Select>
            </FormControl>
          </Grid>
          <Grid item xs={2}>
            <FormControl fullWidth size="small">
              <InputLabel>{<SingleStarLabel label="Department" />}</InputLabel>
              <Select
                value={formData.department}
                name="department"
                onChange={handleSelectChange}
                error={!formData.department}
                label={<SingleStarLabel label="Department" />}
              >
                {departments?.map((dept: any) => (
                  <MenuItem key={dept.DEPARTMENT_ID} value={dept.DEPARTMENT_ID}>
                    {dept.NAME}
                  </MenuItem>
                ))}
              </Select>
            </FormControl>
          </Grid>
          <Grid item xs={2}>
            <TextField
              size="small"
              fullWidth
              label="Short Code"
              name="shortCode"
              value={formData.shortCode}  // Add this
              onChange={handleInputChange} // Add this
              placeholder="e.g. EMP001"
            />
          </Grid>
          <Grid item xs={2}>
            <FormControl fullWidth size="small" required>
              <InputLabel>{<SingleStarLabel label="Emp Type" />}</InputLabel>
              <Select
                value={formData.empType}
                name="empType"
                onChange={handleSelectChange}
                error={!formData.empType}
                label={<SingleStarLabel label="Emp Type" />}
              >
                {employeeTypes?.map((type: any) => (
                  <MenuItem key={type.ID} value={type.ID}>
                    {type.RECORD_WORD}
                  </MenuItem>
                ))}
              </Select>
            </FormControl>
          </Grid>
          <Grid item xs={2}>
            <TextField
              size="small"
              fullWidth
              label="Position"
              name="position"
              value={formData.position}  // Add this
              onChange={handleInputChange} // Add this
              placeholder="e.g. Senior Developer"
            />
          </Grid>

          {/* Row 2 - Personal Info */}
          <Grid item xs={2.4}>
            <TextField
              size="small"
              fullWidth
              value={formData.empName}
              onChange={handleInputChange}
              label={<SingleStarLabel label="Employee Name" />} // Changed from RequiredLabel
              name="empName" // This maps to the formData field
              error={!formData.empName}
              helperText={!formData.empName ? "Employee Name is required" : ""}
              placeholder="e.g. John Smith"
            />
          </Grid>
          <Grid item xs={2.4}>
            <TextField
              size="small"
              fullWidth
              label="Father Name"
              name="fatherName"
              value={formData.fatherName}  // Add this
              onChange={handleInputChange} // Add this
              placeholder="e.g. David Smith"
            />
          </Grid>
          <Grid item xs={2.4}>
            <TextField
              size="small"
              fullWidth
              label="Mother Name"
              name="motherName"
              value={formData.motherName} // Add this
              onChange={handleInputChange} // Add this
              placeholder="e.g. Sarah Smith"
            />
          </Grid>
          <Grid item xs={2.4}>
            <FormControl fullWidth size="small">
              <InputLabel>{<SingleStarLabel label="Designation" />}</InputLabel>
              <Select
                value={formData.designation}
                name="designation"
                onChange={handleSelectChange}
                error={!formData.designation}
                label={<SingleStarLabel label="Designation" />}
              >
                {designations?.map((desig: any) => (
                  <MenuItem
                    key={desig.DESIGNATION_ID}
                    value={desig.DESIGNATION_ID}
                  >
                    {desig.NAME}
                  </MenuItem>
                ))}
              </Select>
            </FormControl>
          </Grid>
          <Grid item xs={2.4}>
            <FormControl fullWidth size="small">
              <InputLabel>Shift</InputLabel>
              <Select
                value={formData.shift}
                name="shift"
                onChange={handleSelectChange}
                label="Shift"
              >
                {shifts?.map((shift: any) => (
                  <MenuItem key={shift.ID} value={shift.ID}>
                    {shift.SHIFT_NAME}
                  </MenuItem>
                ))}
              </Select>
            </FormControl>
          </Grid>

          {/* Row 3 - Contact & Dates */}
          <Grid item xs={2.4}>
            <TextField
              size="small"
              fullWidth
              value={formData.email}
              onChange={handleInputChange}
              label={<SingleStarLabel label="Email" />} // Changed from RequiredLabel
              name="email" // This maps to the formData field
              type="email"
              error={!formData.email}
              helperText={!formData.email ? "Email is required" : ""}
              placeholder="e.g. john.smith@example.com"
            />
          </Grid>
          <Grid item xs={2.4}>
            <TextField 
              size="small" 
              fullWidth 
              label="Phone" 
              name="phoneNo" 
              value={formData.phoneNo} // Add this
              onChange={handleInputChange} // Add this
              placeholder="e.g. 020-12345678"
            />
          </Grid>
          <Grid item xs={2.4}>
            <TextField
              size="small"
              fullWidth
              value={formData.mobileNo} // This maps to the formData field
              onChange={handleInputChange}
              label={<SingleStarLabel label="Mobile No" />} // Changed from RequiredLabel
              name="mobileNo"
              error={!formData.mobileNo}
              helperText={!formData.mobileNo ? "Mobile No is required" : ""}
              placeholder="e.g. 9876543210"
            />
          </Grid>
          <Grid item xs={2.4}>
            <LocalizationProvider dateAdapter={AdapterDateFns}>
              <DatePicker
                label="Birth Date"
                value={formData.dateOfBirth}
                onChange={handleDateChange("dateOfBirth")}
                slotProps={{ textField: { size: "small", fullWidth: true } }}
              />
            </LocalizationProvider>
          </Grid>
          <Grid item xs={2.4}>
            <LocalizationProvider dateAdapter={AdapterDateFns}>
              <DatePicker
                label="Join Date"
                value={formData.dateOfJoin}
                onChange={handleDateChange("dateOfJoin")}
                slotProps={{ textField: { size: "small", fullWidth: true } }}
              />
            </LocalizationProvider>
          </Grid>

          {/* Addresses */}
          <Grid item xs={12} sx={{ mt: 0.5 }}>
            <FormControlLabel
              control={
                <Checkbox
                  checked={sameAsPermAddress}
                  onChange={handleSameAddressChange}
                  size="small"
                />
              }
              label={<Typography variant="caption">Same Address</Typography>}
            />
          </Grid>
          <Grid item xs={6}>
            <Stack spacing={0.5}>
              <TextField
                size="small"
                fullWidth
                multiline
                rows={1}
                label="Permanent Address"
                name="permanentAddress"
                onChange={handleAddressChange}
                placeholder="e.g. 123, Main Street, Apartment 4B"
              />
              <Stack direction="row" spacing={0.5}>
                <TextField
                  size="small"
                  fullWidth
                  label="City"
                  name="permanentCity"
                  onChange={handleAddressChange}
                  placeholder="e.g. Mumbai"
                />
                <TextField
                  size="small"
                  fullWidth
                  label="PIN"
                  name="permanentPinNo"
                  onChange={handleAddressChange}
                  placeholder="e.g. 400001"
                />
              </Stack>
            </Stack>
          </Grid>
          <Grid item xs={6}>
            <Stack spacing={0.5}>
              <TextField
                size="small"
                fullWidth
                multiline
                rows={1}
                label="Local Address"
                name="localAddress"
                value={formData.localAddress}
                onChange={handleInputChange}
                disabled={sameAsPermAddress}
              />
              <Stack direction="row" spacing={0.5}>
                <TextField
                  size="small"
                  fullWidth
                  label="City"
                  name="localCity"
                  value={formData.localCity}
                  onChange={handleInputChange}
                  disabled={sameAsPermAddress}
                />
                <TextField
                  size="small"
                  fullWidth
                  label="PIN"
                  name="localPinNo"
                  value={formData.localPinNo}
                  onChange={handleInputChange}
                  disabled={sameAsPermAddress}
                />
              </Stack>
            </Stack>
          </Grid>

          {/* Row 5 - Additional Details */}
          <Grid item xs={2}>
            <FormControl fullWidth size="small">
              <InputLabel>{<SingleStarLabel label="Sex" />}</InputLabel>
              <Select
                value={formData.sex}
                name="sex"
                onChange={handleSelectChange}
                error={!formData.sex}
                label={<SingleStarLabel label="Sex" />}
              >
                <MenuItem value="male">Male</MenuItem>
                <MenuItem value="female">Female</MenuItem>
                <MenuItem value="other">Other</MenuItem>
              </Select>
            </FormControl>
          </Grid>
          <Grid item xs={2}>
            <FormControl fullWidth size="small">
              <InputLabel>Blood Group</InputLabel>
              <Select
                value={formData.bloodGroup}
                name="bloodGroup"
                onChange={handleSelectChange}
              >
                {["A+", "A-", "B+", "B-", "AB+", "AB-", "O+", "O-"].map(
                  (group) => (
                    <MenuItem key={group} value={group}>
                      {group}
                    </MenuItem>
                  )
                )}
              </Select>
            </FormControl>
          </Grid>
          <Grid item xs={2}>
            <FormControl fullWidth size="small">
              <InputLabel>Marital Status</InputLabel>
              <Select
                value={formData.maritalStatus}
                name="maritalStatus"
                onChange={handleSelectChange}
              >
                <MenuItem value="single">Single</MenuItem>
                <MenuItem value="married">Married</MenuItem>
                <MenuItem value="other">Other</MenuItem>
              </Select>
            </FormControl>
          </Grid>
          <Grid item xs={2}>
            <FormControl fullWidth size="small">
              <InputLabel>Status</InputLabel>
              <Select
                value={formData.status}
                name="status"
                onChange={handleSelectChange}
                label="Status"
              >
                {statuses?.map((status: any) => (
                  <MenuItem key={status.ID} value={status.ID}>
                    {status.RECORD_WORD}
                  </MenuItem>
                ))}
              </Select>
            </FormControl>
          </Grid>
          <Grid item xs={2}>
            <FormControl fullWidth size="small">
              <InputLabel>{<SingleStarLabel label="Category" />}</InputLabel>
              <Select
                value={formData.category}
                name="category"
                onChange={handleSelectChange}
                error={!formData.category}
                label={<SingleStarLabel label="Category" />}
              >
                {categories?.map((category: any) => (
                  <MenuItem
                    key={category.CATEGORY_ID}
                    value={category.CATEGORY_ID}
                  >
                    {category.NAME}
                  </MenuItem>
                ))}
              </Select>
            </FormControl>
          </Grid>
          <Grid item xs={2}>
            <FormControl fullWidth size="small">
              <InputLabel>Active</InputLabel>
              <Select
                value={formData.active}
                name="active"
                onChange={handleSelectChange}
              >
                <MenuItem value="yes">Yes</MenuItem>
                <MenuItem value="no">No</MenuItem>
              </Select>
            </FormControl>
          </Grid>

          {/* Row 6 - IDs and Numbers */}
          <Grid item xs={2}>
            <TextField 
              size="small" 
              fullWidth 
              label="PAN No" 
              name="panNo" 
              value={formData.panNo} // Add this
              onChange={handleInputChange} // Add this
              placeholder="e.g. ABCDE1234F"
            />
          </Grid>
          <Grid item xs={2}>
            <TextField 
              size="small" 
              fullWidth 
              label="UAN No" 
              name="unaNo" 
              value={formData.unaNo} // Add this 
              onChange={handleInputChange} // Add this
              placeholder="e.g. 123456789012"
            />
          </Grid>
          <Grid item xs={2}>
            <TextField
              size="small"
              fullWidth
              label="Bank A/C No"
              name="bankAccountNo"
              value={formData.bankAccountNo} // Add this
              onChange={handleInputChange} // Add this
              placeholder="e.g. 1234567890"
            />
          </Grid>
          <Grid item xs={2}>
            <TextField
              size="small"
              fullWidth
              label="Driving Lic No"
              name="drivingLicNo"
              value={formData.drivingLicNo} // Add this
              onChange={handleInputChange} // Add this
              placeholder="e.g. MH0123456789"
            />
          </Grid>

          {/* Submit Button */}
          <Grid
            item
            xs={12}
            sx={{
              display: "flex",
              justifyContent: "flex-end",
              gap: 2,
              mt: 2,
            }}
          >
            {isEditing && (
              <Button
                type="button"
                variant="outlined"
                color="secondary"
                size="small"
                onClick={resetForm}
              >
                Cancel Edit
              </Button>
            )}
            <Button
              type="submit"
              variant="contained"
              color={isEditing ? "primary" : "primary"}
              size="small"
              sx={{ minWidth: 150 }}
            >
              {getSubmitButtonText()}
            </Button>
          </Grid>
        </Grid>
      </form>
      <SearchEmployeeDialog
        open={openSearch}
        onClose={() => setOpenSearch(false)}
        onSelect={handleSelectEmployee}
        onSearch={handleSearch}
        searchResults={searchResults}
        loading={searchLoading}
      />
    </Paper>
  );
};

export default CreateEmployee;
