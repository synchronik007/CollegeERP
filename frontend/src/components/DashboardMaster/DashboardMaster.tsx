import React, { useState, useEffect, ChangeEvent } from 'react';
import axios from 'axios';
import axiosInstance from "../../api/axios";
import { instituteService } from "../../api/instituteService";
import { universityService } from "../../api/universityService";
import {masterService} from '../../api/masterService';
import employeeService from '../../api/MasterEmployeeService';

interface FormData {
  academicYear: {
    from: string;
    to: string;
  };
  universityId: string;
  instituteId: string;
  courseName: string;
  department: string;
  conditionType: string;
  selectedEmployees: string[];
}

interface Institute {
  UNIVERSITY_ID: any;
  INSTITUTE_ID: number;
  CODE: string;
}

interface University {
  UNIVERSITY_ID: number;
  NAME: string;
}

interface Department {
  DEPARTMENT_ID: number;
  NAME: string;
}

interface Employee {
  EMPLOYEE_ID: string;
  NAME: string;
}

const DashboardMaster: React.FC = () => {
  const [formData, setFormData] = useState<FormData>({
    academicYear: { from: '2024', to: '2025' },
    universityId: '',
    instituteId: '',
    courseName: 'MDS',
    department: '',
    conditionType: 'Dashboard College Wise',
    selectedEmployees: [],
  });

  const [universities, setUniversities] = useState<University[]>([]);
  const [institutes, setInstitutes] = useState<Institute[]>([]);
  const [departments, setDepartments] = useState<Department[]>([]);
  const [employees, setEmployees] = useState<Employee[]>([]);

  useEffect(() => {
    fetchUniversities();
    fetchDepartments();
  }, []);

  useEffect(() => {
    if (formData.universityId) fetchInstitutes(Number(formData.universityId));
  }, [formData.universityId]);

  useEffect(() => {
    if (formData.courseName && formData.department && formData.instituteId) {
      fetchEmployees(formData.courseName, formData.department, formData.instituteId);
    }
  }, [formData.courseName, formData.department, formData.instituteId]);

  useEffect(() => {
    if (formData.courseName && formData.department && formData.instituteId) {
      fetchEmployees(formData.courseName, formData.department, formData.instituteId);
    }
  }, [formData.department]);
  

  const fetchUniversities = async () => {
    try {
      const response = await universityService.getUniversities();
      if (response.status === 200) setUniversities(response.data);
    } catch (error) {
      console.error('Error fetching universities:', error);
    }
  };

  const fetchDepartments = async () => {
    try {
      const response = await axiosInstance.get("/api/master/departments/");
      if (response.status === 200) {
        setDepartments(response.data);
      }
    } catch (error) {
      console.error('Error fetching departments:', error);
    }
  };
  
  
  const fetchEmployees = async (courseName: string, department: string, instituteId: string) => {
    try {
      const response = await axios.get(`/api/employees/?course=${courseName}&department=${department}&institute_id=${instituteId}`);
      if (response.status === 200) setEmployees(response.data);
    } catch (error) {
      console.error('Error fetching employees:', error);
    }
  };

  const fetchInstitutes = async (universityId: number) => {
    try {
      setInstitutes([]);
      const token = localStorage.getItem("token");
      if (!token) return;
      const response = await axiosInstance.get(`/api/master/institutes/?university_id=${universityId}`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      if (response.status === 200) setInstitutes(response.data);
    } catch (error) {
      console.error("Error fetching institutes:", error);
    }
  };

  // Removed redundant fetchEmployees function
  

  const years = Array.from({ length: 2050 - 1980 + 1 }, (_, i) => (1980 + i).toString());

  const handleChange = (e: React.ChangeEvent<HTMLSelectElement | HTMLInputElement>) => {
    const { name, value } = e.target;
    const [parent, child] = name.split('.');
    if (child) {
      setFormData((prev) => ({
        ...prev,
        [parent]: {
          ...prev[parent as keyof FormData] as Record<string, any>,
          [child]: value,
        },
      }));
    } else {
      setFormData({ ...formData, [name]: value });
    }
  };

  const handleInstituteChange = (e: ChangeEvent<HTMLSelectElement>) => {
    const { value } = e.target;
    setFormData((prev) => ({ ...prev, instituteId: value }));
  };

  const handleCheckboxChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const { value, checked } = e.target;
    setFormData((prev) => {
      const selectedEmployees = checked
        ? [...prev.selectedEmployees, value]
        : prev.selectedEmployees.filter((id) => id !== value);
      return { ...prev, selectedEmployees };
    });
  };

  const handleDepartmentChange = async (e: React.ChangeEvent<HTMLSelectElement>) => {
    const { value } = e.target;
    setFormData((prev) => ({ ...prev, department: value }));
  
    if (formData.courseName && formData.instituteId && value) {
      try {
        const response = await axiosInstance.get(
          `/api/establishment/employees/=${formData.department}&department=${value}&institute_id=${formData.instituteId}`
        );
        console.log('API Response:', response.data); // Debug the data
        if (response.status === 200) {
          setEmployees(response.data); // Ensure employees are correctly set
        }
      } catch (error) {
        console.error('Error fetching employees:', error);
      }
    }
  };
  
  
  

  const [editingId, setEditingId] = useState<string | null>(null);
  const handleSubmit = async (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    
    try {
      const token = localStorage.getItem("token");
      if (!token) {
        alert("Token not found. Please log in again.");
        return;
      }
  
      const payload = {
        academicYear: formData.academicYear,
        universityId: formData.universityId,
        instituteId: formData.instituteId,
        courseName: formData.courseName,
        department: formData.department,
        conditionType: formData.conditionType,
        selectedEmployees: formData.selectedEmployees,
        UPDATED_BY: 1,
        CREATED_BY: 1,
      };
      
      if (editingId) {
        await axiosInstance.put(`/api/master/program/${editingId}/`, payload, {
          headers: {
            Authorization: `Bearer ${token}`,
            "Content-Type": "application/json",
          },
        });
        alert("Program updated successfully!");
      } else {
        await axiosInstance.post("/api/master/program/", payload, {
          headers: {
            Authorization: `Bearer ${token}`,
            "Content-Type": "application/json",
          },
        });
        alert("Program saved successfully!");
      }
  
      // Reset form state
      setFormData((prev) => ({
        ...prev,
        academicYear: { from: '2024', to: '2025' },
        universityId: '',
        instituteId: '',
        courseName: 'MDS',
        department: '',
        conditionType: 'Dashboard College Wise',
        selectedEmployees: [],
      }));
  
    } catch (error) {
      console.error("Error saving program:", error);
      alert("Failed to save the program. Please try again.");
    }
  };
  
  

  

  return (
    <div className="container mt-4">
    <h3 className="text-primary">Dashboard Form</h3>
    <form onSubmit={handleSubmit} className="p-4 border rounded bg-light">
      <div className="row mb-3">
        <div className="col-md-6">
          <label>Academic Year</label>
          <div className="d-flex align-items-center">
            <select name="academicYear.from" value={formData.academicYear.from} onChange={handleChange} className="form-select me-2">
              {years.map((year) => (<option key={year} value={year}>{year}</option>))}
            </select>
            <span className="mx-2">-</span>
            <select name="academicYear.to" value={formData.academicYear.to} onChange={handleChange} className="form-select">
              {years.map((year) => (<option key={year} value={year}>{year}</option>))}
            </select>
          </div>
        </div>

     <div className="col-md-6">
            <label>University</label>
            <select name="universityId" value={formData.universityId} onChange={handleChange} className="form-select">
              <option value="">Select University</option>
              {universities.map((university) => (<option key={university.UNIVERSITY_ID} value={university.UNIVERSITY_ID}>{university.NAME}</option>))}
              </select>
          </div>

          <div className="col-md-6">
            <label>Institute Id</label>
            <select
              name="instituteId"
              value={formData.instituteId}
              onChange={handleInstituteChange}
              className="form-select"
            >
            <option value="">Select Institute</option>
              {institutes.map((institute) => (
              <option key={institute.INSTITUTE_ID} value={institute.INSTITUTE_ID}>
              {institute.CODE}
            </option>
       ))}
</select>
          </div>
        </div>
        <div className="row mb-3">
          <div className="col-md-6">
            <label>Course Name</label>
            <select
              name="courseName"
              value={formData.courseName}
              onChange={handleChange}
              className="form-select"
            >
              <option>MDS</option>
              <option>BDS</option>
            </select>
          </div>

          <div className="col-md-6">
            <label>Department</label>
            <select
  name="department"
  value={formData.department}
  onChange={handleDepartmentChange}
  className="form-select"
>
  <option value="">Select Department</option>
  {departments.map((department) => (
    <option key={department.DEPARTMENT_ID} value={department.DEPARTMENT_ID}>
      {department.NAME}
    </option>
  ))}
</select>

          </div>
        </div>

        <div className="mb-3">
          <label>Condition Type</label>
          <select
            name="conditionType"
            value={formData.conditionType}
            onChange={handleChange}
            className="form-select"
          >
            <option>Dashboard College Wise</option>
            <option>Department Wise</option>
          </select>
        </div>

        <div className="mb-3">
  <label>Employees</label>
  {employees.length > 0 ? (
    employees.map((employee) => (
      <div key={employee.EMPLOYEE_ID} className="form-check">
        <input
          type="checkbox"
          id={`employee-${employee.EMPLOYEE_ID}`}
          value={employee.EMPLOYEE_ID}
          checked={formData.selectedEmployees.includes(employee.EMPLOYEE_ID)}
          onChange={handleCheckboxChange}
          className="form-check-input"
        />
        <label htmlFor={`employee-${employee.EMPLOYEE_ID}`} className="form-check-label">
          {employee.NAME} (ID: {employee.EMPLOYEE_ID})
        </label>
      </div>
    ))
  ) : (
    <p>No employees found for the selected department.</p>
  )}
</div>



        <button type="submit" className="btn btn-primary">Save</button>
    </form>
  </div>
  );
};

export default DashboardMaster;