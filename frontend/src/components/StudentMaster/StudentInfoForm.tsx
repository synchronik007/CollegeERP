import React, { useState, useEffect, ChangeEvent, FormEvent } from "react";
import { Form, Button } from "react-bootstrap";
import axios from "axios";
import axiosInstance from '../../api/axios';
import "bootstrap/dist/css/bootstrap.min.css";
import { useForm } from "react-hook-form";

// Define types for form data
interface FormData {
  academicYear: string;
  university: string;
  institute: string;
  program: string;
  branch: string;
  admissionCategory: string;
  admissionQuota: string;
  batch: string;
  formNo: string;
  year: string;
  name: string;
  father: string;
  surname: string;
  gender: string;
  dateOfBirth: string;
  certificateName: string;
  mobileNo: string;
  emailId: string;
  status: string;
 }

 // Define a type for dropdown options
 interface DropdownOption {
  id: number;
  name: string;
 }
 interface University {
    UNIVERSITY_ID: number;
    NAME: string;
    CODE: string;
  }
  
  interface Institute {
    INSTITUTE_ID: number;
    CODE: string;
  }

  interface Program {
    PROGRAM_ID: number;
    NAME: string;
  }

  interface Branch {
    BRANCH_ID: number;
    NAME: string;
  }

  interface Year {
    YEAR_ID: number;
    YEAR: string;
  }

  interface AcademicYear{
    ACADEMIC_YEAR_ID: number;
    ACADEMIC_YEAR: string;
  }

  interface Category{
    CATEGORY_ID: number;
    CODE: string;
  }

  interface Quota{
    QUOTA_ID: number;
    NAME: string;
  }

  const StudentInfoForm = () => {
  const [formData, setFormData] = useState<FormData>({
    academicYear: "",
    university: "",
    institute: "",
    program: "",
    branch: "",
    admissionCategory: "",
    admissionQuota: "",
    batch: "",
    formNo: "",
    year: "",
    name: "",
    father: "",
    surname: "",
    gender: "Male",
    dateOfBirth: "",
    certificateName: "",
    mobileNo: "",
    emailId: "",
    status: "Active",
  });

    // Explicitly define the types of state variables
    const { register, reset, setValue, formState: { errors } } = useForm<FormData>();
    const [universities, setUniversities] = useState<University[]>([]);
    const [institutes, setInstitutes] = useState<Institute[]>([]);
    const [programs, setPrograms] = useState<Program[]>([]);
    const [branches, setBranches] = useState<Branch[]>([]);
    const [years, setYears] = useState<Year[]>([]);
    const [academicYears, setAcademicYears] = useState<AcademicYear[]>([]);
    const [categories, setCategories] = useState<Category[]>([]);
    const [quotas, setQuotas] = useState<Quota[]>([]);
    const [error, setError] = useState("");
    const [editingId, setEditingId] = useState<number | null>(null);

    const [selectedUniversity, setSelectedUniversity] = useState<string>("");
    const [selectedInstitute, setSelectedInstitute] = useState<string>("");
    const [selectedProgram, setSelectedProgram] = useState<string>("");
    const [selectedBranch, setSelectedBranch] = useState<string>("");
    const [selectedYear, setSelectedYear] = useState<string>("");
    const [selectedAcademicYear, setSelectedAcademicYear] = useState<string>("");
    const [selectedCategory, setSelectedCategory] = useState<string>("");
    const [selectedQuota, setSelectedQuota] = useState<string>("");
   

  
  useEffect(() => {
    console.log("Current editing ID:", editingId);
    const fetchUniversities = async () => {
      try {
        const token = localStorage.getItem('token');
        if (!token) return;

        const response = await axiosInstance.get('/api/master/universities/', {
          headers: { Authorization: `Bearer ${token}` },
        });

        if (response.status === 200) {
          setUniversities(response.data);
        }
      } catch (error) {
        console.error('Error fetching universities:', error);
        setError('Failed to load universities');
      }
    };
    fetchUniversities();
  }, []);

  const fetchInstitutes = async (universityId: number) => {
    try {
      const token = localStorage.getItem('token');
      if (!token) return;

      const response = await axiosInstance.get(`/api/master/institutes/?university_id=${universityId}`, {
        headers: { Authorization: `Bearer ${token}` },
      });

      if (response.status === 200) {
        setInstitutes(response.data);
      }
    } catch (error) {
      console.error('Error fetching institutes:', error);
      setError('Failed to load institutes');
    }
  };

    const handleUniversityChange = (e: React.ChangeEvent<unknown>) => {
        const target = e.target as HTMLSelectElement; // Cast to HTMLSelectElement explicitly
        const universityId = parseInt(target.value, 10);
        
        setSelectedUniversity(universityId.toString());
        setInstitutes([]);
    
        if (universityId) {
            fetchInstitutes(universityId);
        }
    
    };

    const handleInstituteChange = (e: React.ChangeEvent<HTMLElement>) => {
            const target = e.target as HTMLSelectElement; // Explicitly cast
            const instituteId = parseInt(target.value, 10);
            setSelectedInstitute(instituteId.toString());
        
            if (instituteId) {
                fetchPrograms(instituteId);
            }
    };

    const fetchPrograms = async (instituteId: number) => {
            setPrograms([]);
            setBranches([]);
            setYears([]);
             
            try {
              const response = await axiosInstance.get(`/api/master/program/?institute_id=${instituteId}`);
              if (response.status === 200) setPrograms(response.data);
            } catch (error) {
              console.error("Error fetching programs:", error);
            }
    };
        
    const fetchBranches = async (programId: number) => {
            setBranches([]);
            setYears([]);
            
            try {
              const response = await axiosInstance.get(`/api/master/branch/?program_id=${programId}`);
              if (response.status === 200) setBranches(response.data);
            } catch (error) {
              console.error("Error fetching branches:", error);
            }
    };

    const handleProgramChange = (e: React.ChangeEvent<unknown>) => {
           const target = e.target as HTMLSelectElement; // Explicitly cast to HTMLSelectElement
           const programId = parseInt(target.value, 10);
           setSelectedProgram(programId.toString());
       
           if (programId) {
               fetchBranches(programId); // Fetch branches based on selected program
           }
    };
   
    const handleBranchChange = (e: React.ChangeEvent<any>) => {
        const target = e.target as HTMLSelectElement; // Explicit cast
        const branchId = parseInt(target.value, 10);
        console.log("Selected Branch ID:", branchId);  // Debug log
        setSelectedBranch(branchId.toString());
       
        if (branchId) {
            fetchYears(branchId);
        }
    };

    const fetchYears = async (branchId: number) => {
               console.log("Fetching years for branch:", branchId);
               setYears([]);  
           
               try {
                   const response = await axiosInstance.get(`/api/master/year/?branch_id=${branchId}`);
                   console.log("API Response:", response.data);
           
                   if (response.status === 200 && Array.isArray(response.data)) {
                       setYears(response.data);
                   } else {
                       console.error("Invalid data format:", response.data);
                   }
               } catch (error) {
                   console.error("Error fetching years:", error);
               }
    };

    const handleYearChange = (e: React.ChangeEvent<HTMLSelectElement>) => {
                   const yearId = parseInt(e.target.value, 10);
                   setSelectedYear(yearId.toString());
    };
    
    useEffect(() => {
                    console.log("Current editing ID:", editingId);
                const fetchAcademicYears = async () => {
                        try {
                          const token = localStorage.getItem('token');
                          if (!token) {
                            alert('Authentication token not found. Please log in again.');
                            return;
                          }
                    
                          const response = await axiosInstance.get('/api/master/academic-years/', {
                            headers: { Authorization: `Bearer ${token}` },
                          });
                    
                          if (response.status === 200) {
                            setAcademicYears(response.data);
                          } else {
                            console.error('Unexpected response status:', response.status, response.data);
                          }
                        } catch (error: any) {
                          if (error.response) {
                            console.error('API Response Error:', error.response.data);
                            alert(`Error: ${JSON.stringify(error.response.data)}`);
                          } else {
                            console.error('Error fetching academic years:', error.message);
                            alert(`Error: ${error.message}`);
                          }
                        }
                      };
                    fetchAcademicYears();
    }, []);

    const handleAcademicYearChange = (e: React.ChangeEvent<HTMLSelectElement>) => {
        const academicYearId = parseInt(e.target.value, 10);
        setSelectedAcademicYear(academicYearId.toString());
    };
      
    useEffect(() => {
        const fetchCategories = async () => {
          try {
            const token = localStorage.getItem("token");
            if (!token) return;
      
            const response = await axiosInstance.get("/api/master/categories/", {
              headers: { Authorization: `Bearer ${token}` },
            });
      
            if (response.status === 200) {
              setCategories(response.data);
            }
          } catch (error) {
            console.error("Error fetching categories:", error);
            setError("Failed to load categories");
          }
        };
      
        fetchCategories();
      }, []);

      const handleCategoryChange = (e: React.ChangeEvent<HTMLSelectElement>) => {
        const categoryId = parseInt(e.target.value, 10);
        setSelectedCategory(categoryId.toString());
    };

    useEffect(() => {
      const fetchQuotas = async () => {
        try {
          const token = localStorage.getItem("token");
          if (!token) return;
    
          const response = await axiosInstance.get("/api/master/quota/", {
            headers: { Authorization: `Bearer ${token}` },
          });
    
          if (response.status === 200) {
            setQuotas(response.data);
          }
        } catch (error) {
          console.error("Error fetching quotas:", error);
        }
      };
    
      fetchQuotas();
    }, []);
    
    const handleQuotaChange = (e: React.ChangeEvent<HTMLSelectElement>) => {
      setSelectedQuota(e.target.value);
    }; 
         

    const handleChange = (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement>) => {
        const { name, value } = e.target;
        setFormData({ ...formData, [name]: value });
    };


  // Handle form submission
  const handleSubmit = (e: FormEvent<HTMLFormElement>) => {
    e.preventDefault();
    console.log("Form Data Submitted:", formData);
    axios.post("/api/student-info", formData)
      .then(() => alert("Student Information Saved Successfully"))
      .catch((err) => console.error("Error submitting form:", err));
  };

  return (
    <div className="container mt-4">
      <h4 className="bg-dark text-white p-2">BASIC STUDENT INFO</h4>
      <form onSubmit={handleSubmit}>
        {/* Academic Year */}
        <div className="row">
          <div className="col-md-3">
          <Form.Group>
            <Form.Label>Academic Year</Form.Label>
            <Form.Control 
                as="select"
                value={selectedAcademicYear}
                onChange={(e) => handleAcademicYearChange(e as unknown as React.ChangeEvent<HTMLSelectElement>)}>
                    <option value="" disabled>Select Academic Year</option>
                    {academicYears.map((y) => (
                        <option key={y.ACADEMIC_YEAR_ID} value={y.ACADEMIC_YEAR_ID}>{y.ACADEMIC_YEAR}</option>
                    ))}
            </Form.Control>
          </Form.Group>
          </div>

          <div className="col-md-3">
            <label>Status</label>
            <div>
              <input type="radio" name="status" value="Active" checked={formData.status === "Active"} onChange={handleChange} /> Active
              <input type="radio" name="status" value="Rejected" className="ms-2" checked={formData.status === "Rejected"} onChange={handleChange} /> Rejected
            </div>
          </div>
        </div>

        {/* University Institute Program */}
        <div className="row mt-2">
          <div className="col-md-3">
                                <Form.Group>
                                    <Form.Label>University</Form.Label>
                                    <Form.Control as="select" value={selectedUniversity} onChange={handleUniversityChange} // No need for additional casting
                                    >
                                        <option value="" disabled>Select University</option>
                                        {universities.map((u) => (
                                            <option key={u.UNIVERSITY_ID} value={u.UNIVERSITY_ID}>{u.NAME}</option>
                                            ))}
                                    </Form.Control>
                                </Form.Group>
          </div>

          <div className="col-md-3">
                                <Form.Group>
                                    <Form.Label>Institute</Form.Label>
                                    <Form.Control as="select" value={selectedInstitute} onChange={handleInstituteChange} disabled={!selectedUniversity}>
                                        <option value="" disabled>Select Institute</option>
                                        {institutes.map((i: Institute) => (
                                            <option key={i.INSTITUTE_ID} value={i.INSTITUTE_ID}>{i.CODE}</option>
                                        ))}
                                    </Form.Control>
                                </Form.Group>
          </div>
          <div className="col-md-3">
                                <Form.Group>
                                    <Form.Label>Program</Form.Label>
                                    <Form.Control as="select" value={selectedProgram} onChange={handleProgramChange} disabled={!selectedInstitute}>
                                        <option value="" disabled>Select Program</option>
                                        {programs.map((p) => (
                                            <option key={p.PROGRAM_ID} value={p.PROGRAM_ID}>{p.NAME}</option>
                                        ))}
                                    </Form.Control>
                                </Form.Group>
          </div>
        </div>

        {/* Branch, Year,  Admission Category */}
        <div className="row mt-2">
          <div className="col-md-3">
          <Form.Group>
                                    <Form.Label>Branch</Form.Label>
                                    <Form.Control as="select" value={selectedBranch} onChange={handleBranchChange} disabled={!selectedProgram}>
                                        <option value="" disabled>Select Branch</option>
                                        {branches.map((b) => (
                                            <option key={b.BRANCH_ID} value={b.BRANCH_ID}>{b.NAME}</option>
                                        ))}
                                    </Form.Control>
                                </Form.Group>
          </div>

          <div className="col-md-3">
                                <Form.Group>
                                    <Form.Label>Year</Form.Label>
                                    <Form.Control 
                                    as="select"
                                    value={selectedYear}
                                    onChange={(e) => handleYearChange(e as unknown as React.ChangeEvent<HTMLSelectElement>)}
                                    disabled={!selectedBranch}>
                                        <option value="" disabled>Select Year</option>
                                        {years.map((y) => (
                                            <option key={y.YEAR_ID} value={y.YEAR_ID}>{y.YEAR}</option>
                                        ))}
                                    </Form.Control>
                                </Form.Group>
          </div>

          <div className="col-md-3">
          <label>Admission Category</label>
          <select
            className="form-control"
            name="admissionCategory"
            value={selectedCategory}
            onChange={handleCategoryChange}
          >
            <option value="">Select Category</option>
            {categories.map((category) => (
                <option key={category.CATEGORY_ID} value={category.CATEGORY_ID}>
                    {category.CODE}
                </option>
            ))}
           </select>

          </div>
        </div>

        {/* Admission Quota, Batch, Form No */}
        <div className="row mt-2">
        <div className="col-md-3">
  <label>Admission Quota</label>
  <select
    className="form-control"
    name="admissionQuota"
    value={selectedQuota}
    onChange={handleQuotaChange}
  >
        <option value="">Select Quota</option>
        {quotas.map((quota) => (
          <option key={quota.QUOTA_ID} value={quota.QUOTA_ID}>
            {quota.NAME}
          </option>
        ))}
      </select>
</div>

          <div className="col-md-3">
          <label>Batch</label>
          <select className="form-control" name="batch" value={formData.batch} onChange={handleChange}>
            {Array.from({ length: 15 }, (_, i) => 2025 + i).map((year) => (
                <option key={year} value={year}>
                    {year}
                </option>
            ))}
          </select>

          </div>

          <div className="col-md-3">
            <label>Form No</label>
            <input type="text" className="form-control" name="formNo" value={formData.formNo} onChange={handleChange} />
          </div>
        </div>

        {/* Other Fields */}
        <div className="row mt-2">
          <div className="col-md-3">
            <label>Name</label>
            <input type="text" className="form-control" name="name" value={formData.name} onChange={handleChange} required />
          </div>

          <div className="col-md-3">
            <label>Father's Name</label>
            <input type="text" className="form-control" name="father" value={formData.father} onChange={handleChange} required />
          </div>

          <div className="col-md-3">
            <label>Surname</label>
            <input type="text" className="form-control" name="surname" value={formData.surname} onChange={handleChange} required />
          </div>
        </div>

        {/* Name As Per Certificate */}
        <div className="row mt-2">
          <div className="col-md-6">
            <label>Name As Per Certificate</label>
            <input type="text" className="form-control" name="certificateName" value={formData.certificateName} onChange={handleChange} />
          </div>

          <div className="col-md-3">
            <label>Email ID</label>
            <input type="email" className="form-control" name="emailId" value={formData.emailId} onChange={handleChange} />
          </div>
        </div>

        {/* Gender, DOB, Mobile, Email */}
        <div className="row mt-2">
          <div className="col-md-3">
            <label>Gender</label>
            <select className="form-control" name="gender" value={formData.gender} onChange={handleChange}>
              <option>Male</option>
              <option>Female</option>
              <option>Other</option>
            </select>
          </div>

          <div className="col-md-3">
            <label>Date of Birth</label>
            <input type="date" className="form-control" name="dateOfBirth" value={formData.dateOfBirth} onChange={handleChange} required />
          </div>

          <div className="col-md-3">
            <label>Mobile No</label>
            <input type="text" className="form-control" name="mobileNo" value={formData.mobileNo} onChange={handleChange} required />
          </div>
        </div>

        {/* Submit Buttons */}
        <div className="mt-4">
          <button type="submit" className="btn btn-primary">Save</button>
          <button type="reset" className="btn btn-secondary ms-2">Clear</button>
        </div>
      </form>
    </div>
  );
};

export default StudentInfoForm;
