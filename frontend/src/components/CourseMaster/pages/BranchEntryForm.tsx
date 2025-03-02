import React, { useState, useEffect } from "react";
import { useForm, SubmitHandler } from "react-hook-form";
import { motion } from "framer-motion";
import axiosInstance from "../../../api/axios";
import { Paper, Button } from "@mui/material";
import { useNavigate } from "react-router-dom";
import "bootstrap/dist/css/bootstrap.min.css";

interface BranchEntryFormInputs {
  BRANCH_ID?: number;
  UNIVERSITY: number;
  INSTITUTE: number;
  PROGRAM: number;
  NAME: string;
  CODE: string;
  DESCRIPTION: string;
  IS_ACTIVE: boolean;
  CREATED_BY: number;
  UPDATED_BY: number;
}

interface University {
  UNIVERSITY_ID: number;
  NAME: string;
}

interface Institute {
  INSTITUTE_ID: number;
  NAME: string;
}

interface Program {
  PROGRAM_ID: number;
  NAME: string;
}

const BranchEntryForm = () => {
  const navigate = useNavigate();
  const { register, handleSubmit, reset, setValue, formState: { errors } } = useForm<BranchEntryFormInputs>();

  const [universities, setUniversities] = useState<University[]>([]);
  const [institutes, setInstitutes] = useState<Institute[]>([]);
  const [programs, setPrograms] = useState<Program[]>([]);
  const [branches, setBranches] = useState<BranchEntryFormInputs[]>([]);
  const [editingId, setEditingId] = useState<number | null>(null);

  useEffect(() => {
    fetchUniversities();
    fetchBranches();
  }, []);

  const fetchUniversities = async () => {
    try {
      const token = localStorage.getItem("token");
      if (!token) return;
      const response = await axiosInstance.get("/api/master/universities/", {
        headers: { Authorization: `Bearer ${token}` }
      });
      if (response.status === 200) setUniversities(response.data);
    } catch (error) {
      console.error("Error fetching universities:", error);
    }
  };

  const fetchInstitutes = async (universityId: number) => {
    try {
      setInstitutes([]);
      setPrograms([]); // Reset programs when university changes
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

  const fetchPrograms = async (instituteId: number) => {
    try {
      setPrograms([]); // Reset programs when institute changes
      const token = localStorage.getItem("token");
      if (!token) return;
      const response = await axiosInstance.get(`/api/master/program/?institute_id=${instituteId}`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      if (response.status === 200) setPrograms(response.data);
    } catch (error) {
      console.error("Error fetching programs:", error);
    }
  };

  const fetchBranches = async () => {
    try {
      const token = localStorage.getItem("token");
      if (!token) return;
      const response = await axiosInstance.get("/api/master/branch/", {
        headers: { Authorization: `Bearer ${token}` }
      });
      if (response.status === 200) setBranches(response.data);
    } catch (error) {
      console.error("Error fetching branches:", error);
    }
  };

  const handleUniversityChange = (e: React.ChangeEvent<HTMLSelectElement>) => {
    const universityId = Number(e.target.value);
    setValue("UNIVERSITY", universityId);
    setValue("INSTITUTE", 0); // Reset institute selection
    setValue("PROGRAM", 0); // Reset program selection
    fetchInstitutes(universityId);
  };

  const handleInstituteChange = (e: React.ChangeEvent<HTMLSelectElement>) => {
    const instituteId = Number(e.target.value);
    setValue("INSTITUTE", instituteId);
    setValue("PROGRAM", 0); // Reset program selection
    fetchPrograms(instituteId);
  };

  const onSubmit: SubmitHandler<BranchEntryFormInputs> = async (data) => {
    try {
      const token = localStorage.getItem("token");
      if (!token) return;

      const payload = { ...data, UPDATED_BY: 1, CREATED_BY: 1 };

      if (editingId) {
        await axiosInstance.put(`/api/master/branch/${editingId}/`, payload, {
          headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" }
        });
        alert("Branch updated successfully!");
      } else {
        await axiosInstance.post("/api/master/branch/", payload, {
          headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" }
        });
        alert("Branch saved successfully!");
      }
      fetchBranches();
      handleClear();
    } catch (error) {
      console.error("Error submitting form:", error);
    }
  };

  const handleClear = () => {
    reset();
    setEditingId(null);
  };

  return (
    <Paper elevation={3} sx={{ p: 3, borderRadius: 2 }}>
      <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.5 }}>
        {/* <h2>Branch Entry Form</h2> */}
        <form onSubmit={handleSubmit(onSubmit)}>
          <div className="row g-3">
            <div className="col-md-6">
              <label className="form-label">University</label>
              <select {...register("UNIVERSITY", { required: true })} className="form-control" onChange={handleUniversityChange}>
                <option value="">Select University</option>
                {universities.map((university) => (
                  <option key={university.UNIVERSITY_ID} value={university.UNIVERSITY_ID}>{university.NAME}</option>
                ))}
              </select>
              {errors.UNIVERSITY && <p className="text-danger">University is required</p>}
            </div>

            <div className="col-md-6">
              <label className="form-label">Institute</label>
              <select {...register("INSTITUTE", { required: true })} className="form-control" onChange={handleInstituteChange}>
                <option value="">Select Institute</option>
                {institutes.map((institute) => (
                  <option key={institute.INSTITUTE_ID} value={institute.INSTITUTE_ID}>{institute.NAME}</option>
                ))}
              </select>
              {errors.INSTITUTE && <p className="text-danger">Institute is required</p>}
            </div>

            <div className="col-md-6">
              <label className="form-label">Program</label>
              <select {...register("PROGRAM", { required: true })} className="form-control">
                <option value="">Select Program</option>
                {programs.map((program) => (
                  <option key={program.PROGRAM_ID} value={program.PROGRAM_ID}>{program.NAME}</option>
                ))}
              </select>
              {errors.PROGRAM && <p className="text-danger">Program is required</p>}
            </div>
        
             <div className="col-md-6">
              <label className="form-label">Branch Name</label>
              <input placeholder="Branch Name" {...register("NAME", { required: true })} className="form-control" />
              {errors.NAME && <p className="text-danger">Branch Name is required</p>}
            </div>
          <div className="col-md-6">
              <label className="form-label">Branch Code</label>
              <input placeholder="Branch Code" {...register("CODE", { required: true })} className="form-control" />
              {errors.CODE && <p className="text-danger">Branch Code is required</p>}
            </div>
          <div className="col-md-6">
              <label className="form-label">Is Active</label>
              <input type="checkbox" {...register("IS_ACTIVE")} className="form-check-input" />
            </div>
            </div>

          <div className="mt-3">
            <Button type="submit" variant="contained" color="primary">Submit</Button>
            <Button type="button" variant="outlined" color="secondary" onClick={handleClear} className="ms-2">Clear</Button>
          </div>
        </form>
      </motion.div>
    </Paper>
  );
};

export default BranchEntryForm;
