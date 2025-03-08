import React, { useState, useEffect } from "react";
import { useForm, SubmitHandler } from "react-hook-form";
import { motion } from "framer-motion";
import axiosInstance from "../../api/axios";
import { Paper } from "@mui/material";
import { useNavigate } from "react-router-dom"; // Import for navigation
import "bootstrap/dist/css/bootstrap.min.css";

interface ProgramEntryFormInputs {
  PROGRAM_ID?: number;
  UNIVERSITY: number;
  INSTITUTE: number;
  INSTITUTE_CODE: string;
  NAME: string;
  CODE: string;
  DURATION_YEARS: number;
  LEVEL: string;
  TYPE: string;
  DESCRIPTION: string;
  IS_ACTIVE: boolean;
  CREATED_BY: number;
  UPDATED_BY: number;
}

interface University {
  UNIVERSITY_ID: number;
  NAME: string;
  CODE: string;
}

interface Institute {
  INSTITUTE_ID: number;
  CODE: string;
  NAME: string;
}

const NameEntryForm = () => {
  const navigate = useNavigate(); // Initialize navigation

  const { register, handleSubmit, reset, setValue, formState: { errors } } = useForm<ProgramEntryFormInputs>();

  const [universities, setUniversities] = useState<University[]>([]);
  const [institutes, setInstitutes] = useState<Institute[]>([]);
  const [programs, setPrograms] = useState<ProgramEntryFormInputs[]>([]);
  const [editingId, setEditingId] = useState<number | null>(null);

  useEffect(() => {
    fetchUniversities();
    fetchPrograms();
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
      setInstitutes([]); // Clear previous data before fetching new ones
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

  const fetchPrograms = async () => {
    try {
      const token = localStorage.getItem("token");
      if (!token) return;
      const response = await axiosInstance.get("/api/master/program/", {
        headers: { Authorization: `Bearer ${token}` }
      });
      if (response.status === 200) setPrograms(response.data);
    } catch (error) {
      console.error("Error fetching programs:", error);
    }
  };

  const handleUniversityChange = (e: React.ChangeEvent<HTMLSelectElement>) => {
    const universityId = Number(e.target.value);
    setValue("UNIVERSITY", universityId);
    fetchInstitutes(universityId);
  };

  const onSubmit: SubmitHandler<ProgramEntryFormInputs> = async (data) => {
    try {
      const token = localStorage.getItem("token");
      if (!token) return;

      const payload = { ...data, UPDATED_BY: 1, CREATED_BY: 1 }; // Ensure user ID is sent

      if (editingId) {
        await axiosInstance.put(`/api/master/program/${editingId}/`, payload, {
          headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" }
        });
        alert("Program updated successfully!");
      } else {
        await axiosInstance.post("/api/master/program/", payload, {
          headers: { Authorization: `Bearer ${token}`, "Content-Type": "application/json" }
        });
        alert("Program saved successfully!");
      }
      fetchPrograms();
      handleClear();
    } catch (error) {
      console.error("Error submitting form:", error);
    }
  };

  const handleEdit = (program: ProgramEntryFormInputs) => {
    setEditingId(program.PROGRAM_ID || null);
    Object.keys(program).forEach((key) => {
      setValue(key as keyof ProgramEntryFormInputs, program[key as keyof ProgramEntryFormInputs]);
    });
  };

  const handleDelete = async (programId: number) => {
    if (!window.confirm("Are you sure you want to delete this program?")) return;
    try {
      const token = localStorage.getItem("token");
      if (!token) return;
      await axiosInstance.delete(`/api/master/program/${programId}/`, {
        headers: { Authorization: `Bearer ${token}` }
      });
      alert("Program deleted successfully!");
      fetchPrograms();
    } catch (error) {
      console.error("Error deleting program:", error);
    }
  };

  const handleClear = () => {
    reset();
    setEditingId(null);
  };

  return (
    <Paper elevation={3} sx={{ p: 3, borderRadius: 2 }}>
      <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.5 }}>
        
        {/* Navigation Bar */}
        {/* <div className="d-flex justify-content-between align-items-center mb-4">
          <h2>Program Entry Form</h2>
        
        </div> */}

        <form onSubmit={handleSubmit(onSubmit)}>
          <div className="row g-3">
            <div className="col-md-6">
              <label className="form-label">University</label>
              <select {...register("UNIVERSITY", { required: true })} className="form-control" onChange={handleUniversityChange}>
                <option value="">Select University</option>
                {universities.map((university) => (
                  <option key={university.UNIVERSITY_ID} value={university.UNIVERSITY_ID}>{university.NAME} ({university.CODE})</option>
                ))}
              </select>
            </div>

            <div className="col-md-6">
              <label className="form-label">Institute</label>
              <select {...register("INSTITUTE", { required: true })} className="form-control">
                <option value="">Select Institute</option>
                {institutes.map((institute) => (
                  <option key={institute.INSTITUTE_ID} value={institute.INSTITUTE_ID}>{institute.NAME}</option>
                ))}
              </select>
            </div>

            <div className="col-md-6">
              <label className="form-label">Program Name</label>
              <input type="text"placeholder="Program Name" {...register("NAME", { required: true })} className="form-control" />
            </div>
          
          <div className="col-md-6">
              <label className="form-label">Code</label>
              <input type="text" placeholder="Code" {...register("CODE", { required: true })} className="form-control" />
            </div>

            <div className="col-md-6">
  <label className="form-label">Duration (Years)</label>
  <select {...register("DURATION_YEARS", { required: true })} className="form-control">
    <option value="">Select Duration</option>
    <option value="1">1 </option>
    <option value="2">2 </option>
    <option value="3">3</option>
    <option value="4">4 </option>
    <option value="5">5 </option>
    <option value="6">6 </option>
  </select>
</div>

            <div className="col-md-6">
              <label className="form-label">Level</label>
              <select {...register("LEVEL", { required: true })} className="form-control">
                <option value="">Select Level</option>
                <option value="UG">Undergraduate</option>
                <option value="PG">Postgraduate</option>
                <option value="DIP">Diploma</option>
              </select>
            </div>
            <div className="col-md-6">
               <label className="form-label">Type</label>
              <select {...register("TYPE", { required: true })} className="form-control">
                <option value="">Select Type</option>
                <option value="FT">Full Time</option>
                <option value="PT">Part Time</option>
              </select>
            </div>

            <div className="col-md-6">
              <label className="form-label">Is Active</label>
              <input type="checkbox" {...register("IS_ACTIVE")} className="form-check-input ms-2" />
            </div>
            </div>

          <div className="text-center mt-4">
            <motion.button whileHover={{ scale: 1.05 }} whileTap={{ scale: 0.95 }} type="submit" className="btn btn-primary">
              {editingId ? "Update" : "Save"}
            </motion.button>
            <button type="button" className="btn btn-danger ms-3" onClick={handleClear}>Clear</button>
          </div>
        </form>
      </motion.div>
    </Paper>
  );
};

export default NameEntryForm;
