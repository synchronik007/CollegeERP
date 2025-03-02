import React, { useState } from "react";
import { Paper } from "@mui/material";
import { motion } from "framer-motion";
import { useNavigate } from "react-router-dom";

// Import all forms and tables (Uncomment when needed)
import ProgramEntryForm from "./ProgramEntryForm";
import CourseEntryForm from "./pages/CourseEntryForm";
import BranchEntryForm from "./pages/BranchEntryForm";
// import SemesterEntryForm from "./pages/SemesterEntryForm";
// import YearEntryForm from "./pages/YearEntryForm";

import ProgramTableView from "./ProgramTableView";
import BranchTableView from "./BranchTableView";
// import CourseList from "./CourseList";
// import BranchList from "./BranchList";
// import SemesterList from "./SemesterList";
// import YearList from "./YearList";

const NameEntryForm = () => {
  const [selectedForm, setSelectedForm] = useState<string>("program"); // Default selection
  const [selectedAction, setSelectedAction] = useState<"create" | "view">("create");
  const navigate = useNavigate();

  return (
    <Paper elevation={3} sx={{ p: 3, borderRadius: 2 }}>
      <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.5 }}>
        <h2 className="text-center mb-4">Master Entry Form</h2>

        {/* Dropdown to Select Entry Type */}
        <select onChange={(e) => setSelectedForm(e.target.value)} className="form-control mb-3">
          <option value="program">Program</option>
          <option value="branch">Branch</option>
          <option value="course">Course</option>
          <option value="semester">Semester</option>
          <option value="year">Year</option>
        </select>

        {/* Create / View Buttons */}
        <div className="d-flex justify-content-center gap-2">
          <button
            className={`btn ${selectedAction === "create" ? "btn-primary" : "btn-outline-primary"} btn-sm`}
            onClick={() => setSelectedAction("create")}
          >
            Create {selectedForm.charAt(0).toUpperCase() + selectedForm.slice(1)}
          </button>
          <button
            className={`btn ${selectedAction === "view" ? "btn-primary" : "btn-outline-primary"} btn-sm`}
            onClick={() => setSelectedAction("view")}
          >
            View {selectedForm.charAt(0).toUpperCase() + selectedForm.slice(1)}
          </button>
        </div>

        {/* Dynamic Rendering of Forms */}
        {selectedAction === "create" && (
          <div className="card mt-3">
            <div className="card-header py-2">
              <h6 className="mb-0">{selectedForm.charAt(0).toUpperCase() + selectedForm.slice(1)} Master</h6>
            </div>
            <div className="card-body p-2">
              {selectedForm === "program" && <ProgramEntryForm />}
              {selectedForm === "course" && <CourseEntryForm />}
              {/* Uncomment when needed */}
              {selectedForm === "branch" && <BranchEntryForm />}
              {/* {selectedForm === "semester" && <SemesterEntryForm />} */}
              {/* {selectedForm === "year" && <YearEntryForm />} */}
            </div>
          </div>
        )}

        {/* Dynamic Rendering of Tables */}
        {selectedAction === "view" && (
          <div className="card mt-3">
            <div className="card-header py-2 d-flex justify-content-between align-items-center">
              <h6 className="mb-0">{selectedForm.charAt(0).toUpperCase() + selectedForm.slice(1)} List</h6>
              {selectedForm === "program" && (
                <button className="btn btn-secondary btn-sm" onClick={() => navigate("/courses")}>
                  Go to Courses
                </button>
              )}
            </div>
            <div className="card-body p-2">
              {selectedForm === "program" && <ProgramTableView />}
              {/* Uncomment when needed */}
              {/* {selectedForm === "course" && <CourseList />} */}
              {selectedForm === "branch" && <BranchTableView />}
              {/* {selectedForm === "semester" && <SemesterList />} */}
              {/* {selectedForm === "year" && <YearList />} */}
            </div>
          </div>
        )}
      </motion.div>
    </Paper>
  );
};

export default NameEntryForm;
