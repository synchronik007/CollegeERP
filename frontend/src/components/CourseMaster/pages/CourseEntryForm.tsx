import React, { useState } from "react";
import { useNavigate } from "react-router-dom";
import { motion } from "framer-motion";
import { Paper } from "@mui/material";
import "bootstrap/dist/css/bootstrap.min.css";
import ProgramTableView from "../ProgramTableView";
import ProgramEntryForm from "../ProgramEntryForm";


const NameEntryForm = () => {
  const navigate = useNavigate();
  const [selectedAction, setSelectedAction] = useState<string | null>(null);

  const handleNavigate = () => {
    navigate("/course-entry");
  };

  return (
    <Paper elevation={2} sx={{ p: 2, borderRadius: 1 }}>
      <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.4 }}>
        <h4 className="text-center mb-3">Program Management</h4>
        <div className="d-flex justify-content-center gap-2">
          <button
            className={`btn ${selectedAction === "create" ? "btn-primary" : "btn-outline-primary"} btn-sm`}
            onClick={() => setSelectedAction("create")}
          >
            Create Program
          </button>
          <button
            className={`btn ${selectedAction === "view" ? "btn-primary" : "btn-outline-primary"} btn-sm`}
            onClick={() => setSelectedAction("view")}
          >
            View Programs
          </button>
        </div>

        {selectedAction === "create" && (
          <div className="card mt-3">
            <div className="card-header py-2">
              <h6 className="mb-0">Program Master</h6>
            </div>
            <div className="card-body p-2">
              <ProgramEntryForm />
            </div>
          </div>
        )}
        

        {selectedAction === "view" && (
          <div className="card mt-3">
            <div className="card-header py-2 d-flex justify-content-between align-items-center">
              <h6 className="mb-0">Programs List</h6>
              <button className="btn btn-secondary btn-sm" onClick={handleNavigate}>Go to Courses</button>
            </div>
            <div className="card-body p-2">
              <ProgramTableView />
            </div>
          </div>
        )}
      </motion.div>
    </Paper>
  );
};

export default NameEntryForm;
