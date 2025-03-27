import React, { useState } from "react";
import { Paper } from "@mui/material";
import { motion } from "framer-motion";
import { useNavigate } from "react-router-dom";
import CasteEntryForm from "./pages/CasteEntryForm";

const NameEntryForm = () => {
  const [selectedAction, setSelectedAction] = useState<"create" | "view">("create");
  const navigate = useNavigate();

  return (
    <Paper elevation={3} sx={{ p: 3, borderRadius: 2 }}>
      <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.5 }}>
        <h2 className="text-center mb-4">Caste Entry Form</h2>

        {/* Create / View Buttons */}
        <div className="d-flex justify-content-center gap-2">
          <button
            className={`btn ${selectedAction === "create" ? "btn-primary" : "btn-outline-primary"} btn-sm`}
            onClick={() => setSelectedAction("create")}
          >
            Create Caste
          </button>
          <button
            className={`btn ${selectedAction === "view" ? "btn-primary" : "btn-outline-primary"} btn-sm`}
            onClick={() => setSelectedAction("view")}
          >
            View Caste
          </button>
        </div>

        {/* Dynamic Rendering of Forms */}
        {selectedAction === "create" && (
          <div className="card mt-3">
            <div className="card-header py-2">
              <h6 className="mb-0">Caste Master</h6>
            </div>
            <div className="card-body p-2">
              <CasteEntryForm />
            </div>
          </div>
        )}

        {/* Dynamic Rendering of Tables */}
        {selectedAction === "view" && (
          <div className="card mt-3">
            <div className="card-header py-2 d-flex justify-content-between align-items-center">
              <h6 className="mb-0">Caste List</h6>
            </div>
            <div className="card-body p-2">
              {/* Table rendering logic here */}
            </div>
          </div>
        )}
      </motion.div>
    </Paper>
  );
};

export default NameEntryForm;
