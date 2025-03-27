import React, { useState } from "react";
import { useForm, SubmitHandler } from "react-hook-form";
import { motion } from "framer-motion";
import axiosInstance from "../../../api/axios";
import { Paper, Button } from "@mui/material";
import "bootstrap/dist/css/bootstrap.min.css";

const CasteEntryForm = () => {
  const { register, handleSubmit, reset } = useForm();
  const [casteName, setCasteName] = useState("");

  const onSubmit = async (data: any) => {
    try {
      await axiosInstance.post("/master/caste/", data);
      console.log("Data submitted successfully:", data);
      reset();
    } catch (error) {
      console.error("Error submitting data:", error);
    }
  };

  return (
    <Paper elevation={3} sx={{ p: 3, borderRadius: 2 }}>
      <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.5 }}>
        <form onSubmit={handleSubmit(onSubmit)}>
          <div className="mb-3">
            <label className="form-label">Caste Name:</label>
            <input
              type="text"
              {...register("casteName", { required: true })}
              className="form-control"
              style={{ width: "200px" }}
            />
          </div>
          <div className="d-flex gap-2">
            <Button type="submit" variant="contained" color="primary">Save</Button>
            <Button type="button" variant="outlined" color="error" onClick={() => reset()}>Clear</Button>
          </div>
        </form>
      </motion.div>
    </Paper>
  );
};

export default CasteEntryForm;