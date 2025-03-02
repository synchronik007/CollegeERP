import React, { useEffect, useState } from "react";
import { Table, Button, Form, Spinner } from "react-bootstrap";
import { Paper } from "@mui/material";
import { useNavigate } from "react-router-dom";
import axiosInstance from "../../api/axios";
import { useSettings } from "../../context/SettingsContext";
import EditModal from "../../components/CourseMaster/Editmodal"; // Ensure this path is correct

interface Program {
  PROGRAM_ID: number;
  NAME: string;
  CODE: string;
  LEVEL: string;
  TYPE: string;
}

const ProgramTableView = () => {
  const [programs, setPrograms] = useState<Program[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [selectedItems, setSelectedItems] = useState<number[]>([]);
  const [selectAll, setSelectAll] = useState(false);
  const [showEditModal, setShowEditModal] = useState(false);
  const [editingProgram, setEditingProgram] = useState<Program | null>(null);
  const { darkMode } = useSettings();
  const navigate = useNavigate();

  useEffect(() => {
    fetchPrograms();
  }, []);

  const fetchPrograms = async () => {
    try {
      const token = localStorage.getItem("token");
      if (!token) return;
      const response = await axiosInstance.get("/api/master/program/", {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (response.status === 200) setPrograms(response.data);
      setLoading(false);
    } catch (error) {
      console.error("Error fetching programs:", error);
      setError("Failed to fetch programs");
      setLoading(false);
    }
  };

  const handleDelete = async (ids: number[]) => {
    if (!window.confirm("Are you sure you want to delete selected programs?")) return;

    try {
      const token = localStorage.getItem("token");
      if (!token) return;

      // Send DELETE requests for each selected program
      await Promise.all(
        ids.map((id) =>
          axiosInstance.delete(`/api/master/program/${id}/`, {
            headers: { Authorization: `Bearer ${token}` },
          })
        )
      );

      alert("Selected programs deleted successfully!");

      // ✅ Remove deleted programs from state immediately
      setPrograms((prevPrograms) =>
        prevPrograms.filter((program) => !ids.includes(program.PROGRAM_ID))
      );

      setSelectedItems([]); // Reset selected checkboxes
      setSelectAll(false);  // Reset "Select All" checkbox

    } catch (error) {
      console.error("Error deleting programs:", error);
      alert("Failed to delete programs");
    }
  };

  const handleEdit = (program: Program) => {
    setEditingProgram(program);
    setShowEditModal(true);
  };

  const handleUpdate = async (updatedProgram: Program) => {
    try {
      const token = localStorage.getItem("token");
      if (!token) return;

      await axiosInstance.put(`/api/master/program/${updatedProgram.PROGRAM_ID}/`, updatedProgram, {
        headers: { Authorization: `Bearer ${token}` },
      });

      // ✅ Update UI instantly
      setPrograms((prevPrograms) =>
        prevPrograms.map((program) =>
          program.PROGRAM_ID === updatedProgram.PROGRAM_ID ? updatedProgram : program
        )
      );

      setShowEditModal(false);
      alert("Program updated successfully!");
    } catch (error) {
      console.error("Error updating program:", error);
      alert("Failed to update program");
    }
  };

  if (loading) return <div><Spinner animation="border" /> Loading...</div>;
  if (error) return <div className="alert alert-danger">{error}</div>;

  return (
    <Paper
      elevation={3}
      sx={{
        p: 2,
        backgroundColor: darkMode ? "#1a1a1a" : "#ffffff",
        color: darkMode ? "#e0e0e0" : "#000000",
      }}
    >
      <div className="d-flex justify-content-between mb-3">
        <h4>Programs List</h4>
        {selectedItems.length > 0 && (
          <Button variant="danger" onClick={() => handleDelete(selectedItems)}>
            Delete Selected ({selectedItems.length})
          </Button>
        )}
      </div>

      <Table striped bordered hover responsive className={darkMode ? "table-dark" : ""}>
        <thead>
          <tr>
            <th>
              <Form.Check
                type="checkbox"
                checked={selectAll}
                onChange={(e) => {
                  setSelectAll(e.target.checked);
                  setSelectedItems(e.target.checked ? programs.map((p) => p.PROGRAM_ID) : []);
                }}
              />
            </th>
            <th>Name</th>
            <th>Code</th>
            <th>Level</th>
            <th>Type</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          {programs.map((program) => (
            <tr key={program.PROGRAM_ID}>
              <td>
                <Form.Check
                  type="checkbox"
                  checked={selectedItems.includes(program.PROGRAM_ID)}
                  onChange={() => {
                    setSelectedItems((prev) =>
                      prev.includes(program.PROGRAM_ID)
                        ? prev.filter((id) => id !== program.PROGRAM_ID)
                        : [...prev, program.PROGRAM_ID]
                    );
                  }}
                />
              </td>
              <td>{program.NAME}</td>
              <td>{program.CODE}</td>
              <td>{program.LEVEL}</td>
              <td>{program.TYPE}</td>
              <td>
                <Button
                  variant="primary"
                  size="sm"
                  className="me-2"
                  onClick={() => handleEdit(program)}
                >
                  Edit
                </Button>
                <Button
                  variant="danger"
                  size="sm"
                  onClick={() => handleDelete([program.PROGRAM_ID])}
                >
                  Delete
                </Button>
              </td>
            </tr>
          ))}
        </tbody>
      </Table>

      {editingProgram && (
  <EditModal
    show={showEditModal}
    onHide={() => setShowEditModal(false)}
    onSave={handleUpdate}
    data={editingProgram} 
    title="Program" // ✅ Added a title prop
  />
)}

    </Paper>
  );
};

export default ProgramTableView;
