import React, { useEffect, useState } from "react";
import axiosInstance from "../../api/axios";
import { Button, Table } from "react-bootstrap";
import { Paper } from "@mui/material";
import EditModal from "../../components/CourseMaster/Editmodal";

interface Semester {
  SEMESTER_ID: number;
  SEMESTER: string;
  BRANCH_NAME: string; // ✅ Display Branch Name
  YEAR_YEAR: string;    // ✅ Display Year Name
  IS_ACTIVE: boolean;
}

const SemesterTableView: React.FC = () => {
  const [semesters, setSemesters] = useState<Semester[]>([]);
  const [showEditModal, setShowEditModal] = useState(false);
  const [editingSemester, setEditingSemester] = useState<{ SEMESTER: string } | null>(null);
  const [selectedSemesterId, setSelectedSemesterId] = useState<number | null>(null);

  useEffect(() => {
    fetchSemesters();
  }, []);

  const fetchSemesters = async () => {
    try {
      const token = localStorage.getItem("token");
      if (!token) return;

      const response = await axiosInstance.get("/api/master/semester/", {
        headers: { Authorization: `Bearer ${token}` },
      });

      if (Array.isArray(response.data)) {
        setSemesters(response.data);
      } else {
        console.error("Expected an array but received:", response.data);
      }
    } catch (error) {
      console.error("Error fetching semesters:", error);
    }
  };

  const handleEdit = (semester: Semester) => {
    setEditingSemester({ SEMESTER: semester.SEMESTER }); // ✅ Edit only semester name
    setSelectedSemesterId(semester.SEMESTER_ID);
    setShowEditModal(true);
  };

  const handleUpdate = async (updatedData: { SEMESTER: string }) => {
    if (selectedSemesterId === null) return;
    try {
      const token = localStorage.getItem("token");
      if (!token) return;

      await axiosInstance.put(
        `/api/master/semester/${selectedSemesterId}/`,
        updatedData, // ✅ Only updating semester name
        { headers: { Authorization: `Bearer ${token}` } }
      );

      setSemesters((prevSemesters) =>
        prevSemesters.map((semester) =>
          semester.SEMESTER_ID === selectedSemesterId
            ? { ...semester, SEMESTER: updatedData.SEMESTER } // ✅ Update only semester name
            : semester
        )
      );

      setShowEditModal(false);
      alert("Semester updated successfully!");
    } catch (error) {
      console.error("Error updating semester:", error);
      alert("Failed to update semester");
    }
  };

  const handleDelete = async (semesterId: number) => {
    if (!window.confirm("Are you sure you want to delete this semester?")) return;
    try {
      const token = localStorage.getItem("token");
      if (!token) return;

      await axiosInstance.delete(`/api/master/semester/${semesterId}/`, {
        headers: { Authorization: `Bearer ${token}` },
      });

      setSemesters((prevSemesters) =>
        prevSemesters.filter((semester) => semester.SEMESTER_ID !== semesterId)
      );
      alert("Semester deleted successfully!");
    } catch (error) {
      console.error("Error deleting semester:", error);
    }
  };

  return (
    <Paper elevation={3} style={{ padding: "20px" }}>
      <h3>Semester Management</h3>
      <Table striped bordered hover>
        <thead>
          <tr>
            <th>Branch Name</th>  {/* ✅ Keep for display */}
            <th>Year Name</th>    {/* ✅ Keep for display */}
            <th>Semester</th>
            <th>Active</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          {semesters.map((semester) => (
            <tr key={semester.SEMESTER_ID}>
              <td>{semester.BRANCH_NAME || "-"}</td> {/* ✅ Display Branch Name */}
              <td>{semester.YEAR_YEAR || "-"}</td>   {/* ✅ Display Year */}
              <td>{semester.SEMESTER}</td>
              <td>{semester.IS_ACTIVE ? "Yes" : "No"}</td>
              <td>
                <Button variant="primary" onClick={() => handleEdit(semester)}>
                  Edit
                </Button>
                <Button
                  variant="danger"
                  onClick={() => handleDelete(semester.SEMESTER_ID)}
                  style={{ marginLeft: "10px" }}
                >
                  Delete
                </Button>
              </td>
            </tr>
          ))}
        </tbody>
      </Table>

      {editingSemester && (
        <EditModal
          show={showEditModal}
          onHide={() => setShowEditModal(false)}
          onSave={handleUpdate}
          data={editingSemester}
          title="Edit Semester Name"
        />
      )}
    </Paper>
  );
};

export default SemesterTableView;
