import React, { useEffect, useState } from "react";
import axiosInstance from "../../api/axios";
import { Button, Table, TableBody, TableCell, TableContainer, TableHead, TableRow, Paper } from "@mui/material";
import EditModal from "../../components/CourseMaster/Editmodal";// ✅ Import the modal



interface Branch {
  BRANCH_ID: number;
  UNIVERSITY: string;
  INSTITUTE: string;
  PROGRAM: string;
  NAME: string;
  CODE: string;
  DESCRIPTION: string;
  IS_ACTIVE: boolean;
}

const BranchTableView: React.FC = () => {
  const [branches, setBranches] = useState<Branch[]>([]);
  const [showEditModal, setShowEditModal] = useState(false);
  const [editingBranch, setEditingBranch] = useState<Branch | null>(null);

  useEffect(() => {
    fetchBranches();
  }, []);

  const fetchBranches = async () => {
    try {
      const token = localStorage.getItem("token");
      if (!token) return;
      const response = await axiosInstance.get("/api/master/branch/", {
        headers: { Authorization: `Bearer ${token}` },
      });
      if (response.status === 200) {
        setBranches(response.data);
      }
    } catch (error) {
      console.error("Error fetching branches:", error);
    }
  };

  const handleEdit = (branch: Branch) => {
    setEditingBranch(branch);
    setShowEditModal(true);
  };

  const handleUpdate = async (updatedBranch: Branch) => {
    try {
      const token = localStorage.getItem("token");
      if (!token) return;

      await axiosInstance.put(`/api/master/branch/${updatedBranch.BRANCH_ID}/`, updatedBranch, {
        headers: { Authorization: `Bearer ${token}` },
      });

      setBranches((prevBranches) =>
        prevBranches.map((branch) =>
          branch.BRANCH_ID === updatedBranch.BRANCH_ID ? updatedBranch : branch
        )
      );

      setShowEditModal(false);
      alert("Branch updated successfully!");
    } catch (error) {
      console.error("Error updating branch:", error);
      alert("Failed to update branch");
    }
  };

  const handleDelete = async (branchId: number) => {
    if (!window.confirm("Are you sure you want to delete this branch?")) return;
    try {
      const token = localStorage.getItem("token");
      if (!token) return;
      await axiosInstance.delete(`/api/master/branch/${branchId}/`, {
        headers: { Authorization: `Bearer ${token}` },
      });
      alert("Branch deleted successfully!");
      fetchBranches();
    } catch (error) {
      console.error("Error deleting branch:", error);
    }
  };

  return (
    <TableContainer component={Paper} elevation={3}>
      <Table>
        <TableHead>
          <TableRow>
            <TableCell>Branch Name</TableCell>
            <TableCell>Code</TableCell>
            <TableCell>University</TableCell>
            <TableCell>Institute</TableCell>
            <TableCell>Program</TableCell>
            <TableCell>Description</TableCell>
            <TableCell>Active</TableCell>
            <TableCell>Actions</TableCell>
          </TableRow>
        </TableHead>
        <TableBody>
          {branches.map((branch) => (
            <TableRow key={branch.BRANCH_ID}>
              <TableCell>{branch.NAME}</TableCell>
              <TableCell>{branch.CODE}</TableCell>
              <TableCell>{branch.UNIVERSITY}</TableCell>
              <TableCell>{branch.INSTITUTE}</TableCell>
              <TableCell>{branch.PROGRAM}</TableCell>
              <TableCell>{branch.DESCRIPTION}</TableCell>
              <TableCell>{branch.IS_ACTIVE ? "Yes" : "No"}</TableCell>
              <TableCell>
                <Button variant="contained" color="primary" onClick={() => handleEdit(branch)}>
                  Edit
                </Button>
                <Button
                  variant="outlined"
                  color="secondary"
                  onClick={() => handleDelete(branch.BRANCH_ID)}
                  style={{ marginLeft: "10px" }}
                >
                  Delete
                </Button>
              </TableCell>
            </TableRow>
          ))}
        </TableBody>
      </Table>

      {editingBranch && (
        <EditModal
          show={showEditModal}
          onHide={() => setShowEditModal(false)}
          onSave={handleUpdate}
          data={editingBranch}
          title="Branch"
        />
      )}
    </TableContainer>
  );
};

export default BranchTableView;
