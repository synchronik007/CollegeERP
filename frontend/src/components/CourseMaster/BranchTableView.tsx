import React, { useEffect, useState } from "react";
import axiosInstance from "../../api/axios";
import { Button, Table, Badge, ButtonGroup } from "react-bootstrap";
import { Paper } from "@mui/material";
import EditModal from "../../components/CourseMaster/Editmodal";

interface Program {
  PROGRAM_ID: number;
  NAME: string;
}

interface Branch {
  BRANCH_ID: number;
  CODE: Program;
  NAME: string;
  PROGRAM_CODE: string;
  INSTITUTE_CODE: string;
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

      setBranches((prevBranches) => prevBranches.filter(branch => branch.BRANCH_ID !== branchId));

      alert("Branch deleted successfully!");
    } catch (error) {
      console.error("Error deleting branch:", error);
    }
  };

  return (
    <Paper elevation={3} style={{ padding: "20px" }}>
      <Table striped bordered hover>
        <thead>
          <tr>
            <th>Branch Code</th>
            <th>Branch Name</th>
            <th>Program Code</th>
            <th>Institute Code</th>
            <th>Status</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          {branches.map((branch) => (
            <tr key={branch.BRANCH_ID}>
              <td>{branch.CODE?.NAME || "-"}</td>
              <td>{branch.NAME}</td>
              <td>{branch.PROGRAM_CODE || "-"}</td>
              <td>{branch.INSTITUTE_CODE || "-"}</td>
              <td>
                <Badge bg={branch.IS_ACTIVE ? "success" : "danger"}>
                  {branch.IS_ACTIVE ? "Active" : "Inactive"}
                </Badge>
              </td>
              <td>
                <ButtonGroup size="sm">
                  <Button variant="primary" onClick={() => handleEdit(branch)}>
                    Edit
                  </Button>
                  <Button variant="danger" onClick={() => handleDelete(branch.BRANCH_ID)}>
                    Delete
                  </Button>
                </ButtonGroup>
              </td>
            </tr>
          ))}
        </tbody>
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
    </Paper>
  );
};

export default BranchTableView;
