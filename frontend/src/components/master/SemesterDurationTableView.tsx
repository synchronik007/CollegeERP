import React, { useState, useEffect } from "react";
import { Table, Button, Card, } from "react-bootstrap";
import axiosInstance from "../../api/axios";
import SemesterDurationForm from "./SemesterDuration";
import ReusableEditModel from "./ReusableEditModel"

interface SemesterDuration {
    SEMESTER_DURATION_ID: number;
    SEMESTER: string;
    START_DATE: string;
    END_DATE: string;
    IS_ACTIVE: boolean;
  }
const SemesterDurationTableView = () => {
    const [semesterDurations, setSemesterDurations] = useState<SemesterDuration[]>([]);
    const [viewMode, setViewMode] = useState("form");
    const [showModal, setShowModal] = useState(false);
    const [editItem, setEditItem] = useState<Partial<SemesterDuration> | null>(null);

    useEffect(() => {
        if (viewMode === "table") {
            fetchSemesterDurations();
        }
    }, [viewMode]);

    const fetchSemesterDurations = async () => {
        try {
            const token = localStorage.getItem("token");
            if (!token) return;
            
            const response = await axiosInstance.get("/api/master/semester-duration/", {
                headers: { Authorization: `Bearer ${token}` },
            });

            if (response.status === 200) {
                setSemesterDurations(response.data);
            }
        } catch (error) {
            console.error("Error fetching semester durations:", error);
        }
    };
    const handleEdit = (item: SemesterDuration) => {
        console.log("Editing Item:", item); // Debugging
        setEditItem({
          SEMESTER_DURATION_ID: item.SEMESTER_DURATION_ID, // Ensure this is set correctly
          START_DATE: item.START_DATE,
          END_DATE: item.END_DATE,
        });
        setShowModal(true);
      };
    
      const handleSave = async (updatedData: Partial<SemesterDuration>) => {
        console.log("Before Saving:", { ...updatedData, SEMESTER_DURATION_ID: editItem?.SEMESTER_DURATION_ID }); // Debugging
      
        const token = localStorage.getItem("token");
        if (!token) {
          console.error("Missing token");
          return;
        }
      
        // Ensure SEMESTER_DURATION_ID is not undefined
        const semesterDurationID = editItem?.SEMESTER_DURATION_ID;
      
        if (!semesterDurationID) {
          console.error("Missing SEMESTER_DURATION_ID:", updatedData);
          return;
        }
      
        console.log("Sending Update:", { ...updatedData, SEMESTER_DURATION_ID: semesterDurationID });
      
        try {
          const response = await axiosInstance.put(
            `/api/master/semester-duration/${semesterDurationID}/`,
            {
              START_DATE: updatedData.START_DATE,
              END_DATE: updatedData.END_DATE,
            },
            { headers: { Authorization: `Bearer ${token}` } }
          );
          console.log("Update Success:", response.data); 
          setShowModal(false);
          fetchSemesterDurations();
        } catch (error) {
          console.error("Update Error:", error);
        }
      };   
    

    const handleDelete = async (id: number) => {
        try {
            const token = localStorage.getItem("token");
            if (!token) return;
            
            await axiosInstance.delete(`/api/master/semester-duration/${id}/`, {
                headers: { Authorization: `Bearer ${token}` },
            });

            fetchSemesterDurations();
        } catch (error) {
            console.error("Error deleting semester duration:", error);
        }
    };

    const semesterFields: { name: keyof SemesterDuration; label: string; type: string; readOnly?: boolean }[] = [
        { name: "SEMESTER_DURATION_ID", label: "Semester Duration ID", type: "text", readOnly: true },
        { name: "START_DATE", label: "Start Date", type: "date" },
        { name: "END_DATE", label: "End Date", type: "date" }
      ];

    return (
        <div className="container mt-4">
            <div className="d-flex justify-content-center mb-3">
                <Button variant="primary" className="me-3" onClick={() => setViewMode("form")}>Add Semester Duration</Button>
                <Button variant="secondary" onClick={() => setViewMode("table")}>View Semester Durations</Button>
            </div>

            {viewMode === "form" ? (
                <SemesterDurationForm />
            ) : (
                <Card className="p-4 shadow-lg rounded-3 bg-white">
                    <Card.Body>
                        <h3 className="text-center mb-4">Semester Duration List</h3>
                        <Table striped bordered hover responsive>
                            <thead>
                                <tr>
                                    <th>Semester</th>
                                    <th>Start Date</th>
                                    <th>End Date</th>
                                    <th>Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                                {semesterDurations.length > 0 ? (
                                    semesterDurations.map((duration, index) => (
                                        <tr key={index}>
                                            <td>{duration.SEMESTER}</td>
                                            <td>{duration.START_DATE}</td>
                                            <td>{duration.END_DATE}</td>
                                            <td>
                                                <Button 
                                                    variant="warning" 
                                                    size="sm" 
                                                    className="me-2"
                                                    onClick={() => handleEdit(duration)}
                                                >
                                                    Edit
                                                </Button>
                                                <Button 
                                                    variant="danger" 
                                                    size="sm" 
                                                    onClick={() => handleDelete(duration.SEMESTER_DURATION_ID)}
                                                >
                                                    Delete
                                                </Button>
                                            </td>
                                        </tr>
                                    ))
                                ) : (
                                    <tr>
                                        <td colSpan={4} className="text-center">No records found</td>
                                    </tr>
                                )}
                            </tbody>
                        </Table>
                    </Card.Body>
                </Card>
            )}
                        {/* Edit Modal */}
                        {editItem && (
                <ReusableEditModel
                    show={showModal}
                    item={editItem}
                    onSave={handleSave}
                    onClose={() => setShowModal(false)}
                    formTitle="Edit Semester Duration"
                    fields={semesterFields} // ✅ Use `semesterFields`
                />
            )}

        </div>
    );
};

export default SemesterDurationTableView;
