import React, { useState, useEffect } from "react";
import { Modal, Button, Form } from "react-bootstrap";

interface EditModalProps<T extends Record<string, any>> {
  show: boolean;
  onHide: () => void;
  onSave: (updatedData: T) => void;
  data: T | null; // Allow null initially
  title: string; // Custom title for different forms
}

const EditModal = <T extends Record<string, any>>({ show, onHide, onSave, data, title }: EditModalProps<T>) => {
  const [formData, setFormData] = useState<T>({} as T); // Default empty object

  useEffect(() => {
    if (data) {
      setFormData(data);
    }
  }, [data]);

  const handleChange = (key: keyof T, value: string) => {
    setFormData((prev) => ({ ...prev, [key]: value }));
  };

  const handleSave = () => {
    if (formData) {
      onSave(formData);
      onHide();
    }
  };

  const excludedFields = ["PROGRAM_ID", "CREATED_BY", "INSTITUTE", "DESCRIPTION", "UPDATED_BY", "IS_ACTIVE", 'PROGRAM','BRANCH_ID'];

  return (
    <Modal show={show} onHide={onHide} centered>
      <Modal.Header closeButton>
        <Modal.Title>Edit {title}</Modal.Title> {/* Dynamic Title */}
      </Modal.Header>
      <Modal.Body>
        <Form>
          {Object.keys(formData)
            .filter((key) => !excludedFields.includes(key)) // Remove unwanted fields
            .map((key) => (
              <Form.Group key={key} className="mb-3">
                <Form.Label>{key.replace("_", " ")}</Form.Label>
                <Form.Control
                  type="text"
                  value={(formData[key] as string) || ""}
                  onChange={(e) => handleChange(key as keyof T, e.target.value)}
                />
              </Form.Group>
            ))}
        </Form>
      </Modal.Body>
      <Modal.Footer>
        <Button variant="secondary" onClick={onHide}>
          Cancel
        </Button>
        <Button variant="primary" onClick={handleSave}>
          Save Changes
        </Button>
      </Modal.Footer>
    </Modal>
  );
};

export default EditModal;
