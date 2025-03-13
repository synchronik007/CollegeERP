import React, { useState, useEffect } from "react";
import { Modal, Button, Form } from "react-bootstrap";

interface Semester_Duration_Interface {
  SEMESTER_DURATION_ID?: number;
}

interface EditModalProps<T extends Semester_Duration_Interface > {
  show: boolean;
  item: Partial<T> | null;
  onSave: (updatedData: T) => void;
  onClose: () => void;
  formTitle: string;
  fields: { name: keyof T; label: string; type: string; readOnly?: boolean }[];
}

const EditModal = <T extends Semester_Duration_Interface >({
  show,
  item,
  onSave,
  onClose,
  formTitle,
  fields,
}: EditModalProps<T>) => {
  
  const [formData, setFormData] = useState<Partial<T>>({
    
  });

  useEffect(() => {
    if (item) {
        setFormData(item);
    }
}, [item]);


  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const { name, value } = e.target;
    setFormData((prev) => ({
        ...prev,
        [name]: value,
    }));
  };

  const handleSubmit = () => {
    if (formData) {
      console.log("Submitting Data:", formData);
      onSave({
        ...formData,
        SEMESTER_DURATION_ID: item?.SEMESTER_DURATION_ID, // Ensure ID is retained
      } as T);
    }
  };

  return (
    <Modal show={show} onHide={onClose} backdrop="static" centered>
      <Modal.Header closeButton>
        <Modal.Title>{formTitle}</Modal.Title>
      </Modal.Header>
      <Modal.Body>
        <Form>
          {fields.map((field) => (
            <Form.Group key={String(field.name)} controlId={`form${String(field.name)}`}>
              <Form.Label>{field.label}</Form.Label>
              <Form.Control
                type={field.type}
                name={String(field.name)} 
                value={(formData[field.name] as string) || ""}
                onChange={handleChange}
                readOnly={field.readOnly}
                required
              />
            </Form.Group>
          ))}
        </Form>
      </Modal.Body>
      <Modal.Footer>
        <Button variant="secondary" onClick={onClose}>
          Cancel
        </Button>
        <Button variant="primary" onClick={handleSubmit}>
          Save Changes
        </Button>
      </Modal.Footer>
    </Modal>
  );
};

export default EditModal;
