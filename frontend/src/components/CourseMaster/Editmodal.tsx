import React, { useState, useEffect } from "react";
import { Modal, Button, Form } from "react-bootstrap";
import axiosInstance from '../../api/axios';

interface Program {
  PROGRAM_ID: number;
  CODE: string;
  NAME: string;
}

interface Institute {
  INSTITUTE_ID: number;
  CODE: string;
  NAME: string;
}

interface EditModalProps<T extends Record<string, any>> {
  show: boolean;
  onHide: () => void;
  onSave: (updatedData: T) => void;
  data: T | null; // Allow null initially
  title: string; // Custom title for different forms
}

const EditModal = <T extends Record<string, any>>({ show, onHide, onSave, data, title }: EditModalProps<T>) => {
  const [formData, setFormData] = useState<T>({} as T); // Default empty object
  const [programs, setPrograms] = useState<Program[]>([]);
  const [institutes, setInstitutes] = useState<Institute[]>([]);
  const [errors, setErrors] = useState<{[key: string]: string}>({});

  useEffect(() => {
    if (show && data) {
      fetchInstitutes();
      fetchPrograms();
      setFormData(data);
    }
  }, [show, data]);

  const fetchInstitutes = async () => {
    try {
      const response = await axiosInstance.get('/api/master/institutes/');
      setInstitutes(response.data);
    } catch (error) {
      console.error('Error fetching institutes:', error);
      setErrors(prev => ({...prev, institute: 'Failed to load institutes'}));
    }
  };

  const fetchPrograms = async () => {
    try {
      const response = await axiosInstance.get('/api/master/program/');
      setPrograms(response.data);
    } catch (error) {
      console.error('Error fetching programs:', error);
      setErrors(prev => ({...prev, program: 'Failed to load programs'}));
    }
  };

  const handleChange = (e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement>) => {
    const { name, value } = e.target;
    setFormData(prev => ({
      ...prev,
      [name]: value
    }));
    // Clear error when field is changed
    setErrors(prev => ({...prev, [name]: ''}));
  };

  const validateForm = () => {
    const newErrors: {[key: string]: string} = {};
    
    if (!formData.CODE) {
      newErrors.code = 'Code is required';
    }
    if (!formData.NAME) {
      newErrors.name = 'Name is required';
    }
    if (title.toLowerCase() === 'branch' && !formData.PROGRAM) {
      newErrors.program = 'Program is required';
    }

    setErrors(newErrors);
    return Object.keys(newErrors).length === 0;
  };

  const handleSubmit = () => {
    if (validateForm()) {
      onSave(formData);
    }
  };

  const excludedFields = ["PROGRAM_ID", "CREATED_BY", "INSTITUTE", "DESCRIPTION", "UPDATED_BY", "IS_ACTIVE","SEMESTER_ID","PROGRAM","BRANCH_ID","BRANCH","YEAR_ID"];

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
                  name={key}
                  value={(formData[key] as string) || ""}
                  onChange={handleChange}
                  isInvalid={!!errors[key]}
                />
                <Form.Control.Feedback type="invalid">
                  {errors[key]}
                </Form.Control.Feedback>
              </Form.Group>
            ))}

          {title.toLowerCase() === 'branch' && (
            <>
              <Form.Group className="mb-3">
                <Form.Label>Program</Form.Label>
                <Form.Select
                  name="PROGRAM"
                  value={formData.PROGRAM || ''}
                  onChange={handleChange}
                  isInvalid={!!errors.program}
                >
                  <option value="">Select Program</option>
                  {programs.map(program => (
                    <option key={program.PROGRAM_ID} value={program.PROGRAM_ID}>
                      {program.CODE} - {program.NAME}
                    </option>
                  ))}
                </Form.Select>
                <Form.Control.Feedback type="invalid">
                  {errors.program}
                </Form.Control.Feedback>
              </Form.Group>

              <Form.Group className="mb-3">
                <Form.Label>Institute</Form.Label>
                <Form.Control
                  type="text"
                  value={formData.INSTITUTE_CODE || ''}
                  disabled
                  readOnly
                />
              </Form.Group>
            </>
          )}
        </Form>
      </Modal.Body>
      <Modal.Footer>
        <Button variant="secondary" onClick={onHide}>
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