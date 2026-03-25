import axios from "./axios";

export const employeeService = {
  createEmployee: async (formData: FormData) => {
    try {
      // Log form data for debugging (excluding file content)
      for (const [key, value] of formData.entries()) {
        if (typeof value !== "string") {
          const fileValue = value as File;
          console.log(`${key}: File - ${fileValue.name} (${fileValue.type})`);
        } else {
          console.log(`${key}:`, value);
        }
      }

      const response = await axios.post(
        "/api/establishment/employees/",
        formData,
        {
          headers: {
            "Content-Type": "multipart/form-data",
            Accept: "application/json",
          },
          transformRequest: [
            function (data) {
              return data; // Return FormData as-is
            },
          ],
          responseType: "json",
        }
      );

      return response;
    } catch (error: any) {
      console.error("API Error Details:", {
        message: error.message,
        response: error.response?.data,
        status: error.response?.status,
      });
      throw error;
    }
  },

  updateEmployee: async (employeeId: string, formData: FormData) => {
    try {
      // Log the form data being sent for debugging
      console.log("Update FormData contents:");
      for (const [key, value] of formData.entries()) {
        if (typeof value !== "string") {
          const fileValue = value as File;
          console.log(`${key}: File - ${fileValue.name}`);
        } else {
          console.log(`${key}:`, value);
        }
      }

      const response = await axios.patch(
        `/api/establishment/employees/${employeeId}/`,  // Remove API_URL prefix since axios is already configured
        formData,
        {
          headers: {
            "Content-Type": "multipart/form-data",
            Accept: "application/json",
          },
          transformRequest: [
            function (data) {
              return data; // Return FormData as-is
            },
          ],
          responseType: "json",
        }
      );

      console.log("Update Response:", response);
      return response;
    } catch (error: any) {
      console.error("Update Error Details:", {
        message: error.message,
        data: error.response?.data,
        status: error.response?.status,
        url: error.config?.url
      });
      throw error;
    }
  },

  searchEmployees: (query: string) => {
    return axios.get(`/api/establishment/employees/search/`, {  // Remove API_URL prefix
      params: { query },
    });
  },

  getEmployee: async (employeeId: string) => {
    try {
      const response = await axios.get(`/api/establishment/employees/${employeeId}/`);
      // Add detailed debugging
      console.log('API Response:', {
        data: response.data,
        designation: response.data?.DESIGNATION,
        department: response.data?.DEPARTMENT
      });
      return response;
    } catch (error) {
      console.error('Error fetching employee:', error);
      throw error;
    }
  },

  createQualification: async (employeeId: string, qualificationData: any) => {
    try {
      // Convert empty strings to null
      const formattedData = Object.entries(qualificationData).reduce((acc, [key, value]) => {
        acc[key] = value === "" ? null : value;
        return acc;
      }, {} as any);

      console.log('Sending formatted qualification data:', formattedData);

      const response = await axios.post(
        `/api/establishment/employees/${employeeId}/add_qualification/`,
        formattedData,
        {
          headers: {
            'Content-Type': 'application/json',
          }
        }
      );

      console.log('Qualification creation response:', response);
      return response;
    } catch (error: any) {
      console.error("Error creating qualification:", {
        error,
        data: error.response?.data,
        status: error.response?.status
      });
      throw error;
    }
  },

  getQualifications: async (employeeId: string) => {
    try {
      const response = await axios.get(
        `/api/establishment/employees/${employeeId}/qualifications/`
      );
      console.log('Fetched qualifications:', response.data);
      return response;
    } catch (error) {
      console.error("Error fetching qualifications:", error);
      throw error;
    }
  },

  updateQualification: async (employeeId: string, qualificationId: string, data: any) => {
    try {
      // Clean up the data
      // Clean up the data
      const cleanData = Object.entries(data).reduce((acc, [key, value]) => {
        if (value !== undefined && value !== '') { // Allow null, undefined is removed
          acc[key] = value;
        }
        return acc;
      }, {} as any);

      console.log('Updating qualification:', cleanData);

      // Updated URL structure to use query parameter
      const response = await axios.patch(
        `/api/establishment/employees/${employeeId}/update_qualification/?qualification_id=${qualificationId}`,
        cleanData,
        {
          headers: {
            'Content-Type': 'application/json',
          }
        }
      );
      return response;
    } catch (error) {
      console.error("Error updating qualification:", error);
      throw error;
    }
  }
};

export default employeeService;
