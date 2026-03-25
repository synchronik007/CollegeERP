import axiosInstance from "./axios";

export interface SubjectItem {
  SUBJECT_ID: number;
  SUBJECT_CODE: string;
  SUBJECT_NAME: string;
  IS_ACTIVE: boolean;
}

export interface TeacherItem {
  user_id: string;
  name: string;
  username: string;
}

export interface StudentItem {
  student_id: string;
  name: string;
}

export interface AllocationItem {
  ALLOCATION_ID: number;
  TEACHER: string;
  SUBJECT: number;
  IS_ACTIVE: boolean;
  teacher_id?: string;
  teacher_name?: string;
  subject_id?: number;
  subject_name?: string;
}

export interface EnrollmentItem {
  ENROLLMENT_ID: number;
  STUDENT: string;
  SUBJECT: number;
  IS_ACTIVE: boolean;
  student_id?: string;
  student_name?: string;
  subject_id?: number;
  subject_name?: string;
}

export interface SessionSummaryItem {
  session_id: number;
  subject_id: number;
  subject_name: string;
  teacher_id: string;
  teacher_name: string;
  session_date: string;
  started_at: string;
  total_records: number;
  present_records: number;
}

export interface SessionCreatePayload {
  subject_id: number;
  teacher_id: string;
  date: string;
  started_at: string;
  client_request_id: string;
}

const attendanceService = {
  listSubjects: () => axiosInstance.get<SubjectItem[]>("/api/attendance/admin/subjects/"),
  createSubject: (payload: Partial<SubjectItem>) =>
    axiosInstance.post<SubjectItem>("/api/attendance/admin/subjects/", payload),
  updateSubject: (id: number, payload: Partial<SubjectItem>) =>
    axiosInstance.put<SubjectItem>(`/api/attendance/admin/subjects/${id}/`, payload),
  deleteSubject: (id: number) => axiosInstance.delete(`/api/attendance/admin/subjects/${id}/`),

  listTeachers: () => axiosInstance.get<TeacherItem[]>("/api/attendance/admin/teachers"),
  listStudents: (query?: string) =>
    axiosInstance.get<StudentItem[]>("/api/attendance/admin/students", {
      params: query ? { q: query } : undefined,
    }),

  listAllocations: () =>
    axiosInstance.get<AllocationItem[]>("/api/attendance/admin/teacher-subject-allocations/"),
  createAllocation: (payload: Partial<AllocationItem>) =>
    axiosInstance.post<AllocationItem>("/api/attendance/admin/teacher-subject-allocations/", payload),
  deleteAllocation: (id: number) =>
    axiosInstance.delete(`/api/attendance/admin/teacher-subject-allocations/${id}/`),

  listEnrollments: () =>
    axiosInstance.get<EnrollmentItem[]>("/api/attendance/admin/student-enrollments/"),
  createEnrollment: (payload: Partial<EnrollmentItem>) =>
    axiosInstance.post<EnrollmentItem>("/api/attendance/admin/student-enrollments/", payload),
  deleteEnrollment: (id: number) =>
    axiosInstance.delete(`/api/attendance/admin/student-enrollments/${id}/`),

  listSessions: (subjectId?: number) =>
    axiosInstance.get<SessionSummaryItem[]>("/api/attendance/admin/sessions", {
      params: subjectId ? { subject_id: subjectId } : undefined,
    }),
  createSession: (payload: SessionCreatePayload) =>
    axiosInstance.post<{ session_id: number; id: number; message: string }>("/api/attendance/sessions", payload),
};

export default attendanceService;
