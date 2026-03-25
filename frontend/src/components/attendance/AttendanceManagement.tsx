import React, { useCallback, useEffect, useMemo, useState } from "react";
import {
  Alert,
  Box,
  Button,
  Chip,
  CircularProgress,
  FormControl,
  Grid,
  InputLabel,
  MenuItem,
  Paper,
  Select,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Tab,
  Tabs,
  TextField,
  Typography,
} from "@mui/material";
import attendanceService, {
  AllocationItem,
  EnrollmentItem,
  SessionCreatePayload,
  SessionSummaryItem,
  StudentItem,
  SubjectItem,
  TeacherItem,
} from "../../api/attendanceService";

const tabLabel = ["Subjects", "Teacher Allocation", "Student Enrollment", "Session Explorer"];

const panelStyles = {
  borderRadius: 3,
  p: 2.5,
  border: "1px solid #e3e8ef",
  boxShadow: "0 10px 24px rgba(7, 20, 35, 0.06)",
  background:
    "linear-gradient(180deg, rgba(255,255,255,0.95) 0%, rgba(248,250,253,0.95) 100%)",
};

export default function AttendanceManagement() {
  const [tab, setTab] = useState(0);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string>("");
  const [success, setSuccess] = useState<string>("");

  const [subjects, setSubjects] = useState<SubjectItem[]>([]);
  const [teachers, setTeachers] = useState<TeacherItem[]>([]);
  const [students, setStudents] = useState<StudentItem[]>([]);
  const [allocations, setAllocations] = useState<AllocationItem[]>([]);
  const [enrollments, setEnrollments] = useState<EnrollmentItem[]>([]);
  const [sessions, setSessions] = useState<SessionSummaryItem[]>([]);

  const [subjectCode, setSubjectCode] = useState("");
  const [subjectName, setSubjectName] = useState("");
  const [selectedTeacher, setSelectedTeacher] = useState("");
  const [selectedSubjectForAllocation, setSelectedSubjectForAllocation] = useState<number | "">("");
  const [selectedStudent, setSelectedStudent] = useState("");
  const [studentSearch, setStudentSearch] = useState("");
  const [selectedSubjectForEnrollment, setSelectedSubjectForEnrollment] = useState<number | "">("");
  const [sessionSubjectFilter, setSessionSubjectFilter] = useState<number | "">("");
  const [sessionTeacher, setSessionTeacher] = useState("");
  const [sessionSubject, setSessionSubject] = useState<number | "">("");
  const [sessionDate, setSessionDate] = useState(new Date().toISOString().slice(0, 10));

  const subjectMap = useMemo(
    () => Object.fromEntries(subjects.map((s) => [s.SUBJECT_ID, `${s.SUBJECT_CODE} - ${s.SUBJECT_NAME}`])),
    [subjects]
  );

  const teacherMap = useMemo(
    () => Object.fromEntries(teachers.map((t) => [t.user_id, `${t.name} (${t.user_id})`])),
    [teachers]
  );

  const loadData = useCallback(async () => {
    setLoading(true);
    setError("");
    const results = await Promise.allSettled([
      attendanceService.listSubjects(),
      attendanceService.listTeachers(),
      attendanceService.listAllocations(),
      attendanceService.listEnrollments(),
      attendanceService.listSessions(
        typeof sessionSubjectFilter === "number" ? sessionSubjectFilter : undefined
      ),
    ]);

    const [subjectRes, teacherRes, allocationRes, enrollmentRes, sessionRes] = results;

    if (subjectRes.status === "fulfilled") setSubjects(subjectRes.value.data || []);
    if (teacherRes.status === "fulfilled") setTeachers(teacherRes.value.data || []);
    if (allocationRes.status === "fulfilled") setAllocations(allocationRes.value.data || []);
    if (enrollmentRes.status === "fulfilled") setEnrollments(enrollmentRes.value.data || []);
    if (sessionRes.status === "fulfilled") setSessions(sessionRes.value.data || []);

    const failed = [subjectRes, teacherRes, allocationRes, enrollmentRes, sessionRes].filter(
      (r) => r.status === "rejected"
    ) as PromiseRejectedResult[];

    if (failed.length > 0) {
      const first: any = failed[0]?.reason;
      setError(first?.response?.data?.message || "Some attendance sections failed to load");
    }

    setLoading(false);
  }, [sessionSubjectFilter]);

  useEffect(() => {
    loadData();
  }, [loadData]);

  useEffect(() => {
    const fetchStudents = async () => {
      try {
        const res = await attendanceService.listStudents(studentSearch.trim() || undefined);
        setStudents(res.data || []);
      } catch {
        setStudents([]);
      }
    };
    fetchStudents();
  }, [studentSearch]);

  const handleCreateSubject = async () => {
    if (!subjectCode.trim() || !subjectName.trim()) return;
    setError("");
    setSuccess("");
    try {
      await attendanceService.createSubject({
        SUBJECT_CODE: subjectCode.trim(),
        SUBJECT_NAME: subjectName.trim(),
        IS_ACTIVE: true,
      });
      setSubjectCode("");
      setSubjectName("");
      setSuccess("Subject created");
      loadData();
    } catch (e: any) {
      setError(e?.response?.data?.detail || "Failed to create subject");
    }
  };

  const handleCreateAllocation = async () => {
    if (!selectedTeacher || typeof selectedSubjectForAllocation !== "number") return;
    setError("");
    setSuccess("");
    try {
      await attendanceService.createAllocation({
        TEACHER: selectedTeacher,
        SUBJECT: selectedSubjectForAllocation,
        IS_ACTIVE: true,
      });
      setSelectedTeacher("");
      setSelectedSubjectForAllocation("");
      setSuccess("Teacher allocation created");
      loadData();
    } catch (e: any) {
      setError(e?.response?.data?.detail || "Failed to create allocation");
    }
  };

  const handleCreateEnrollment = async () => {
    if (!selectedStudent || typeof selectedSubjectForEnrollment !== "number") return;
    setError("");
    setSuccess("");
    try {
      await attendanceService.createEnrollment({
        STUDENT: selectedStudent,
        SUBJECT: selectedSubjectForEnrollment,
        IS_ACTIVE: true,
      });
      setSelectedStudent("");
      setSelectedSubjectForEnrollment("");
      setSuccess("Student enrollment created");
      loadData();
    } catch (e: any) {
      setError(e?.response?.data?.detail || "Failed to create enrollment");
    }
  };

  const handleCreateSession = async () => {
    if (!sessionTeacher || typeof sessionSubject !== "number" || !sessionDate) return;
    setError("");
    setSuccess("");
    try {
      const payload: SessionCreatePayload = {
        subject_id: sessionSubject,
        teacher_id: sessionTeacher,
        date: sessionDate,
        started_at: new Date().toISOString(),
        client_request_id: `web-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
      };
      await attendanceService.createSession(payload);
      setSuccess("Attendance session created");
      loadData();
    } catch (e: any) {
      setError(e?.response?.data?.message || "Failed to create session");
    }
  };

  return (
    <Box sx={{ p: { xs: 1, md: 2 } }}>
      <Paper sx={{ ...panelStyles, mb: 2 }}>
        <Typography variant="h5" sx={{ fontWeight: 700, color: "#17324d" }}>
          Attendance Control Center
        </Typography>
        <Typography variant="body2" color="text.secondary" sx={{ mt: 0.5 }}>
          Manage subjects, teacher assignment, student enrollment, and monitor attendance sessions.
        </Typography>
        <Box sx={{ mt: 2, display: "flex", gap: 1, flexWrap: "wrap" }}>
          <Chip label={`Subjects: ${subjects.length}`} color="primary" variant="outlined" />
          <Chip label={`Allocations: ${allocations.length}`} color="info" variant="outlined" />
          <Chip label={`Enrollments: ${enrollments.length}`} color="success" variant="outlined" />
          <Chip label={`Sessions: ${sessions.length}`} color="warning" variant="outlined" />
        </Box>
      </Paper>

      {error && <Alert severity="error" sx={{ mb: 2 }}>{error}</Alert>}
      {success && <Alert severity="success" sx={{ mb: 2 }}>{success}</Alert>}

      <Paper sx={panelStyles}>
        <Tabs value={tab} onChange={(_, value) => setTab(value)} variant="scrollable" sx={{ mb: 2 }}>
          {tabLabel.map((label) => (
            <Tab key={label} label={label} />
          ))}
        </Tabs>

        {loading ? (
          <Box sx={{ display: "flex", justifyContent: "center", py: 6 }}>
            <CircularProgress />
          </Box>
        ) : (
          <>
            {tab === 0 && (
              <>
                <Grid container spacing={2} sx={{ mb: 2 }}>
                  <Grid item xs={12} md={4}>
                    <TextField label="Subject Code" fullWidth value={subjectCode} onChange={(e) => setSubjectCode(e.target.value)} />
                  </Grid>
                  <Grid item xs={12} md={6}>
                    <TextField label="Subject Name" fullWidth value={subjectName} onChange={(e) => setSubjectName(e.target.value)} />
                  </Grid>
                  <Grid item xs={12} md={2}>
                    <Button fullWidth variant="contained" sx={{ height: "100%" }} onClick={handleCreateSubject}>
                      Add
                    </Button>
                  </Grid>
                </Grid>
                <Box sx={{ display: "grid", gap: 1 }}>
                  {subjects.map((subject) => (
                    <Paper key={subject.SUBJECT_ID} sx={{ p: 1.5, display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                      <Typography>
                        <b>{subject.SUBJECT_CODE}</b> - {subject.SUBJECT_NAME}
                      </Typography>
                      <Button color="error" onClick={async () => { await attendanceService.deleteSubject(subject.SUBJECT_ID); loadData(); }}>
                        Delete
                      </Button>
                    </Paper>
                  ))}
                </Box>
              </>
            )}

            {tab === 1 && (
              <>
                <Grid container spacing={2} sx={{ mb: 2 }}>
                  <Grid item xs={12} md={5}>
                    <FormControl fullWidth>
                      <InputLabel>Teacher</InputLabel>
                      <Select value={selectedTeacher} label="Teacher" onChange={(e) => setSelectedTeacher(e.target.value)}>
                        {teachers.map((teacher) => (
                          <MenuItem key={teacher.user_id} value={teacher.user_id}>
                            {teacher.name} ({teacher.user_id})
                          </MenuItem>
                        ))}
                      </Select>
                    </FormControl>
                  </Grid>
                  <Grid item xs={12} md={5}>
                    <FormControl fullWidth>
                      <InputLabel>Subject</InputLabel>
                      <Select
                        value={selectedSubjectForAllocation}
                        label="Subject"
                        onChange={(e) => setSelectedSubjectForAllocation(e.target.value as number)}
                      >
                        {subjects.map((subject) => (
                          <MenuItem key={subject.SUBJECT_ID} value={subject.SUBJECT_ID}>
                            {subject.SUBJECT_CODE} - {subject.SUBJECT_NAME}
                          </MenuItem>
                        ))}
                      </Select>
                    </FormControl>
                  </Grid>
                  <Grid item xs={12} md={2}>
                    <Button fullWidth variant="contained" sx={{ height: "100%" }} onClick={handleCreateAllocation}>
                      Assign
                    </Button>
                  </Grid>
                </Grid>
                <Box sx={{ height: 420 }}>
                  <TableContainer>
                    <Table size="small">
                      <TableHead>
                        <TableRow>
                          <TableCell>ID</TableCell>
                          <TableCell>Teacher</TableCell>
                          <TableCell>Subject</TableCell>
                          <TableCell align="right">Action</TableCell>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        {allocations.map((row) => (
                          <TableRow key={row.ALLOCATION_ID}>
                            <TableCell>{row.ALLOCATION_ID}</TableCell>
                            <TableCell>{row.teacher_name || teacherMap[row.TEACHER] || row.TEACHER}</TableCell>
                            <TableCell>{row.subject_name || subjectMap[row.SUBJECT] || row.SUBJECT}</TableCell>
                            <TableCell align="right">
                              <Button color="error" onClick={async () => { await attendanceService.deleteAllocation(row.ALLOCATION_ID); loadData(); }}>
                                Delete
                              </Button>
                            </TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </TableContainer>
                </Box>
              </>
            )}

            {tab === 2 && (
              <>
                <Grid container spacing={2} sx={{ mb: 2 }}>
                  <Grid item xs={12} md={4}>
                    <TextField
                      label="Search Student"
                      fullWidth
                      value={studentSearch}
                      onChange={(e) => setStudentSearch(e.target.value)}
                      placeholder="Type student id or name"
                    />
                  </Grid>
                  <Grid item xs={12} md={4}>
                    <FormControl fullWidth>
                      <InputLabel>Student</InputLabel>
                      <Select value={selectedStudent} label="Student" onChange={(e) => setSelectedStudent(e.target.value)}>
                        {students.map((student) => (
                          <MenuItem key={student.student_id} value={student.student_id}>
                            {student.student_id} - {student.name}
                          </MenuItem>
                        ))}
                      </Select>
                    </FormControl>
                  </Grid>
                  <Grid item xs={12} md={3}>
                    <FormControl fullWidth>
                      <InputLabel>Subject</InputLabel>
                      <Select
                        value={selectedSubjectForEnrollment}
                        label="Subject"
                        onChange={(e) => setSelectedSubjectForEnrollment(e.target.value as number)}
                      >
                        {subjects.map((subject) => (
                          <MenuItem key={subject.SUBJECT_ID} value={subject.SUBJECT_ID}>
                            {subject.SUBJECT_CODE} - {subject.SUBJECT_NAME}
                          </MenuItem>
                        ))}
                      </Select>
                    </FormControl>
                  </Grid>
                  <Grid item xs={12} md={1}>
                    <Button fullWidth variant="contained" sx={{ height: "100%" }} onClick={handleCreateEnrollment}>
                      Add
                    </Button>
                  </Grid>
                </Grid>
                <Box sx={{ height: 420 }}>
                  <TableContainer>
                    <Table size="small">
                      <TableHead>
                        <TableRow>
                          <TableCell>ID</TableCell>
                          <TableCell>Student</TableCell>
                          <TableCell>Subject</TableCell>
                          <TableCell align="right">Action</TableCell>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        {enrollments.map((row) => (
                          <TableRow key={row.ENROLLMENT_ID}>
                            <TableCell>{row.ENROLLMENT_ID}</TableCell>
                            <TableCell>{row.student_name || row.student_id || row.STUDENT}</TableCell>
                            <TableCell>{row.subject_name || subjectMap[row.SUBJECT] || row.SUBJECT}</TableCell>
                            <TableCell align="right">
                              <Button color="error" onClick={async () => { await attendanceService.deleteEnrollment(row.ENROLLMENT_ID); loadData(); }}>
                                Delete
                              </Button>
                            </TableCell>
                          </TableRow>
                        ))}
                      </TableBody>
                    </Table>
                  </TableContainer>
                </Box>
              </>
            )}

            {tab === 3 && (
              <>
                <Grid container spacing={2} sx={{ mb: 2 }}>
                  <Grid item xs={12} md={4}>
                    <FormControl fullWidth>
                      <InputLabel>Teacher</InputLabel>
                      <Select
                        value={sessionTeacher}
                        label="Teacher"
                        onChange={(e) => setSessionTeacher(e.target.value)}
                      >
                        {teachers.map((teacher) => (
                          <MenuItem key={teacher.user_id} value={teacher.user_id}>
                            {teacher.name} ({teacher.user_id})
                          </MenuItem>
                        ))}
                      </Select>
                    </FormControl>
                  </Grid>
                  <Grid item xs={12} md={4}>
                    <FormControl fullWidth>
                      <InputLabel>Subject</InputLabel>
                      <Select
                        value={sessionSubject}
                        label="Subject"
                        onChange={(e) => setSessionSubject(e.target.value as number)}
                      >
                        {subjects.map((subject) => (
                          <MenuItem key={subject.SUBJECT_ID} value={subject.SUBJECT_ID}>
                            {subject.SUBJECT_CODE} - {subject.SUBJECT_NAME}
                          </MenuItem>
                        ))}
                      </Select>
                    </FormControl>
                  </Grid>
                  <Grid item xs={12} md={2}>
                    <TextField
                      fullWidth
                      type="date"
                      label="Date"
                      InputLabelProps={{ shrink: true }}
                      value={sessionDate}
                      onChange={(e) => setSessionDate(e.target.value)}
                    />
                  </Grid>
                  <Grid item xs={12} md={2}>
                    <Button fullWidth variant="contained" sx={{ height: "100%" }} onClick={handleCreateSession}>
                      Create Session
                    </Button>
                  </Grid>
                </Grid>

                <Box sx={{ mb: 2, maxWidth: 340 }}>
                  <FormControl fullWidth>
                    <InputLabel>Filter by Subject</InputLabel>
                    <Select
                      value={sessionSubjectFilter}
                      label="Filter by Subject"
                      onChange={(e) => setSessionSubjectFilter(e.target.value as number | "")}
                    >
                      <MenuItem value="">All Subjects</MenuItem>
                      {subjects.map((subject) => (
                        <MenuItem key={subject.SUBJECT_ID} value={subject.SUBJECT_ID}>
                          {subject.SUBJECT_CODE} - {subject.SUBJECT_NAME}
                        </MenuItem>
                      ))}
                    </Select>
                  </FormControl>
                </Box>
                <Box sx={{ height: 500 }}>
                  <TableContainer>
                    <Table size="small">
                      <TableHead>
                        <TableRow>
                          <TableCell>Session</TableCell>
                          <TableCell>Date</TableCell>
                          <TableCell>Subject</TableCell>
                          <TableCell>Teacher</TableCell>
                          <TableCell>Total</TableCell>
                          <TableCell>Present</TableCell>
                          <TableCell>Present %</TableCell>
                        </TableRow>
                      </TableHead>
                      <TableBody>
                        {sessions.length === 0 && (
                          <TableRow>
                            <TableCell colSpan={7} align="center" sx={{ py: 3, color: "text.secondary" }}>
                              No sessions yet. Create one above to populate explorer.
                            </TableCell>
                          </TableRow>
                        )}
                        {sessions.map((row) => {
                          const pct = row.total_records ? Math.round((row.present_records / row.total_records) * 100) : 0;
                          return (
                            <TableRow key={row.session_id}>
                              <TableCell>{row.session_id}</TableCell>
                              <TableCell>{row.session_date}</TableCell>
                              <TableCell>{row.subject_name}</TableCell>
                              <TableCell>{row.teacher_name}</TableCell>
                              <TableCell>{row.total_records}</TableCell>
                              <TableCell>{row.present_records}</TableCell>
                              <TableCell>{pct}%</TableCell>
                            </TableRow>
                          );
                        })}
                      </TableBody>
                    </Table>
                  </TableContainer>
                </Box>
              </>
            )}
          </>
        )}
      </Paper>
    </Box>
  );
}
