# Attendance System Detailed Implementation Plan (Django + React Web + Flutter Mobile)

## 1. Objective and Scope
Build a real-time attendance system using your existing Django backend, PostgreSQL database, React web app, and Flutter mobile app.

This plan covers:
- New and modified database tables for attendance workflow
- Admin web forms and table views to maintain attendance master data
- API behavior for teacher and student mobile flows
- Mobile app role-based experience for Teacher and Student only
- End-to-end flow from roster sync to attendance submission to student summary

This document is planning only. No code changes are included in this phase.

## 2. Business Requirements Interpreted from Your Request

### 2.1 Core Business Rules
- Teacher can only take attendance for allocated subjects.
- Student can only view own attendance summary.
- Attendance session is created once per lecture event.
- Attendance records are stored in bulk per session.
- Face recognition runs on mobile device, not backend.
- Missing student embedding should be generated in background and synced back.

### 2.2 Platform Rules
- Backend: Django only (no C# implementation).
- Web app: Admin operations for attendance setup and data maintenance.
- Mobile app: Teacher and Student login only.

## 3. Current System Alignment

### 3.1 Existing Strengths
- Existing auth flow in Django with login plus OTP verification.
- Existing role concept in designation and permissions.
- Existing React admin dashboard shell for form and master table management.
- Existing Flutter app now has base API, role shell, and attendance feature scaffolding.

### 3.2 Gaps to Close
- Dedicated attendance data model layer is missing.
- APIs for teacher-subject, roster, session, and records need stable implementation and response contracts.
- Admin web forms for attendance tables are not complete.
- Mobile flow must become fully strict live backend mode with robust error and queue behavior.

## 4. Data Model Plan (Django)

## 4.1 New Attendance Domain App
Create a dedicated Django app: attendance

## 4.2 Proposed Tables and Fields

### A) students table (existing entity extension)
Purpose: hold face metadata for recognition.

Fields to add or confirm:
- face_image_url: text or URL field, nullable
- face_embedding: JSON field storing 128 float array, nullable
- embedding_version: varchar, nullable
- embedding_updated_at: datetime, nullable

Indexes:
- index on student_id
- optional partial index where face_embedding is not null

### B) subjects table (existing or new master)
Purpose: subject catalog.

Fields:
- id
- subject_code (unique)
- subject_name
- branch/program linkage if needed
- semester linkage if needed
- is_active

Indexes:
- unique index on subject_code

### C) teacher_subject_allocations
Purpose: map teacher to teachable subjects and time window.

Fields:
- id
- teacher_id (FK to user or employee)
- subject_id (FK)
- academic_year_id (FK)
- term_id or semester_id (FK)
- valid_from
- valid_to
- is_active

Constraints:
- unique combination on teacher_id, subject_id, academic context

### D) student_enrollments
Purpose: map students to subjects.

Fields:
- id
- student_id (FK)
- subject_id (FK)
- academic_year_id (FK)
- term_id or semester_id (FK)
- enrollment_status
- enrolled_on

Constraints:
- unique combination on student_id, subject_id, academic context

### E) attendance_sessions
Purpose: one lecture attendance capture event.

Fields:
- id
- subject_id (FK)
- teacher_id (FK)
- session_date
- started_at
- ended_at
- source (mobile)
- client_request_id (uuid for idempotency)
- total_students_snapshot
- created_by
- created_at

Constraints:
- unique on client_request_id

### F) attendance_records
Purpose: per student result for one session.

Fields:
- id
- session_id (FK)
- student_id (FK)
- status (Present, Absent)
- confidence_score (nullable)
- marked_by (teacher id)
- is_manual_override (boolean)
- override_reason (nullable)
- created_at

Constraints:
- unique on session_id plus student_id

Indexes:
- index on student_id
- index on session_id
- index on status

## 4.3 Migration Strategy
- Step 1: add new attendance tables with nullable optional fields.
- Step 2: deploy web forms to populate subject allocations and enrollments.
- Step 3: validate data integrity with admin reports.
- Step 4: enable mobile strict live mode after baseline data exists.

## 5. Web App Plan (React Admin) for Forms and Tables

## 5.1 Admin Menu Modules to Add
New web modules under admin dashboard:
- Attendance Subject Master
- Teacher Subject Allocation
- Student Enrollment Manager
- Attendance Session Explorer
- Attendance Record Explorer
- Embedding Status Monitor

## 5.2 Form Specifications

### Subject Master Form
Fields:
- subject_code
- subject_name
- context fields (program/branch/semester)
Validation:
- code unique
- name non-empty

### Teacher Allocation Form
Fields:
- teacher
- subject
- academic year/term
- validity date range
Validation:
- no duplicate active allocation in same term

### Student Enrollment Form
Fields:
- student
- subject
- academic year/term
Validation:
- no duplicate enrollment in same term

### Embedding Status Panel
Columns:
- student id
- student name
- face image available yes/no
- embedding available yes/no
- last embedding update
Actions:
- manual trigger not required now (mobile lazy sync will handle)

### Attendance Session and Records View
Session columns:
- session id
- date/time
- subject
- teacher
- total students
Record columns:
- student
- status
- confidence
- manual override flag

## 5.3 Web API Integration Plan for Admin
- CRUD for subjects
- CRUD for allocations
- CRUD for enrollments
- read-only session and records listing for auditing

## 6. Mobile App Plan (Flutter) - Teacher and Student Only

## 6.1 Authentication and Role Control
- Use existing Django login and OTP endpoints.
- Persist token and user profile locally.
- Restrict mobile access to roles:
  - Teacher role -> teacher flow screens
  - Student role -> student summary screens
- All other roles blocked with role-not-supported message.

## 6.2 Teacher Flow (Exact Runtime)

### Phase A: Lazy Sync
1. Teacher logs in.
2. App calls teacher-subject endpoint.
3. For each selected class roster, app fetches students and embedding data.
4. If student has face_image_url but no embedding:
- app downloads image
- app generates embedding on-device
- app calls patch embedding endpoint
5. Sync progress shown silently with status indicator.

### Phase B: Classroom Scan
1. Teacher selects subject and starts session.
2. App opens camera.
3. Teacher captures 1 to 3 frames.
4. App runs on-device face detection and embedding extraction.
5. App compares detected embeddings with roster embeddings in RAM.
6. App computes best-match present set and confidence values.

### Phase C: Review and Submit
1. Show student grid with default status from matching.
2. Teacher manually toggles corrections.
3. Submit creates session then bulk records.
4. If submission fails:
- queue locally with idempotency key
- retry on next network availability or next submit action

## 6.3 Student Flow
1. Student logs in.
2. App calls student summary endpoint.
3. Display:
- overall percentage
- present classes
- total classes
- optional per-subject summary in later phase

## 7. API Contract Plan (Django)

## 7.1 Mobile Endpoints (Strict Live)
- GET /api/teachers/{id}/subjects
- GET /api/subjects/{id}/students
- PATCH /api/students/{id}/embedding
- POST /api/attendance/sessions
- POST /api/attendance/sessions/{id}/records
- GET /api/students/{id}/summary

## 7.2 Response Standards
All endpoints should return:
- status
- message
- data payload
- error details for validation failures

## 7.3 Idempotency Plan
- session create must accept client_request_id
- duplicate client_request_id returns existing session reference

## 8. Real-Time and Reliability Design

## 8.1 Real-Time Requirements
- web and mobile fetch from live database per request
- no stale hardcoded data in production mode

## 8.2 Offline Queue Rules
- queue attendance payload if session or records call fails
- queue includes teacher, subject, records, request id, timestamp
- retry policy with backoff

## 8.3 Data Safety Rules
- roster embeddings only kept in RAM during scan/review
- clear temporary recognition data after submit/cancel

## 9. Security and Access Plan
- JWT bearer for protected endpoints.
- endpoint authorization checks:
  - teacher can access only own allocations
  - teacher can submit only for allocated subject
  - student can fetch only own summary
- audit fields on attendance writes.

## 10. Detailed Delivery Phases

### Phase 1: Data and Admin Foundation
- create attendance app models and migrations
- add admin web forms and list tables
- seed and validate subject, allocation, enrollment data

### Phase 2: Core APIs
- build and test all six mobile endpoints
- enforce role and data ownership checks
- add idempotent session create behavior

### Phase 3: Mobile Teacher Core
- complete strict role login
- teacher subject list and roster fetch
- review and submit with offline queue

### Phase 4: Mobile Face Pipeline
- production-grade embedding model integration
- lazy sync generation and patch
- capture to recognition to review pipeline tuning

### Phase 5: Mobile Student View
- summary dashboard from live API
- refresh and state handling

### Phase 6: Hardening
- performance tests with class size target
- edge-case handling (no face, duplicate face, low confidence)
- audit and reporting on web

## 11. Acceptance Criteria

### Data Layer
- all six attendance tables/entities are available and validated
- subject allocation and enrollment entries can be fully managed from web

### Teacher Mobile
- teacher sees only allocated subjects
- attendance can be captured, reviewed, submitted, and persisted
- offline submit retries successfully

### Student Mobile
- student sees live attendance summary from backend

### Web Admin
- admin can create and maintain subjects, allocations, enrollments
- admin can inspect sessions and records

## 12. Risks and Mitigations
- Risk: inconsistent roster data
  - Mitigation: allocation and enrollment validation rules and duplicate prevention
- Risk: face mismatch quality
  - Mitigation: confidence threshold plus manual override
- Risk: duplicate sessions
  - Mitigation: client_request_id idempotency
- Risk: partial failure on submit
  - Mitigation: queued retry workflow and immutable audit logs

## 13. Execution Readiness Checklist
- Attendance schema approved
- Web form fields approved
- API response contract approved
- Role matrix approved (Teacher, Student)
- Mobile UX flow approved
- Go-live sequence approved

---

If approved, next step will be implementation in this order:
1) Django data models and migrations
2) React admin forms and table management
3) Django attendance APIs
4) Flutter strict live role-based flows
5) Face pipeline and offline queue production hardening
