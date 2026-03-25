# Syncronik Flutter Attendance Implementation Plan

## Goal
Build a production-ready Flutter attendance app using your current backend and API contract, with face-recognition pipeline on-device and server-side attendance persistence.

## Architecture Decision
- Pattern: Feature-first modular architecture with clean boundaries.
- Why: Simple enough for fast progress, scalable for camera/ML/offline later.
- Layers:
  - Presentation: pages + controllers
  - Data: API services + DTO mapping
  - Domain: entity models and workflow orchestration

## Current Build Scope (Implemented Now)
- App bootstrap and modular folder setup
- API client layer with JSON request/response handling
- Attendance service with endpoints and mock fallback
- Teacher flow:
  - Subject list
  - Subject roster
  - Attendance review and submit
- Student flow:
  - Attendance summary

## Backend API Mapping
- `GET /api/teachers/{id}/subjects` -> teacher subject list
- `GET /api/subjects/{id}/students` -> class roster + embeddings
- `PATCH /api/students/{id}/embedding` -> lazy sync embedding upload
- `POST /api/attendance/sessions` -> create lecture session
- `POST /api/attendance/sessions/{id}/records` -> submit records
- `GET /api/students/{id}/summary` -> student attendance status

## Stepwise Development Plan

### Phase 1: API Contract Finalization
1. Confirm request/response schema with backend team.
2. Add auth token flow and role-based endpoint access.
3. Add response error contract (validation, authorization, server error).

### Phase 2: Teacher Authentication + Session
1. Implement login and secure token storage.
2. Add teacher profile and assigned subject cache.
3. Add session timeout and refresh handling.

### Phase 3: Lazy Sync Engine
1. On teacher login, prefetch subjects and student roster.
2. Detect missing embeddings and generate on-device from passport photo.
3. Upload generated vectors using `PATCH /students/{id}/embedding`.
4. Add progress indicators and retry queue.

### Phase 4: Camera + Face Recognition Pipeline
1. Integrate camera capture (1-3 frames per class).
2. Integrate ML Kit face detection.
3. Convert detected faces to embeddings.
4. Compare embeddings with in-memory class roster.
5. Produce confidence scores and present/absent draft.

### Phase 5: Review and Correction UX
1. Show visual roster with recognized and unrecognized tags.
2. Allow one-tap manual override per student.
3. Show confidence and missing-face hints.

### Phase 6: Attendance Submit Reliability
1. Create session first.
2. Submit record batch second.
3. Add idempotency key to avoid duplicate submits.
4. Add offline queue and retry job.

### Phase 7: Student View
1. Student login and role routing.
2. Summary page from `GET /students/{id}/summary`.
3. Subject-wise trend chart and alert thresholds.

### Phase 8: Production Hardening
1. Encrypt tokens and sensitive cache.
2. Clear embedding RAM after submission.
3. Add telemetry for scan time and override rate.
4. Add integration tests and device matrix testing.

## Immediate Next Build Items
1. Add auth module and secure token handling.
2. Replace mock fallback with strict API mode per environment.
3. Integrate camera and ML plugins.
4. Implement lazy sync worker and local persistent queue.
