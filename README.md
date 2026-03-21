# CS-432_Assignment-2

## Document CRUD UI Operations

This application provides comprehensive UI support for all CRUD (Create, Read, Update, Delete) operations on documents through a secure, permission-based interface.

### Features

#### 1. **Create Documents** (CREATE)
- **Location**: `/documents` page - "+ Create Document" button
- **Accessibility**: All authenticated users
- **Restrictions**:
  - Regular users can only create documents in their own organization
  - Regular users can only create documents with themselves as the owner
  - Admins can create documents for any organization and user
- **Modal Form**:
  - Document Name (required)
  - Document Size, Number of Pages, File Path
  - Confidentiality Level
  - Password Protection (optional checkbox with password field)
  - Admin-only fields: Owner User ID, Organization ID

#### 2. **Read Documents** (READ)
- **Location**: `/documents` page - Documents table with metadata
- **Features**:
  - Lists all documents the user has access to
  - Shows document metadata: ID, Name, Owner, Organization, Confidentiality
  - Displays password protection status (Protected/Open tags)
  - Shows user's access level (Owner/Edit/View tags)
  - Click "View" button to open document viewer
- **Document Viewer** (`/documents/<doc_id>/view`):
  - Displays document metadata in a grid
  - Password prompt (if document is password-protected)
  - Embedded iframe to view document content
  - Access level indicator (Owner/Edit/View)

#### 3. **Update Documents** (UPDATE)
- **Location**: `/documents/<doc_id>/view` page - "Modify Document" section
- **Accessibility**: Users with Edit permission or document owners
- **Editable Fields**:
  - Document Name, Size, Number of Pages
  - File Path, Confidentiality Level
  - Owner User ID, Organization ID
  - Password Protection toggle + password field
- **Changes**:
  - Updates are saved via the secure PUT `/api/documents/<id>` endpoint
  - Real-time validation and success/error feedback
  - Restricted to users with CanEdit flag

#### 4. **Delete Documents** (DELETE)
- **Location**: `/documents/<doc_id>/view` page - "Delete Document" button (red, danger state)
- **Accessibility**: Users with Delete permission or document owners
- **Process**:
  - Displays delete confirmation modal
  - Shows document name and ID for confirmation
  - Deletion is permanent and cannot be undone
  - After deletion, user is redirected to `/documents` page
- **Button Visibility**: Only shown if user has CanDelete flag

### API Endpoints (Backend)

| Method | Endpoint | Purpose | Access Control |
|--------|----------|---------|-----------------|
| GET | `/api/documents` | List accessible documents | Permission-filtered |
| POST | `/api/documents` | Create new document | Regular users: own org only; Admins: any org |
| GET | `/api/documents/<id>` | Get document details | Permission-filtered |
| PUT | `/api/documents/<id>` | Update document | Requires Edit permission or ownership |
| DELETE | `/api/documents/<id>` | Delete document | Requires Delete permission or ownership |

### Permission Model

**Admins**: Full CRUD access to all documents

**Regular Users**: 
- **Can Create**: Documents in their organization (as self-owner only)
- **Can Read**: Own documents + documents with View/Edit/Delete permissions
- **Can Update**: Own documents + documents with Edit permission
- **Can Delete**: Own documents + documents with Delete permission

### UI Components

#### Modal Forms
- **Create Document Modal**: Fully responsive modal with conditional fields for admins
- **Delete Confirmation Modal**: Prevents accidental deletion with clear confirmation

#### Status Messages
- Success messages (green) for successful operations
- Error messages (red) with detailed error descriptions
- Loading states during API calls

#### Responsive Design
- Mobile-optimized modal and form layouts
- Touch-friendly button sizes and spacing
- Adaptive grid layouts for various screen sizes

### Workflow Examples

**Regular User - Create & Then Edit**:
1. Click "+ Create Document" on `/documents` page
2. Fill in document details (Name, Size, Confidentiality, etc.)
3. Optionally enable password protection
4. Click "Create Document" button
5. Document appears in the table after successful creation
6. Click "View" to open the document viewer
7. In the viewer, modify metadata in the "Modify Document" form
8. Click "Save Changes" to persist updates

**Regular User - View & Delete Owned Document**:
1. Navigate to `/documents` page
2. Click "View" on a document they own (Owner tag visible)
3. In the viewer, click "Delete Document" button
4. Confirm deletion in modal popup
5. After deletion, redirected back to `/documents` page

**Admin - Grant Edit Access Then Allow User to Modify**:
1. Admin creates a document via `/documents` modal
2. Admin grants "Edit" permission to another user via `/api/permissions/grant` endpoint
3. That user logs in, sees the document in their list
4. User opens the document viewer and can now modify all metadata
5. Changes are saved to the database

### Testing Guide

**Test Account**: Use credentials from `userpasswords_seed_zk9jm55e.csv`
- Example: `chinmay1` / `ztiJisWE0nAj4u`

**Test Scenarios**:
1. **Create**: Login as regular user, click Create, fill form, verify document appears
2. **Read**: Verify only accessible documents are listed; click View to open
3. **Update**: Click View → Edit metadata → Save → Verify changes persisted
4. **Delete**: Click Delete → Confirm → Verify document removed from list

---