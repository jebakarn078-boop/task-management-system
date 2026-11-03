const $ = id => document.getElementById(id);

let editingId = null;
let employees = [];


/* =========================================================
   JWT AUTHENTICATION
========================================================= */

/**
 * Get the JWT token stored in the browser.
 */
function getToken() {
    return localStorage.getItem('access_token');
}

/**
 * Get the logged-in user's role.
 */
function getUserRole() {
    return localStorage.getItem('role');
}

/**
 * Store login information.
 */
function saveLogin(data) {
    localStorage.setItem('access_token', data.access_token);
    localStorage.setItem('refresh_token', data.refresh_token);
    localStorage.setItem('user_id', data.user_id);
    localStorage.setItem('username', data.username);
    localStorage.setItem('role', data.role);
}

async function refreshAccessToken() {
    const refreshToken = localStorage.getItem('refresh_token');

    if (!refreshToken) {
        return false;
    }

    const response = await fetch('/api/refresh', {
        method: 'POST',
        headers: {
            Authorization: `Bearer ${refreshToken}`
        }
    });

    if (!response.ok) {
        return false;
    }

    const data = await response.json();

    localStorage.setItem(
        'access_token',
        data.access_token
    );

    localStorage.setItem(
        'user_id',
        data.user_id
    );

    localStorage.setItem(
        'username',
        data.username
    );

    localStorage.setItem(
        'role',
        data.role
    );

    return true;
}
function clearLogin() {
    localStorage.removeItem('access_token');
    localStorage.removeItem('refresh_token');
    localStorage.removeItem('user_id');
    localStorage.removeItem('username');
    localStorage.removeItem('role');

    window.location.href = '/';
}

async function logout() {
    const button = $('logoutButton');
    button.disabled = true;

    try {
        await api(
            '/api/logout',
            {
                method: 'POST',
                body: JSON.stringify({
                    refresh_token: localStorage.getItem('refresh_token')
                })
            },
            true,
            false
        );

        clearLogin();
    } catch (error) {
        showToast(`Logout failed: ${error.message}`);
    } finally {
        button.disabled = false;
    }
}

/* =========================================================
   SCREEN AND USER UI
========================================================= */

/**
 * Show the dashboard after successful login.
 */
function showDashboard() {
    $('loginScreen').classList.add('hidden');
    $('dashboard').classList.remove('hidden');

    updateUserUI();
}

/**
 * Show the login screen.
 */
function showLoginScreen() {
    $('dashboard').classList.add('hidden');
    $('loginScreen').classList.remove('hidden');
}

/**
 * Update the dashboard with logged-in user information.
 */
function updateUserUI() {
    const username =
        localStorage.getItem('username') || 'User';

    const role =
        localStorage.getItem('role') || 'Employee';

    $('sidebarUsername').textContent = username;
    $('sidebarRole').textContent = role;
    $('welcomeUsername').textContent = username;

    const userInitials = initials(username);

    $('userAvatar').textContent = userInitials;
    $('topAvatar').textContent = userInitials;

    /*
     * Only Admin users can create tasks.
     */
    const isAdmin = role === 'Admin';

    $('newTaskButton').classList.toggle(
        'hidden',
        !isAdmin
    );
}


/* =========================================================
   LOGIN
========================================================= */

/**
 * Login function.
 */
async function loginUser(username, password) {
    const response = await fetch('/api/login', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            username,
            password
        })
    });

    const data = await response.json();

    if (!response.ok) {
        throw new Error(
            data.errors?.join(' ') ||
            data.error ||
            data.msg ||
            'Login failed.'
        );
    }

    saveLogin(data);

    return data;
}


/* =========================================================
   API HELPER
========================================================= */

/**
 * Automatically adds the JWT to every protected API request.
 */
async function api(
    url,
    options = {},
    allowRefresh = true,
    clearOnAuthFailure = true
) {

    const token = getToken();

    const headers = {
        'Content-Type': 'application/json',
        ...(options.headers || {})
    };

    if (token) {
        headers.Authorization = `Bearer ${token}`;
    }

    let response;
    try {
        response = await fetch(url, {
            ...options,
            headers
        });
    } catch (error) {
        throw new Error('Network error. Check your connection and try again.');
    }

    let data;
    try {
        data = await response.json();
    } catch (error) {
        if (response.ok) {
            throw new Error('The server returned an invalid response.');
        }
        data = {};
    }

    /*
       Access token may have expired.
       Try to get a new access token using
       the refresh token.
    */
    if (response.status === 401 && allowRefresh) {

        const refreshed =
            await refreshAccessToken();

        if (refreshed) {

            /*
               Retry the original request
               with the new access token.
            */
            return api(
                url,
                options,
                false,
                clearOnAuthFailure
            );
        }

        /*
           Refresh token also failed.
           Log the user out.
        */
        if (clearOnAuthFailure) {
            clearLogin();
        }

        throw new Error(
            'Session expired. Please login again.'
        );
    }

    /*
       403 = authenticated but not permitted.
    */
    if (response.status === 403) {
        throw new Error(
            data.error ||
            data.msg ||
            'You do not have permission to perform this action.'
        );
    }

    if (!response.ok) {
        const statusMessages = {
            401: 'Your session is no longer valid. Please log in again.',
            404: 'The requested item was not found.',
            500: 'The server encountered an error. Please try again later.'
        };

        throw new Error(
            data.errors?.join(' ') ||
            data.error ||
            data.msg ||
            statusMessages[response.status] ||
            `Request failed with status ${response.status}.`
        );
    }

    return data;
}


/* =========================================================
   UI HELPERS
========================================================= */

/**
 * Generate initials from a name.
 */
function initials(name = '') {
    return name
        .split(' ')
        .map(part => part[0])
        .join('')
        .slice(0, 2)
        .toUpperCase();
}

/**
 * Format date for display.
 */
function dateText(date) {
    if (!date) {
        return 'â€”';
    }

    return new Date(`${date}T00:00:00`).toLocaleDateString(
        'en-US',
        {
            month: 'short',
            day: 'numeric',
            year: 'numeric'
        }
    );
}

/**
 * Show toast message.
 */
function showToast(message) {
    const toast = $('toast');

    if (!toast) {
        return;
    }

    toast.textContent = message;
    toast.classList.add('show');

    setTimeout(
        () => toast.classList.remove('show'),
        2600
    );
}

/**
 * Prevent HTML injection when displaying user data.
 */
function escapeHtml(text) {
    const div = document.createElement('div');

    div.textContent = text;

    return div.innerHTML;
}


/* =========================================================
   EMPLOYEES
========================================================= */

async function loadEmployees() {
    employees = await api('/api/employees');

    $('membersStat').textContent = employees.length;

    const options =
        '<option value="">All assignees</option>' +
        employees
            .map(
                employee => `
                    <option value="${employee.id}">
                        ${escapeHtml(employee.name)}
                    </option>
                `
            )
            .join('');

    $('employeeFilter').innerHTML = options;

    $('employeeId').innerHTML =
        '<option value="">Unassigned</option>' +
        employees
            .map(
                employee => `
                    <option value="${employee.id}">
                        ${escapeHtml(employee.name)}
                    </option>
                `
            )
            .join('');

    $('employeeList').innerHTML = employees
        .map(
            employee => `
                <article class="team-card">
                    <span class="person-dot">
                        ${initials(employee.name)}
                    </span>

                    <div>
                        <strong>
                            ${escapeHtml(employee.name)}
                        </strong>

                        <small>
                            ${escapeHtml(employee.department)}
                            Â·
                            ${escapeHtml(employee.role)}
                        </small>
                    </div>
                </article>
            `
        )
        .join('');
}


/* =========================================================
   STATISTICS
========================================================= */

async function loadStats() {
    const stats = await api('/api/stats');

    $('totalStat').textContent =
        stats.total || 0;

    $('progressStat').textContent =
        stats.in_progress || 0;

    $('completedStat').textContent =
        stats.completed || 0;

    $('completionRate').textContent =
        `${stats.total
            ? Math.round(
                (stats.completed / stats.total) * 100
            )
            : 0
        }% completion rate`;
}


/* =========================================================
   TASK FILTERS
========================================================= */

function clearTaskFilters() {
    const statusSelect = $('statusFilter');
    const employeeSelect = $('employeeFilter');
    const searchInput = $('searchInput');

    if (statusSelect) {
        statusSelect.selectedIndex = 0;
    }

    if (employeeSelect) {
        employeeSelect.selectedIndex = 0;
    }

    if (searchInput) {
        searchInput.value = '';
    }
}


/* =========================================================
   LOAD TASKS
========================================================= */

async function loadTasks() {
    const params = new URLSearchParams();

    const statusValue =
        $('statusFilter').value;

    const employeeValue =
        $('employeeFilter').value;

    const searchValue =
        $('searchInput').value.trim();

    if (statusValue) {
        params.set(
            'status',
            statusValue
        );
    }

    if (employeeValue) {
        params.set(
            'employee_id',
            employeeValue
        );
    }

    if (searchValue) {
        params.set(
            'search',
            searchValue
        );
    }

    const queryString =
        params.toString();

    const url =
        queryString
            ? `/api/tasks?${queryString}`
            : '/api/tasks';

    const tasks = await api(url);

    const isAdmin =
        getUserRole() === 'Admin';

    $('taskRows').innerHTML = tasks
        .map(
            task => `
                <tr>
                    <td data-label="Task">
                        <span class="task-title">
                            ${escapeHtml(task.title)}
                        </span>

                        <span class="task-desc">
                            ${escapeHtml(
                                task.description ||
                                'No description'
                            )}
                        </span>
                    </td>

                    <td data-label="Assignee">
                        <span class="assignee">
                            <span class="person-dot">
                                ${initials(
                                    task.employee_name ||
                                    'NA'
                                )}
                            </span>

                            ${escapeHtml(
                                task.employee_name ||
                                'Unassigned'
                            )}
                        </span>
                    </td>

                    <td data-label="Status">
                        ${
                            isAdmin
                                ? `
                                    <span
                                        class="badge ${task.status
                                            .toLowerCase()
                                            .replace(' ', '-')}"
                                    >
                                        ${escapeHtml(task.status)}
                                    </span>
                                `
                                : `
                                    <select
                                        class="task-status-control"
                                        aria-label="Update task status"
                                        data-action="status"
                                        data-task-id="${task.id}"
                                        data-previous-status="${escapeHtml(task.status)}"
                                    >
                                        ${['Pending', 'In Progress', 'Completed']
                                            .map(status => `
                                                <option
                                                    value="${status}"
                                                    ${task.status === status ? 'selected' : ''}
                                                >
                                                    ${status}
                                                </option>
                                            `)
                                            .join('')}
                                    </select>
                                `
                        }
                    </td>

                    <td data-label="Priority">
                        <span
                            class="priority ${task.priority.toLowerCase()}"
                        >
                            ${escapeHtml(task.priority)}
                        </span>
                    </td>

                    <td data-label="Due date">
                        ${dateText(task.due_date)}
                    </td>

                    <td
                        class="row-actions"
                        data-label="Actions"
                    >
                        ${
                            isAdmin
                                ? `
                                    <button
                                        type="button"
                                        class="action-button edit-button"
                                        title="Edit task"
                                        data-action="edit"
                                        data-task-id="${task.id}"
                                    >
                                        Edit
                                    </button>

                                    <button
                                        type="button"
                                        class="action-button delete-button"
                                        title="Delete task"
                                        data-action="delete"
                                        data-task-id="${task.id}"
                                    >
                                        Delete
                                    </button>
                                `
                                : `
                                    <span class="task-permission">
                                        Update status above
                                    </span>
                                `
                        }
                    </td>
                </tr>
            `
        )
        .join('');

    $('emptyState').classList.toggle(
        'hidden',
        tasks.length > 0
    );
}


/* =========================================================
   TASK MODAL
========================================================= */

function openModal(minDueDate) {
    /*
     * Restrict the date picker to valid due dates:
     * - creating: today or later (must not be before the creation date)
     * - editing: the task's existing due date or later, so a task that
     *   already has a past due date keeps that date selectable
     */
    $('dueDate').min = minDueDate || new Date().toISOString().slice(0, 10);

    $('taskModal').classList.remove('hidden');

    setTimeout(
        () => $('title').focus(),
        50
    );
}

function closeModal() {
    $('taskModal').classList.add('hidden');

    $('taskForm').reset();
    $('taskId').value = '';

    editingId = null;

    $('modalTitle').textContent =
        'Create new task';
}


/* =========================================================
   EDIT TASK
========================================================= */

async function openEdit(id) {
    try {
        /*
         * Backend authorization is still the real security.
         */
        if (getUserRole() !== 'Admin') {
            showToast(
                'Only Admin can edit tasks.'
            );

            return;
        }

        const task =
            await api(`/api/tasks/${id}`);

        editingId = id;

        $('modalTitle').textContent =
            'Edit task';

        $('taskId').value = id;

        $('title').value =
            task.title;

        $('description').value =
            task.description || '';

        $('employeeId').value =
            task.employee_id || '';

        $('dueDate').value =
            task.due_date || '';

        $('status').value =
            task.status;

        $('priority').value =
            task.priority;

        openModal(task.due_date || undefined);
    } catch (error) {
        showToast(error.message);
    }
}


/* =========================================================
   DELETE TASK
========================================================= */

async function removeTask(id) {
    if (getUserRole() !== 'Admin') {
        showToast(
            'Only Admin can delete tasks.'
        );

        return;
    }

    if (!confirm('Delete this task?')) {
        return;
    }

    try {
        await api(
            `/api/tasks/${id}`,
            {
                method: 'DELETE'
            }
        );

        showToast(
            'Task deleted'
        );

        try {
            await Promise.all([
                loadTasks(),
                loadStats()
            ]);
        } catch (error) {
            showToast(
                `Task deleted, but the dashboard could not refresh: ${error.message}`
            );
        }
    } catch (error) {
        showToast(error.message);
    }
}


/* =========================================================
   CREATE / UPDATE TASK
========================================================= */

$('taskForm').addEventListener(
    'submit',
    async event => {
        event.preventDefault();

        /*
         * Only Admin can create or update tasks.
         */
        if (getUserRole() !== 'Admin') {
            showToast(
                'Only Admin can manage tasks.'
            );

            return;
        }

        const employeeValue = $('employeeId').value;

        const data = {
            title:
                $('title').value,

            description:
                $('description').value,

            employee_id:
                employeeValue ? Number(employeeValue) : null,

            due_date:
                $('dueDate').value || null,

            status:
                $('status').value,

            priority:
                $('priority').value
        };

        const wasEditing =
            Boolean(editingId);

        try {
            await api(
                wasEditing
                    ? `/api/tasks/${editingId}`
                    : '/api/tasks',
                {
                    method:
                        wasEditing
                            ? 'PUT'
                            : 'POST',

                    body:
                        JSON.stringify(data)
                }
            );

            closeModal();

            showToast(
                wasEditing
                    ? 'Task updated'
                    : 'Task created'
            );

            await Promise.all([
                loadTasks(),
                loadStats()
            ]);
        } catch (error) {
            showToast(error.message);
        }
    }
);


/* =========================================================
   TASK BUTTONS
========================================================= */

$('taskRows').addEventListener(
    'click',
    event => {
        const button =
            event.target.closest(
                'button[data-action]'
            );

        if (!button) {
            return;
        }

        const id =
            Number(button.dataset.taskId);

        if (
            button.dataset.action ===
            'edit'
        ) {
            openEdit(id);
        }

        if (
            button.dataset.action ===
            'delete'
        ) {
            removeTask(id);
        }
    }
);

$('taskRows').addEventListener(
    'change',
    async event => {
        const select =
            event.target.closest(
                'select[data-action="status"]'
            );

        if (!select) {
            return;
        }

        const previousStatus =
            select.dataset.previousStatus;

        select.disabled = true;

        try {
            await api(
                `/api/tasks/${select.dataset.taskId}/status`,
                {
                    method: 'PATCH',
                    body: JSON.stringify({
                        status: select.value
                    })
                }
            );

            select.dataset.previousStatus =
                select.value;

            showToast('Task status updated.');

            try {
                await loadStats();
            } catch (error) {
                showToast(
                    `Status updated, but statistics could not refresh: ${error.message}`
                );
            }
        } catch (error) {
            select.value = previousStatus;
            showToast(error.message);
        } finally {
            select.disabled = false;
        }
    }
);


/* =========================================================
   GENERAL EVENTS
========================================================= */

$('newTaskButton').onclick =
    () => openModal();

$('closeModal').onclick =
    closeModal;

$('cancelButton').onclick =
    closeModal;

$('taskModal').onclick =
    event => {
        if (
            event.target.id ===
            'taskModal'
        ) {
            closeModal();
        }
    };

$('statusFilter').onchange =
    loadTasks;

$('employeeFilter').onchange =
    loadTasks;

$('searchInput').oninput =
    () => {
        clearTimeout(
            window.searchTimer
        );

        window.searchTimer =
            setTimeout(
                loadTasks,
                250
            );
    };


/* =========================================================
   VIEW ALL TASKS
========================================================= */

async function viewAllTasks() {
    clearTimeout(
        window.searchTimer
    );

    clearTaskFilters();

    await loadTasks();

    $('tasks').scrollIntoView({
        behavior: 'smooth',
        block: 'start'
    });

    showToast(
        'Showing all tasks'
    );
}

$('viewAll').addEventListener(
    'click',
    () => {
        viewAllTasks()
            .catch(
                error =>
                    showToast(
                        error.message
                    )
            );
    }
);


/* =========================================================
   HELP
========================================================= */

$('helpButton').onclick =
    () => {
        showToast(
            'Tip: use filters and search to find tasks quickly.'
        );
    };


/* =========================================================
   LOGIN FORM
========================================================= */

$('loginForm').addEventListener(
    'submit',
    async event => {
        event.preventDefault();

        const username =
            $('loginUsername').value.trim();

        const password =
            $('loginPassword').value;

        $('loginError').textContent =
            '';

        try {
            await loginUser(
                username,
                password
            );

            $('loginUsername').value =
                '';

            $('loginPassword').value =
                '';

            showDashboard();

            await Promise.all([
                loadEmployees(),
                loadStats(),
                loadTasks()
            ]);

            showToast(
                'Login successful.'
            );
        } catch (error) {
            $('loginError').textContent =
                error.message;
        }
    }
);

$('showSignupButton').addEventListener(
    'click',
    () => {
        $('loginError').textContent = '';
        $('loginForm').classList.add('hidden');
        $('signupForm').classList.remove('hidden');
        $('signupUsername').focus();
    }
);

$('showLoginButton').addEventListener(
    'click',
    () => {
        $('signupError').textContent = '';
        $('signupForm').classList.add('hidden');
        $('loginForm').classList.remove('hidden');
        $('loginUsername').focus();
    }
);

$('signupForm').addEventListener(
    'submit',
    async event => {
        event.preventDefault();

        const username =
            $('signupUsername').value.trim();

        const password =
            $('signupPassword').value;

        const passwordConfirm =
            $('signupPasswordConfirm').value;

        $('signupError').textContent = '';

        if (password !== passwordConfirm) {
            $('signupError').textContent =
                'Passwords do not match.';
            return;
        }

        try {
            const response = await fetch('/api/register', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    username,
                    password
                })
            });

            const data = await response.json();

            if (!response.ok) {
                throw new Error(
                    data.error ||
                    data.msg ||
                    'Sign up failed.'
                );
            }

            $('signupForm').reset();
            $('loginUsername').value = username;
            $('signupForm').classList.add('hidden');
            $('loginForm').classList.remove('hidden');
            $('loginError').textContent =
                'Account created. Please log in.';
        } catch (error) {
            $('signupError').textContent =
                error.message;
        }
    }
);


/* =========================================================
   LOGOUT
========================================================= */

$('logoutButton').addEventListener(
    'click',
    () => {
        logout();
    }
);


/* =========================================================
   INITIALIZATION
========================================================= */

/**
 * Check whether a JWT already exists.
 *
 * If a token exists:
 * Show the dashboard and load data.
 *
 * If no token exists:
 * Show the login screen.
 */
if (getToken()) {
    showDashboard();

    Promise.all([
        loadEmployees(),
        loadStats(),
        loadTasks()
    ])
        .catch(
            error =>
                showToast(
                    error.message
                )
        );
} else {
    showLoginScreen();
}