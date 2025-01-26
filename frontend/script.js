
/* ----------------------------------
 *  System functions section
 * ---------------------------------- */



const SERVER = 'http://127.0.0.1:5000'; // Base URL for the server

async function logout() {
    console.log("Logging out...");
  
    // Get the token from localStorage
    const token = localStorage.getItem("accessToken");
    if (!token) {
      console.log("No token found, redirecting to login page...");
      window.location.href = "/login.html"; // Redirect if no token
      return;
    }
  
    try {
      // Make a logout request to the server
      await axios.post(`${SERVER}/logout`, {}, {
        headers: { Authorization: `Bearer ${token}` }
      });
  
      // If successful, remove the token and redirect
      localStorage.removeItem("accessToken");
      console.log("Logged out successfully");
      alert("You have been logged out.");
      window.location.href = "/login.html"; // Redirect to login page
    } catch (err) {
      console.error("Logout error:", err);
      alert("Logout failed. Check the console for details.");
    }
  }
  


function register() {
    const username = document.getElementById('registerUsername').value;
    const password = document.getElementById('registerPassword').value;
    const confirmPassword = document.getElementById('confirmPassword').value;
    const name = document.getElementById('name').value;
    const city = document.getElementById('city').value;
    const age = parseInt(document.getElementById('age').value, 10);
    const errorMessage = document.getElementById('registerErrorMessage');
    const successMessage = document.getElementById('registerSuccessMessage');

    // Validation checks
    if (!username || !password || !name || !city || !age) {
        errorMessage.textContent = 'All fields are required.';
        return;
    }

    if (password !== confirmPassword) {
        errorMessage.textContent = 'Passwords do not match.';
        return;
    }

    if (age < 5) {
        errorMessage.textContent = 'Minimum age is 5.';
        return;
    }

    // JSON payload for registration
    const payload = {
        username: username,
        password: password,
        name: name,
        city: city,
        age: age,
    };

    axios.post(`${SERVER}/register`, payload, {
        headers: {
            'Content-Type': 'application/json',
        },
    })
        .then(response => {
            // Show success message
            successMessage.textContent = response.data.sucess || 'Registration successful!';
            successMessage.style.display = 'block';
            errorMessage.textContent = '';
            event.preventDefault();
            window.location.href = 'index.html'
            // window.location.href = 'index.html'
        })
        .catch(error => {
            if (error.response) {
                errorMessage.textContent = error.response.data.error || 'An error occurred.';
            } else {
                errorMessage.textContent = 'Unable to connect to the server.';
            }
            successMessage.style.display = 'none';
            console.error('Registration error:', error);
        });
}



/*****************************************************
 *  LOGIN FUNCTION
 *****************************************************/
async function login() {
    const username = document.getElementById('username').value.trim();
    const password = document.getElementById('password').value.trim();
    const errorDiv = document.getElementById('loginError');

    if (!username || !password) {
        errorDiv.textContent = "Please enter a username and password.";
        return;
    }

    try {
        const payload = { username, password };
        const response = await axios.post(`${SERVER}/login`, payload, {
            headers: { 'Content-Type': 'application/json' },
        });

        const { access_token, refresh_token } = response.data;
        localStorage.setItem('accessToken', access_token);
        localStorage.setItem('refreshToken', refresh_token);

        const decoded = jwt_decode(access_token);
        // Instead of decoded.sub.role, do this:
        const userRole = decoded.role;

        const roleToUrl = {
            admin: 'admin_dashboard.html',
            librarian: 'lib_dashboard.html',
            customer: 'cust_dashboard.html',
        };

        if (roleToUrl[userRole]) {
            window.location.href = roleToUrl[userRole];
        } else {
            errorDiv.textContent = `Unknown role: ${userRole}`;
        }
    }
     catch (err) {
    console.error("Login error:", err);
    errorDiv.textContent = err.response?.data?.error || err.message || "An error occurred.";
}
}



// Render the dashboard dynamically based on role
function renderDashboard() {
    const role = getUserRole();

    if (!role) {
        document.getElementById('content').innerHTML = '<p>Error: Unable to determine user role.</p>';
        return;
    }

    if (role === 'admin') {
        renderAdminDashboard();
    } else {
        document.getElementById('content').innerHTML = `<p>Access denied for role: ${role}</p>`;
    }
}


// On page load, render the appropriate dashboard
document.addEventListener('DOMContentLoaded', () => {
    renderDashboard();
});



/***** On page load, check tokens and set up interceptors *****/
document.addEventListener('DOMContentLoaded', () => {
    // Set up the Axios interceptor for token refresh
    setupAxiosInterceptors();

    // Optionally, you can immediately verify or refresh the token:
    // checkOrRefreshToken();
});

/***** Axios Interceptor for Automatic Token Refresh *****/
function setupAxiosInterceptors() {
    axios.interceptors.request.use((config) => {
        // Attach access token to every request if available
        const accessToken = localStorage.getItem('accessToken');
        if (accessToken) {
            config.headers.Authorization = `Bearer ${accessToken}`;
        }
        return config;
    });

    axios.interceptors.response.use(
        response => response, // pass success responses through
        async (error) => {
            // If we get a 401, try to refresh the token
            if (error.response && error.response.status === 401) {
                console.warn("Access token might be expired, attempting refresh...");

                // Attempt a token refresh
                const refreshed = await attemptTokenRefresh();
                if (refreshed) {
                    // Retry the original request with the new token
                    return axios(error.config);
                } else {
                    // Refresh failed: redirect to login
                    console.error("Refresh token failed or missing. Redirecting to login...");
                    window.location.href = `${server}/index.html`;
                }
            }
            return Promise.reject(error);
        }
    );
}
/***** Attempt to Refresh the Access Token *****/
async function attemptTokenRefresh() {
    const refreshToken = localStorage.getItem('refreshToken');
    if (!refreshToken) return false; // no refresh token => cannot refresh

    try {
        // Make a POST request to /refresh
        const response = await axios.post(`${SERVER}/refresh`, null, {
            headers: {
                Authorization: `Bearer ${refreshToken}`,
            }
        });
        if (response.data.access_token) {
            localStorage.setItem('accessToken', response.data.access_token);
            console.log("Token refreshed successfully.");
            return true;
        }
    } catch (err) {
        console.error("Refresh token request failed:", err);
        return false;
    }
    return false;
}

/***** (Optional) Check or Refresh Token on page load *****/
async function checkOrRefreshToken() {
    // If you want to force-check token validity on page load, you might do a simple request:
    try {
        await axios.get(`${SERVER}/admin_read?role=all`);
    } catch (err) {
        console.error("Initial token check failed:", err);
    }
}


/***** Get User Role from JWT Token *****/
function getUserRole() {
    const accessToken = localStorage.getItem('accessToken');
    if (!accessToken) {
        return null; // no token => no role
    }

    try {
        // Decode the JWT payload
        const decoded = jwt_decode(accessToken);

        // Return the role from the token payload
        // (Assumes your token includes something like: { "role": "admin" })
        return decoded.role || null;
    } catch (err) {
        console.error("Failed to decode token:", err);
        return null;
    }
}

/***** Render the dashboard dynamically based on role *****/
function renderDashboard() {
    const role = getUserRole();

    if (!role) {
        document.getElementById('content').innerHTML = '<p>Error: Unable to determine user role.</p>';
        return;
    }

    if (role === 'admin') {
        renderAdminDashboard();
    } else {
        document.getElementById('content').innerHTML = `<p>Access denied for role: ${role}</p>`;
    }
}

// On page load, render the appropriate dashboard
document.addEventListener('DOMContentLoaded', () => {
    renderDashboard();
});

/***** On page load, check tokens and set up interceptors *****/
document.addEventListener('DOMContentLoaded', () => {
    setupAxiosInterceptors();
    // checkOrRefreshToken(); // optional
});

/***** Axios Interceptor for Automatic Token Refresh *****/
function setupAxiosInterceptors() {
    axios.interceptors.request.use((config) => {
        const accessToken = localStorage.getItem('accessToken');
        if (accessToken) {
            config.headers.Authorization = `Bearer ${accessToken}`;
        }
        return config;
    });

    axios.interceptors.response.use(
        response => response,
        async (error) => {
            if (error.response && error.response.status === 401) {
                console.warn("Access token expired? Attempting refresh...");
                const refreshed = await attemptTokenRefresh();
                if (refreshed) {
                    // Retry original request
                    return axios(error.config);
                } else {
                    // Refresh failed - redirect to login
                    window.location.href = 'index.html';
                }
            }
            return Promise.reject(error);
        }
    );
}

/***** Attempt to Refresh the Access Token *****/
async function attemptTokenRefresh() {
    const refreshToken = localStorage.getItem('refreshToken');
    if (!refreshToken) return false;

    try {
        const response = await axios.post(`${SERVER}/refresh`, null, {
            headers: {
                Authorization: `Bearer ${refreshToken}`,
            }
        });
        if (response.data.access_token) {
            localStorage.setItem('accessToken', response.data.access_token);
            console.log("Token refreshed successfully");
            return true;
        }
    } catch (err) {
        console.error("Refresh token request failed:", err);
        return false;
    }
    return false;
}

/***** (Optional) Check or Refresh Token on page load *****/
async function checkOrRefreshToken() {
    try {
        await axios.get(`${SERVER}/admin_read?role=all`);
    } catch (err) {
        console.error("Initial token check failed:", err);
    }
}





// Decode JWT and extract role
async function getUsers() {
    event.preventDefault;
    const role = document.getElementById('roleFilter').value;
    const feedback = document.getElementById('readFeedback');
    const tableBody = document.querySelector('#usersTable tbody');

    // Clear old data
    feedback.textContent = "";
    tableBody.innerHTML = "";

    try {
        // 1. Retrieve the token from local storage
        const token = localStorage.getItem("accessToken");

        // 2. Call your protected Flask route with the Bearer token
        const response = await axios.get(`${SERVER}/admin_read?role=${role}`, {
            headers: {
                Authorization: `Bearer ${token}`
            }
        });

        // 3. Process the response
        const users = response.data;
        console.log(users);

        if (!Array.isArray(users) || users.length === 0) {
            feedback.textContent = "No users found.";
            return;
        }

        users.forEach(user => {
            const row = document.createElement('tr');
            row.innerHTML = `
          <td>${user.id}</td>
          <td>${user.username}</td>
          <td>${user.role}</td>
          <td>${user.status}</td>
          <td><button onclick="toggleUserStatus(event,${user.id})">
              ${user.status ? 'Deactivate' : 'Reactivate'}
          </button></td>
        `;
            tableBody.appendChild(row);
        });

    } catch (err) {
        // Handle errors
        console.error(err);
        if (err.response) {
            feedback.textContent = err.response.data.error || "Error loading users";
        } else {
            feedback.textContent = "Server connection error";
        }
    }
}



/* ----------------------------------
 *  Admin section
 * ---------------------------------- */



/***********************************
 *        CREATE LIBRARIAN
 ***********************************/
async function createLibrarian() {
    const username = document.getElementById('librarianUsername').value;
    const password = document.getElementById('librarianPassword').value;
    const name = document.getElementById('librarianName').value;
    const city = document.getElementById('librarianCity').value;
    const age = parseInt(document.getElementById('librarianAge').value, 10);
    const feedback = document.getElementById('librarianFeedback');

    // Simple validation
    if (!username || !password || !name || !city || !age) {
        feedback.textContent = "All fields are required";
        return;
    }
    if (age < 18) {
        feedback.textContent = "Librarian must be at least 18 years old";
        return;
    }

    try {
        const payload = { username, password, name, city, age };
        const response = await axios.post(`${SERVER}/create_librarian`, payload);
        feedback.style.color = "green";
        feedback.textContent = response.data.message || "Librarian created successfully";

    } catch (err) {
        feedback.style.color = "red";
        if (err.response) {
            feedback.textContent = err.response.data.error || err.response.data.Error || "Error creating librarian";
        } else {
            feedback.textContent = "Server connection error";
        }
        console.error(err);
    }
}

/***********************************
 *        CREATE ADMIN
 ***********************************/
async function createAdmin() {
    const username = document.getElementById('adminUsername').value;
    const password = document.getElementById('adminPassword').value;
    const name = document.getElementById('adminName').value;
    const city = document.getElementById('adminCity').value;
    const age = parseInt(document.getElementById('adminAge').value, 10);
    const feedback = document.getElementById('adminFeedback');

    // Simple validation
    if (!username || !password || !name || !city || !age) {
        feedback.textContent = "All fields are required";
        return;
    }
    if (age < 18) {
        feedback.textContent = "Admin must be at least 18 years old";
        return;
    }

    try {
        const payload = { username, password, name, city, age };
        const response = await axios.post(`${SERVER}/create_admin`, payload);
        feedback.style.color = "green";
        feedback.textContent = response.data.message || "Admin created successfully";

    } catch (err) {
        feedback.style.color = "red";
        if (err.response) {
            feedback.textContent = err.response.data.error || err.response.data.Error || "Error creating admin";
        } else {
            feedback.textContent = "Server connection error";
        }
        console.error(err);
    }
}

/***********************************
 *        READ USERS
 ***********************************/
async function getUsers() {
    const role = document.getElementById('roleFilter').value;
    const feedback = document.getElementById('readFeedback');
    const tableBody = document.querySelector('#usersTable tbody');

    // Clear old data
    feedback.textContent = "";
    tableBody.innerHTML = "";

    try {
        // Retrieve the token you stored somewhere (localStorage, a cookie, etc.)
        const token = localStorage.getItem("access_token");
        // or however you’ve chosen to store/manage the token.

        // Send the token in the Authorization header
        const response = await axios.get(`${SERVER}/admin_read?role=${role}`, {
            headers: {
                Authorization: `Bearer ${token}`
            }
        });

        const users = response.data;

        if (!Array.isArray(users) || users.length === 0) {
            feedback.textContent = "No users found.";
            return;
        }

        // Populate table
        users.forEach(user => {
            const row = document.createElement('tr');
            row.innerHTML = `
          <td>${user.id}</td>
          <td>${user.username}</td>
          <td>${user.role}</td>
          <td>${user.status}</td>
          <td><button type="button" onclick="toggleUserStatus(event,${user.id})">${user.status ? 'Deactivate' : 'Reactivate'}</button></td>
        `;
            tableBody.appendChild(row);
        });

    } catch (err) {
        console.error(err);
        if (err.response) {
            feedback.textContent = err.response.data.error || "Error loading users";
        } else {
            feedback.textContent = "Server connection error";
        }
    }
}

/***********************************
 *        UPDATE USER
 ***********************************/
async function updateUser() {
    const userId = parseInt(document.getElementById('updateUserId').value, 10);
    const username = document.getElementById('updateUsername').value.trim();
    const role = document.getElementById('updateRole').value;
    const name = document.getElementById('updateName').value.trim();
    const city = document.getElementById('updateCity').value.trim();
    const ageValue = document.getElementById('updateAge').value.trim();
    const feedback = document.getElementById('updateFeedback');

    if (!userId) {
        feedback.textContent = "User ID is required";
        return;
    }

    // Build the object only with fields that have values
    let newData = {};
    if (username) newData.username = username;
    if (role) newData.role = role;
    if (name) newData.name = name;
    if (city) newData.city = city;
    if (ageValue) newData.age = parseInt(ageValue, 10);

    if (Object.keys(newData).length === 0) {
        feedback.textContent = "No fields to update.";
        return;
    }

    try {
        const payload = {
            user_id: userId,
            new_data: newData
        };
        const response = await axios.put(`${SERVER}/admin_user_update`, payload);
        feedback.style.color = "green";
        feedback.textContent = response.data.message || "User updated successfully";

    } catch (err) {
        feedback.style.color = "red";
        if (err.response) {
            feedback.textContent = err.response.data.error || "Error updating user";
        } else {
            feedback.textContent = "Server connection error";
        }
        console.error(err);
    }
}

/***********************************
 *   TOGGLE USER STATUS (DELETE)
 ***********************************/
async function toggleUserStatus(event,userId) {
    event.preventDefault
    const feedback = document.getElementById('readFeedback');

    if (!userId) {
        feedback.textContent = "Invalid user ID";
        return;
    }

    try {
        const payload = { user_id: userId };
        const response = await axios.delete(`${SERVER}/admin_delete_user`, { data: payload });
        feedback.style.color = "green";
        feedback.textContent = response.data.message || "User status updated";

        // Reload the user list automatically
        // getUsers();
    } catch (err) {
        feedback.style.color = "red"
    }
}


/* ----------------------------------
 *  Librarian section
 * ---------------------------------- */


/**
 * Helper: Get the token from localStorage
 */
function getAuthHeaders() {
  const accessToken = localStorage.getItem("accessToken");
  return {
    Authorization: "Bearer " + accessToken,
    "Content-Type": "application/json",
  };
}

/* ----------------------------------
 *  USERS CRUD
 * ---------------------------------- */

// Create a new user
async function librarianCreateUser() {
  try {
    const payload = {
      username: document.getElementById("createUserUsername").value,
      password: document.getElementById("createUserPassword").value,
      name: document.getElementById("createUserName").value,
      city: document.getElementById("createUserCity").value,
      age: parseInt(document.getElementById("createUserAge").value),
    };

    const res = await axios.post(`${SERVER}/librarian_create_user`, payload, {
      headers: getAuthHeaders(),
    });

    alert(res.data.message);
  } catch (err) {
    console.error(err);
    alert(err.response?.data?.error || err.message);
  }
}

// Read all customers
async function librarianReadUsers() {
  try {
    const res = await axios.get(`${SERVER}/librarian_read_user`, {
      headers: getAuthHeaders(),
    });

    // Clear existing list
    const userList = document.getElementById("userList");
    userList.innerHTML = "";

    // Display each user
    res.data.forEach((user) => {
      const li = document.createElement("li");
      li.textContent = `ID: ${user.id}, Username: ${user.username}, Role: ${user.role}, Status: ${user.status}, Name: ${user.name}, City: ${user.city}, Age: ${user.age}`;
      userList.appendChild(li);
    });
  } catch (err) {
    console.error(err);
    alert(err.response?.data?.error || err.message);
  }
}

// search customer by name

async function searchCustomerByName() {
    const customerName = document.getElementById('searchCustomerName').value.trim();
    const searchResults = document.getElementById('customerSearchResults');
  
    if (!customerName) {
      alert('Please enter a customer name.');
      return;
    }
  
    try {
      const token = localStorage.getItem('accessToken');
      if (!token) {
        alert('No token found! Please log in.');
        return;
      }
  
      const response = await axios.get(`${SERVER}/customers/search`, {
        headers: {
          Authorization: `Bearer ${token}`,
        },
        params: {
          name: customerName,
        },
      });
  
      console.log('Server response:', response.data);
  
      // Clear existing results
      searchResults.innerHTML = '';
  
      const customers = Array.isArray(response.data) ? response.data : [response.data];
  
      // Display results
      if (customers.length === 0 || !customers[0].user_id) {
        searchResults.innerHTML = '<li>No customers found</li>';
      } else {
        customers.forEach((customer) => {
          const li = document.createElement('li');
          li.textContent = `User ID: ${customer.user_id}, Username: ${customer.username}, 
                            Name: ${customer.name}, City: ${customer.city}, 
                            Age: ${customer.age}, Status: ${customer.status}`;
          searchResults.appendChild(li);
        });
      }
    } catch (error) {
      console.error('Error searching for customer:', error);
  
      // Handle errors
      if (error.response && error.response.status === 403) {
        alert('You are not authorized to perform this action.');
      } else {
        alert('Failed to search for the customer. Check the console for details.');
      }
    }
  }
  

// Update an existing user
async function librarianUpdateUser() {
  try {
    const userId = parseInt(document.getElementById("updateUserId").value);
    const new_data = {};

    // Build new_data only if fields are provided
    const newUsername = document.getElementById("updateUserUsername").value;
    const newName = document.getElementById("updateUserName").value;
    const newCity = document.getElementById("updateUserCity").value;
    const newAge = document.getElementById("updateUserAge").value;

    if (newUsername) new_data.username = newUsername;
    if (newName) new_data.name = newName;
    if (newCity) new_data.city = newCity;
    if (newAge) new_data.age = parseInt(newAge);

    const payload = {
      user_id: userId,
      new_data,
    };

    const res = await axios.put(`${SERVER}/librarian_update_user`, payload, {
      headers: getAuthHeaders(),
    });

    alert(res.data.message);
  } catch (err) {
    console.error(err);
    alert(err.response?.data?.error || err.message);
  }
}

// Delete (or toggle) user
async function librarianDeleteUser() {
  try {
    const userId = parseInt(document.getElementById("deleteUserId").value);
    const payload = {
      user_id: userId,
    };

    const res = await axios.delete(`${SERVER}/librarian_delete_user`, {
      headers: getAuthHeaders(),
      data: payload,
    });

    alert(res.data.message);
  } catch (err) {
    console.error(err);
    alert(err.response?.data?.error || err.message);
  }
}

/* ----------------------------------
 *  BOOKS CRUD
 * ---------------------------------- */

// Create a new book
async function librarianCreateBook() {
  try {
    const payload = {
      book_name: document.getElementById("createBookName").value,
      author: document.getElementById("createBookAuthor").value,
      year_published: parseInt(document.getElementById("createBookYear").value),
      type: parseInt(document.getElementById("createBookType").value),
      quantity: parseInt(document.getElementById("createBookQuantity").value),
    };

    const res = await axios.post(`${SERVER}/create_book`, payload, {
      headers: getAuthHeaders(),
    });

    alert(res.data.message);
  } catch (err) {
    console.error(err);
    alert(err.response?.data?.error || err.message);
  }
}

// Read (filtered) books
async function librarianReadBooks() {
  try {
    const filterValue = document.getElementById("bookFilter").value;
    const res = await axios.get(`${SERVER}/librarian_read_books?filter=${filterValue}`, {
      headers: getAuthHeaders(),
    });

    const bookList = document.getElementById("bookList");
    bookList.innerHTML = "";

    res.data.forEach((book) => {
      const li = document.createElement("li");
      li.textContent = `ID: ${book.book_id}, Name: ${book.book_name}, Author: ${book.author}, Year: ${book.year_published}, Type: ${book.type}, Qty: ${book.quantity}, Status: ${book.status}`;
      bookList.appendChild(li);
    });
  } catch (err) {
    console.error(err);
    alert(err.response?.data?.error || err.message);
  }
}

// Update a book
async function librarianUpdateBook() {
  try {
    const bookId = parseInt(document.getElementById("updateBookId").value);
    const new_data = {};

    const newName = document.getElementById("updateBookName").value;
    const newAuthor = document.getElementById("updateBookAuthor").value;
    const newYear = document.getElementById("updateBookYear").value;
    const newType = document.getElementById("updateBookType").value;
    const newQty = document.getElementById("updateBookQuantity").value;

    if (newName) new_data.book_name = newName;
    if (newAuthor) new_data.author = newAuthor;
    if (newYear) new_data.year_published = parseInt(newYear);
    if (newType) new_data.type = parseInt(newType);
    if (newQty) new_data.quantity = parseInt(newQty);

    const payload = {
      book_id: bookId,
      new_data,
    };

    const res = await axios.put(`${SERVER}/update_book`, payload, {
      headers: getAuthHeaders(),
    });

    alert(res.data.message);
  } catch (err) {
    console.error(err);
    alert(err.response?.data?.error || err.message);
  }
}

// Delete (or toggle) book
async function librarianDeleteBook() {
  try {
    const bookId = parseInt(document.getElementById("deleteBookId").value);
    const payload = {
      book_id: bookId,
    };

    const res = await axios.delete(`${SERVER}/delete_book`, {
      headers: getAuthHeaders(),
      data: payload,
    });

    alert(res.data.message);
  } catch (err) {
    console.error(err);
    alert(err.response?.data?.error || err.message);
  }
}

/* ----------------------------------
 *  LOANS CRUD
 * ---------------------------------- */

// Create new loan
async function librarianCreateLoan() {
  try {
    const payload = {
      book_id: parseInt(document.getElementById("createLoanBookId").value),
      user_id: parseInt(document.getElementById("createLoanUserId").value),
    };

    const res = await axios.put(`${SERVER}/create_loan`, payload, {
      headers: getAuthHeaders(),
    });

    alert(res.data.message);
  } catch (err) {
    console.error(err);
    alert(err.response?.data?.error || err.message);
  }
}

// Read all loans
async function librarianReadLoans() {
  try {
    const res = await axios.get(`${SERVER}/librarian_read_loans`, {
      headers: getAuthHeaders(),
    });

    const loanList = document.getElementById("loanList");
    loanList.innerHTML = "";

    if (Array.isArray(res.data)) {
      res.data.forEach((loan) => {
        const li = document.createElement("li");
        li.textContent = `Loan ID: ${loan.loan_id}, Book ID: ${loan.book_id}, User ID: ${loan.user_id}, Loan Date: ${loan.loan_date}, Return Date: ${loan.return_date}, Status: ${loan.status}, Is Late: ${loan.is_late}`;
        loanList.appendChild(li);
      });
    } else {
      // If there's an error or no loans
      loanList.innerHTML = JSON.stringify(res.data);
    }
  } catch (err) {
    console.error(err);
    alert(err.response?.data?.error || err.message);
  }
}

// Update a loan
async function librarianUpdateLoan() {
  try {
    const loanId = parseInt(document.getElementById("updateLoanId").value);

    const newBookId = document.getElementById("updateLoanBookId").value;
    const newUserId = document.getElementById("updateLoanUserId").value;
    const newLoanDate = document.getElementById("updateLoanDate").value;
    const newReturnDate = document.getElementById("updateReturnDate").value;

    const new_data = {};
    if (newBookId) new_data.book_id = parseInt(newBookId);
    if (newUserId) new_data.user_id = parseInt(newUserId);
    if (newLoanDate) new_data.loan_date = newLoanDate; // "YYYY-MM-DD"
    if (newReturnDate) new_data.return_date = newReturnDate; // "YYYY-MM-DD"

    const payload = {
      loan_id: loanId,
      new_data,
    };

    const res = await axios.put(`${SERVER}/update_loan`, payload, {
      headers: getAuthHeaders(),
    });

    alert(res.data.message);
  } catch (err) {
    console.error(err);
    alert(err.response?.data?.error || err.message);
  }
}

// Close (or toggle) loan
async function librarianCloseLoan() {
    try {
      const loanId = parseInt(document.getElementById("closeLoanId").value);
      const payload = {
        loan_id: loanId,
      };
  
      const res = await axios.delete(`${SERVER}/close_loan`, {
        headers: getAuthHeaders(),
        data: payload, // important for DELETE
      });
  
      alert(res.data.message);
    } catch (err) {
      console.error(err);
      alert(err.response?.data?.error || err.message);
    }
  }
  
// get only late loads
async function librarianGetLateLoans() {
    try {
      const token = localStorage.getItem('accessToken');
      if (!token) {
        alert('No token found! Please log in.');
        return;
      }
  
      const response = await axios.get(`${SERVER}/loans/late`, {
        headers: {
          Authorization: `Bearer ${token}`,
        },
      });
  
      const lateLoans = response.data;
      const lateLoanList = document.getElementById('lateLoanList');
  
      lateLoanList.innerHTML = ''; // Clear existing items
  
      lateLoans.forEach((loan) => {
        const li = document.createElement('li');
        li.textContent = `Loan ID: ${loan.loan_id}, Book ID: ${loan.book_id}, User ID: ${loan.user_id}, 
                          Loan Date: ${loan.loan_date}, Return Date: ${loan.return_date}, Status: ${loan.status}`;
        lateLoanList.appendChild(li);
      });
    } catch (error) {
      console.error('Error fetching late loans:', error);
      alert('Failed to fetch late loans. Check the console for details.');
    }
  }
  

//   find book by name

async function searchBookByName() {
    const bookName = document.getElementById('searchBookName').value.trim();
    const searchResults = document.getElementById('searchResults');
  
    if (!bookName) {
      alert('Please enter a book name.');
      return;
    }
  
    try {
      const token = localStorage.getItem('accessToken');
      if (!token) {
        alert('No token found! Please log in.');
        return;
      }
  
      const response = await axios.get(`${SERVER}/books/search`, {
        headers: {
          Authorization: `Bearer ${token}`,
        },
        params: {
          name: bookName,
        },
      });
  
      console.log('Server response:', response.data);
  
      // Clear existing results
      searchResults.innerHTML = '';
  
      const books = Array.isArray(response.data) ? response.data : [response.data];
  
      // Display results
      if (books.length === 0 || !books[0].book_id) {
        searchResults.innerHTML = '<li>No books found</li>';
      } else {
        books.forEach((book) => {
          const li = document.createElement('li');
          li.textContent = `Book ID: ${book.book_id}, Name: ${book.book_name}, 
                            Author: ${book.author}, Year: ${book.year_published}, 
                            Quantity: ${book.quantity}, Status: ${book.status}`;
          searchResults.appendChild(li);
        });
      }
    } catch (error) {
      console.error('Error searching for book:', error);
      alert('Failed to search for the book. Check the console for details.');
    }
  }
    


/* ----------------------------------
 *  Customer section
 * ---------------------------------- */

/* ----------------------------------
 *  View all active books
 * ---------------------------------- */



  async function viewActiveBooks() {
    const token = localStorage.getItem("accessToken");
  
    if (!token) {
      alert("Please log in to view active books.");
      return;
    }
  
    try {
      const decoded = jwt_decode(token);
      if (decoded.role !== "customer") {
        alert("Access denied. This feature is only available for customers.");
        return;
      }
  
      const response = await axios.get(`${SERVER}/user_read_books`, {
        headers: {
          Authorization: `Bearer ${token}`,
        },
      });
  
      const books = response.data;
      const bookList = document.getElementById("activeBooksList");
  
      // Clear the list
      bookList.innerHTML = "";
  
      if (books.length === 0) {
        bookList.innerHTML = "<li>No active books found.</li>";
      } else {
        books.forEach((book) => {
          const li = document.createElement("li");
          li.textContent = `Book ID: ${book.book_id}, Name: ${book.book_name}, Author: ${book.author}, 
                            Year: ${book.year_published}, Type: ${book.type}, Quantity: ${book.quantity}`;
          bookList.appendChild(li);
        });
      }
    } catch (error) {
      console.error("Error fetching active books:", error);
      alert("Failed to fetch active books.");
    }
  }
  

/* ----------------------------------
 *  View own users loans
 * ---------------------------------- */



async function viewMyLoans() {
    const token = localStorage.getItem("accessToken");
  
    if (!token) {
      alert("Please log in to view your loans.");
      return;
    }
  
    try {
      const decoded = jwt_decode(token);
      if (decoded.role !== "customer") {
        alert("Access denied. This feature is only available for customers.");
        return;
      }
  
      const response = await axios.get(`${SERVER}/user_read_loans`, {
        headers: {
          Authorization: `Bearer ${token}`,
        },
      });
  
      const loans = response.data;
      const loanList = document.getElementById("myLoansList");
  
      // Clear the list
      loanList.innerHTML = "";
  
      if (loans.error) {
        loanList.innerHTML = `<li>${loans.error}</li>`;
        return;
      }
  
      if (loans.length === 0) {
        loanList.innerHTML = "<li>No loans found.</li>";
      } else {
        loans.forEach((loan) => {
          const li = document.createElement("li");
          li.textContent = `Loan ID: ${loan.loan_id}, Book ID: ${loan.book_ID}, Loan Date: ${loan.loan_date}, 
                            Return Date: ${loan.return_date}, Status: ${loan.status ? "Returned" : "Not Returned"}, 
                            Is Late: ${loan.is_late ? "Yes" : "No"}`;
          loanList.appendChild(li);
        });
      }
    } catch (error) {
      console.error("Error fetching loans:", error);
  
      if (error.response) {
        const status = error.response.status;
        if (status === 403) {
          alert("You are not authorized to view loans.");
        } else if (status === 404) {
          alert("No loans found.");
        } else {
          alert("An error occurred. Please try again.");
        }
      } else {
        alert("Failed to connect to the server. Check your network.");
      }
    }
  }
  
  