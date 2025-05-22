# Data Pond

**Data Pond** is a simple CRUD application for user-based file storage, built with FastAPI and Python.  
It features JWT authentication, user management (admin and regular users), and file storage in per-user folders.

<figure>
<img src="data-pond.png" alt="Data Pond" width="600">
<figcaption><b><i>- George, it is a data lake but smaller!</i></b></figcaption>
</figure>

## Features

- RESTful API documented with Swagger (`/docs`)
- Secure authentication with JWT and bcrypt-hashed passwords
- User management (add, edit, delete, search) for admins only
- Upload, list, download, and delete files per user
- Configurable file size limit (default 10MB)
- Embedded SQLite database (easy to switch to MongoDB)
- On startup, a default admin user (`admin`/`admin`) is created

## Installation

1. **Clone the repository:**
   ```sh
   git clone https://github.com/jlopezr/data-pond
   cd data-pond
   ```

2. **Install dependencies:**
   ```sh
   pip install -r requirements.txt
   ```

3. **Run the application:**
   ```sh
   uvicorn main:app --reload
   ```

4. **Access the interactive documentation:**
   - [http://localhost:8000/docs](http://localhost:8000/docs)

## Quick Usage

- **Login:**  
  Make a POST request to `/token` with username and password to get a JWT token.
  - Default user: `admin`
  - Default password: `admin`

- **Users:**  
  Only admins can create, edit, delete, and list users.

- **Files:**  
  Users can upload, list, download, and delete their own files.  
  Admins can list files for any user using the `username` parameter in `/files/`.

## Configuration

- **File size limit:**  
  Change the `MAX_FILE_SIZE` variable in `main.py`.

- **Database:**  
  Uses SQLite by default. To switch to MongoDB, adapt the configuration and models in `main.py`.

## Folder Structure

```
data-pond/
│
├── main.py
├── requirements.txt
├── README.md
└── data/
    └── {username}/
        └── your_files...
```

## License

MIT
